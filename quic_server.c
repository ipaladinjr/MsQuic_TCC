// Compile with: gcc chownat_quic_server.c -o chownat_quic_server -lmsquic -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <msquic.h> // Make sure this path is correct for your system

// CONFIG
#define CONTROL_PORT 50071
#define QUIC_PORT 50072
#define LOCAL_PORT 80
#define REMOTE_ADDR "127.0.0.1"
#define BUFFER_SIZE 4096
#define CERT_FILE "server_cert.pem"
#define KEY_FILE "server_key.pem"

// MSQUIC globals
const QUIC_API_TABLE* MsQuic;
HQUIC Registration = NULL;
HQUIC Configuration = NULL;
HQUIC Listener = NULL;
HQUIC QuicStream = NULL;

// Forward declarations
void cleanup();

QUIC_STATUS QUIC_API ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            write(1, Event->RECEIVE.Buffers->Buffer, Event->RECEIVE.Buffers->Length); // Print to stdout
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("QUIC: Connection established\n");
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("QUIC: Connection shutdown\n");
            MsQuic->ConnectionClose(Connection);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            printf("QUIC: Stream started\n");
            QuicStream = Event->PEER_STREAM_STARTED.Stream;
            MsQuic->SetCallbackHandler(QuicStream, (void*)ServerStreamCallback, NULL);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

void msquic_init() {
    if (QUIC_FAILED(MsQuicOpen2(&MsQuic))) {
        fprintf(stderr, "MsQuicOpen2 failed\n");
        exit(1);
    }
    QUIC_BUFFER alpn = {4, (uint8_t*)"chow"};

    if (QUIC_FAILED(MsQuic->RegistrationOpen(NULL, &Registration))) {
        fprintf(stderr, "RegistrationOpen failed\n");
        exit(1);
    }
    if (QUIC_FAILED(MsQuic->ConfigurationOpen(
            Registration,
            &alpn, 1,
            NULL, 0,
            NULL,
            &Configuration))) {
        fprintf(stderr, "ConfigurationOpen failed\n");
        exit(1);
    }

    // --- Server: Load self-signed certificate via pointer struct ---
    static QUIC_CERTIFICATE_FILE cert_file = {0};
    cert_file.CertificateFile = CERT_FILE;
    cert_file.PrivateKeyFile = KEY_FILE;

    QUIC_CREDENTIAL_CONFIG cred_config = {0};
    cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    cred_config.CertificateFile = &cert_file;

    if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(Configuration, &cred_config))) {
        fprintf(stderr, "ConfigurationLoadCredential failed\n");
        exit(1);
    }
}

void start_quic_listener(uint16_t port) {
    if (QUIC_FAILED(MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        fprintf(stderr, "ListenerOpen failed\n");
        exit(1);
    }
    QUIC_ADDR addr = {0};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, port);
    QUIC_BUFFER alpn = {4, (uint8_t*)"chow"};
    if (QUIC_FAILED(MsQuic->ListenerStart(Listener, &alpn, 1, &addr))) {
        fprintf(stderr, "ListenerStart failed\n");
        exit(1);
    }
    printf("QUIC: Listening on port %d\n", port);
}

void msquic_cleanup() {
    if (Listener) MsQuic->ListenerClose(Listener);
    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
}

// UDP hole-punch control logic, simplified
void control_loop() {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in local = {0}, remote = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons(CONTROL_PORT);
    local.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        perror("bind");
        exit(1);
    }
    socklen_t rlen = sizeof(remote);
    char buf[128];
    printf("Waiting for client UDP handshake...\n");
    while (1) {
        int n = recvfrom(udp_sock, buf, sizeof(buf)-1, 0, (struct sockaddr*)&remote, &rlen);
        if (n > 0 && strncmp(buf, "01\n", 3) == 0) {
            printf("Received connect request from client\n");
            sendto(udp_sock, "03\n", 3, 0, (struct sockaddr*)&remote, rlen); // handshake
            break;
        }
    }
    close(udp_sock);
    printf("UDP handshake done, starting QUIC...\n");
    start_quic_listener(QUIC_PORT);
    printf("Ready for QUIC connections\n");
    // Demo: read stdin and send to client via QUIC
    while (1) {
        char data[BUFFER_SIZE];
        ssize_t nread = read(0, data, sizeof(data));
        if (nread > 0 && QuicStream) {
            QUIC_BUFFER buf = {.Length = nread, .Buffer = (uint8_t*)data};
            MsQuic->StreamSend(QuicStream, &buf, 1, QUIC_SEND_FLAG_NONE, NULL);
        }
    }
}

int main() {
    msquic_init();
    control_loop();
    msquic_cleanup();
    return 0;
}
