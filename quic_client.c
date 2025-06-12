// Compile with: gcc chownat_quic_client.c -o chownat_quic_client -lmsquic -lpthread

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
#include <netinet/in.h>
#include <msquic.h> 

// CONFIG
#define CONTROL_PORT 50071
#define QUIC_PORT 50072
#define REMOTE_ADDR "127.0.0.1"
#define BUFFER_SIZE 4096

// MSQUIC globals
const QUIC_API_TABLE* MsQuic;
HQUIC Registration = NULL;
HQUIC Configuration = NULL;
HQUIC Connection = NULL;
HQUIC QuicStream = NULL;

// Forward declarations
void cleanup();

QUIC_STATUS QUIC_API ClientStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            write(1, Event->RECEIVE.Buffers->Buffer, Event->RECEIVE.Buffers->Length); 
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ClientConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("QUIC: Connected to server\n");
            MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, NULL, &QuicStream);
            MsQuic->StreamStart(QuicStream, QUIC_STREAM_START_FLAG_IMMEDIATE);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("QUIC: Connection shutdown\n");
            MsQuic->ConnectionClose(Connection);
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

    QUIC_SETTINGS Settings = {0};

    if (QUIC_FAILED(MsQuic->ConfigurationOpen(
            Registration,
            &alpn, 1,
            &Settings, sizeof(Settings),
            NULL,
            &Configuration))) {
        fprintf(stderr, "ConfigurationOpen failed\n");
        exit(1);
    }

    QUIC_CREDENTIAL_CONFIG CredConfig = {0};
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed!\n");
        exit(1);
    }

}

void msquic_cleanup() {
    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
}

void start_quic_client(const char* remote_addr, uint16_t port) {
    if (QUIC_FAILED(MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
        fprintf(stderr, "ConnectionOpen failed\n");
        exit(1);
    }
    QUIC_STATUS status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, remote_addr, port);
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "ConnectionStart failed: 0x%x\n", status);
        exit(1);
    }
    printf("QUIC: Connecting to %s:%d\n", remote_addr, port);
}

// UDP handshake to punch NAT hole
void udp_handshake(const char* remote_addr, uint16_t port) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    inet_pton(AF_INET, remote_addr, &remote.sin_addr);
    char buf[128];
    printf("Sending UDP connect to server...\n");
    sendto(udp_sock, "01\n", 3, 0, (struct sockaddr*)&remote, sizeof(remote));
    socklen_t rlen = sizeof(remote);
    int n = recvfrom(udp_sock, buf, sizeof(buf)-1, 0, (struct sockaddr*)&remote, &rlen);
    if (n > 0 && strncmp(buf, "03\n", 3) == 0) {
        printf("UDP handshake complete\n");
    } else {
        fprintf(stderr, "Failed UDP handshake\n");
        exit(1);
    }
    close(udp_sock);
}

int main() {
    udp_handshake(REMOTE_ADDR, CONTROL_PORT);
    msquic_init();
    start_quic_client(REMOTE_ADDR, QUIC_PORT);
    while (1) {
        char data[BUFFER_SIZE];
        ssize_t nread = read(0, data, sizeof(data));
        if (nread > 0 && QuicStream) {
            QUIC_BUFFER buf = {.Length = nread, .Buffer = (uint8_t*)data};
            MsQuic->StreamSend(QuicStream, &buf, 1, QUIC_SEND_FLAG_NONE, NULL);
        }
    }
    msquic_cleanup();
    return 0;
}
