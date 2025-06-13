// Compile with: gcc quicserver.c -o quicserver -lmsquic -lpthread

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
#include <msquic.h>

// CONFIG
#define QUIC_PORT 50072
#define LOCAL_TCP_PORT 8080
#define BUFFER_SIZE 4096
#define CERT_FILE "server_cert.pem"
#define KEY_FILE "server_key.pem"

// MSQUIC globals
const QUIC_API_TABLE* MsQuic;
HQUIC Registration = NULL;
HQUIC Configuration = NULL;
HQUIC Listener = NULL;
HQUIC QuicStream = NULL;
HQUIC CurrentConnection = NULL;

// TCP relay globals
int tcp_server = -1;
int tcp_client = -1;

void close_tcp_client() {
    if (tcp_client != -1) {
        printf("[TCP] Closing connection with local TCP client.\n");
        close(tcp_client);
        tcp_client = -1;
    }
}

int setup_local_tcp_server(uint16_t port) {
    printf("[TCP] Creating local TCP server socket on 127.0.0.1:%d\n", port);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[TCP][ERROR] socket");
        exit(1);
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[TCP][ERROR] bind");
        close(sock);
        exit(1);
    }
    if (listen(sock, 5) < 0) {
        perror("[TCP][ERROR] listen");
        close(sock);
        exit(1);
    }
    printf("[TCP] Local TCP server listening.\n");
    return sock;
}

void msquic_cleanup() {
    printf("[CLEANUP] Cleaning up msquic resources...\n");
    if (Listener) MsQuic->ListenerClose(Listener);
    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
    printf("[CLEANUP] Done cleaning up msquic resources.\n");
}

QUIC_STATUS QUIC_API ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    printf("[QUIC] Stream event type: %d\n", Event->Type);
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            printf("[QUIC] Received %llu bytes from remote peer. Relaying to TCP client...\n",
                   (unsigned long long)Event->RECEIVE.TotalBufferLength);
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                printf("[QUIC] Processing buffer %u of %u (length: %u)\n", 
                       i+1, Event->RECEIVE.BufferCount, Event->RECEIVE.Buffers[i].Length);
                if (tcp_client != -1) {
                    ssize_t nwritten = write(tcp_client,
                        Event->RECEIVE.Buffers[i].Buffer,
                        Event->RECEIVE.Buffers[i].Length);
                    if (nwritten < 0) {
                        perror("[TCP][ERROR] write to tcp_client");
                        close_tcp_client();
                    } else {
                        printf("[RELAY] Wrote %zd bytes to TCP client.\n", nwritten);
                    }
                } else {
                    printf("[RELAY][WARN] No TCP client connected, data dropped.\n");
                }
            }
            MsQuic->StreamReceiveComplete(Stream, Event->RECEIVE.TotalBufferLength);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[QUIC] Stream shutdown complete. Closing stream handle.\n");
            MsQuic->StreamClose(Stream);
            if (Stream == QuicStream) {
                QuicStream = NULL;
            }
            break;
        default:
            printf("[QUIC] Unhandled stream event type: %d\n", Event->Type);
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
    printf("[QUIC] Connection event type: %d\n", Event->Type);
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[QUIC] Connection established (client handshake complete).\n");
            CurrentConnection = Connection;
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            printf("[QUIC] *** PEER_STREAM_STARTED EVENT RECEIVED! ***\n");
            printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
            QuicStream = Event->PEER_STREAM_STARTED.Stream;
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
            printf("[QUIC] Stream callback handler set successfully.\n");
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("[QUIC] Connection shutdown complete.\n");
            MsQuic->ConnectionClose(Connection);
            if (Connection == CurrentConnection) {
                CurrentConnection = NULL;
                QuicStream = NULL;
            }
            break;
        default:
            printf("[QUIC] Unhandled connection event type: %d\n", Event->Type);
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
    printf("[QUIC] Listener event type: %d\n", Event->Type);
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            printf("[QUIC] New QUIC connection received. Setting configuration and callback handler.\n");
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            printf("[QUIC] Connection callback handler set successfully.\n");
            QUIC_STATUS status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            if (QUIC_FAILED(status)) {
                printf("[QUIC][ERROR] Failed to set connection configuration: 0x%x\n", status);
            } else {
                printf("[QUIC] Connection configuration set successfully.\n");
            }
            return status;
        default:
            printf("[QUIC] Unhandled listener event type: %d\n", Event->Type);
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

void msquic_init() {
    printf("[QUIC] Initializing msquic API...\n");
    if (QUIC_FAILED(MsQuicOpen2(&MsQuic))) {
        fprintf(stderr, "[QUIC][ERROR] MsQuicOpen2 failed\n");
        exit(1);
    }
    QUIC_BUFFER alpn = {4, (uint8_t*)"chow"};

    printf("[QUIC] Opening registration context...\n");
    if (QUIC_FAILED(MsQuic->RegistrationOpen(NULL, &Registration))) {
        fprintf(stderr, "[QUIC][ERROR] RegistrationOpen failed\n");
        exit(1);
    }

    // **ADD STREAM SETTINGS**
    QUIC_SETTINGS Settings = {0};
    Settings.PeerBidiStreamCount = 10;     // Allow 10 bidirectional streams from peer
    Settings.PeerUnidiStreamCount = 10;    // Allow 10 unidirectional streams from peer
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;



    printf("[QUIC] Opening configuration context...\n");
    if (QUIC_FAILED(MsQuic->ConfigurationOpen(
            Registration,
            &alpn, 1,
            &Settings, sizeof(Settings),  // **PASS SETTINGS**
            NULL,
            &Configuration))) {
        fprintf(stderr, "[QUIC][ERROR] ConfigurationOpen failed\n");
        exit(1);
    }


    printf("[QUIC] Loading server certificate and key for TLS...\n");
    static QUIC_CERTIFICATE_FILE cert_file = {0};
    cert_file.CertificateFile = CERT_FILE;
    cert_file.PrivateKeyFile = KEY_FILE;

    QUIC_CREDENTIAL_CONFIG cred_config = {0};
    cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    cred_config.CertificateFile = &cert_file;

    if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(Configuration, &cred_config))) {
        fprintf(stderr, "[QUIC][ERROR] ConfigurationLoadCredential failed\n");
        exit(1);
    }
   printf("[QUIC] msquic API and TLS configuration loaded successfully.\n");
   printf("[QUIC] Server configured to accept up to 10 bidirectional and 10 unidirectional streams.\n");
}

int main() {
    printf("[INIT] Starting QUIC relay server...\n");
    msquic_init();

    printf("[QUIC] Opening listener for new incoming connections...\n");
    if (QUIC_FAILED(MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        fprintf(stderr, "[QUIC][ERROR] ListenerOpen failed\n");
        exit(1);
    }
    QUIC_ADDR addr = {0};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, QUIC_PORT);
    QUIC_BUFFER alpn = {4, (uint8_t*)"chow"};
    printf("[QUIC] Starting QUIC listener on port %d...\n", QUIC_PORT);
    if (QUIC_FAILED(MsQuic->ListenerStart(Listener, &alpn, 1, &addr))) {
        fprintf(stderr, "[QUIC][ERROR] ListenerStart failed\n");
        exit(1);
    }
    printf("[QUIC] Listener running: waiting for incoming QUIC connections.\n");

    tcp_server = setup_local_tcp_server(LOCAL_TCP_PORT);

    fd_set rfds;
    int maxfd;
    char data[BUFFER_SIZE];
    printf("[MAIN] Ready: Accepting TCP on 127.0.0.1:%d, QUIC on port %d\n", LOCAL_TCP_PORT, QUIC_PORT);

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(tcp_server, &rfds);
        maxfd = tcp_server;
        if (tcp_client != -1) {
            FD_SET(tcp_client, &rfds);
            if (tcp_client > maxfd) maxfd = tcp_client;
        }
        int ready = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (ready < 0) {
            perror("[MAIN][ERROR] select");
            break;
        }
        // Accept new TCP connection
        if (FD_ISSET(tcp_server, &rfds)) {
            if (tcp_client == -1) {
                tcp_client = accept(tcp_server, NULL, NULL);
                if (tcp_client < 0) {
                    perror("[TCP][ERROR] accept");
                    tcp_client = -1;
                } else {
                    printf("[TCP] Accepted new local TCP client.\n");
                }
            } else {
                int tmp = accept(tcp_server, NULL, NULL);
                close(tmp);
                printf("[TCP][WARN] Already have a client; refused new connection.\n");
            }
        }
        // Read from local TCP client and send to QUIC stream
        if (tcp_client != -1 && FD_ISSET(tcp_client, &rfds)) {
            ssize_t nread = read(tcp_client, data, sizeof(data));
            if (nread > 0) {
                printf("[RELAY] Read %zd bytes from TCP client\n", nread);
                if (QuicStream && CurrentConnection) {
                    printf("[RELAY] Relaying to QUIC peer...\n");
                    QUIC_BUFFER buf = {.Length = (uint32_t)nread, .Buffer = (uint8_t*)data};
                    QUIC_STATUS qs = MsQuic->StreamSend(QuicStream, &buf, 1, QUIC_SEND_FLAG_NONE, NULL);
                    if (QUIC_FAILED(qs)) {
                        fprintf(stderr, "[QUIC][ERROR] StreamSend failed (status=0x%x)\n", qs);
                    } else {
                        printf("[RELAY] Sent %zd bytes to QUIC peer.\n", nread);
                    }
                } else {
                    printf("[RELAY][WARN] No QUIC stream available (QuicStream=%p, CurrentConnection=%p), data dropped.\n", 
                           (void*)QuicStream, (void*)CurrentConnection);
                }
            } else if (nread == 0) {
                printf("[TCP] TCP client disconnected (EOF).\n");
                close_tcp_client();
            } else if (nread < 0) {
                perror("[TCP][ERROR] read tcp_client");
                close_tcp_client();
            }
        }
    }
    msquic_cleanup();
    if (tcp_server != -1) close(tcp_server);
    if (tcp_client != -1) close(tcp_client);
    printf("[EXIT] QUIC relay server exiting.\n");
    return 0;
}
