// Compile with: gcc quicclient.c -o quicclient -lmsquic -lpthread

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
#define REMOTE_ADDR "127.0.0.1"
#define BUFFER_SIZE 4096
#define LOCAL_TCP_PORT 44444

// MSQUIC globals
const QUIC_API_TABLE* MsQuic;
HQUIC Registration = NULL;
HQUIC Configuration = NULL;
HQUIC Connection = NULL;
HQUIC QuicStream = NULL;

// Connection state
bool connection_ready = false;

// TCP relay globals
int tcp_server = -1;
int tcp_client = -1;

void close_tcp_client() {
    if (tcp_client != -1) {
        printf("[TCP] Closing local TCP client connection.\n");
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

// Forward declarations
void msquic_cleanup();
void start_quic_client(const char* remote_addr, uint16_t port);
void ensure_quic_stream();

QUIC_STATUS QUIC_API ClientStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            printf("[QUIC] Received %llu bytes from remote peer. Relaying to TCP client...\n",
                   (unsigned long long)Event->RECEIVE.TotalBufferLength);
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
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

QUIC_STATUS QUIC_API ClientConnectionCallback(HQUIC ConnectionHandle, void* Context, QUIC_CONNECTION_EVENT* Event) {
    printf("[QUIC] Connection event type: %d\n", Event->Type);
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[QUIC] Connected to server! Connection is stable and ready.\n");
            connection_ready = true;
            // Give the server a moment to be ready for streams
            printf("[QUIC] Waiting 200ms for server to be ready for streams...\n");
            usleep(200000); // 200ms delay
            ensure_quic_stream();
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("[QUIC] Connection shutdown complete. Will reconnect on next request.\n");
            MsQuic->ConnectionClose(ConnectionHandle);
            Connection = NULL;
            QuicStream = NULL;
            connection_ready = false;
            break;
        default:
            printf("[QUIC] Unhandled connection event type: %d\n", Event->Type);
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

    QUIC_SETTINGS Settings = {0};

    printf("[QUIC] Opening configuration context...\n");
    if (QUIC_FAILED(MsQuic->ConfigurationOpen(
            Registration,
            &alpn, 1,
            &Settings, sizeof(Settings),
            NULL,
            &Configuration))) {
        fprintf(stderr, "[QUIC][ERROR] ConfigurationOpen failed\n");
        exit(1);
    }

    QUIC_CREDENTIAL_CONFIG CredConfig = {0};
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    printf("[QUIC] Using no certificate validation for compatibility\n");

    printf("[QUIC] Loading credentials for client...\n");
    if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("[QUIC][ERROR] ConfigurationLoadCredential failed!\n");
        exit(1);
    }
    printf("[QUIC] msquic API and credentials loaded successfully.\n");
}

void msquic_cleanup() {
    printf("[CLEANUP] Cleaning up msquic resources...\n");
    if (QuicStream) MsQuic->StreamClose(QuicStream);
    if (Connection) MsQuic->ConnectionClose(Connection);
    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
    if (MsQuic) MsQuicClose(MsQuic);
    printf("[CLEANUP] Done cleaning up msquic resources.\n");
}

void start_quic_client(const char* remote_addr, uint16_t port) {
    if (Connection != NULL) {
        printf("[QUIC] Connection already exists or starting, skipping new ConnectionOpen.\n");
        return;
    }
    printf("[QUIC] Opening client connection context...\n");
    if (QUIC_FAILED(MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
        fprintf(stderr, "[QUIC][ERROR] ConnectionOpen failed\n");
        Connection = NULL;
        return;
    }
    printf("[QUIC] Starting connection to %s:%d...\n", remote_addr, port);
    QUIC_STATUS status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, remote_addr, port);
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "[QUIC][ERROR] ConnectionStart failed: 0x%x\n", status);
        MsQuic->ConnectionClose(Connection);
        Connection = NULL;
        return;
    }
    printf("[QUIC] Connection initiated. Waiting for handshake...\n");
}

void ensure_quic_stream() {
    if (Connection == NULL) {
        printf("[QUIC] No QUIC connection, attempting to start one...\n");
        start_quic_client(REMOTE_ADDR, QUIC_PORT);
        for(int i=0; i<10 && !connection_ready; ++i) {
            usleep(100000); // Wait up to 1 second
        }
        if (!connection_ready) {
            printf("[QUIC] Failed to establish connection in time for stream.\n");
            return;
        }
    }

    if (!connection_ready) {
        printf("[QUIC] Connection not ready, cannot create stream.\n");
        return;
    }

    if (QuicStream == NULL) {
        printf("[QUIC] Creating new stream...\n");
        QUIC_STATUS status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, NULL, &QuicStream);
        if (QUIC_FAILED(status)) {
            fprintf(stderr, "[QUIC][ERROR] StreamOpen failed with status: 0x%x\n", status);
            QuicStream = NULL;
            return;
        }
        status = MsQuic->StreamStart(QuicStream, QUIC_STREAM_START_FLAG_IMMEDIATE);
        if (QUIC_FAILED(status)) {
            fprintf(stderr, "[QUIC][ERROR] StreamStart failed with status: 0x%x\n", status);
            MsQuic->StreamClose(QuicStream);
            QuicStream = NULL;
            return;
        }
        printf("[QUIC] New stream created and started successfully.\n");
    }
}

int main() {
    printf("[INIT] Starting QUIC relay client...\n");
    msquic_init();
    start_quic_client(REMOTE_ADDR, QUIC_PORT);

    tcp_server = setup_local_tcp_server(LOCAL_TCP_PORT);

    fd_set rfds;
    int maxfd;
    char data[BUFFER_SIZE];
    printf("[MAIN] Ready: Accepting TCP on 127.0.0.1:%d, QUIC to %s:%d\n", LOCAL_TCP_PORT, REMOTE_ADDR, QUIC_PORT);

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
        // Read from local TCP client and send to QUIC
        if (tcp_client != -1 && FD_ISSET(tcp_client, &rfds)) {
            ssize_t nread = read(tcp_client, data, sizeof(data));
            if (nread > 0) {
                printf("[RELAY] Read %zd bytes from TCP client, relaying to QUIC peer...\n", nread);
                ensure_quic_stream();
                if (QuicStream != NULL) {
                    QUIC_BUFFER buf = {.Length = (uint32_t)nread, .Buffer = (uint8_t*)data};
                    QUIC_STATUS qs = MsQuic->StreamSend(QuicStream, &buf, 1, QUIC_SEND_FLAG_NONE, NULL);
                    if (QUIC_FAILED(qs)) {
                        fprintf(stderr, "[QUIC][ERROR] StreamSend failed (status=0x%x)\n", qs);
                        if (QuicStream) {
                            MsQuic->StreamClose(QuicStream);
                            QuicStream = NULL;
                        }
                    } else {
                        printf("[RELAY] Sent %zd bytes to QUIC peer.\n", nread);
                    }
                } else {
                    printf("[RELAY][WARN] No QUIC stream available, data dropped.\n");
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
    printf("[EXIT] QUIC relay client exiting.\n");
    return 0;
}
