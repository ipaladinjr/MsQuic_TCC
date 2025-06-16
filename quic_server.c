// https://ibb.co/mrKMTxc3
// https://ibb.co/r2xC7kQw
// https://ibb.co/pcBV0wm
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
#include <netinet/tcp.h>
#include <fcntl.h>
#include <msquic.h>

// CONFIG - Make server IP configurable  
#define QUIC_PORT 50072
#define LOCAL_TCP_PORT 8081
#define SERVER_IP "0.0.0.0"  // **ADD THIS LINE** - Listen on all interfaces for network access
#define BUFFER_SIZE 4096
#define CERT_FILE "server_cert.pem"
#define KEY_FILE "server_key.pem"
#define MAX_BUFFER_SIZE 8192

// Data buffering
static char pending_data[MAX_BUFFER_SIZE];
static size_t pending_data_len = 0;

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
        printf("[TCP][DEBUG] Closing connection with local TCP client (fd=%d).\n", tcp_client);
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
    
    // **SET TCP_NODELAY TO AVOID NAGLE ALGORITHM DELAYS**
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
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
    printf("[TCP] Local TCP server listening on fd=%d.\n", sock);
    return sock;
}

void msquic_cleanup() {
    printf("[CLEANUP] Cleaning up msquic resources...\n");
    if (Listener) {
        printf("[CLEANUP] Closing Listener...\n");
        MsQuic->ListenerClose(Listener);
    }
    if (Configuration) {
        printf("[CLEANUP] Closing Configuration...\n");
        MsQuic->ConfigurationClose(Configuration);
    }
    if (Registration) {
        printf("[CLEANUP] Closing Registration...\n");
        MsQuic->RegistrationClose(Registration);
    }
    if (MsQuic) {
        printf("[CLEANUP] Closing MsQuic...\n");
        MsQuicClose(MsQuic);
    }
    printf("[CLEANUP] Done cleaning up msquic resources.\n");
}

QUIC_STATUS QUIC_API ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    printf("[QUIC][DEBUG] ========== STREAM CALLBACK START ==========\n");
    printf("[QUIC][DEBUG] Stream callback invoked: Stream=%p, Event->Type=%d\n", (void*)Stream, Event->Type);
    printf("[QUIC][DEBUG] Current QuicStream=%p, tcp_client=%d\n", (void*)QuicStream, tcp_client);
    
    // **CHECK IF THIS IS STILL OUR ACTIVE STREAM**
    if (Stream != QuicStream) {
        printf("[QUIC][WARNING] Event for unknown stream %p (expected %p)\n", (void*)Stream, (void*)QuicStream);
    }
    
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            printf("[QUIC][DEBUG] *** RECEIVE EVENT ***\n");
            printf("[QUIC] Received %llu bytes from remote peer. Current stream=%p\n",
                   (unsigned long long)Event->RECEIVE.TotalBufferLength, (void*)QuicStream);
            printf("[QUIC][DEBUG] BufferCount=%u\n", Event->RECEIVE.BufferCount);
            
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                printf("[QUIC][DEBUG] Processing buffer %u: %u bytes\n", i, Event->RECEIVE.Buffers[i].Length);
                
                // **PRINT RECEIVED DATA FOR DEBUGGING**
                printf("[QUIC][DEBUG] Data content: ");
                for (uint32_t j = 0; j < Event->RECEIVE.Buffers[i].Length && j < 50; j++) {
                    char c = ((char*)Event->RECEIVE.Buffers[i].Buffer)[j];
                    if (c >= 32 && c <= 126) {
                        printf("%c", c);
                    } else {
                        printf("\\x%02x", (unsigned char)c);
                    }
                }
                printf("\n");
                
                if (tcp_client != -1) {
                    printf("[QUIC][DEBUG] Writing to tcp_client (fd=%d)\n", tcp_client);
                    ssize_t nwritten = write(tcp_client,
                        Event->RECEIVE.Buffers[i].Buffer,
                        Event->RECEIVE.Buffers[i].Length);
                    
                    printf("[QUIC][DEBUG] write() returned: %zd (errno=%d: %s)\n", 
                           nwritten, errno, strerror(errno));
                    
                    if (nwritten < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            printf("[TCP][WARN] TCP client buffer full, buffering data...\n");
                            if (pending_data_len + Event->RECEIVE.Buffers[i].Length < MAX_BUFFER_SIZE) {
                                memcpy(pending_data + pending_data_len, 
                                       Event->RECEIVE.Buffers[i].Buffer, 
                                       Event->RECEIVE.Buffers[i].Length);
                                pending_data_len += Event->RECEIVE.Buffers[i].Length;
                                printf("[RELAY][BUFFER] Buffered %u bytes due to TCP backpressure (total: %zu)\n", 
                                       Event->RECEIVE.Buffers[i].Length, pending_data_len);
                            } else {
                                printf("[RELAY][ERROR] Buffer full, dropping data!\n");
                            }
                        } else {
                            perror("[TCP][ERROR] write to tcp_client");
                            close_tcp_client();
                        }
                    } else if ((size_t)nwritten < Event->RECEIVE.Buffers[i].Length) {
                        printf("[TCP][WARN] Partial write (%zd/%u bytes), buffering remainder...\n",
                               nwritten, Event->RECEIVE.Buffers[i].Length);
                        size_t remaining = Event->RECEIVE.Buffers[i].Length - nwritten;
                        if (pending_data_len + remaining < MAX_BUFFER_SIZE) {
                            memcpy(pending_data + pending_data_len,
                                   Event->RECEIVE.Buffers[i].Buffer + nwritten,
                                   remaining);
                            pending_data_len += remaining;
                            printf("[RELAY][BUFFER] Buffered %zu remaining bytes (total: %zu)\n",
                                   remaining, pending_data_len);
                        }
                        printf("[RELAY] Successfully wrote %zd bytes to TCP client.\n", nwritten);
                    } else {
                        printf("[RELAY] Successfully wrote %zd bytes to TCP client.\n", nwritten);
                    }
                } else {
                    printf("[QUIC][DEBUG] No TCP client, buffering data\n");
                    if (pending_data_len + Event->RECEIVE.Buffers[i].Length < MAX_BUFFER_SIZE) {
                        memcpy(pending_data + pending_data_len, 
                               Event->RECEIVE.Buffers[i].Buffer, 
                               Event->RECEIVE.Buffers[i].Length);
                        pending_data_len += Event->RECEIVE.Buffers[i].Length;
                        printf("[RELAY][BUFFER] Buffered %u bytes (total: %zu). Waiting for TCP client...\n", 
                               Event->RECEIVE.Buffers[i].Length, pending_data_len);
                    } else {
                        printf("[RELAY][WARN] Buffer full, data dropped.\n");
                    }
                }
            }
            
            printf("[QUIC][DEBUG] Calling StreamReceiveComplete for %llu bytes\n", 
                   (unsigned long long)Event->RECEIVE.TotalBufferLength);
            MsQuic->StreamReceiveComplete(Stream, Event->RECEIVE.TotalBufferLength);
            printf("[QUIC][DEBUG] StreamReceiveComplete returned successfully\n");
            break;
            
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            printf("[QUIC][DEBUG] *** SEND_COMPLETE EVENT ***\n");
            printf("[QUIC] Send completed successfully.\n");
            break;
            
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            printf("[QUIC][CRITICAL] *** PEER_SEND_SHUTDOWN EVENT ***\n");
            printf("[QUIC][CRITICAL] Peer shut down send direction! Stream may become unusable.\n");
            break;
            
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            printf("[QUIC][CRITICAL] *** PEER_SEND_ABORTED EVENT ***\n");
            printf("[QUIC][CRITICAL] Peer aborted send! Stream is broken.\n");
            // Mark stream as broken
            if (Stream == QuicStream) {
                printf("[QUIC][CRITICAL] Clearing broken QuicStream reference\n");
                QuicStream = NULL;
            }
            break;
            
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            printf("[QUIC][DEBUG] *** SEND_SHUTDOWN_COMPLETE EVENT ***\n");
            printf("[QUIC] Send shutdown complete.\n");
            break;
            
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[QUIC][CRITICAL] *** SHUTDOWN_COMPLETE EVENT ***\n");
            printf("[QUIC][CRITICAL] Stream shutdown complete. Stream is being destroyed.\n");
            if (Stream == QuicStream) {
                printf("[QUIC][CRITICAL] Our active stream is being destroyed!\n");
                QuicStream = NULL;
            }
            MsQuic->StreamClose(Stream);
            printf("[QUIC][DEBUG] Stream handle closed\n");
            break;
            
        default:
            printf("[QUIC][WARNING] *** UNHANDLED STREAM EVENT %d ***\n", Event->Type);
            break;
    }
    
    printf("[QUIC][DEBUG] Stream callback completed, returning SUCCESS\n");
    printf("[QUIC][DEBUG] ========== STREAM CALLBACK END ==========\n");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
    printf("[QUIC][DEBUG] ========== CONNECTION CALLBACK START ==========\n");
    printf("[QUIC][DEBUG] Connection callback: Connection=%p, Event->Type=%d\n", (void*)Connection, Event->Type);
    printf("[QUIC][DEBUG] Current CurrentConnection=%p, QuicStream=%p\n", (void*)CurrentConnection, (void*)QuicStream);
    
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[QUIC][DEBUG] *** CONNECTED EVENT ***\n");
            printf("[QUIC] Connection established (client handshake complete).\n");
            printf("[QUIC] Connection is stable and ready for streams.\n");
            CurrentConnection = Connection;
            printf("[QUIC][DEBUG] Set CurrentConnection to %p\n", (void*)CurrentConnection);
            break;
            
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("[QUIC][CRITICAL] *** SHUTDOWN_COMPLETE EVENT ***\n");
            printf("[QUIC][CRITICAL] Connection shutdown complete! Connection is being destroyed.\n");
            if (Connection == CurrentConnection) {
                printf("[QUIC][CRITICAL] Our active connection is being destroyed!\n");
                CurrentConnection = NULL;
                QuicStream = NULL;
                printf("[QUIC][DEBUG] Cleared CurrentConnection and QuicStream\n");
            }
            MsQuic->ConnectionClose(Connection);
            break;
            
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            printf("[QUIC][DEBUG] *** PEER_STREAM_STARTED EVENT ***\n");
            printf("[QUIC] *** PEER_STREAM_STARTED EVENT RECEIVED! ***\n");
            printf("[QUIC][DEBUG] New stream: %p (previous stream: %p)\n", 
                   Event->PEER_STREAM_STARTED.Stream, (void*)QuicStream);
            
            // **ALWAYS UPDATE TO THE NEW STREAM**
            QuicStream = Event->PEER_STREAM_STARTED.Stream;
            // **SetCallbackHandler returns void - no status check needed**
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
            printf("[QUIC] Stream callback handler set successfully for stream %p\n", (void*)QuicStream);
            break;
            
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            printf("[QUIC][WARNING] *** SHUTDOWN_INITIATED_BY_TRANSPORT EVENT ***\n");
            printf("[QUIC][WARNING] Connection shutdown initiated by transport (error condition).\n");
            break;
            
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            printf("[QUIC][WARNING] *** SHUTDOWN_INITIATED_BY_PEER EVENT ***\n");
            printf("[QUIC][WARNING] Connection shutdown initiated by peer.\n");
            break;
            
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
            printf("[QUIC][DEBUG] *** STREAMS_AVAILABLE EVENT ***\n");
            printf("[QUIC] Streams available event.\n");
            break;
            
        case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
            printf("[QUIC][DEBUG] *** PEER_NEEDS_STREAMS EVENT ***\n");
            printf("[QUIC] Peer needs streams event.\n");
            break;
            
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
            printf("[QUIC][DEBUG] *** IDEAL_PROCESSOR_CHANGED EVENT ***\n");
            printf("[QUIC] Ideal processor changed event.\n");
            break;
            
        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
            printf("[QUIC][DEBUG] *** DATAGRAM_STATE_CHANGED EVENT ***\n");
            printf("[QUIC] Datagram state changed event.\n");
            break;
            
        default:
            printf("[QUIC][WARNING] *** UNHANDLED CONNECTION EVENT %d ***\n", Event->Type);
            break;
    }
    printf("[QUIC][DEBUG] ========== CONNECTION CALLBACK END ==========\n");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
    printf("[QUIC][DEBUG] ========== LISTENER CALLBACK START ==========\n");
    printf("[QUIC] Listener event type: %d\n", Event->Type);
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            printf("[QUIC][DEBUG] *** NEW_CONNECTION EVENT ***\n");
            printf("[QUIC] New QUIC connection received. Setting configuration and callback handler.\n");
            printf("[QUIC][DEBUG] New connection: %p\n", Event->NEW_CONNECTION.Connection);
            
            // **SetCallbackHandler returns void - no status check needed**
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            printf("[QUIC] Connection callback handler set successfully.\n");
            
            QUIC_STATUS status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            if (QUIC_FAILED(status)) {
                printf("[QUIC][ERROR] Failed to set connection configuration: 0x%x\n", status);
            } else {
                printf("[QUIC] Connection configuration set successfully.\n");
            }
            printf("[QUIC][DEBUG] ========== LISTENER CALLBACK END ==========\n");
            return status;
        default:
            printf("[QUIC][WARNING] *** UNHANDLED LISTENER EVENT %d ***\n", Event->Type);
            break;
    }
    printf("[QUIC][DEBUG] ========== LISTENER CALLBACK END ==========\n");
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

    // **CORRECT FLOW CONTROL SETTINGS FOR YOUR MSQUIC VERSION**
    QUIC_SETTINGS Settings = {0};
    Settings.PeerBidiStreamCount = 10;              // Allow 10 bidirectional streams from peer
    Settings.PeerUnidiStreamCount = 10;             // Allow 10 unidirectional streams from peer
    Settings.ConnFlowControlWindow = 16777216;      // 16MB connection flow control window
    Settings.StreamRecvWindowDefault = 1048576;     // 1MB per-stream receive window (correct name)
    Settings.MaxBytesPerKey = 274877906944ULL;      // Large key update threshold
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IdleTimeoutMs = 60000;                 // 60 second idle timeout
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.IsSet.ConnFlowControlWindow = TRUE;
    Settings.IsSet.StreamRecvWindowDefault = TRUE;  // Correct IsSet name
    Settings.IsSet.MaxBytesPerKey = TRUE;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    Settings.IsSet.IdleTimeoutMs = TRUE;

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
    printf("[QUIC] Server configured with enhanced flow control: 16MB conn window, 1MB stream window\n");
}

// **HELPER FUNCTION TO ATTEMPT WRITING BUFFERED DATA**
void try_flush_pending_data() {
    if (tcp_client != -1 && pending_data_len > 0) {
        printf("[RELAY][DEBUG] Attempting to flush %zu buffered bytes to tcp_client (fd=%d)\n", 
               pending_data_len, tcp_client);
        ssize_t nwritten = write(tcp_client, pending_data, pending_data_len);
        printf("[RELAY][DEBUG] Flush write() returned: %zd (errno=%d)\n", nwritten, errno);
        
        if (nwritten > 0) {
            printf("[RELAY] Flushed %zd buffered bytes to TCP client.\n", nwritten);
            if ((size_t)nwritten == pending_data_len) {
                pending_data_len = 0; // All data sent
            } else {
                // Move remaining data to beginning of buffer
                memmove(pending_data, pending_data + nwritten, pending_data_len - nwritten);
                pending_data_len -= nwritten;
                printf("[RELAY] %zu bytes still buffered.\n", pending_data_len);
            }
        } else if (nwritten < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("[TCP][ERROR] Failed to flush buffered data");
            close_tcp_client();
        }
    }
}

int main() {
    printf("[INIT] Starting QUIC relay server...\n");
    msquic_init();

    printf("[QUIC] Opening listener for new incoming connections...\n");
    if (QUIC_FAILED(MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        fprintf(stderr, "[QUIC][ERROR] ListenerOpen failed\n");
        exit(1);
    }
    
    // **SIMPLE ADDRESS SETUP:**
    QUIC_ADDR addr = {0};
    QuicAddrFromString(SERVER_IP, QUIC_PORT, &addr);  // **USE QuicAddrFromString HELPER**
    
    QUIC_BUFFER alpn = {4, (uint8_t*)"chow"};
    printf("[QUIC] Starting QUIC listener on %s:%d...\n", SERVER_IP, QUIC_PORT);
    if (QUIC_FAILED(MsQuic->ListenerStart(Listener, &alpn, 1, &addr))) {
        fprintf(stderr, "[QUIC][ERROR] ListenerStart failed\n");
        exit(1);
    }
    printf("[QUIC] Listener running: waiting for incoming QUIC connections.\n");

    tcp_server = setup_local_tcp_server(LOCAL_TCP_PORT);

    fd_set rfds, wfds;
    int maxfd;
    char data[BUFFER_SIZE];
    printf("[MAIN] Ready: Accepting TCP on 127.0.0.1:%d, QUIC on port %d\n", LOCAL_TCP_PORT, QUIC_PORT);

    while (1) {
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(tcp_server, &rfds);
        maxfd = tcp_server;
        if (tcp_client != -1) {
            FD_SET(tcp_client, &rfds);
            if (pending_data_len > 0) {
                FD_SET(tcp_client, &wfds); // **MONITOR FOR WRITABILITY WHEN BUFFER HAS DATA**
            }
            if (tcp_client > maxfd) maxfd = tcp_client;
        }
        
        printf("[MAIN][DEBUG] Calling select() - tcp_server=%d, tcp_client=%d, pending_data_len=%zu\n", 
               tcp_server, tcp_client, pending_data_len);
        
        // **USE SELECT WITH BOTH READ AND WRITE SETS**
        int ready = select(maxfd + 1, &rfds, &wfds, NULL, NULL);
        if (ready < 0) {
            perror("[MAIN][ERROR] select");
            break;
        }
        
        printf("[MAIN][DEBUG] select() returned %d ready descriptors\n", ready);
        
        // **CHECK IF TCP CLIENT IS READY FOR WRITING**
        if (tcp_client != -1 && FD_ISSET(tcp_client, &wfds)) {
            printf("[MAIN][DEBUG] TCP client is writable, flushing buffer\n");
            try_flush_pending_data();
        }
        
        // Accept new TCP connection
        if (FD_ISSET(tcp_server, &rfds)) {
            printf("[MAIN][DEBUG] New TCP connection available\n");
            if (tcp_client == -1) {
                tcp_client = accept(tcp_server, NULL, NULL);
                if (tcp_client < 0) {
                    perror("[TCP][ERROR] accept");
                    tcp_client = -1;
                } else {
                    printf("[TCP] Accepted new local TCP client (fd=%d).\n", tcp_client);
                    
                    // **SET TCP CLIENT TO NON-BLOCKING MODE**
                    int flags = fcntl(tcp_client, F_GETFL, 0);
                    fcntl(tcp_client, F_SETFL, flags | O_NONBLOCK);
                    printf("[TCP][DEBUG] Set tcp_client to non-blocking mode\n");
                    
                    // **SET TCP_NODELAY**
                    int opt = 1;
                    setsockopt(tcp_client, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
                    printf("[TCP][DEBUG] Set TCP_NODELAY on tcp_client\n");
                    
                    // **DELIVER BUFFERED DATA**
                    try_flush_pending_data();
                }
            } else {
                // Refuse additional connections
                int tmp = accept(tcp_server, NULL, NULL);
                close(tmp);
                printf("[TCP][WARN] Already have a client; refused new connection.\n");
            }
        }
        
        // Read from local TCP client and send to QUIC stream
        if (tcp_client != -1 && FD_ISSET(tcp_client, &rfds)) {
            printf("[MAIN][DEBUG] TCP client has data to read\n");
            ssize_t nread = read(tcp_client, data, sizeof(data));
            printf("[MAIN][DEBUG] read() returned %zd bytes from tcp_client\n", nread);
            
            if (nread > 0) {
                printf("[RELAY] Read %zd bytes from TCP client\n", nread);
                printf("[RELAY][DEBUG] Current QuicStream=%p, CurrentConnection=%p\n", 
                       (void*)QuicStream, (void*)CurrentConnection);
                
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
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("[TCP][ERROR] read tcp_client");
                    close_tcp_client();
                } else {
                    printf("[TCP][DEBUG] read() returned EAGAIN/EWOULDBLOCK\n");
                }
            }
        }
    }
    
    msquic_cleanup();
    if (tcp_server != -1) close(tcp_server);
    if (tcp_client != -1) close(tcp_client);
    printf("[EXIT] QUIC relay server exiting.\n");
    return 0;
}
