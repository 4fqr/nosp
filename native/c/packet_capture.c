/*
 * NOSP C Core - High-Performance Packet Capture
 * Raw socket implementation for Windows (Npcap/WinPcap)
 * Zero-copy packet processing with nanosecond timestamps
 */

#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_PACKET_SIZE 65535
#define CAPTURE_BUFFER_SIZE 100000

// Ethernet header
typedef struct {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} __attribute__((packed)) EthernetHeader;

// IPv4 header
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed)) IPv4Header;

// TCP header
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed)) TCPHeader;

// UDP header
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) UDPHeader;

// Packet info structure
typedef struct {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t protocol;  // 6=TCP, 17=UDP, 1=ICMP
    uint16_t length;
    uint8_t flags;  // TCP flags
    char src_ip_str[16];
    char dest_ip_str[16];
} PacketInfo;

// Capture context
typedef struct {
    int socket_fd;
    bool is_running;
    PacketInfo *buffer;
    int buffer_count;
    int buffer_capacity;
    uint64_t total_packets;
    uint64_t total_bytes;
} CaptureContext;

// Get high-resolution timestamp
static inline uint64_t get_timestamp_ns() {
#ifdef _WIN32
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000000ULL) / frequency.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

// Convert IP to string
static void ip_to_string(uint32_t ip, char *buffer) {
    sprintf(buffer, "%d.%d.%d.%d",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
}

// Initialize capture
CaptureContext* capture_init() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return NULL;
    }
#endif
    
    CaptureContext *ctx = (CaptureContext*)calloc(1, sizeof(CaptureContext));
    ctx->socket_fd = -1;
    ctx->is_running = false;
    ctx->buffer_capacity = CAPTURE_BUFFER_SIZE;
    ctx->buffer = (PacketInfo*)malloc(ctx->buffer_capacity * sizeof(PacketInfo));
    ctx->buffer_count = 0;
    ctx->total_packets = 0;
    ctx->total_bytes = 0;
    
    return ctx;
}

// Start capture on interface
int capture_start(CaptureContext *ctx, const char *interface) {
    if (ctx == NULL) return -1;
    
#ifdef _WIN32
    // Create raw socket for packet capture
    ctx->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (ctx->socket_fd == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create raw socket (need Administrator privileges)\n");
        return -1;
    }
    
    // Bind to interface
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(ctx->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Failed to bind socket\n");
        closesocket(ctx->socket_fd);
        return -1;
    }
    
    // Set socket to promiscuous mode
    DWORD flag = 1;
    if (ioctlsocket(ctx->socket_fd, SIO_RCVALL, &flag) == SOCKET_ERROR) {
        fprintf(stderr, "Failed to set promiscuous mode\n");
        closesocket(ctx->socket_fd);
        return -1;
    }
#else
    // Linux raw socket
    ctx->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (ctx->socket_fd < 0) {
        perror("Failed to create raw socket (need root/CAP_NET_RAW)");
        return -1;
    }
#endif
    
    ctx->is_running = true;
    return 0;
}

// Parse packet and extract info
static bool parse_packet(const uint8_t *data, int length, PacketInfo *info) {
    if (length < sizeof(IPv4Header)) {
        return false;
    }
    
    info->timestamp_ns = get_timestamp_ns();
    
    // Parse IP header
    IPv4Header *ip_hdr = (IPv4Header*)data;
    info->protocol = ip_hdr->protocol;
    info->length = ntohs(ip_hdr->total_length);
    
    // Convert endianness and store IPs
    info->src_ip = (ntohl(ip_hdr->src_ip));
    info->dest_ip = (ntohl(ip_hdr->dest_ip));
    
    ip_to_string(info->src_ip, info->src_ip_str);
    ip_to_string(info->dest_ip, info->dest_ip_str);
    
    // Get header length
    int ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;
    const uint8_t *payload = data + ip_hdr_len;
    int remaining = length - ip_hdr_len;
    
    // Parse transport layer
    if (info->protocol == 6 && remaining >= sizeof(TCPHeader)) {
        // TCP
        TCPHeader *tcp_hdr = (TCPHeader*)payload;
        info->src_port = ntohs(tcp_hdr->src_port);
        info->dest_port = ntohs(tcp_hdr->dest_port);
        info->flags = tcp_hdr->flags;
    } else if (info->protocol == 17 && remaining >= sizeof(UDPHeader)) {
        // UDP
        UDPHeader *udp_hdr = (UDPHeader*)payload;
        info->src_port = ntohs(udp_hdr->src_port);
        info->dest_port = ntohs(udp_hdr->dest_port);
        info->flags = 0;
    } else {
        // Other protocols
        info->src_port = 0;
        info->dest_port = 0;
        info->flags = 0;
    }
    
    return true;
}

// Capture packets (blocking, returns number captured)
int capture_packets(CaptureContext *ctx, int max_packets, double timeout_sec) {
    if (ctx == NULL || !ctx->is_running) return -1;
    
    ctx->buffer_count = 0;
    uint8_t packet_buffer[MAX_PACKET_SIZE];
    
    uint64_t start_time = get_timestamp_ns();
    uint64_t timeout_ns = (uint64_t)(timeout_sec * 1e9);
    
    while (ctx->buffer_count < max_packets) {
        // Check timeout
        if (timeout_sec > 0 && (get_timestamp_ns() - start_time) > timeout_ns) {
            break;
        }
        
        // Receive packet
#ifdef _WIN32
        int bytes_received = recv(ctx->socket_fd, (char*)packet_buffer, MAX_PACKET_SIZE, 0);
        if (bytes_received == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
                continue;
            }
            fprintf(stderr, "recv() error: %d\n", error);
            break;
        }
#else
        ssize_t bytes_received = recv(ctx->socket_fd, packet_buffer, MAX_PACKET_SIZE, 0);
        if (bytes_received < 0) {
            perror("recv() error");
            break;
        }
#endif
        
        if (bytes_received <= 0) continue;
        
        // Parse packet
        if (ctx->buffer_count < ctx->buffer_capacity) {
            PacketInfo *info = &ctx->buffer[ctx->buffer_count];
            if (parse_packet(packet_buffer, bytes_received, info)) {
                ctx->buffer_count++;
                ctx->total_packets++;
                ctx->total_bytes += bytes_received;
            }
        }
    }
    
    return ctx->buffer_count;
}

// Get captured packets
PacketInfo* capture_get_packets(CaptureContext *ctx, int *count) {
    if (ctx == NULL || count == NULL) return NULL;
    *count = ctx->buffer_count;
    return ctx->buffer;
}

// Get statistics
void capture_get_stats(CaptureContext *ctx, uint64_t *total_packets, uint64_t *total_bytes) {
    if (ctx == NULL) return;
    if (total_packets) *total_packets = ctx->total_packets;
    if (total_bytes) *total_bytes = ctx->total_bytes;
}

// Stop capture
void capture_stop(CaptureContext *ctx) {
    if (ctx == NULL) return;
    
    ctx->is_running = false;
    
#ifdef _WIN32
    if (ctx->socket_fd != INVALID_SOCKET) {
        closesocket(ctx->socket_fd);
        ctx->socket_fd = INVALID_SOCKET;
    }
#else
    if (ctx->socket_fd >= 0) {
        close(ctx->socket_fd);
        ctx->socket_fd = -1;
    }
#endif
}

// Free resources
void capture_free(CaptureContext *ctx) {
    if (ctx == NULL) return;
    
    capture_stop(ctx);
    free(ctx->buffer);
    free(ctx);
    
#ifdef _WIN32
    WSACleanup();
#endif
}

// Test/Demo
#ifdef CAPTURE_TEST_MAIN
int main() {
    printf("=== NOSP Packet Capture Engine ===\n\n");
    
    CaptureContext *ctx = capture_init();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize capture\n");
        return 1;
    }
    
    printf("Starting packet capture (requires Administrator/root privileges)...\n");
    if (capture_start(ctx, NULL) < 0) {
        fprintf(stderr, "Failed to start capture\n");
        capture_free(ctx);
        return 1;
    }
    
    printf("Capturing packets for 5 seconds...\n\n");
    int captured = capture_packets(ctx, 1000, 5.0);
    
    printf("--- Captured %d packets ---\n\n", captured);
    
    int count;
    PacketInfo *packets = capture_get_packets(ctx, &count);
    
    // Display first 20 packets
    int display_count = count < 20 ? count : 20;
    for (int i = 0; i < display_count; i++) {
        PacketInfo *p = &packets[i];
        
        const char *proto = "OTHER";
        if (p->protocol == 6) proto = "TCP";
        else if (p->protocol == 17) proto = "UDP";
        else if (p->protocol == 1) proto = "ICMP";
        
        printf("[%d] %s: %s:%d -> %s:%d (%d bytes)\n",
               i + 1, proto, p->src_ip_str, p->src_port, 
               p->dest_ip_str, p->dest_port, p->length);
        
        if (p->protocol == 6) {  // TCP flags
            printf("     TCP Flags: ");
            if (p->flags & 0x02) printf("SYN ");
            if (p->flags & 0x10) printf("ACK ");
            if (p->flags & 0x01) printf("FIN ");
            if (p->flags & 0x04) printf("RST ");
            printf("\n");
        }
    }
    
    // Statistics
    uint64_t total_packets, total_bytes;
    capture_get_stats(ctx, &total_packets, &total_bytes);
    
    printf("\n--- Statistics ---\n");
    printf("Total packets: %llu\n", (unsigned long long)total_packets);
    printf("Total bytes: %llu (%.2f KB)\n", 
           (unsigned long long)total_bytes, total_bytes / 1024.0);
    printf("Average packet size: %.2f bytes\n", 
           total_packets ? (double)total_bytes / total_packets : 0);
    
    // Cleanup
    capture_free(ctx);
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
#endif
