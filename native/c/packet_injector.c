

#include "packet_injector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif


typedef struct {
    uint8_t  ihl:4;          

    uint8_t  version:4;      

    uint8_t  tos;            

    uint16_t tot_len;        

    uint16_t id;             

    uint16_t frag_off;       

    uint8_t  ttl;            

    uint8_t  protocol;       

    uint16_t check;          

    uint32_t saddr;          

    uint32_t daddr;          

} IPHeader;


typedef struct {
    uint16_t source;         

    uint16_t dest;           

    uint32_t seq;            

    uint32_t ack_seq;        

    uint8_t  doff:4;         

    uint8_t  res1:4;         

    uint8_t  flags;          

    uint16_t window;         

    uint16_t check;          

    uint16_t urg_ptr;        

} TCPHeader;


typedef struct {
    uint32_t saddr;          

    uint32_t daddr;          

    uint8_t  zero;           

    uint8_t  protocol;       

    uint16_t tcp_len;        

} PseudoHeader;


static uint16_t calculate_checksum(void* buf, int len) {
    uint16_t* data = (uint16_t*)buf;
    uint32_t sum = 0;
    
    

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    
    

    if (len == 1) {
        sum += *(uint8_t*)data;
    }
    
    

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
}


int injector_init(InjectorContext* ctx) {
    if (!ctx) {
        fprintf(stderr, "NULL context pointer\n");
        return -1;
    }
    
    memset(ctx, 0, sizeof(InjectorContext));
    
#ifdef _WIN32
    

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return -1;
    }
#endif
    
    

    ctx->raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->raw_socket < 0) {
#ifdef _WIN32
        fprintf(stderr, "Raw socket creation failed: %d\n", WSAGetLastError());
        fprintf(stderr, "ERROR: Administrator privileges required!\n");
#else
        perror("socket");
        fprintf(stderr, "ERROR: Root privileges required!\n");
#endif
        return -1;
    }
    
    

    int one = 1;
    if (setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, 
                   (const char*)&one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        injector_cleanup(ctx);
        return -1;
    }
    
    ctx->packets_injected = 0;
    ctx->is_initialized = 1;
    
    return 0;
}


void injector_cleanup(InjectorContext* ctx) {
    if (!ctx || !ctx->is_initialized) {
        return;
    }
    
    if (ctx->raw_socket >= 0) {
#ifdef _WIN32
        closesocket(ctx->raw_socket);
#else
        close(ctx->raw_socket);
#endif
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    ctx->is_initialized = 0;
}


int inject_tcp_rst(InjectorContext* ctx, 
                   const char* src_ip, const char* dst_ip,
                   uint16_t src_port, uint16_t dst_port,
                   uint32_t seq_num) {
    if (!ctx || !ctx->is_initialized) {
        fprintf(stderr, "Injector not initialized\n");
        return -1;
    }
    
    

    char packet[sizeof(IPHeader) + sizeof(TCPHeader)];
    memset(packet, 0, sizeof(packet));
    
    IPHeader* ip = (IPHeader*)packet;
    TCPHeader* tcp = (TCPHeader*)(packet + sizeof(IPHeader));
    
    

    ip->version = 4;
    ip->ihl = 5;               

    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;             

    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    
    

    ip->check = calculate_checksum(ip, sizeof(IPHeader));
    
    

    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq_num);
    tcp->ack_seq = 0;
    tcp->doff = 5;             

    tcp->res1 = 0;
    tcp->flags = 0x04;         

    tcp->window = 0;
    tcp->check = 0;            

    tcp->urg_ptr = 0;
    
    

    PseudoHeader pseudo;
    pseudo.saddr = ip->saddr;
    pseudo.daddr = ip->daddr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(TCPHeader));
    
    

    char checksum_buf[sizeof(PseudoHeader) + sizeof(TCPHeader)];
    memcpy(checksum_buf, &pseudo, sizeof(PseudoHeader));
    memcpy(checksum_buf + sizeof(PseudoHeader), tcp, sizeof(TCPHeader));
    
    tcp->check = calculate_checksum(checksum_buf, sizeof(checksum_buf));
    
    

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dst_port);
    dest_addr.sin_addr.s_addr = inet_addr(dst_ip);
    
    int sent = sendto(ctx->raw_socket, packet, sizeof(packet), 0,
                      (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (sent < 0) {
#ifdef _WIN32
        fprintf(stderr, "sendto failed: %d\n", WSAGetLastError());
#else
        perror("sendto");
#endif
        return -1;
    }
    
    ctx->packets_injected++;
    return 0;
}


int inject_bidirectional_rst(InjectorContext* ctx,
                              const char* local_ip, const char* remote_ip,
                              uint16_t local_port, uint16_t remote_port) {
    

    if (inject_tcp_rst(ctx, local_ip, remote_ip, local_port, remote_port, 0) < 0) {
        return -1;
    }
    
    

    if (inject_tcp_rst(ctx, remote_ip, local_ip, remote_port, local_port, 0) < 0) {
        return -1;
    }
    
    return 0;
}


uint64_t injector_get_stats(InjectorContext* ctx) {
    if (!ctx || !ctx->is_initialized) {
        return 0;
    }
    return ctx->packets_injected;
}



#ifdef BUILD_TEST
int main(int argc, char** argv) {
    printf("NOSP EVENT HORIZON - Packet Injector Test\n");
    printf("==========================================\n\n");
    
    if (argc < 6) {
        printf("Usage: %s <src_ip> <dst_ip> <src_port> <dst_port> <seq_num>\n", argv[0]);
        printf("Example: %s 192.168.1.100 192.168.1.200 12345 80 1000\n\n", argv[0]);
        printf("WARNING: Requires Administrator/root privileges!\n");
        return 1;
    }
    
    const char* src_ip = argv[1];
    const char* dst_ip = argv[2];
    uint16_t src_port = (uint16_t)atoi(argv[3]);
    uint16_t dst_port = (uint16_t)atoi(argv[4]);
    uint32_t seq_num = (uint32_t)atol(argv[5]);
    
    InjectorContext ctx;
    
    printf("Initializing packet injector...\n");
    if (injector_init(&ctx) < 0) {
        fprintf(stderr, "Failed to initialize injector\n");
        return 1;
    }
    printf("✓ Raw socket created\n\n");
    
    printf("Injecting TCP RST packet:\n");
    printf("  Source: %s:%u\n", src_ip, src_port);
    printf("  Destination: %s:%u\n", dst_ip, dst_port);
    printf("  Sequence: %u\n\n", seq_num);
    
    if (inject_tcp_rst(&ctx, src_ip, dst_ip, src_port, dst_port, seq_num) < 0) {
        fprintf(stderr, "Injection failed\n");
        injector_cleanup(&ctx);
        return 1;
    }
    
    printf("✓ RST packet injected successfully\n");
    printf("  Total injections: %llu\n\n", 
           (unsigned long long)injector_get_stats(&ctx));
    
    

    printf("Testing bidirectional RST injection...\n");
    if (inject_bidirectional_rst(&ctx, src_ip, dst_ip, src_port, dst_port) < 0) {
        fprintf(stderr, "Bidirectional injection failed\n");
    } else {
        printf("✓ Bidirectional RST injected\n");
        printf("  Total injections: %llu\n\n",
               (unsigned long long)injector_get_stats(&ctx));
    }
    
    injector_cleanup(&ctx);
    printf("==========================================\n");
    printf("Test complete\n");
    
    return 0;
}
#endif
