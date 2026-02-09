/*
 * NOSP C Core - Packet Capture Header
 * High-performance raw socket packet capture
 */

#ifndef NOSP_PACKET_CAPTURE_H
#define NOSP_PACKET_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque context type
typedef struct CaptureContext CaptureContext;

// Packet information structure
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

// Initialize capture context
CaptureContext* capture_init(void);

// Start capturing on interface (NULL = default interface)
int capture_start(CaptureContext *ctx, const char *interface);

// Capture packets (blocking)
// Returns number of packets captured
// timeout_sec: 0 = no timeout
int capture_packets(CaptureContext *ctx, int max_packets, double timeout_sec);

// Get captured packets
PacketInfo* capture_get_packets(CaptureContext *ctx, int *count);

// Get statistics
void capture_get_stats(CaptureContext *ctx, uint64_t *total_packets, uint64_t *total_bytes);

// Stop capture
void capture_stop(CaptureContext *ctx);

// Free resources
void capture_free(CaptureContext *ctx);

#ifdef __cplusplus
}
#endif

#endif // NOSP_PACKET_CAPTURE_H
