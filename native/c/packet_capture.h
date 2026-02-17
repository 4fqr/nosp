

#ifndef NOSP_PACKET_CAPTURE_H
#define NOSP_PACKET_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif



typedef struct CaptureContext CaptureContext;



typedef struct {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t protocol;  

    uint16_t length;
    uint8_t flags;  

    char src_ip_str[16];
    char dest_ip_str[16];
} PacketInfo;



CaptureContext* capture_init(void);



int capture_start(CaptureContext *ctx, const char *interface);







int capture_packets(CaptureContext *ctx, int max_packets, double timeout_sec);



PacketInfo* capture_get_packets(CaptureContext *ctx, int *count);



void capture_get_stats(CaptureContext *ctx, uint64_t *total_packets, uint64_t *total_bytes);



void capture_stop(CaptureContext *ctx);



void capture_free(CaptureContext *ctx);

#ifdef __cplusplus
}
#endif

#endif 

