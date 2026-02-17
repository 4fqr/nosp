

#ifndef PACKET_INJECTOR_H
#define PACKET_INJECTOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    int raw_socket;              

    uint64_t packets_injected;   

    int is_initialized;          

} InjectorContext;


int injector_init(InjectorContext* ctx);


void injector_cleanup(InjectorContext* ctx);


int inject_tcp_rst(InjectorContext* ctx,
                   const char* src_ip, const char* dst_ip,
                   uint16_t src_port, uint16_t dst_port,
                   uint32_t seq_num);


int inject_bidirectional_rst(InjectorContext* ctx,
                              const char* local_ip, const char* remote_ip,
                              uint16_t local_port, uint16_t remote_port);


uint64_t injector_get_stats(InjectorContext* ctx);

#ifdef __cplusplus
}
#endif

#endif 

