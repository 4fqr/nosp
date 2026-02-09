/**
 * NOSP EVENT HORIZON - Packet Injector Header
 * ============================================
 * 
 * Public API for TCP RST packet injection.
 * 
 * Author: NOSP Team
 * Contact: 4fqr5@atomicmail.io
 */

#ifndef PACKET_INJECTOR_H
#define PACKET_INJECTOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque injector context structure.
 * 
 * Contains raw socket handle and injection statistics.
 */
typedef struct {
    int raw_socket;              // Raw socket file descriptor
    uint64_t packets_injected;   // Total packets injected
    int is_initialized;          // Initialization flag
} InjectorContext;

/**
 * Initialize packet injector and create raw socket.
 * 
 * Requires Administrator (Windows) or root (Linux) privileges.
 * 
 * @param ctx Pointer to InjectorContext to initialize
 * @return 0 on success, -1 on error
 */
int injector_init(InjectorContext* ctx);

/**
 * Cleanup and close injector resources.
 * 
 * @param ctx Pointer to InjectorContext
 */
void injector_cleanup(InjectorContext* ctx);

/**
 * Inject a TCP RST packet to forcibly close a connection.
 * 
 * Crafts and sends a raw TCP/IP packet with the RST flag set.
 * The target connection will immediately terminate.
 * 
 * @param ctx Injector context
 * @param src_ip Source IP address (dotted decimal)
 * @param dst_ip Destination IP address (dotted decimal)
 * @param src_port Source TCP port
 * @param dst_port Destination TCP port
 * @param seq_num TCP sequence number (use 0 if unknown)
 * @return 0 on success, -1 on error
 */
int inject_tcp_rst(InjectorContext* ctx,
                   const char* src_ip, const char* dst_ip,
                   uint16_t src_port, uint16_t dst_port,
                   uint32_t seq_num);

/**
 * Inject bidirectional TCP RST packets to kill a connection.
 * 
 * Sends RST packets in both directions for guaranteed termination.
 * 
 * @param ctx Injector context
 * @param local_ip Local endpoint IP
 * @param remote_ip Remote endpoint IP
 * @param local_port Local TCP port
 * @param remote_port Remote TCP port
 * @return 0 on success, -1 on error
 */
int inject_bidirectional_rst(InjectorContext* ctx,
                              const char* local_ip, const char* remote_ip,
                              uint16_t local_port, uint16_t remote_port);

/**
 * Get injection statistics.
 * 
 * @param ctx Injector context
 * @return Number of packets injected
 */
uint64_t injector_get_stats(InjectorContext* ctx);

#ifdef __cplusplus
}
#endif

#endif // PACKET_INJECTOR_H
