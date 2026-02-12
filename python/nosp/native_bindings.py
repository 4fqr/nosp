"""
NOSP Native C Module Wrappers
==============================

Python bindings for high-performance C modules:
- Packet capture (raw sockets)
- Packet injection (TCP RST)
- Pattern matching (malware signatures)
"""

import ctypes
import platform
import os
from pathlib import Path
from typing import Optional, Tuple, List
import logging

logger = logging.getLogger(__name__)

NATIVE_DIR = Path(__file__).parent.parent.parent / "native" / "c"

if platform.system() == "Windows":
    LIB_EXT = ".dll"
else:
    LIB_EXT = ".so"


class PacketInfo(ctypes.Structure):
    """Captured packet information"""
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("src_ip", ctypes.c_uint32),
        ("dest_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dest_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("length", ctypes.c_uint16),
        ("flags", ctypes.c_uint8),
        ("src_ip_str", ctypes.c_char * 16),
        ("dest_ip_str", ctypes.c_char * 16),
    ]


class InjectorContext(ctypes.Structure):
    """Packet injector context"""
    _fields_ = [
        ("raw_socket", ctypes.c_int),
        ("packets_injected", ctypes.c_uint64),
        ("is_initialized", ctypes.c_int),
    ]


class PacketCapture:
    """
    High-performance packet capture using C module.
    
    Features:
    - Raw socket capture (requires root/admin)
    - Zero-copy packet processing
    - Nanosecond timestamps
    - TCP/UDP/ICMP support
    """
    
    def __init__(self):
        self.lib = None
        self.ctx = None
        self._load_library()
    
    def _load_library(self):
        """Load packet capture shared library"""
        lib_path = NATIVE_DIR / f"packet_capture{LIB_EXT}"
        
        if not lib_path.exists():
            logger.warning(f"Packet capture library not found: {lib_path}")
            return
        
        try:
            self.lib = ctypes.CDLL(str(lib_path))
            
            self.lib.capture_init.restype = ctypes.c_void_p
            self.lib.capture_start.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self.lib.capture_start.restype = ctypes.c_int
            self.lib.capture_packets.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_double]
            self.lib.capture_packets.restype = ctypes.c_int
            self.lib.capture_get_packets.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            self.lib.capture_get_packets.restype = ctypes.POINTER(PacketInfo)
            self.lib.capture_stop.argtypes = [ctypes.c_void_p]
            self.lib.capture_free.argtypes = [ctypes.c_void_p]
            
            logger.info("✓ Packet capture library loaded")
        except Exception as e:
            logger.error(f"Failed to load packet capture library: {e}")
            self.lib = None
    
    def start(self, interface: Optional[str] = None) -> bool:
        """
        Start packet capture.
        
        Args:
            interface: Network interface name (None = default)
            
        Returns:
            True if started successfully
        """
        if not self.lib:
            return False
        
        self.ctx = self.lib.capture_init()
        if not self.ctx:
            logger.error("Failed to initialize capture context")
            return False
        
        interface_bytes = interface.encode('utf-8') if interface else None
        result = self.lib.capture_start(self.ctx, interface_bytes)
        
        if result != 0:
            logger.error("Failed to start packet capture (need root/admin)")
            return False
        
        logger.info("✓ Packet capture started")
        return True
    
    def capture(self, max_packets: int = 100, timeout: float = 1.0) -> List[dict]:
        """
        Capture packets.
        
        Args:
            max_packets: Maximum packets to capture
            timeout: Timeout in seconds (0 = no timeout)
            
        Returns:
            List of captured packet dictionaries
        """
        if not self.lib or not self.ctx:
            return []
        
        count = self.lib.capture_packets(self.ctx, max_packets, timeout)
        
        if count <= 0:
            return []
        
        packet_count = ctypes.c_int()
        packets_ptr = self.lib.capture_get_packets(self.ctx, ctypes.byref(packet_count))
        
        if not packets_ptr:
            return []
        
        results = []
        for i in range(packet_count.value):
            pkt = packets_ptr[i]
            results.append({
                'timestamp_ns': pkt.timestamp_ns,
                'src_ip': pkt.src_ip_str.decode('utf-8'),
                'dst_ip': pkt.dest_ip_str.decode('utf-8'),
                'src_port': pkt.src_port,
                'dst_port': pkt.dest_port,
                'protocol': pkt.protocol,
                'length': pkt.length,
                'flags': pkt.flags
            })
        
        return results
    
    def stop(self):
        """Stop packet capture"""
        if self.lib and self.ctx:
            self.lib.capture_stop(self.ctx)
            self.lib.capture_free(self.ctx)
            self.ctx = None
            logger.info("✓ Packet capture stopped")


class PacketInjector:
    """
    TCP RST packet injection for forcibly terminating connections.
    
    Features:
    - Raw socket injection (requires root/admin)
    - Custom TCP/IP header crafting
    - Checksum calculation
    - Bidirectional RST
    """
    
    def __init__(self):
        self.lib = None
        self.ctx = InjectorContext()
        self._load_library()
    
    def _load_library(self):
        """Load packet injector shared library"""
        lib_path = NATIVE_DIR / f"packet_injector{LIB_EXT}"
        
        if not lib_path.exists():
            logger.warning(f"Packet injector library not found: {lib_path}")
            return
        
        try:
            self.lib = ctypes.CDLL(str(lib_path))
            
            self.lib.injector_init.argtypes = [ctypes.POINTER(InjectorContext)]
            self.lib.injector_init.restype = ctypes.c_int
            self.lib.injector_cleanup.argtypes = [ctypes.POINTER(InjectorContext)]
            self.lib.inject_tcp_rst.argtypes = [
                ctypes.POINTER(InjectorContext),
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_uint16, ctypes.c_uint16,
                ctypes.c_uint32
            ]
            self.lib.inject_tcp_rst.restype = ctypes.c_int
            self.lib.inject_bidirectional_rst.argtypes = [
                ctypes.POINTER(InjectorContext),
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_uint16, ctypes.c_uint16
            ]
            self.lib.inject_bidirectional_rst.restype = ctypes.c_int
            self.lib.injector_get_stats.argtypes = [ctypes.POINTER(InjectorContext)]
            self.lib.injector_get_stats.restype = ctypes.c_uint64
            
            logger.info("✓ Packet injector library loaded")
        except Exception as e:
            logger.error(f"Failed to load packet injector library: {e}")
            self.lib = None
    
    def initialize(self) -> bool:
        """
        Initialize packet injector (requires admin/root).
        
        Returns:
            True if initialized successfully
        """
        if not self.lib:
            return False
        
        result = self.lib.injector_init(ctypes.byref(self.ctx))
        
        if result != 0:
            logger.error("Failed to initialize injector (need root/admin)")
            return False
        
        logger.info("✓ Packet injector initialized")
        return True
    
    def inject_rst(self, src_ip: str, dst_ip: str, 
                   src_port: int, dst_port: int,
                   seq_num: int = 0) -> bool:
        """
        Inject TCP RST packet to kill connection.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            seq_num: TCP sequence number (0 if unknown)
            
        Returns:
            True if injected successfully
        """
        if not self.lib or not self.ctx.is_initialized:
            return False
        
        result = self.lib.inject_tcp_rst(
            ctypes.byref(self.ctx),
            src_ip.encode('utf-8'),
            dst_ip.encode('utf-8'),
            src_port,
            dst_port,
            seq_num
        )
        
        if result != 0:
            logger.error("Failed to inject RST packet")
            return False
        
        logger.info(f"✓ Injected RST: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        return True
    
    def kill_connection(self, local_ip: str, remote_ip: str,
                       local_port: int, remote_port: int) -> bool:
        """
        Kill connection with bidirectional RST packets.
        
        Args:
            local_ip: Local endpoint IP
            remote_ip: Remote endpoint IP
            local_port: Local port
            remote_port: Remote port
            
        Returns:
            True if killed successfully
        """
        if not self.lib or not self.ctx.is_initialized:
            return False
        
        result = self.lib.inject_bidirectional_rst(
            ctypes.byref(self.ctx),
            local_ip.encode('utf-8'),
            remote_ip.encode('utf-8'),
            local_port,
            remote_port
        )
        
        if result != 0:
            logger.error("Failed to kill connection")
            return False
        
        logger.info(f"✓ Connection killed: {local_ip}:{local_port} <-> {remote_ip}:{remote_port}")
        return True
    
    def get_stats(self) -> int:
        """
        Get number of packets injected.
        
        Returns:
            Packet injection count
        """
        if not self.lib or not self.ctx.is_initialized:
            return 0
        
        return self.lib.injector_get_stats(ctypes.byref(self.ctx))
    
    def cleanup(self):
        """Cleanup injector resources"""
        if self.lib and self.ctx.is_initialized:
            self.lib.injector_cleanup(ctypes.byref(self.ctx))
            logger.info("✓ Packet injector cleaned up")


_capture_instance: Optional[PacketCapture] = None
_injector_instance: Optional[PacketInjector] = None


def get_packet_capture() -> PacketCapture:
    """Get global packet capture instance"""
    global _capture_instance
    if _capture_instance is None:
        _capture_instance = PacketCapture()
    return _capture_instance


def get_packet_injector() -> PacketInjector:
    """Get global packet injector instance"""
    global _injector_instance
    if _injector_instance is None:
        _injector_instance = PacketInjector()
    return _injector_instance


if __name__ == "__main__":
    import sys
    
    print("NOSP Native C Module Test")
    print("=" * 60)
    
    if os.getuid() != 0:
        print("ERROR: This test requires root/Administrator privileges")
        sys.exit(1)
    
    print("\nTesting Packet Injector...")
    injector = PacketInjector()
    
    if injector.initialize():
        print("✓ Injector initialized")
        print(f"  Stats: {injector.get_stats()} packets injected")
        injector.cleanup()
    else:
        print("✗ Injector failed to initialize")
    
    print("\nTesting Packet Capture...")
    capture = PacketCapture()
    
    if capture.start():
        print("✓ Capture started")
        print("  Capturing packets (5 second timeout)...")
        
        packets = capture.capture(max_packets=10, timeout=5.0)
        print(f"  Captured {len(packets)} packets")
        
        for i, pkt in enumerate(packets[:5]):
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(pkt['protocol'], "OTHER")
            print(f"    [{i+1}] {proto}: {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
        
        capture.stop()
    else:
        print("✗ Capture failed to start")
    
    print("\n" + "=" * 60)
    print("Test complete")
