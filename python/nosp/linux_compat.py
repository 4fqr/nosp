"""
Linux-compatible process monitoring using eBPF or audit
"""

import logging
import platform
import subprocess
import json
from typing import List, Dict
from .errors import report_exception

logger = logging.getLogger(__name__)

IS_LINUX =platform .system ()=='Linux'

class LinuxProcessMonitor :
    def __init__ (self ):
        self .monitoring =False
        self .backends =self ._detect_backends ()
        logger .info (f"Linux monitoring backends available: {', '.join (self .backends )if self .backends else 'none'}")

    def _detect_backends (self ):
        backends =[]

        try:
            subprocess.run(['which', 'auditd'], check=True, capture_output=True)
            backends.append('auditd')
        except Exception:
            pass

        try:
            subprocess.run(['which', 'bpftrace'], check=True, capture_output=True)
            backends.append('bpftrace')
        except Exception:
            pass

        backends .append ('psutil')

        return backends

    def start_monitoring (self ):
        if not IS_LINUX :
            logger .error ("LinuxProcessMonitor only works on Linux")
            return False

        if 'auditd'in self .backends :
            return self ._start_auditd_monitoring ()
        elif 'psutil'in self .backends :
            return self ._start_psutil_monitoring ()
        else :
            logger .warning ("No suitable monitoring backend found")
            return False

    def _start_auditd_monitoring (self ):
        try :
            subprocess .run ([
            'auditctl','-a','always,exit',
            '-F','arch=b64',
            '-S','execve',
            '-k','nosp_exec'
            ],check =True ,capture_output =True )

            logger .info ("✓ Auditd monitoring enabled")
            self .monitoring =True
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to setup auditd: {e}")
            report_exception(e, context="LinuxProcessMonitor._start_auditd_monitoring")
            return False
        except FileNotFoundError as e:
            logger.error("auditctl not found. Install auditd package.")
            report_exception(e, context="LinuxProcessMonitor._start_auditd_monitoring")
            return False

    def _start_psutil_monitoring (self ):
        try :
            import psutil
            logger .info ("✓ Using psutil for process monitoring")
            self .monitoring =True
            return True
        except ImportError as e:
            logger.error("psutil not available")
            report_exception(e, context="LinuxProcessMonitor._start_psutil_monitoring")
            return False

    def get_events (self )->List [Dict ]:
        if not self .monitoring :
            return []

        if 'auditd'in self .backends :
            return self ._get_auditd_events ()
        elif 'psutil'in self .backends :
            return self ._get_psutil_events ()

        return []

    def _get_auditd_events (self )->List [Dict ]:
        try:
            result = subprocess.run(
                ['ausearch', '-k', 'nosp_exec', '--format', 'json'],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                return json.loads(result.stdout)
            return []
        except Exception:
            return []

    def _get_psutil_events (self )->List [Dict ]:
        try :
            import psutil
            events =[]

            for proc in psutil .process_iter (['pid','name','username','create_time','cmdline']):
                try :
                    info =proc .info
                    events .append ({
                    'pid':info ['pid'],
                    'name':info ['name'],
                    'username':info ['username'],
                    'cmdline':' '.join (info ['cmdline'])if info ['cmdline']else '',
                    'create_time':info ['create_time']
                    })
                except (psutil .NoSuchProcess ,psutil .AccessDenied ):
                    continue

            return events
        except ImportError :
            return []

    def stop_monitoring (self ):
        if 'auditd'in self .backends :
            try :
                subprocess .run (['auditctl','-D'],check =True ,capture_output =True )
                logger .info ("✓ Auditd monitoring disabled")
            except Exception:
                pass

        self.monitoring = False

class LinuxUSBMonitor :
    def __init__ (self ):
        self .udev_available =self ._check_udev ()

    def _check_udev (self ):
        try :
            import pyudev
            return True
        except ImportError :
            logger .warning ("pyudev not available. USB monitoring limited.")
            return False

    def get_devices (self )->List [Dict ]:
        if not self .udev_available :
            return self ._get_devices_lsusb ()

        try:
            import pyudev
            context = pyudev.Context()
            devices = []

            for device in context.list_devices(subsystem='usb'):
                if device.device_type == 'usb_device':
                    devices.append({
                        'vendor_id': device.get('ID_VENDOR_ID', 'unknown'),
                        'product_id': device.get('ID_MODEL_ID', 'unknown'),
                        'vendor': device.get('ID_VENDOR', 'unknown'),
                        'model': device.get('ID_MODEL', 'unknown'),
                        'serial': device.get('ID_SERIAL_SHORT', 'unknown'),
                        'devpath': device.device_path,
                    })

            return devices
        except Exception as e:
            logger.error(f"Failed to enumerate USB devices: {e}")
            return []

    def _get_devices_lsusb (self )->List [Dict ]:
        try:
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = []

            for line in result.stdout.splitlines():
                if line.strip():
                    devices.append({'raw': line})

            return devices
        except Exception:
            return []

    def block_device (self ,device_id :str )->bool :
        logger .warning ("USB device blocking on Linux requires udev rules")
        rule_path ="/etc/udev/rules.d/99-nosp-usb-block.rules"

        rule =f'SUBSYSTEM=="usb", ATTRS{{idVendor}}=="{device_id [:4 ]}", ATTRS{{idProduct}}=="{device_id [5 :]}", MODE="0000"\n'

        try :
            with open (rule_path ,'a')as f :
                f .write (rule )

            subprocess .run (['udevadm','control','--reload-rules'],check =True )
            logger .info (f"✓ USB device {device_id } blocked via udev")
            return True
        except PermissionError as e:
            logger.error("Root privileges required to block USB devices")
            report_exception(e, context="LinuxUSBMonitor.block_device")
            return False
        except Exception as e:
            logger.error(f"Failed to block USB device: {e}")
            report_exception(e, context="LinuxUSBMonitor.block_device")
            return False

class LinuxNetworkMonitor :
    def __init__ (self ):
        self .nfqueue_available =self ._check_nfqueue ()

    def _check_nfqueue (self ):
        try :
            import netfilterqueue
            return True
        except ImportError :
            logger .warning ("netfilterqueue not available. Install with: pip install NetfilterQueue")
            return False

    from .stability import retry

    @retry(max_attempts=2, initial_delay=0.1, backoff=2.0, exceptions=(Exception,))
    def start_packet_capture (self ,callback ):
        if not self .nfqueue_available :
            logger .error ("NetfilterQueue not available")
            return False

        try :
            from netfilterqueue import NetfilterQueue

            nfqueue =NetfilterQueue ()
            nfqueue .bind (1 ,callback )

            subprocess .run ([
            'iptables','-I','FORWARD','-j','NFQUEUE','--queue-num','1'
            ],check =True )

            logger .info ("✓ Packet capture started")
            nfqueue .run ()
            return True
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            report_exception(e, context="LinuxNetworkMonitor.start_packet_capture")
            return False
