"""
Platform compatibility layer for NOSP
"""

import sys
import platform
import logging
from .errors import report_exception

logger = logging.getLogger(__name__)

IS_WINDOWS =platform .system ()=='Windows'
IS_LINUX =platform .system ()=='Linux'
IS_MACOS =platform .system ()=='Darwin'

def get_platform ():
    return platform .system ()

def is_admin ():
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            report_exception(e, context="is_admin_windows")
            return False
    else:
        import os
        return os.geteuid() == 0

def require_admin (func ):
    def wrapper (*args ,**kwargs ):
        if not is_admin ():
            logger .error (f"{func .__name__ } requires administrator/root privileges")
            return None
        return func (*args ,**kwargs )
    return wrapper

def get_process_list ():
    try:
        import psutil
        return [p.info for p in psutil.process_iter(['pid', 'name', 'username', 'cmdline'])]
    except ImportError as e:
        logger.warning("psutil not available")
        report_exception(e, context="get_process_list")
        return []

def get_system_info ():
    return {
    'platform':platform .system (),
    'platform_release':platform .release (),
    'platform_version':platform .version (),
    'architecture':platform .machine (),
    'processor':platform .processor (),
    'python_version':sys .version
    }

class WindowsFeatureStub :
    def __init__ (self ,feature_name ):
        self .feature_name =feature_name
        logger .warning (f"⚠ {feature_name } is not available on {platform .system ()}")

    def __getattr__ (self ,name ):
        def method (*args ,**kwargs ):
            logger .debug (f"{self .feature_name }.{name }() called on non-Windows platform")
            return None
        return method
