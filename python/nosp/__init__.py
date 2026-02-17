"""
NOSP - Null OS Security Program
Main Application Entry Point

A next-generation, privacy-first security monitor powered by Rust and AI.
"""

__version__ = "0.1.0"

from .errors import Result, NospError, graceful, ensure_no_raise, report_exception  # re-export helpers

__all__ = ['database', 'ai_engine', 'risk_scorer', 'native_bindings', 'linux_compat', 'platform_compat', 'Result', 'NospError']

# Register structured exception hook for uncaught exceptions
import sys

def _nosp_excepthook(exc_type, exc_value, exc_traceback):
    try:
        # avoid recursion
        if exc_value is None:
            return
        report_exception(exc_value, context="uncaught_exception")
    except Exception:
        pass

sys.excepthook = _nosp_excepthook
