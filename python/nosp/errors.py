from dataclasses import dataclass, asdict
import logging
import json
import traceback
import sys
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)
_error_log_path = "nosp_error.log"


@dataclass
class Result:
    success: bool
    value: Any = None
    error_code: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    details: Optional[dict] = None


class NospError(Exception):
    def __init__(self, message: str, code: Optional[str] = None, suggestion: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.suggestion = suggestion
        self.details = details or {}


def _write_structured_log(entry: dict) -> None:
    try:
        with open(_error_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        logger.debug("Failed to write structured error log", exc_info=True)


def suggestion_for_exception(exc: Exception, context: Optional[str] = None) -> str:
    """Return a short remediation hint for common exceptions."""
    msg = str(exc)
    if isinstance(exc, FileNotFoundError):
        return "Verify the file path exists and permissions; ensure the path is not empty."
    if isinstance(exc, PermissionError):
        return "Run with elevated privileges (Administrator / root) or adjust filesystem/ACL permissions."
    if isinstance(exc, ImportError):
        name = getattr(exc, 'name', None) or msg.split(' ')[-1]
        return f"Install missing dependency (e.g. `pip install {name}`) or check your PYTHONPATH."
    if isinstance(exc, TimeoutError):
        return "Operation timed out; increase timeout or check network/IO responsiveness."
    # Generic fallback
    return "See `details` for diagnostics; check environment, permissions, and required dependencies."


def report_exception(exc: Exception, context: Optional[str] = None) -> None:
    entry = {
        "timestamp": time.time(),
        "module": context or "nosp",
        "type": exc.__class__.__name__,
        "message": str(exc),
        "suggestion": suggestion_for_exception(exc, context),
        "traceback": traceback.format_exc(),
    }
    logger.error("Structured error: %s", entry)
    _write_structured_log(entry)


def graceful(return_on_error: Any = None, wrap_result: bool = True) -> Callable:
    """Decorator to make functions return a Result on exception or a safe fallback.

    - return_on_error: explicit fallback value (used when wrap_result=False)
    - wrap_result: if True, return `Result` dataclass; otherwise return raw value or fallback
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            try:
                val = func(*args, **kwargs)
                if wrap_result:
                    return Result(success=True, value=val)
                return val
            except NospError as ne:
                report_exception(ne, context=func.__name__)
                res = Result(success=False, message=str(ne), error_code=ne.code, suggestion=ne.suggestion, details=ne.details)
                return res if wrap_result else (return_on_error if return_on_error is not None else None)
            except Exception as e:
                report_exception(e, context=func.__name__)
                suggestion = suggestion_for_exception(e, context=func.__name__)
                res = Result(success=False, message=str(e), suggestion=suggestion, details={"exc_type": e.__class__.__name__})
                return res if wrap_result else (return_on_error if return_on_error is not None else None)
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    return decorator


def ensure_no_raise(func: Callable) -> Callable:
    """Decorator variant that logs exceptions but never re-raises (legacy compatibility)."""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            report_exception(e, context=func.__name__)
            return None

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper
