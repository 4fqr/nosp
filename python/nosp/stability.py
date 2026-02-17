"""Stability helpers: centralized logging, retry/backoff, health registry and graceful shutdown.

Purpose:
- Provide consistent logging/rotation for `nosp.log` and `nosp_error.log`.
- Retry decorator with exponential backoff for transient operations.
- Simple health registry for components and a graceful shutdown helper.
- Lightweight and dependency-free.
"""
from __future__ import annotations
import logging
import time
import threading
from logging.handlers import RotatingFileHandler
from typing import Callable, Any, Tuple, Type

_log_lock = threading.Lock()
_components = {}


def configure_logging(log_file: str = "nosp.log", error_log: str = "nosp_error.log", level: int = logging.INFO) -> None:
    """Configure root logger with rotating file handlers and console output.

    Safe to call multiple times.
    """
    with _log_lock:
        logger = logging.getLogger()
        # avoid duplicate configuration
        if getattr(logger, "__nosp_configured", False):
            return
        logger.setLevel(level)

        fmt = logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s")

        # console handler
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        # rotating general log
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        # rotating error log (separate file)
        eh = RotatingFileHandler(error_log, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        eh.setLevel(logging.ERROR)
        eh.setFormatter(fmt)
        logger.addHandler(eh)

        logger.info("Logging configured (nosp)")
        logger.__nosp_configured = True


def retry(max_attempts: int = 3, initial_delay: float = 0.2, backoff: float = 2.0, exceptions: Tuple[Type[BaseException], ...] = (Exception,), logger: logging.Logger | None = None):
    """Retry decorator with exponential backoff for transient operations.

    Usage:
      @retry(max_attempts=4, initial_delay=0.5)
      def may_fail(...):
          ...
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            _logger = logger or logging.getLogger(func.__module__)
            delay = initial_delay
            attempt = 1
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    if attempt >= max_attempts:
                        _logger.error("Function %s failed after %d attempts: %s", func.__name__, attempt, exc)
                        raise
                    _logger.warning("Transient error in %s (attempt %d/%d): %s — retrying in %.2fs",
                                    func.__name__, attempt, max_attempts, exc, delay)
                    time.sleep(delay)
                    delay *= backoff
                    attempt += 1
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    return decorator


def register_component(name: str, status: str = "ok", details: dict | None = None) -> None:
    _components[name] = {"status": status, "details": details or {}, "updated": time.time()}


def set_component_status(name: str, status: str, details: dict | None = None) -> None:
    if name in _components:
        _components[name]["status"] = status
        _components[name]["details"] = details or _components[name].get("details", {})
        _components[name]["updated"] = time.time()
    else:
        register_component(name, status, details)


def get_health() -> dict:
    return {"components": _components.copy(), "timestamp": time.time()}


def graceful_shutdown(components: dict) -> None:
    """Attempt to stop long-running components cleanly.

    `components` should be a dict of name -> object with optional `stop`, `cleanup`, or `close` methods.
    """
    logger = logging.getLogger("nosp.stability")
    for name, obj in components.items():
        try:
            if hasattr(obj, "stop"):
                obj.stop()
                logger.info("Stopped component: %s", name)
            elif hasattr(obj, "cleanup"):
                obj.cleanup()
                logger.info("Cleaned up component: %s", name)
            elif hasattr(obj, "close"):
                obj.close()
                logger.info("Closed component: %s", name)
        except Exception as e:
            logger.exception("Error while shutting down %s: %s", name, e)
            set_component_status(name, "error", {"shutdown_error": str(e)})
