"""Logging utility."""

import sys
import logging
from datetime import datetime

LOG_LEVEL_VERBOSE = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARNING = 2
LOG_LEVEL_ERROR = 3
LOG_LEVEL_FATAL = 4

_level_names = {
    0: "VERBOSE",
    1: "INFO",
    2: "WARNING",
    3: "ERROR",
    4: "FATAL",
}

_current_level = LOG_LEVEL_VERBOSE
_log_file = None


def set_log_level(level: int):
    global _current_level
    _current_level = level


def write_log(id: int, message: str, level: int = LOG_LEVEL_INFO):
    global _current_level, _log_file
    if level < _current_level:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_name = _level_names.get(level, "UNKNOWN")
    log_line = f"[{timestamp}] [{level_name}] {message}"

    if _log_file:
        _log_file.write(log_line + "\n")
        _log_file.flush()
    else:
        print(log_line, file=sys.stderr)


class Logger:
    """Simple logger that mimics subconverter's logging behavior."""
    
    def info(self, msg):
        write_log(0, msg, LOG_LEVEL_INFO)
    
    def warning(self, msg):
        write_log(0, msg, LOG_LEVEL_WARNING)
    
    def error(self, msg):
        write_log(0, msg, LOG_LEVEL_ERROR)
    
    def verbose(self, msg):
        write_log(0, msg, LOG_LEVEL_VERBOSE)


logger = Logger()
