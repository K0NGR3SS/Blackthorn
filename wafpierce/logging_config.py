"""
Logging Configuration for WAFPierce
Structured logging with file and console handlers
"""
import logging
import logging.config
import os
from typing import Optional

from .constants import DEFAULT_LOG_LEVEL, LOG_FORMAT
from .config import get_log_dir


def setup_logging(
    level: str = DEFAULT_LOG_LEVEL,
    log_file: Optional[str] = None,
    log_to_file: bool = True,
) -> None:
    """
    Configure logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional custom log file path
        log_to_file: Whether to log to file
    """
    # Determine log file path
    if log_file is None and log_to_file:
        log_dir = get_log_dir()
        log_file = os.path.join(log_dir, 'wafpierce.log')
    
    # Build handlers
    handlers = {
        'console': {
            'class': 'logging.StreamHandler',
            'level': level,
            'formatter': 'detailed',
            'stream': 'ext://sys.stdout',
        },
    }
    
    if log_to_file and log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        handlers['file'] = {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': level,
            'formatter': 'detailed',
            'filename': log_file,
            'maxBytes': 10 * 1024 * 1024,  # 10 MB
            'backupCount': 5,
            'encoding': 'utf-8',
        }
    
    # Logging configuration
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'detailed': {
                'format': LOG_FORMAT,
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
            'simple': {
                'format': '%(levelname)s - %(message)s',
            },
        },
        'handlers': handlers,
        'root': {
            'level': level,
            'handlers': list(handlers.keys()),
        },
        'loggers': {
            'wafpierce': {
                'level': level,
                'handlers': list(handlers.keys()),
                'propagate': False,
            },
            'urllib3': {
                'level': 'WARNING',  # Reduce noise from urllib3
                'handlers': list(handlers.keys()),
                'propagate': False,
            },
            'requests': {
                'level': 'WARNING',  # Reduce noise from requests
                'handlers': list(handlers.keys()),
                'propagate': False,
            },
        },
    }
    
    logging.config.dictConfig(config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


# Default logging setup
setup_logging()