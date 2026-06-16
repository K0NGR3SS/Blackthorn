"""
Shared Configuration Utilities
Platform-independent config directory and path management
"""
import os
from typing import Optional

from .constants import (
    CONFIG_DIR_NAME,
    DATABASE_FILENAME,
    GUI_PREFS_FILENAME,
    PLUGINS_DIR_NAME,
)


def get_config_dir() -> str:
    """
    Get the platform-appropriate config directory.
    
    Returns:
        Path to the config directory
    """
    if os.name == 'nt':  # Windows
        base = os.getenv('APPDATA') or os.path.expanduser('~')
    else:  # Unix-like (Linux, macOS)
        base = os.path.join(os.path.expanduser('~'), '.config')
    
    return os.path.join(base, CONFIG_DIR_NAME)


def ensure_config_dir() -> str:
    """
    Get the config directory, creating it if it doesn't exist.
    
    Returns:
        Path to the config directory
    """
    d = get_config_dir()
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def get_database_path() -> str:
    """
    Get the path to the SQLite database.
    
    Returns:
        Path to the database file
    """
    return os.path.join(ensure_config_dir(), DATABASE_FILENAME)


def get_gui_prefs_path() -> str:
    """
    Get the path to the GUI preferences file.
    
    Returns:
        Path to the GUI prefs JSON file
    """
    return os.path.join(ensure_config_dir(), GUI_PREFS_FILENAME)


def get_plugins_dir() -> str:
    """
    Get the plugins directory path.
    
    Returns:
        Path to the plugins directory
    """
    return os.path.join(ensure_config_dir(), PLUGINS_DIR_NAME)


def ensure_plugins_dir() -> str:
    """
    Get the plugins directory, creating it if it doesn't exist.
    
    Returns:
        Path to the plugins directory
    """
    d = get_plugins_dir()
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def get_log_dir() -> str:
    """
    Get the directory for log files.
    
    Returns:
        Path to the log directory
    """
    d = os.path.join(get_config_dir(), 'logs')
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d