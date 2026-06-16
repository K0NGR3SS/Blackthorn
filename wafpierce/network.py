"""
Network Utilities with Connection Pooling
Optimized HTTP session management
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional

from .constants import (
    DEFAULT_MAX_RETRIES,
    NETWORK_RETRIES,
    CONNECTION_POOL_CONNECTIONS,
    CONNECTION_POOL_MAXSIZE,
    DEFAULT_USER_AGENT,
)


def create_optimized_session(
    max_retries: int = DEFAULT_MAX_RETRIES,
    pool_connections: int = CONNECTION_POOL_CONNECTIONS,
    pool_maxsize: int = CONNECTION_POOL_MAXSIZE,
    verify_ssl: bool = True,
    user_agent: str = DEFAULT_USER_AGENT,
) -> requests.Session:
    """
    Create a session with connection pooling and retry logic.
    
    Args:
        max_retries: Maximum number of retry attempts
        pool_connections: Number of connection pools to cache
        pool_maxsize: Maximum number of connections per pool
        verify_ssl: Whether to verify SSL certificates
        user_agent: User-Agent string to use
    
    Returns:
        Configured requests.Session object
    """
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    
    # Create adapter with connection pooling
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
    )
    
    # Mount adapter for both HTTP and HTTPS
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default headers
    session.headers.update({
        'User-Agent': user_agent,
    })
    
    # SSL verification (only if explicitly disabled for backwards compatibility)
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        session.verify = False
    
    return session


def create_simple_session(
    timeout: int = 30,
    verify_ssl: bool = True,
) -> requests.Session:
    """
    Create a simple session without connection pooling.
    Useful for quick one-off requests.
    
    Args:
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
    
    Returns:
        Configured requests.Session object
    """
    session = requests.Session()
    session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
    
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        session.verify = False
    
    return session