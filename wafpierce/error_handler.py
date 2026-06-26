"""
Error Handler Utilities
Provides retry logic, graceful degradation, and error logging
"""
import time
import logging
import warnings
import random
import re
from functools import wraps
from typing import Callable, Any, Optional, Tuple, Type, Dict, List
from urllib.parse import urlparse
import requests
from urllib3.exceptions import InsecureRequestWarning

from .exceptions import (
    TargetUnreachableError,
    RequestTimeoutError,
    SSLError,
    DNSResolutionError,
    TooManyRedirectsError,
    ProxyError,
    RateLimitError,
    NetworkError,
    BackendDetectionError,
    InvalidTargetError,
    InvalidSchemeError,
)


logger = logging.getLogger(__name__)


# Blocked hostnames for security
BLOCKED_HOSTNAMES = frozenset([
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
])


def validate_url_strict(url: str, allow_local: bool = False) -> str:
    """
    Strictly validate and sanitize target URL (raises exceptions).
    
    Args:
        url: The URL to validate
        allow_local: Whether to allow localhost addresses
    
    Returns:
        The validated URL
    
    Raises:
        InvalidTargetError: If URL is invalid
        InvalidSchemeError: If scheme is not http/https
    """
    if not url:
        raise InvalidTargetError("URL cannot be empty")
    
    # Basic URL parsing
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ('http', 'https'):
        raise InvalidSchemeError(f"Invalid scheme: {parsed.scheme}. Must be http or https.")
    
    if not parsed.netloc:
        raise InvalidTargetError("No valid hostname in URL")
    
    # Check for blocked hostnames (security)
    hostname = parsed.hostname.lower() if parsed.hostname else ''
    
    if not allow_local and hostname in BLOCKED_HOSTNAMES:
        raise InvalidTargetError("Localhost addresses not allowed for security reasons")
    
    # Check for IP addresses that might be internal
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(hostname):
        # It's an IP address, check for private ranges
        try:
            octets = [int(o) for o in hostname.split('.')]
            # Check for private IP ranges (RFC 1918)
            if octets[0] in (10, 172, 192):
                if not allow_local:
                    raise InvalidTargetError("Private IP addresses not allowed for security reasons")
        except (ValueError, IndexError):
            pass  # Invalid IP format, let it through
    
    return url


def retry_on_network_error(
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    exceptions: Tuple[Type[Exception], ...] = (NetworkError,),
    jitter: float = 0.0,
    on_retry: Optional[Callable[[int, int, Exception, float], None]] = None,
):
    """
    Decorator to retry function on network errors with exponential backoff
    
    Args:
        max_retries: Maximum number of retry attempts
        backoff_factor: Multiplier for exponential backoff (wait = backoff_factor * (2 ** attempt))
        exceptions: Tuple of exception types to catch and retry
        jitter: Random seconds added to backoff delay (0 disables jitter)
        on_retry: Optional callback(attempt, max_retries, exception, wait_time)
    
    Usage:
        @retry_on_network_error(max_retries=3, backoff_factor=0.5)
        def make_request(url):
            return requests.get(url)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor * (2 ** attempt)
                        if jitter > 0:
                            wait_time += random.uniform(0, jitter)
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries} failed: {e}. "
                            f"Retrying in {wait_time:.1f}s..."
                        )
                        if on_retry:
                            try:
                                on_retry(attempt + 1, max_retries, e, wait_time)
                            except Exception as cb_err:
                                logger.debug(f"Retry callback failed: {cb_err}")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} attempts failed: {e}")
            
            # Re-raise the last exception if all retries failed
            raise last_exception
        
        return wrapper
    return decorator


def handle_request_errors(url: str, exception: Exception) -> None:
    """
    Convert requests library exceptions to WAFPierce exceptions
    
    Args:
        url: The URL that was being requested
        exception: The exception that was raised
    
    Raises:
        Appropriate WAFPierce exception based on the requests exception type
    """
    if isinstance(exception, requests.exceptions.ConnectionError):
        # Check for specific connection errors
        error_msg = str(exception).lower()
        
        if 'name or service not known' in error_msg or 'nodename nor servname' in error_msg:
            raise DNSResolutionError(
                f"DNS lookup failed for {url}",
                details={'url': url, 'original_error': str(exception)}
            )
        elif 'certificate verify failed' in error_msg:
            raise SSLError(
                f"SSL certificate verification failed for {url}",
                details={'url': url, 'original_error': str(exception)}
            )
        elif 'proxy' in error_msg:
            raise ProxyError(
                f"Proxy connection failed for {url}",
                details={'url': url, 'original_error': str(exception)}
            )
        else:
            raise TargetUnreachableError(
                f"Cannot connect to {url}",
                details={'url': url, 'original_error': str(exception)}
            )
    
    elif isinstance(exception, requests.exceptions.Timeout):
        raise RequestTimeoutError(
            f"Request to {url} timed out",
            details={'url': url, 'original_error': str(exception)}
        )
    
    elif isinstance(exception, requests.exceptions.SSLError):
        raise SSLError(
            f"SSL error for {url}",
            details={'url': url, 'original_error': str(exception)}
        )
    
    elif isinstance(exception, requests.exceptions.TooManyRedirects):
        raise TooManyRedirectsError(
            f"Too many redirects for {url}",
            details={'url': url, 'original_error': str(exception)}
        )
    
    elif isinstance(exception, requests.exceptions.HTTPError):
        # Check for rate limiting
        if hasattr(exception, 'response') and exception.response is not None:
            if exception.response.status_code == 429:
                retry_after = exception.response.headers.get('Retry-After', 'unknown')
                raise RateLimitError(
                    f"Rate limit exceeded for {url}",
                    details={
                        'url': url,
                        'retry_after': retry_after,
                        'status_code': 429
                    }
                )
    
    # If we can't classify it, re-raise as generic NetworkError
    raise NetworkError(
        f"Network error for {url}: {str(exception)}",
        details={'url': url, 'original_error': str(exception)}
    )


def safe_request(
    url: str,
    method: str = 'GET',
    headers: Optional[dict] = None,
    timeout: int = 5,
    allow_redirects: bool = False,
    **kwargs
) -> Optional[requests.Response]:
    """
    Make a safe HTTP request with comprehensive error handling
    
    Args:
        url: Target URL
        method: HTTP method
        headers: Request headers
        timeout: Request timeout in seconds
        allow_redirects: Whether to follow redirects
        **kwargs: Additional arguments to pass to requests
    
    Returns:
        Response object if successful, None if failed gracefully
    
    Raises:
        WAFPierce exceptions for various error conditions
    """
    try:
        if method.upper() == 'GET':
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        elif method.upper() == 'POST':
            response = requests.post(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        elif method.upper() == 'HEAD':
            response = requests.head(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        else:
            response = requests.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        
        return response
    
    except Exception as e:
        handle_request_errors(url, e)


class GracefulErrorHandler:
    """
    Context manager for graceful error handling in scan operations
    Logs errors but allows scan to continue
    """
    
    def __init__(self, operation_name: str, continue_on_error: bool = True):
        self.operation_name = operation_name
        self.continue_on_error = continue_on_error
        self.error_count = 0
        self.errors = []
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.error_count += 1
            self.errors.append({
                'type': exc_type.__name__,
                'message': str(exc_val),
                'operation': self.operation_name
            })
            
            logger.error(f"Error in {self.operation_name}: {exc_val}")
            
            # Suppress the exception if continue_on_error is True
            if self.continue_on_error:
                logger.info(f"Continuing despite error in {self.operation_name}")
                return True  # Suppress exception
            
        return False  # Don't suppress exception
    
    def get_error_summary(self) -> dict:
        """Get summary of all errors encountered"""
        return {
            'error_count': self.error_count,
            'errors': self.errors
        }


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format and scheme
    
    Args:
        url: URL to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)
        
        if not parsed.scheme:
            return False, "URL must include scheme (http:// or https://)"
        
        if parsed.scheme not in ['http', 'https']:
            return False, f"Invalid scheme '{parsed.scheme}'. Must be http or https"
        
        if not parsed.netloc:
            return False, "URL must include domain/host"
        
        return True, None
    
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"


def setup_logging(log_file: Optional[str] = None, level: str = 'INFO') -> logging.Logger:
    """
    Configure logging for WAFPierce
    
    Args:
        log_file: Optional log file path
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    # Configure package logger (idempotent across repeated setup calls)
    logger = logging.getLogger('wafpierce')
    logger.setLevel(log_level)
    logger.propagate = False

    # Clear existing handlers to avoid duplicate log lines.
    for h in list(logger.handlers):
        logger.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass

    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create log file {log_file}: {e}")
    
    return logger


# ============= Backend Detection Utilities =============

def suppress_ssl_warnings():
    """
    Suppress SSL warnings when making requests with verify=False
    Use sparingly and only for backend detection probes
    """
    warnings.filterwarnings('ignore', category=InsecureRequestWarning)


def safe_backend_request(
    url: str,
    method: str = 'HEAD',
    timeout: int = 5,
    verify: bool = True,
    suppress_errors: bool = True,
    **kwargs
) -> Optional[requests.Response]:
    """
    Make a safe request specifically for backend detection
    
    Args:
        url: Target URL
        method: HTTP method (default HEAD for efficiency)
        timeout: Request timeout in seconds
        verify: Whether to verify SSL certificates
        suppress_errors: If True, return None on errors instead of raising
        **kwargs: Additional arguments to pass to requests
    
    Returns:
        Response object if successful, None if failed and suppress_errors=True
    """
    if not verify:
        suppress_ssl_warnings()
    
    try:
        response = requests.request(
            method,
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=False,
            **kwargs
        )
        return response
    except requests.exceptions.SSLError as e:
        if suppress_errors:
            logger.debug(f"SSL error for {url}: {e}")
            return None
        raise SSLError(
            f"SSL error for {url}",
            details={'url': url, 'original_error': str(e)}
        )
    except requests.exceptions.Timeout as e:
        if suppress_errors:
            logger.debug(f"Timeout for {url}: {e}")
            return None
        raise RequestTimeoutError(
            f"Request to {url} timed out",
            details={'url': url, 'original_error': str(e)}
        )
    except requests.exceptions.ConnectionError as e:
        if suppress_errors:
            logger.debug(f"Connection error for {url}: {e}")
            return None
        raise TargetUnreachableError(
            f"Cannot connect to {url}",
            details={'url': url, 'original_error': str(e)}
        )
    except Exception as e:
        if suppress_errors:
            logger.debug(f"Request error for {url}: {e}")
            return None
        raise BackendDetectionError(
            f"Backend detection request failed for {url}",
            details={'url': url, 'original_error': str(e)}
        )


def analyze_headers_safely(
    headers: Dict[str, str],
    body: str = ""
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Safely analyze response headers for backend indicators
    
    Args:
        headers: Response headers dictionary
        body: Response body text (optional)
    
    Returns:
        Tuple of (indicators_dict, errors_list)
    """
    indicators = {}
    errors = []
    
    try:
        # Normalize headers to lowercase
        normalized = {k.lower(): v for k, v in headers.items()}
        
        # AWS-specific headers to check
        aws_header_checks = [
            # S3 indicators
            ('x-amz-request-id', 's3_detected', 'S3'),
            ('x-amz-id-2', 's3_detected', 'S3'),
            ('x-amz-bucket-region', 's3_detected', 'S3'),
            # ELB/ALB indicators
            ('x-amzn-requestid', 'elb_detected', 'ALB/NLB'),
            ('x-amzn-trace-id', 'elb_detected', 'ALB'),
            # API Gateway
            ('x-amz-apigw-id', 'api_gateway_detected', 'API Gateway'),
            # Lambda
            ('x-amz-function-error', 'lambda_detected', 'Lambda'),
            ('x-amz-executed-version', 'lambda_detected', 'Lambda'),
            # CloudFront
            ('x-amz-cf-id', 'cloudfront_detected', 'CloudFront'),
            ('x-amz-cf-pop', 'cloudfront_detected', 'CloudFront'),
            # MediaPackage/MediaStore
            ('x-mediapackage-request-id', 'media_detected', 'MediaPackage'),
        ]
        
        for header, indicator_key, service_name in aws_header_checks:
            if header in normalized:
                indicators[indicator_key] = True
                indicators[f"{indicator_key}_header"] = header
                indicators[f"{indicator_key}_service"] = service_name
        
        # Check Server header
        if 'server' in normalized:
            indicators['server_software'] = normalized['server']
            
            # Identify specific server types
            server_lower = normalized['server'].lower()
            if 'amazons3' in server_lower:
                indicators['s3_detected'] = True
            elif 'awselb' in server_lower or 'elb' in server_lower:
                indicators['elb_detected'] = True
        
        # Check X-Powered-By
        if 'x-powered-by' in normalized:
            indicators['powered_by'] = normalized['x-powered-by']
        
        # Check Via header for proxies/CDN
        if 'via' in normalized:
            indicators['via_header'] = normalized['via']
            if 'cloudfront' in normalized['via'].lower():
                indicators['cloudfront_detected'] = True
        
        # Check for caching headers (CDN indicators)
        cache_headers = ['x-cache', 'x-cache-hit', 'cf-cache-status']
        for ch in cache_headers:
            if ch in normalized:
                indicators['cdn_cache_header'] = ch
                indicators['cdn_cache_value'] = normalized[ch]
                break
        
    except Exception as e:
        errors.append(f"Header analysis error: {str(e)}")
        logger.error(f"Error analyzing headers: {e}")
    
    return indicators, errors


class BackendDetectionHandler:
    """
    Context manager for backend detection operations
    Provides graceful error handling and result aggregation
    """
    
    def __init__(self, detection_type: str, continue_on_error: bool = True):
        self.detection_type = detection_type
        self.continue_on_error = continue_on_error
        self.results = []
        self.errors = []
        self.error_count = 0
    
    def __enter__(self):
        logger.debug(f"Starting {self.detection_type} detection")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.error_count += 1
            self.errors.append({
                'type': exc_type.__name__,
                'message': str(exc_val),
                'detection_type': self.detection_type
            })
            
            logger.error(f"Error in {self.detection_type} detection: {exc_val}")
            
            if self.continue_on_error:
                logger.info(f"Continuing despite error in {self.detection_type}")
                return True
        
        logger.debug(f"Completed {self.detection_type} detection: {len(self.results)} results, {self.error_count} errors")
        return False
    
    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a detection result"""
        result['detection_type'] = self.detection_type
        self.results.append(result)
    
    def add_error(self, error_msg: str) -> None:
        """Add an error without raising exception"""
        self.errors.append({
            'type': 'ManualError',
            'message': error_msg,
            'detection_type': self.detection_type
        })
        self.error_count += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of detection results and errors"""
        return {
            'detection_type': self.detection_type,
            'result_count': len(self.results),
            'error_count': self.error_count,
            'results': self.results,
            'errors': self.errors
        }