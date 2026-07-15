"""
WAFPierce Application Constants
Centralized constants for the entire application
"""

from . import __version__
from .branding import PRODUCT_NAME

# Timeouts (seconds)
DEFAULT_TIMEOUT = 30
SCAN_TIMEOUT = 60
CONNECT_TIMEOUT = 10

# Threading
DEFAULT_THREADS = 5
MAX_THREADS = 50
MIN_THREADS = 1

# Delays (seconds)
DEFAULT_DELAY = 0.2
MIN_DELAY = 0.01
MAX_DELAY = 5.0

# Retries
DEFAULT_MAX_RETRIES = 3
NETWORK_RETRIES = 3

# UI
DEFAULT_WINDOW_SIZE = (980, 640)
DEFAULT_WINDOW_GEOMETRY = '980x640'
QT_GEOMETRY = '1000x640'
DEFAULT_FONT_SIZE = 12

# Network
DEFAULT_USER_AGENT = f'{PRODUCT_NAME}/{__version__} (authorized web security research)'
MAX_REDIRECTS = 5
CONNECTION_POOL_CONNECTIONS = 10
CONNECTION_POOL_MAXSIZE = 20

# Scan Categories
DEFAULT_CATEGORIES = [
    'header_manipulation',
    'encoding_obfuscation',
    'protocol_level',
    'cache_control',
    'injection_testing',
    'security_misconfig',
    'business_logic',
    'jwt_auth',
    'graphql_attacks',
    'ssrf_advanced',
    'pdf_document',
    'cloud_security',
    'advanced_payloads',
    'info_disclosure',
    'detection_recon',
]

# Severity Levels
SEVERITY_CRITICAL = 'CRITICAL'
SEVERITY_HIGH = 'HIGH'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_LOW = 'LOW'
SEVERITY_INFO = 'INFO'

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}

# File paths
CONFIG_DIR_NAME = 'wafpierce'
DATABASE_FILENAME = 'wafpierce.db'
GUI_PREFS_FILENAME = 'gui_prefs.json'
PLUGINS_DIR_NAME = 'plugins'

# Logging
DEFAULT_LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
