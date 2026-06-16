"""PySide6 GUI for WAFPierce (subprocess-backed)

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

# path to bundled logo (used for watermark/icon)
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo_Temp', 'logo_wafpierce.png')

# Use shared config module
from .config import get_gui_prefs_path


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
    return defaults


# ==================== TRANSLATIONS ====================
TRANSLATIONS = {
    'en': {
        'window_title': 'WAFPierce - GUI (Qt)',
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
        'legal_disclaimer_title': 'WAFPierce - Legal Disclaimer',
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
        'legal_disclaimer': """WAFPierce – Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is provided solely for legitimate security research and authorized penetration testing. You must obtain explicit, written permission from the system owner before testing any network, application, or device that you do not personally own.

Unauthorized access to computer systems, networks, or data is illegal and may result in criminal and/or civil penalties under applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation in your jurisdiction.

By clicking "I Agree", you acknowledge and confirm that:

• You will only test systems that you own or have explicit written authorization to test
• You will comply with all applicable local, national, and international laws and regulations
• You accept full responsibility for your actions and use of this tool
• You understand that misuse of this tool may result in legal consequences

Limitation of Liability:
The developers, contributors, distributors, and owners of WAFPierce assume no liability for misuse, damage, legal consequences, data loss, service disruption, or any other harm resulting from the use or inability to use this tool. This software is provided "as is", without warranty of any kind, expressed or implied. You agree that you use this tool entirely at your own risk.""",
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
        'window_title': 'WAFPierce - واجهة المستخدم',
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
        'legal_disclaimer_title': 'WAFPierce - إخلاء المسؤولية القانونية',
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
        'legal_disclaimer': """WAFPierce - إخلاء المسؤولية القانونية

لاختبار الأمان المصرح به فقط

تم توفير هذه الأداة فقط لأبحاث الأمان المشروعة واختبار الاختراق المصرح به. يجب عليك الحصول على إذن كتابي صريح من مالك النظام قبل اختبار أي شبكة أو تطبيق أو جهاز لا تملكه شخصياً.

الوصول غير المصرح به إلى أنظمة الكمبيوتر أو الشبكات أو البيانات غير قانوني وقد يؤدي إلى عقوبات جنائية و/أو مدنية بموجب القوانين المعمول بها.

بالنقر على "أوافق"، فإنك تقر وتؤكد أنك:

• ستختبر فقط الأنظمة التي تملكها أو لديك إذن كتابي صريح لاختبارها
• ستلتزم بجميع القوانين واللوائح المحلية والوطنية والدولية المعمول بها
• تتحمل المسؤولية الكاملة عن أفعالك واستخدامك لهذه الأداة
• تفهم أن سوء استخدام هذه الأداة قد يؤدي إلى عواقب قانونية

حدود المسؤولية:
لا يتحمل المطورون والمساهمون والموزعون وأصحاب WAFPierce أي مسؤولية عن سوء الاستخدام أو الضرر أو العواقب القانونية أو فقدان البيانات أو انقطاع الخدمة أو أي ضرر آخر ناتج عن استخدام هذه الأداة أو عدم القدرة على استخدامها. يتم توفير هذا البرنامج "كما هو" بدون أي ضمان من أي نوع. أنت توافق على أنك تستخدم هذه الأداة على مسؤوليتك الخاصة بالكامل.""",
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
        'window_title': 'WAFPierce - Інтерфейс',
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
        'legal_disclaimer_title': 'WAFPierce - ЛЕГАЛЬНИЙ ДИСКЛЕЙМЕР',
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
        'legal_disclaimer': """WAFPierce – Юридична відомість

ТІЛЬКИ ДЛЯ АВТОРИЗОВАНОГО ТЕСТУВАННЯ БЕЗПЕКИ

Цей інструмент надається виключно для законних досліджень безпеки та авторизованого тестування на проникнення. Ви повинні отримати явний письмовий дозвіл від власника системи перед тестуванням будь-якої мережі, додатку або пристрою, яким ви особисто не володієте.

Несанкціонований доступ до комп'ютерних систем, мереж або даних є незаконним і може призвести до кримінальної та/або цивільної відповідальності згідно з чинним законодавством.

Натискаючи "Погоджуюсь", ви підтверджуєте, що:

• Ви будете тестувати лише системи, якими володієте або маєте явний письмовий дозвіл на тестування
• Ви будете дотримуватися всіх застосовних місцевих, національних та міжнародних законів і правил
• Ви берете на себе повну відповідальність за свої дії та використання цього інструменту
• Ви розумієте, що неправильне використання цього інструменту може призвести до юридичних наслідків

Обмеження відповідальності:
Розробники, учасники, дистриб'ютори та власники WAFPierce не несуть жодної відповідальності за неправильне використання, збитки, юридичні наслідки, втрату даних, переривання обслуговування або будь-яку іншу шкоду, що виникає внаслідок використання або неможливості використання цього інструменту. Це програмне забезпечення надається "як є" без будь-яких гарантій. Ви погоджуєтесь, що використовуєте цей інструмент повністю на власний ризик.""",
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
    path = _get_config_path()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(prefs, f, indent=2)
    except Exception:
        pass


LEGAL_DISCLAIMER = """WAFPierce – Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is provided solely for legitimate security research and authorized penetration testing. You must obtain explicit, written permission from the system owner before testing any network, application, or device that you do not personally own.

Unauthorized access to computer systems, networks, or data is illegal and may result in criminal and/or civil penalties under applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation in your jurisdiction.

By clicking "I Agree", you acknowledge and confirm that:

• You will only test systems that you own or have explicit written authorization to test
• You will comply with all applicable local, national, and international laws and regulations
• You accept full responsibility for your actions and use of this tool
• You understand that misuse of this tool may result in legal consequences

Limitation of Liability:
The developers, contributors, distributors, and owners of WAFPierce assume no liability for misuse, damage, legal consequences, data loss, service disruption, or any other harm resulting from the use or inability to use this tool. This software is provided "as is", without warranty of any kind, expressed or implied. You agree that you use this tool entirely at your own risk."""


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
                "WAFPierce failed to start.\n\nThe application bundle appears to be corrupted or incomplete.\nPlease re-download the application.",
                "WAFPierce - Error",
                0x10  # MB_ICONERROR
            )
        except Exception:
            pass
        sys.exit(1)
    
    # For non-frozen (development) mode, show console message
    print("\n" + "="*70)
    print("❌ MISSING REQUIRED PACKAGES")
    print("="*70)
    print("\nWAFPierce requires PySide6 for the graphical user interface.")
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
    from PySide6.QtGui import QFont, QFontDatabase
    
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
    dialog.setFixedSize(650, 520)
    dialog.setStyleSheet(f"""
        QDialog {{ background-color: #0f1112; }}
        QLabel {{ color: #d7e1ea; font-family: '{selected_font}'; }}
        QTextEdit {{ background-color: #16181a; color: #d7e1ea; border: none; font-family: '{selected_font}'; }}
        QPushButton {{ padding: 12px 30px; font-size: 12px; font-weight: bold; border-radius: 4px; font-family: '{selected_font}'; }}
    """)
    
    layout = QVBoxLayout(dialog)
    layout.setSpacing(15)
    layout.setContentsMargins(20, 20, 20, 20)
    
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

        def __init__(self, targets, threads, delay, concurrent=1, use_concurrent=True, retry_failed=0, selected_categories=None, proxy_config=None, enable_http_logging=False, enable_ssl_analysis=False, parent=None):
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
            self._abort = False
            # track running subprocesses so abort() can terminate them
            self._running_procs = {}

        def abort(self):
            self._abort = True
            # try to terminate any running subprocesses
            try:
                for p in list(getattr(self, '_running_procs', {}).values()):
                    try:
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
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    env['PYTHONUNBUFFERED'] = '1'  # Force unbuffered output
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
                size = self._prefs.get('qt_geometry', '1000x640')
                if isinstance(size, str) and 'x' in size:
                    w, h = size.split('x', 1)
                    self.resize(int(float(w)), int(float(h)))
                else:
                    self.resize(1000, 640)
            except Exception:
                self.resize(1000, 640)
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
                QShortcut(QKeySequence('Ctrl+D'), self, self._show_dashboard)
                
                # Ctrl+E - Results explorer
                QShortcut(QKeySequence('Ctrl+E'), self, self.show_results_summary)
                
                # Ctrl+, - Settings
                QShortcut(QKeySequence('Ctrl+,'), self, self._open_qt_settings)
                
                # Ctrl+P - Custom Payloads
                QShortcut(QKeySequence('Ctrl+P'), self, self._show_payloads_dialog)
                
                # Escape - Stop scan
                QShortcut(QKeySequence('Escape'), self, self.stop_scan)
                
                # F5 - Refresh/Start scan
                QShortcut(QKeySequence('F5'), self, self.start_scan)
                
                # Ctrl+L - Timeline
                QShortcut(QKeySequence('Ctrl+L'), self, self._show_timeline_viewer)
                
                # Ctrl+M - Plugin Manager
                QShortcut(QKeySequence('Ctrl+M'), self, self._show_plugin_manager)
                
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

        def _build_ui(self):
            v = QVBoxLayout(self)
            self._layout_main = v

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
            top.addWidget(QLabel(_t('target_url', self._lang)))
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
            
            # small compact settings button at the top-right
            try:
                top.addStretch()
                
                # Dashboard button
                dash_btn = QPushButton('📈')
                dash_btn.setFixedHeight(28)
                dash_btn.setFixedWidth(35)
                dash_btn.setToolTip(_t('dashboard', self._lang) if 'dashboard' in TRANSLATIONS.get(self._lang, {}) else 'Dashboard')
                dash_btn.clicked.connect(self._show_dashboard)
                top.addWidget(dash_btn)
                
                # Payloads button
                payload_btn = QPushButton('🎯')
                payload_btn.setFixedHeight(28)
                payload_btn.setFixedWidth(35)
                payload_btn.setToolTip(_t('custom_payloads', self._lang) if 'custom_payloads' in TRANSLATIONS.get(self._lang, {}) else 'Custom Payloads')
                payload_btn.clicked.connect(self._show_payloads_dialog)
                top.addWidget(payload_btn)
                
                # Scheduled Scans button
                schedule_btn = QPushButton('⏰')
                schedule_btn.setFixedHeight(28)
                schedule_btn.setFixedWidth(35)
                schedule_btn.setToolTip(_t('scheduled_scans', self._lang) if 'scheduled_scans' in TRANSLATIONS.get(self._lang, {}) else 'Scheduled Scans')
                schedule_btn.clicked.connect(self._show_scheduled_scans_dialog)
                top.addWidget(schedule_btn)
                
                # Timeline button
                timeline_btn = QPushButton('📅')
                timeline_btn.setFixedHeight(28)
                timeline_btn.setFixedWidth(35)
                timeline_btn.setToolTip(_t('scan_timeline', self._lang) if 'scan_timeline' in TRANSLATIONS.get(self._lang, {}) else 'Scan Timeline')
                timeline_btn.clicked.connect(self._show_timeline_viewer)
                top.addWidget(timeline_btn)
                
                # Plugins button
                plugins_btn = QPushButton('🔌')
                plugins_btn.setFixedHeight(28)
                plugins_btn.setFixedWidth(35)
                plugins_btn.setToolTip(_t('plugins', self._lang) if 'plugins' in TRANSLATIONS.get(self._lang, {}) else 'Plugins')
                plugins_btn.clicked.connect(self._show_plugin_manager)
                top.addWidget(plugins_btn)
                
                sbtn = QPushButton(_t('settings', self._lang))
                sbtn.setFixedHeight(28)
                sbtn.clicked.connect(self._open_qt_settings)
                top.addWidget(sbtn)
            except Exception:
                pass
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
            opts.addWidget(QLabel(_t('threads', self._lang)))
            opts.addWidget(self.threads_spin)
            opts.addWidget(QLabel(_t('concurrent', self._lang)))
            opts.addWidget(self.concurrent_spin)
            opts.addWidget(self.use_concurrent_chk)
            opts.addSpacing(10)
            opts.addWidget(QLabel(_t('delay', self._lang)))
            opts.addWidget(self.delay_spin)
            v.addLayout(opts)

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
                legend_h.addWidget(_legend_label('queued', _t('queued', self._lang), '#2b2f33'))
                legend_h.addWidget(_legend_label('running', _t('running', self._lang), '#3b82f6'))
                legend_h.addWidget(_legend_label('done', _t('done', self._lang), '#163f19'))
                legend_h.addWidget(_legend_label('error', _t('error', self._lang), '#ff4d4d'))
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
                            f"background-image: url('{css_path}'); background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
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
                    background-color: #2b2f33;
                    color: #d7e1ea;
                    border: none;
                    padding: 8px 20px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #3b4045;
                }
                QPushButton:disabled {
                    background-color: #1e2124;
                    color: #666;
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
            self.results_btn.clicked.connect(self.show_results_summary)
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
            self.start_btn.clicked.connect(self.start_scan)
            self.stop_btn = QPushButton(_t('stop', self._lang))
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
                    self.setWindowTitle('WAFPierce - [HACKER MODE ACTIVATED] 💀')
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
                    self.setWindowTitle('WAFPierce - GUI (Qt)')
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
            
            # Show scan category selection dialog
            selected_categories = self._show_scan_selection_dialog()
            if selected_categories is None:
                # User cancelled
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
            self._worker = QtWorker(targets, threads, delay, concurrent_val, use_concurrent, retry_failed, selected_categories, proxy_config=self._proxy_config, enable_http_logging=self._enable_http_logging, enable_ssl_analysis=self._enable_ssl_analysis)
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
            self._worker_thread.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            # Generate scan ID and add to database/timeline
            import uuid
            self._current_scan_id = str(uuid.uuid4())
            try:
                if self._db:
                    # Start scan record in database
                    self._db.create_scan(
                        scan_id=self._current_scan_id,
                        targets=targets,
                        settings={'threads': threads, 'delay': delay, 'concurrent': concurrent_val, 'categories': selected_categories, 'waf_detected': waf_name}
                    )
                    # Add timeline event for scan start
                    self._db.add_timeline_event(
                        scan_id=self._current_scan_id,
                        target=targets[0] if len(targets) == 1 else f'{len(targets)} targets',
                        event_type='scan_started',
                        event_data={'targets': targets, 'waf': waf_name, 'categories': selected_categories}
                    )
            except Exception:
                pass
            
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
                
                def on_accept():
                    self._selected_evasion_profile = evasion_combo.currentData()
                
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
                                self._db.add_result(self._current_scan_id, result)
                            except Exception:
                                pass
            except Exception:
                pass

        def _on_target_summary(self, target, done_list, errors):
            try:
                self._per_target_results[target] = {
                    'done': list(done_list) if isinstance(done_list, list) else [],
                    'errors': list(errors) if isinstance(errors, list) else [],
                    'tmp': self._target_tmp_map.get(target)
                }
            except Exception:
                pass

        def _on_finished(self):
            self.append_log(_t('run_finished', self._lang))
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
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

        def _open_qt_settings(self):
            try:
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('settings ⚙️', self._lang))
                layout = QtWidgets.QVBoxLayout(dlg)

                try:
                    prefs = _load_prefs()
                except Exception:
                    prefs = {}

                # font size
                h2 = QtWidgets.QHBoxLayout()
                h2.addWidget(QLabel(_t('font_size', self._lang)))
                font_spin = QSpinBox()
                font_spin.setRange(8, 20)
                try:
                    font_spin.setValue(int(prefs.get('font_size', 11)))
                except Exception:
                    font_spin.setValue(11)
                h2.addWidget(font_spin)
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
                retry_layout.addWidget(QLabel(_t('retry_failed', self._lang)))
                retry_spin = QSpinBox()
                retry_spin.setRange(0, 5)
                try:
                    retry_spin.setValue(int(prefs.get('retry_failed', 0)))
                except Exception:
                    retry_spin.setValue(0)
                retry_layout.addWidget(retry_spin)
                layout.addLayout(retry_layout)

                # UI density
                density_layout = QtWidgets.QHBoxLayout()
                density_layout.addWidget(QLabel(_t('ui_density', self._lang)))
                density_combo = QtWidgets.QComboBox()
                density_combo.addItems([_t('compact', self._lang), _t('comfortable', self._lang), _t('spacious', self._lang)])
                try:
                    current_density = prefs.get('ui_density', 'comfortable')
                    density_map = {'compact': 0, 'comfortable': 1, 'spacious': 2}
                    density_combo.setCurrentIndex(density_map.get(current_density, 1))
                except Exception:
                    pass
                density_layout.addWidget(density_combo)
                layout.addLayout(density_layout)

                # Language selection
                lang_layout = QtWidgets.QHBoxLayout()
                lang_layout.addWidget(QLabel(_t('language')))
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
                proxy_type_layout.addWidget(QLabel(_t('proxy_type', self._lang) if 'proxy_type' in TRANSLATIONS.get(self._lang, {}) else 'Type:'))
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
                proxy_layout.addLayout(proxy_type_layout)
                
                # Custom proxy fields
                custom_proxy_widget = QtWidgets.QWidget()
                custom_proxy_layout = QVBoxLayout(custom_proxy_widget)
                custom_proxy_layout.setContentsMargins(0, 0, 0, 0)
                
                host_layout = QHBoxLayout()
                host_layout.addWidget(QLabel(_t('proxy_host', self._lang) if 'proxy_host' in TRANSLATIONS.get(self._lang, {}) else 'Host:'))
                proxy_host_edit = QLineEdit()
                proxy_host_edit.setPlaceholderText('127.0.0.1')
                try:
                    proxy_host_edit.setText(prefs.get('proxy_host', '127.0.0.1'))
                except Exception:
                    pass
                host_layout.addWidget(proxy_host_edit)
                custom_proxy_layout.addLayout(host_layout)
                
                port_layout = QHBoxLayout()
                port_layout.addWidget(QLabel(_t('proxy_port', self._lang) if 'proxy_port' in TRANSLATIONS.get(self._lang, {}) else 'Port:'))
                proxy_port_spin = QSpinBox()
                proxy_port_spin.setRange(1, 65535)
                try:
                    proxy_port_spin.setValue(int(prefs.get('proxy_port', 9050)))
                except Exception:
                    proxy_port_spin.setValue(9050)
                port_layout.addWidget(proxy_port_spin)
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

                btn_h = QtWidgets.QHBoxLayout()
                save_btn = QPushButton(_t('save'))
                cancel_btn = QPushButton(_t('cancel'))
                btn_h.addWidget(save_btn)
                btn_h.addWidget(cancel_btn)
                layout.addLayout(btn_h)

                def _save_qt():
                    try:
                        old_lang = prefs.get('language', 'en')
                        new_lang = lang_combo.currentData()
                        
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
                            
                            dlg.accept()
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
                    try:
                        dlg.accept()
                    except Exception:
                        dlg.close()

                save_btn.clicked.connect(_save_qt)
                cancel_btn.clicked.connect(dlg.reject)
                dlg.exec()
            except Exception:
                pass

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
                            f"background-image: url('{css_path}'); background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
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
    <title>WAFPierce Scan Report</title>
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
        <h1>🛡️ WAFPierce Scan Report</h1>
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
            
            html += '''        <p class="generated">Report generated by WAFPierce - Web Application Firewall Bypass Scanner</p>
    </div>
</body>
</html>'''
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)

        def show_results_summary(self):
            """Show results organized by severity and target in a separate dialog with site list."""
            if not self._results:
                QMessageBox.information(self, _t('no_results', self._lang), _t('no_results_msg', self._lang))
                return
            
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
            
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('results_explorer', self._lang))
            dlg.resize(1100, 700)
            dlg.setStyleSheet("""
                QDialog { background-color: #0f1112; }
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
                    
                    parent.setExpanded(True)
            
            def on_site_selected():
                """Handle site selection change."""
                update_results_tree()
                details_text.clear()
            
            def on_result_selected():
                """Show details for selected result."""
                sel = results_tree.currentItem()
                if not sel or sel.childCount() > 0:  # Skip category headers
                    details_text.clear()
                    return
                
                r = sel.data(0, 257)  # Qt.UserRole + 1
                if not r:
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
            
            def expand_all():
                results_tree.expandAll()
            
            def collapse_all():
                results_tree.collapseAll()
            
            # Connect signals
            site_list.currentItemChanged.connect(on_site_selected)
            sort_combo.currentIndexChanged.connect(lambda: update_results_tree())
            filter_combo.currentIndexChanged.connect(lambda: update_results_tree())
            search_edit.textChanged.connect(lambda: update_results_tree())
            results_tree.currentItemChanged.connect(on_result_selected)
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
            close_btn.clicked.connect(dlg.accept)
            bottom_layout.addWidget(close_btn)
            
            # Add bottom layout to right panel
            right_panel.addLayout(bottom_layout)
            
            dlg.exec()
        
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
        def _show_dashboard(self):
            """Show statistics dashboard."""
            from PySide6.QtCore import Qt
            
            try:
                if self._db:
                    stats = self._db.get_dashboard_stats()
                else:
                    stats = {'total_scans': 0, 'total_findings': 0, 'total_bypasses': 0, 'severity_distribution': {}, 'top_techniques': []}
                
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('dashboard', self._lang) if 'dashboard' in TRANSLATIONS.get(self._lang, {}) else '📈 Dashboard')
                dlg.resize(800, 600)
                dlg.setStyleSheet("""
                    QDialog { background-color: #0f1112; }
                    QLabel { color: #d7e1ea; }
                    QGroupBox { color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; }
                    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
                """)
                
                layout = QVBoxLayout(dlg)
                
                # Header
                header = QLabel('📈 ' + (_t('statistics', self._lang) if 'statistics' in TRANSLATIONS.get(self._lang, {}) else 'Statistics'))
                header.setFont(QFont('', 16, QFont.Bold))
                header.setStyleSheet('color: #58a6ff;')
                layout.addWidget(header)
                
                # Summary cards
                summary_layout = QHBoxLayout()
                
                def create_stat_card(title, value, color='#d7e1ea'):
                    card = QtWidgets.QFrame()
                    card.setStyleSheet(f'background-color: #16181a; border: 1px solid #2b2f33; border-radius: 8px; padding: 15px;')
                    card_layout = QVBoxLayout(card)
                    val_label = QLabel(str(value))
                    val_label.setFont(QFont('', 24, QFont.Bold))
                    val_label.setStyleSheet(f'color: {color};')
                    val_label.setAlignment(Qt.AlignCenter)
                    title_label = QLabel(title)
                    title_label.setStyleSheet('color: #8b949e; font-size: 12px;')
                    title_label.setAlignment(Qt.AlignCenter)
                    card_layout.addWidget(val_label)
                    card_layout.addWidget(title_label)
                    return card
                
                summary_layout.addWidget(create_stat_card(_t('total_scans', self._lang) if 'total_scans' in TRANSLATIONS.get(self._lang, {}) else 'Total Scans', stats.get('total_scans', 0), '#58a6ff'))
                summary_layout.addWidget(create_stat_card(_t('total_findings', self._lang) if 'total_findings' in TRANSLATIONS.get(self._lang, {}) else 'Total Findings', stats.get('total_findings', 0), '#ffa500'))
                summary_layout.addWidget(create_stat_card(_t('total_bypasses', self._lang) if 'total_bypasses' in TRANSLATIONS.get(self._lang, {}) else 'Bypasses', stats.get('total_bypasses', 0), '#22c55e'))
                
                layout.addLayout(summary_layout)
                
                # Severity distribution
                sev_group = QtWidgets.QGroupBox(_t('severity_distribution', self._lang) if 'severity_distribution' in TRANSLATIONS.get(self._lang, {}) else 'Severity Distribution')
                sev_layout = QHBoxLayout(sev_group)
                
                sev_dist = stats.get('severity_distribution', {})
                sev_colors = {'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#ca8a04', 'LOW': '#2563eb', 'INFO': '#6b7280'}
                
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    count = sev_dist.get(sev, 0)
                    sev_label = QLabel(f'{sev}: {count}')
                    sev_label.setStyleSheet(f'color: {sev_colors.get(sev, "#d7e1ea")}; font-weight: bold; padding: 10px; background: #16181a; border-radius: 4px;')
                    sev_layout.addWidget(sev_label)
                
                layout.addWidget(sev_group)
                
                # Top techniques
                tech_group = QtWidgets.QGroupBox(_t('top_techniques', self._lang) if 'top_techniques' in TRANSLATIONS.get(self._lang, {}) else 'Top Techniques')
                tech_layout = QVBoxLayout(tech_group)
                
                top_tech = stats.get('top_techniques', [])[:5]
                for t in top_tech:
                    tech_label = QLabel(f"• {t.get('technique', 'Unknown')}: {t.get('count', 0)}")
                    tech_label.setStyleSheet('color: #d7e1ea; padding: 5px;')
                    tech_layout.addWidget(tech_label)
                
                if not top_tech:
                    tech_label = QLabel('No data available yet')
                    tech_label.setStyleSheet('color: #8b949e; font-style: italic;')
                    tech_layout.addWidget(tech_label)
                
                layout.addWidget(tech_group)
                
                # Compare scans button
                compare_btn = QPushButton('🔍 ' + (_t('compare_scans', self._lang) if 'compare_scans' in TRANSLATIONS.get(self._lang, {}) else 'Compare Scans'))
                compare_btn.clicked.connect(lambda: self._show_compare_scans_dialog())
                layout.addWidget(compare_btn)
                
                # Close button
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(dlg.accept)
                layout.addWidget(close_btn)
                
                dlg.exec()
            except Exception as e:
                QMessageBox.critical(self, 'Dashboard Error', str(e))

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
        def _show_timeline_viewer(self):
            """Show scan history timeline viewer."""
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
                
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('scan_timeline', self._lang) if 'scan_timeline' in TRANSLATIONS.get(self._lang, {}) else '📅 Scan Timeline')
                dlg.resize(900, 650)
                dlg.setStyleSheet(f"""
                    QDialog {{ background-color: #0f1112; font-family: '{selected_font}'; }}
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
                
                # Close button
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(dlg.accept)
                layout.addWidget(close_btn)
                
                dlg.exec()
            except Exception as e:
                QMessageBox.critical(self, 'Timeline Error', str(e))

        # ==================== PLUGIN MANAGER ====================
        def _show_plugin_manager(self):
            """Show plugin manager dialog."""
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
                
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('plugin_manager', self._lang) if 'plugin_manager' in TRANSLATIONS.get(self._lang, {}) else '🔌 Plugin Manager')
                dlg.resize(850, 600)
                dlg.setStyleSheet(f"""
                    QDialog {{ background-color: #0f1112; font-family: '{selected_font}'; }}
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
                
                create_info = QLabel('🔧 Create Your Own Plugin\\n\\nWAFPierce plugins are Python files that inherit from the BypassPlugin base class.')
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
Example WAFPierce Plugin Template
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
# All WAFPierce plugins must inherit from BypassPlugin
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
    # These appear in the WAFPierce plugin list/UI
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
# WAFPierce automatically loads plugins using this
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
                
                # Close button
                close_btn = QPushButton(_t('close', self._lang))
                close_btn.clicked.connect(dlg.accept)
                layout.addWidget(close_btn)
                
                dlg.exec()
            except Exception as e:
                import traceback
                QMessageBox.critical(self, 'Plugin Manager Error', f'{str(e)}\\n\\n{traceback.format_exc()}')

        # ==================== CUSTOM PAYLOADS ====================
        def _show_payloads_dialog(self):
            """Show custom payloads management dialog."""
            try:
                if not self._db:
                    QMessageBox.warning(self, 'Payloads', 'Database is not available.')
                    return

                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('custom_payloads', self._lang) if 'custom_payloads' in TRANSLATIONS.get(self._lang, {}) else '🎯 Custom Payloads')
                dlg.resize(600, 500)
                dlg.setStyleSheet("""
                    QDialog { background-color: #0f1112; }
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
                close_btn.clicked.connect(dlg.accept)
                layout.addWidget(close_btn)
                
                dlg.exec()
            except Exception as e:
                QMessageBox.critical(self, 'Payloads Error', str(e))

        def _show_scheduled_scans_dialog(self):
            """Show scheduled scans management dialog."""
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
                
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('scheduled_scans', self._lang) if 'scheduled_scans' in TRANSLATIONS.get(self._lang, {}) else '⏰ Scheduled Scans')
                dlg.resize(700, 550)
                dlg.setStyleSheet(f"""
                    QDialog {{ background-color: #0f1112; font-family: '{selected_font}'; }}
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
                table.setColumnCount(5)
                table.setHorizontalHeaderLabels(['Target', 'Schedule', 'Next Run', 'Status', 'Actions'])
                table.horizontalHeader().setStretchLastSection(True)
                table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
                
                def refresh_table():
                    table.setRowCount(0)
                    if self._db:
                        schedules = self._db.get_scheduled_scans()
                        for i, sched in enumerate(schedules):
                            table.insertRow(i)
                            table.setItem(i, 0, QtWidgets.QTableWidgetItem(sched.get('target', 'N/A')))
                            table.setItem(i, 1, QtWidgets.QTableWidgetItem(sched.get('schedule_type', 'once')))
                            table.setItem(i, 2, QtWidgets.QTableWidgetItem(sched.get('next_run', 'N/A')))
                            status_txt = '🟢 Active' if sched.get('enabled', True) else '⚪ Disabled'
                            table.setItem(i, 3, QtWidgets.QTableWidgetItem(status_txt))
                            
                            # Action button
                            del_btn = QPushButton('🗑️')
                            del_btn.setFixedWidth(35)
                            sched_id = sched.get('id')
                            del_btn.clicked.connect(lambda checked, sid=sched_id: delete_schedule(sid))
                            table.setCellWidget(i, 4, del_btn)
                
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
                close_btn.clicked.connect(dlg.accept)
                btn_layout.addWidget(close_btn)
                
                layout.addLayout(btn_layout)
                
                # Info label
                info_label = QLabel('ℹ️ Note: Scheduled scans run when the application is open.')
                info_label.setStyleSheet('color: #8b949e; font-size: 11px;')
                layout.addWidget(info_label)
                
                dlg.exec()
            except Exception as e:
                QMessageBox.critical(self, 'Scheduled Scans Error', str(e))

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
                            results=results
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
            dark_palette.setColor(QPalette.Highlight, QColor(59, 130, 246))
            dark_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            app.setPalette(dark_palette)
        except Exception:
            pass
        
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