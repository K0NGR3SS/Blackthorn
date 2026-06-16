"""
SQLite Database for WAFPierce - Historical scan data storage
Stores scan results, payloads, and statistics
"""
import sqlite3
import json
import os
import time
from typing import Optional, List, Dict, Any
from datetime import datetime

from .config import get_database_path


class WAFPierceDB:
    """Database handler for WAFPierce."""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_database_path()
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Scans table - stores scan sessions
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                targets TEXT,
                total_findings INTEGER DEFAULT 0,
                total_bypasses INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',
                settings TEXT,
                waf_detected TEXT
            )
        ''')
        
        # Results table - stores individual findings
        c.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                technique TEXT,
                category TEXT,
                severity TEXT,
                cvss_score REAL,
                bypass INTEGER DEFAULT 0,
                reason TEXT,
                url TEXT,
                payload TEXT,
                response_code INTEGER,
                response_time REAL,
                cve_id TEXT,
                cwe_id TEXT,
                reference_url TEXT,
                raw_request TEXT,
                raw_response TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        # Create index for faster queries
        c.execute('CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_results_target ON results(target)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_results_severity ON results(severity)')
        
        # Legacy templates table (kept for database compatibility)
        c.execute('''
            CREATE TABLE IF NOT EXISTS templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                settings TEXT NOT NULL,
                categories TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Custom payloads table
        c.execute('''
            CREATE TABLE IF NOT EXISTS custom_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                payload TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'MEDIUM',
                cve_id TEXT,
                cwe_id TEXT,
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Evasion profiles table
        c.execute('''
            CREATE TABLE IF NOT EXISTS evasion_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                waf_type TEXT NOT NULL,
                description TEXT,
                techniques TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                success_rate REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scheduled scans table
        c.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                targets TEXT NOT NULL,
                template_id INTEGER,
                schedule_type TEXT NOT NULL,
                schedule_time TEXT NOT NULL,
                next_run TIMESTAMP,
                last_run TIMESTAMP,
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (template_id) REFERENCES templates(id)
            )
        ''')
        
        # Proxy configurations table
        c.execute('''
            CREATE TABLE IF NOT EXISTS proxy_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                proxy_type TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT,
                password TEXT,
                enabled INTEGER DEFAULT 1,
                is_default INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Statistics table for dashboard
        c.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                total_scans INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                total_bypasses INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                most_common_waf TEXT,
                avg_scan_time REAL DEFAULT 0.0,
                UNIQUE(date)
            )
        ''')
        
        # Persistent targets table - stores scanned sites with their results
        c.execute('''
            CREATE TABLE IF NOT EXISTS persistent_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                last_scan_id TEXT,
                last_scanned TIMESTAMP,
                status TEXT DEFAULT 'queued',
                findings_count INTEGER DEFAULT 0,
                waf_detected TEXT,
                results_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (last_scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        # Plugins table - stores installed/registered plugins
        c.execute('''
            CREATE TABLE IF NOT EXISTS plugins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                version TEXT NOT NULL,
                author TEXT,
                description TEXT,
                category TEXT DEFAULT 'bypass',
                file_path TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_run TIMESTAMP,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                rating REAL DEFAULT 0.0,
                downloads INTEGER DEFAULT 0,
                source TEXT DEFAULT 'local',
                checksum TEXT
            )
        ''')
        
        # Scan queue state table - stores queued targets when app closes
        c.execute('''
            CREATE TABLE IF NOT EXISTS scan_queue_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'queued',
                position INTEGER,
                settings_json TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan timeline events table - detailed scan events for timeline
        c.execute('''
            CREATE TABLE IF NOT EXISTS scan_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Insert default evasion profiles
        self._insert_default_evasion_profiles()
        self._insert_default_proxy_configs()
    
    def _insert_default_evasion_profiles(self):
        """Insert default WAF evasion profiles."""
        default_profiles = [
            {
                'name': 'Cloudflare Bypass',
                'waf_type': 'cloudflare',
                'description': 'Techniques optimized for bypassing Cloudflare WAF',
                'techniques': json.dumps([
                    'unicode_normalization', 'case_variation', 'double_encoding',
                    'comment_injection', 'whitespace_bypass', 'header_manipulation'
                ])
            },
            {
                'name': 'AWS WAF Bypass',
                'waf_type': 'aws_waf',
                'description': 'Techniques optimized for bypassing AWS WAF',
                'techniques': json.dumps([
                    'encoding_obfuscation', 'parameter_pollution', 'chunked_encoding',
                    'protocol_manipulation', 'header_injection'
                ])
            },
            {
                'name': 'Akamai Bypass',
                'waf_type': 'akamai',
                'description': 'Techniques optimized for bypassing Akamai WAF',
                'techniques': json.dumps([
                    'null_byte_injection', 'unicode_bypass', 'verb_tampering',
                    'cache_poisoning', 'host_header_injection'
                ])
            },
            {
                'name': 'Imperva/Incapsula Bypass',
                'waf_type': 'imperva',
                'description': 'Techniques optimized for bypassing Imperva WAF',
                'techniques': json.dumps([
                    'double_encoding', 'unicode_normalization', 'http2_bypass',
                    'content_type_manipulation', 'boundary_manipulation'
                ])
            },
            {
                'name': 'ModSecurity Bypass',
                'waf_type': 'modsecurity',
                'description': 'Techniques optimized for bypassing ModSecurity',
                'techniques': json.dumps([
                    'comment_bypass', 'case_variation', 'encoding_bypass',
                    'whitespace_manipulation', 'sql_comment_injection'
                ])
            },
            {
                'name': 'F5 BIG-IP Bypass',
                'waf_type': 'f5_bigip',
                'description': 'Techniques optimized for bypassing F5 BIG-IP ASM',
                'techniques': json.dumps([
                    'protocol_smuggling', 'chunked_transfer', 'header_manipulation',
                    'multipart_bypass', 'json_injection'
                ])
            },
        ]
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        for profile in default_profiles:
            try:
                c.execute('''
                    INSERT OR IGNORE INTO evasion_profiles (name, waf_type, description, techniques)
                    VALUES (?, ?, ?, ?)
                ''', (profile['name'], profile['waf_type'], profile['description'], profile['techniques']))
            except Exception:
                pass
        
        conn.commit()
        conn.close()
    
    def _insert_default_proxy_configs(self):
        """Insert default proxy configurations."""
        default_proxies = [
            {
                'name': 'Tor (Default)',
                'proxy_type': 'socks5',
                'host': '127.0.0.1',
                'port': 9050,
                'is_default': 0
            },
            {
                'name': 'Tor Browser',
                'proxy_type': 'socks5',
                'host': '127.0.0.1',
                'port': 9150,
                'is_default': 0
            },
            {
                'name': 'Burp Suite',
                'proxy_type': 'http',
                'host': '127.0.0.1',
                'port': 8080,
                'is_default': 0
            },
        ]
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        for proxy in default_proxies:
            try:
                c.execute('''
                    INSERT OR IGNORE INTO proxy_configs (name, proxy_type, host, port, is_default)
                    VALUES (?, ?, ?, ?, ?)
                ''', (proxy['name'], proxy['proxy_type'], proxy['host'], proxy['port'], proxy['is_default']))
            except Exception:
                pass
        
        conn.commit()
        conn.close()
    
    # ==================== SCAN OPERATIONS ====================
    
    def create_scan(self, scan_id: str, targets: List[str], settings: dict = None) -> str:
        """Create a new scan session."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO scans (scan_id, targets, settings)
            VALUES (?, ?, ?)
        ''', (scan_id, json.dumps(targets), json.dumps(settings or {})))
        conn.commit()
        conn.close()
        return scan_id
    
    def finish_scan(self, scan_id: str, total_findings: int, total_bypasses: int, waf_detected: str = None):
        """Mark a scan as finished."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            UPDATE scans SET finished_at = CURRENT_TIMESTAMP, 
                            status = 'completed',
                            total_findings = ?,
                            total_bypasses = ?,
                            waf_detected = ?
            WHERE scan_id = ?
        ''', (total_findings, total_bypasses, waf_detected, scan_id))
        conn.commit()
        conn.close()
        
        # Update daily statistics
        self._update_daily_stats(total_findings, total_bypasses)
    
    def _update_daily_stats(self, findings: int, bypasses: int):
        """Update daily statistics."""
        today = datetime.now().strftime('%Y-%m-%d')
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT id FROM statistics WHERE date = ?', (today,))
        if c.fetchone():
            c.execute('''
                UPDATE statistics SET 
                    total_scans = total_scans + 1,
                    total_findings = total_findings + ?,
                    total_bypasses = total_bypasses + ?
                WHERE date = ?
            ''', (findings, bypasses, today))
        else:
            c.execute('''
                INSERT INTO statistics (date, total_scans, total_findings, total_bypasses)
                VALUES (?, 1, ?, ?)
            ''', (today, findings, bypasses))
        
        conn.commit()
        conn.close()
    
    def add_result(self, scan_id: str, result: dict):
        """Add a finding to the database."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO results (
                scan_id, target, technique, category, severity, cvss_score,
                bypass, reason, url, payload, response_code, response_time,
                cve_id, cwe_id, reference_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            result.get('target', ''),
            result.get('technique', ''),
            result.get('category', ''),
            result.get('severity', 'INFO'),
            result.get('cvss_score', 0.0),
            1 if result.get('bypass', False) else 0,
            result.get('reason', ''),
            result.get('url', ''),
            result.get('payload', ''),
            result.get('response_code', 0),
            result.get('response_time', 0.0),
            result.get('cve_id', ''),
            result.get('cwe_id', ''),
            result.get('reference_url', '')
        ))
        
        conn.commit()
        conn.close()
    
    def get_scan_history(self, limit: int = 50) -> List[dict]:
        """Get recent scan history."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''
            SELECT * FROM scans ORDER BY started_at DESC LIMIT ?
        ''', (limit,))
        
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_scan_results(self, scan_id: str) -> List[dict]:
        """Get all results for a specific scan."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM results WHERE scan_id = ?', (scan_id,))
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def compare_scans(self, scan_id_1: str, scan_id_2: str) -> dict:
        """Compare two scans and return differences."""
        results_1 = self.get_scan_results(scan_id_1)
        results_2 = self.get_scan_results(scan_id_2)
        
        # Create sets of (target, technique, category) tuples for comparison
        set_1 = {(r['target'], r['technique'], r['category']) for r in results_1}
        set_2 = {(r['target'], r['technique'], r['category']) for r in results_2}
        
        new_findings = set_2 - set_1
        fixed_findings = set_1 - set_2
        unchanged = set_1 & set_2
        
        return {
            'new': [r for r in results_2 if (r['target'], r['technique'], r['category']) in new_findings],
            'fixed': [r for r in results_1 if (r['target'], r['technique'], r['category']) in fixed_findings],
            'unchanged_count': len(unchanged),
            'scan_1_total': len(results_1),
            'scan_2_total': len(results_2)
        }
    
    # ==================== PERSISTENT TARGETS ====================
    
    def save_persistent_target(self, target: str, status: str, scan_id: str = None, 
                               findings_count: int = 0, waf_detected: str = None, results: list = None):
        """Save or update a persistent target."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT id FROM persistent_targets WHERE target = ?', (target,))
        existing = c.fetchone()
        
        if existing:
            c.execute('''
                UPDATE persistent_targets SET 
                    last_scan_id = ?,
                    last_scanned = CURRENT_TIMESTAMP,
                    status = ?,
                    findings_count = ?,
                    waf_detected = ?,
                    results_json = ?
                WHERE target = ?
            ''', (scan_id, status, findings_count, waf_detected, 
                  json.dumps(results) if results else None, target))
        else:
            c.execute('''
                INSERT INTO persistent_targets (target, last_scan_id, last_scanned, status, 
                                                findings_count, waf_detected, results_json)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
            ''', (target, scan_id, status, findings_count, waf_detected,
                  json.dumps(results) if results else None))
        
        conn.commit()
        conn.close()
    
    def get_persistent_targets(self) -> List[dict]:
        """Get all persistent targets with their last scan status."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM persistent_targets ORDER BY last_scanned DESC')
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def delete_persistent_target(self, target: str):
        """Delete a persistent target."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM persistent_targets WHERE target = ?', (target,))
        conn.commit()
        conn.close()
    
    # ==================== CUSTOM PAYLOADS ====================
    
    def add_custom_payload(self, name: str, category: str, payload: str, 
                          description: str = '', severity: str = 'MEDIUM',
                          cve_id: str = None, cwe_id: str = None):
        """Add a custom payload."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO custom_payloads (name, category, payload, description, severity, cve_id, cwe_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, category, payload, description, severity, cve_id, cwe_id))
        
        conn.commit()
        conn.close()
    
    def get_custom_payloads(self, category: str = None) -> List[dict]:
        """Get custom payloads, optionally filtered by category."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if category:
            c.execute('SELECT * FROM custom_payloads WHERE category = ? AND enabled = 1', (category,))
        else:
            c.execute('SELECT * FROM custom_payloads WHERE enabled = 1')
        
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]

    def delete_custom_payload(self, payload_id: int) -> bool:
        """Delete a custom payload by ID.

        Returns:
            True if a row was deleted, otherwise False.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM custom_payloads WHERE id = ?', (payload_id,))
        deleted = c.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
    
    def import_payloads_from_file(self, filepath: str) -> int:
        """Import payloads from a JSON or text file."""
        imported = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try JSON first
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            self.add_custom_payload(
                                name=item.get('name', f'Imported {imported}'),
                                category=item.get('category', 'custom'),
                                payload=item.get('payload', ''),
                                description=item.get('description', ''),
                                severity=item.get('severity', 'MEDIUM'),
                                cve_id=item.get('cve_id'),
                                cwe_id=item.get('cwe_id')
                            )
                            imported += 1
            except json.JSONDecodeError:
                # Try line-by-line (plain text payloads)
                for i, line in enumerate(content.splitlines()):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_custom_payload(
                            name=f'Imported Payload {i+1}',
                            category='custom',
                            payload=line,
                            description='Imported from file'
                        )
                        imported += 1
        except Exception:
            pass
        
        return imported
    
    # ==================== EVASION PROFILES ====================
    
    def get_evasion_profiles(self, waf_type: str = None) -> List[dict]:
        """Get evasion profiles, optionally filtered by WAF type."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if waf_type:
            c.execute('SELECT * FROM evasion_profiles WHERE waf_type = ? AND enabled = 1', (waf_type,))
        else:
            c.execute('SELECT * FROM evasion_profiles WHERE enabled = 1')
        
        rows = c.fetchall()
        conn.close()
        
        profiles = []
        for row in rows:
            p = dict(row)
            p['techniques'] = json.loads(p['techniques'])
            profiles.append(p)
        
        return profiles
    
    # ==================== PROXY CONFIGS ====================
    
    def get_proxy_configs(self) -> List[dict]:
        """Get all proxy configurations."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM proxy_configs ORDER BY name')
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def add_proxy_config(self, name: str, proxy_type: str, host: str, port: int,
                        username: str = None, password: str = None):
        """Add a new proxy configuration."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT OR REPLACE INTO proxy_configs (name, proxy_type, host, port, username, password)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, proxy_type, host, port, username, password))
        
        conn.commit()
        conn.close()
    
    def set_default_proxy(self, proxy_id: int):
        """Set a proxy as the default."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Clear existing default
        c.execute('UPDATE proxy_configs SET is_default = 0')
        # Set new default
        c.execute('UPDATE proxy_configs SET is_default = 1 WHERE id = ?', (proxy_id,))
        
        conn.commit()
        conn.close()
    
    def get_default_proxy(self) -> Optional[dict]:
        """Get the default proxy configuration."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM proxy_configs WHERE is_default = 1 AND enabled = 1')
        row = c.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    # ==================== SCHEDULED SCANS ====================
    
    def add_scheduled_scan(self, target: str = None, name: str = None, targets: List[str] = None,
                          schedule_type: str = 'once', scheduled_time: str = None,
                          schedule_time: str = None, template_id: int = None, settings: dict = None):
        """Add a scheduled scan."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Handle both old and new parameter styles
        if target and not targets:
            targets = [target]
        if scheduled_time and not schedule_time:
            schedule_time = scheduled_time
        if not name:
            name = f"Scan {target or 'Unknown'}"
        
        c.execute('''
            INSERT INTO scheduled_scans (name, targets, template_id, schedule_type, schedule_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, json.dumps(targets or []), template_id, schedule_type, schedule_time))
        
        conn.commit()
        conn.close()
    
    def delete_scheduled_scan(self, scan_id: int):
        """Delete a scheduled scan by ID."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM scheduled_scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()
    
    def get_scheduled_scans(self) -> List[dict]:
        """Get all scheduled scans."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM scheduled_scans')
        rows = c.fetchall()
        conn.close()
        
        scans = []
        for row in rows:
            s = dict(row)
            try:
                s['targets'] = json.loads(s.get('targets', '[]'))
            except Exception:
                s['targets'] = []
            # Get first target for display
            s['target'] = s['targets'][0] if s['targets'] else 'N/A'
            # Get next run from schedule_time
            s['next_run'] = s.get('schedule_time', 'N/A')
            scans.append(s)
        
        return scans
    
    # ==================== STATISTICS / DASHBOARD ====================
    
    def get_dashboard_stats(self) -> dict:
        """Get statistics for dashboard display."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Total counts
        c.execute('SELECT COUNT(*) FROM scans')
        total_scans = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM results')
        total_findings = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM results WHERE bypass = 1')
        total_bypasses = c.fetchone()[0]
        
        # Severity distribution
        c.execute('SELECT severity, COUNT(*) FROM results GROUP BY severity')
        severity_dist = {row[0]: row[1] for row in c.fetchall()}
        
        # Most common techniques
        c.execute('''
            SELECT technique, COUNT(*) as cnt FROM results 
            GROUP BY technique ORDER BY cnt DESC LIMIT 10
        ''')
        top_techniques = [{'technique': row[0], 'count': row[1]} for row in c.fetchall()]
        
        # Recent activity (last 7 days)
        c.execute('''
            SELECT date, total_scans, total_findings, total_bypasses 
            FROM statistics ORDER BY date DESC LIMIT 7
        ''')
        recent_activity = [
            {'date': row[0], 'scans': row[1], 'findings': row[2], 'bypasses': row[3]}
            for row in c.fetchall()
        ]
        
        # Most scanned targets
        c.execute('''
            SELECT target, COUNT(*) as cnt FROM persistent_targets 
            GROUP BY target ORDER BY cnt DESC LIMIT 5
        ''')
        top_targets = [{'target': row[0], 'count': row[1]} for row in c.fetchall()]
        
        # WAF distribution
        c.execute('''
            SELECT waf_detected, COUNT(*) FROM scans 
            WHERE waf_detected IS NOT NULL AND waf_detected != ''
            GROUP BY waf_detected
        ''')
        waf_dist = {row[0]: row[1] for row in c.fetchall()}
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'total_bypasses': total_bypasses,
            'severity_distribution': severity_dist,
            'top_techniques': top_techniques,
            'recent_activity': recent_activity,
            'top_targets': top_targets,
            'waf_distribution': waf_dist
        }

    # ==================== PLUGINS ====================
    
    def save_plugin(self, name: str, version: str, file_path: str, author: str = '', 
                    description: str = '', category: str = 'bypass', source: str = 'local', checksum: str = None):
        """Save or update a plugin."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT id FROM plugins WHERE name = ?', (name,))
        existing = c.fetchone()
        
        if existing:
            c.execute('''
                UPDATE plugins SET version = ?, author = ?, description = ?, category = ?, 
                                   file_path = ?, source = ?, checksum = ?
                WHERE name = ?
            ''', (version, author, description, category, file_path, source, checksum, name))
        else:
            c.execute('''
                INSERT INTO plugins (name, version, author, description, category, file_path, source, checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, version, author, description, category, file_path, source, checksum))
        
        conn.commit()
        conn.close()
    
    def get_plugins(self, enabled_only: bool = False) -> List[dict]:
        """Get all registered plugins."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if enabled_only:
            c.execute('SELECT * FROM plugins WHERE enabled = 1 ORDER BY name')
        else:
            c.execute('SELECT * FROM plugins ORDER BY name')
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def toggle_plugin(self, name: str, enabled: bool):
        """Enable or disable a plugin."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('UPDATE plugins SET enabled = ? WHERE name = ?', (1 if enabled else 0, name))
        conn.commit()
        conn.close()
    
    def delete_plugin(self, name: str):
        """Delete a plugin."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM plugins WHERE name = ?', (name,))
        conn.commit()
        conn.close()
    
    def update_plugin_stats(self, name: str, success: bool):
        """Update plugin success/fail count after execution."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        if success:
            c.execute('UPDATE plugins SET success_count = success_count + 1, last_run = CURRENT_TIMESTAMP WHERE name = ?', (name,))
        else:
            c.execute('UPDATE plugins SET fail_count = fail_count + 1, last_run = CURRENT_TIMESTAMP WHERE name = ?', (name,))
        conn.commit()
        conn.close()
    
    # ==================== SCAN QUEUE STATE ====================
    
    def save_scan_queue(self, targets: List[dict]):
        """Save the current scan queue state when app closes."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Clear existing queue
        c.execute('DELETE FROM scan_queue_state')
        
        # Save current queue
        for i, t in enumerate(targets):
            c.execute('''
                INSERT INTO scan_queue_state (target, status, position, settings_json)
                VALUES (?, ?, ?, ?)
            ''', (t.get('target', ''), t.get('status', 'queued'), i, json.dumps(t.get('settings', {}))))
        
        conn.commit()
        conn.close()
    
    def get_scan_queue(self) -> List[dict]:
        """Get the saved scan queue state."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM scan_queue_state ORDER BY position')
        rows = c.fetchall()
        conn.close()
        
        result = []
        for row in rows:
            r = dict(row)
            try:
                r['settings'] = json.loads(r.get('settings_json', '{}'))
            except:
                r['settings'] = {}
            result.append(r)
        
        return result
    
    def clear_scan_queue(self):
        """Clear the saved scan queue."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM scan_queue_state')
        conn.commit()
        conn.close()
    
    # ==================== SCAN TIMELINE ====================
    
    def add_timeline_event(self, scan_id: str, target: str, event_type: str, event_data: dict = None):
        """Add an event to the scan timeline."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO scan_timeline (scan_id, target, event_type, event_data)
            VALUES (?, ?, ?, ?)
        ''', (scan_id, target, event_type, json.dumps(event_data) if event_data else None))
        conn.commit()
        conn.close()
    
    def get_timeline(self, target: str = None, limit: int = 100) -> List[dict]:
        """Get scan timeline events, optionally filtered by target."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if target:
            c.execute('''
                SELECT t.*, s.status as scan_status, s.total_findings, s.waf_detected 
                FROM scan_timeline t
                LEFT JOIN scans s ON t.scan_id = s.scan_id
                WHERE t.target = ?
                ORDER BY t.timestamp DESC LIMIT ?
            ''', (target, limit))
        else:
            c.execute('''
                SELECT t.*, s.status as scan_status, s.total_findings, s.waf_detected 
                FROM scan_timeline t
                LEFT JOIN scans s ON t.scan_id = s.scan_id
                ORDER BY t.timestamp DESC LIMIT ?
            ''', (limit,))
        
        rows = c.fetchall()
        conn.close()
        
        result = []
        for row in rows:
            r = dict(row)
            try:
                r['event_data'] = json.loads(r.get('event_data', '{}')) if r.get('event_data') else {}
            except:
                r['event_data'] = {}
            result.append(r)
        
        return result
    
    def get_target_scan_history(self, target: str) -> List[dict]:
        """Get all scans for a specific target for comparison."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''
            SELECT s.* FROM scans s
            WHERE s.targets LIKE ?
            ORDER BY s.started_at DESC
        ''', (f'%{target}%',))
        
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]


# CVE/CWE Reference Database for common vulnerabilities
CVE_CWE_REFERENCES = {
    'SQL Injection': {
        'cwe_id': 'CWE-89',
        'cwe_name': 'SQL Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/89.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2021-22205', 'CVE-2019-12384', 'CVE-2018-15133']
    },
    'XSS': {
        'cwe_id': 'CWE-79',
        'cwe_name': 'Cross-site Scripting (XSS)',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/79.html',
        'cvss_base': 6.1,
        'severity': 'MEDIUM',
        'common_cves': ['CVE-2021-41773', 'CVE-2020-11022', 'CVE-2019-11358']
    },
    'Command Injection': {
        'cwe_id': 'CWE-78',
        'cwe_name': 'OS Command Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/78.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2021-44228', 'CVE-2021-21972', 'CVE-2020-5902']
    },
    'Path Traversal': {
        'cwe_id': 'CWE-22',
        'cwe_name': 'Path Traversal',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/22.html',
        'cvss_base': 7.5,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-41773', 'CVE-2020-17519', 'CVE-2019-16278']
    },
    'LFI': {
        'cwe_id': 'CWE-98',
        'cwe_name': 'Local File Inclusion',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/98.html',
        'cvss_base': 7.5,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-21315', 'CVE-2020-9484']
    },
    'RFI': {
        'cwe_id': 'CWE-98',
        'cwe_name': 'Remote File Inclusion',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/98.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2018-7600', 'CVE-2017-9841']
    },
    'SSRF': {
        'cwe_id': 'CWE-918',
        'cwe_name': 'Server-Side Request Forgery',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/918.html',
        'cvss_base': 8.6,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-21975', 'CVE-2020-15148', 'CVE-2019-17558']
    },
    'XXE': {
        'cwe_id': 'CWE-611',
        'cwe_name': 'XML External Entity',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/611.html',
        'cvss_base': 7.5,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-21994', 'CVE-2019-12415', 'CVE-2018-1000613']
    },
    'SSTI': {
        'cwe_id': 'CWE-1336',
        'cwe_name': 'Server-Side Template Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/1336.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2022-22954', 'CVE-2020-17530', 'CVE-2019-11581']
    },
    'LDAP Injection': {
        'cwe_id': 'CWE-90',
        'cwe_name': 'LDAP Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/90.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2021-44228']
    },
    'NoSQL Injection': {
        'cwe_id': 'CWE-943',
        'cwe_name': 'NoSQL Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/943.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2021-22911', 'CVE-2020-35665']
    },
    'CRLF Injection': {
        'cwe_id': 'CWE-93',
        'cwe_name': 'CRLF Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/93.html',
        'cvss_base': 6.1,
        'severity': 'MEDIUM',
        'common_cves': ['CVE-2021-22555', 'CVE-2019-16782']
    },
    'Header Injection': {
        'cwe_id': 'CWE-113',
        'cwe_name': 'HTTP Response Splitting',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/113.html',
        'cvss_base': 6.1,
        'severity': 'MEDIUM',
        'common_cves': ['CVE-2020-7943', 'CVE-2019-5418']
    },
    'IDOR': {
        'cwe_id': 'CWE-639',
        'cwe_name': 'Insecure Direct Object Reference',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/639.html',
        'cvss_base': 6.5,
        'severity': 'MEDIUM',
        'common_cves': ['CVE-2021-38314', 'CVE-2020-36193']
    },
    'JWT Attack': {
        'cwe_id': 'CWE-347',
        'cwe_name': 'JWT Verification Bypass',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/347.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2022-21449', 'CVE-2018-0114']
    },
    'GraphQL Injection': {
        'cwe_id': 'CWE-89',
        'cwe_name': 'GraphQL Injection',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/89.html',
        'cvss_base': 7.5,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-3007', 'CVE-2020-11104']
    },
    'Deserialization': {
        'cwe_id': 'CWE-502',
        'cwe_name': 'Unsafe Deserialization',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/502.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2021-44228', 'CVE-2020-1938', 'CVE-2019-12384']
    },
    'Open Redirect': {
        'cwe_id': 'CWE-601',
        'cwe_name': 'Open Redirect',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/601.html',
        'cvss_base': 4.3,
        'severity': 'LOW',
        'common_cves': ['CVE-2021-22204', 'CVE-2020-8945']
    },
    'CORS Bypass': {
        'cwe_id': 'CWE-942',
        'cwe_name': 'CORS Misconfiguration',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/942.html',
        'cvss_base': 5.3,
        'severity': 'MEDIUM',
        'common_cves': ['CVE-2021-21432', 'CVE-2020-8840']
    },
    'Cache Poisoning': {
        'cwe_id': 'CWE-444',
        'cwe_name': 'HTTP Request/Response Smuggling',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/444.html',
        'cvss_base': 7.5,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-33193', 'CVE-2020-11984']
    },
    'Host Header Injection': {
        'cwe_id': 'CWE-644',
        'cwe_name': 'Host Header Attack',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/644.html',
        'cvss_base': 6.1,
        'severity': 'MEDIUM',
        'common_cves': ['CVE-2020-1938', 'CVE-2019-0221']
    },
    'Prototype Pollution': {
        'cwe_id': 'CWE-1321',
        'cwe_name': 'Prototype Pollution',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/1321.html',
        'cvss_base': 7.5,
        'severity': 'HIGH',
        'common_cves': ['CVE-2021-25928', 'CVE-2020-28500', 'CVE-2019-10744']
    },
    'Buffer Overflow': {
        'cwe_id': 'CWE-120',
        'cwe_name': 'Buffer Overflow',
        'cwe_url': 'https://cwe.mitre.org/data/definitions/120.html',
        'cvss_base': 9.8,
        'severity': 'CRITICAL',
        'common_cves': ['CVE-2021-3156', 'CVE-2020-1472', 'CVE-2019-14287']
    },
}


def get_cve_cwe_reference(technique: str) -> Optional[dict]:
    """Get CVE/CWE reference information for a technique."""
    # Direct match
    if technique in CVE_CWE_REFERENCES:
        return CVE_CWE_REFERENCES[technique]
    
    # Partial match
    technique_lower = technique.lower()
    for key, value in CVE_CWE_REFERENCES.items():
        if key.lower() in technique_lower or technique_lower in key.lower():
            return value
    
    # Pattern matching
    patterns = {
        'sql': 'SQL Injection',
        'xss': 'XSS',
        'command': 'Command Injection',
        'traversal': 'Path Traversal',
        'lfi': 'LFI',
        'rfi': 'RFI',
        'ssrf': 'SSRF',
        'xxe': 'XXE',
        'ssti': 'SSTI',
        'template': 'SSTI',
        'ldap': 'LDAP Injection',
        'nosql': 'NoSQL Injection',
        'crlf': 'CRLF Injection',
        'header': 'Header Injection',
        'idor': 'IDOR',
        'jwt': 'JWT Attack',
        'graphql': 'GraphQL Injection',
        'deserial': 'Deserialization',
        'redirect': 'Open Redirect',
        'cors': 'CORS Bypass',
        'cache': 'Cache Poisoning',
        'host header': 'Host Header Injection',
        'prototype': 'Prototype Pollution',
        'buffer': 'Buffer Overflow',
    }
    
    for pattern, ref_key in patterns.items():
        if pattern in technique_lower:
            return CVE_CWE_REFERENCES.get(ref_key)
    
    return None
