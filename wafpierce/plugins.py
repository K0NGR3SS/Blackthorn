"""
WAFPierce Plugin System
Allows users to create custom bypass modules and share them with the community
"""
import os
import sys
import json
import hashlib
import importlib.util
import io
import re
import types
import tokenize
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from abc import ABC, abstractmethod

# Use shared config module
from .config import ensure_plugins_dir


class BypassPlugin(ABC):
    """
    Base class for WAFPierce bypass plugins.
    
    To create a custom plugin:
    1. Create a new .py file in the plugins directory
    2. Create a class that inherits from BypassPlugin
    3. Implement the required methods
    4. Register your plugin by creating an instance at module level
    
    Example:
        class MyCustomBypass(BypassPlugin):
            name = "My Custom Bypass"
            version = "1.0.0"
            author = "Your Name"
            description = "Description of what this bypass does"
            category = "encoding"  # bypass, encoding, header, injection, etc.
            
            def execute(self, target, session, **kwargs):
                # Your bypass logic here
                payload = self.encode_payload(kwargs.get('payload', ''))
                return self.make_request(target, payload)
    """
    
    # Plugin metadata (override these in your plugin)
    name: str = "Unnamed Plugin"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = "No description provided"
    category: str = "bypass"
    tags: List[str] = []
    
    # WAF compatibility (empty = all WAFs)
    compatible_wafs: List[str] = []
    
    # Plugin settings
    settings: Dict[str, Any] = {}
    
    def __init__(self):
        self.enabled = True
        self.last_run = None
        self.success_count = 0
        self.fail_count = 0
    
    @abstractmethod
    def execute(self, target: str, session: Any, **kwargs) -> Dict[str, Any]:
        """
        Execute the bypass technique.
        
        Args:
            target: Target URL
            session: requests.Session object
            **kwargs: Additional arguments (payload, headers, etc.)
        
        Returns:
            Dict with keys:
                - success: bool
                - bypass: bool (did it bypass the WAF?)
                - response: response object or None
                - technique: str (name of technique used)
                - reason: str (why this is considered a bypass/success)
                - severity: str (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        pass
    
    def setup(self, config: Dict[str, Any] = None):
        """Optional setup method called before first execution."""
        if config:
            self.settings.update(config)
    
    def teardown(self):
        """Optional cleanup method called after all executions."""
        pass
    
    def validate_target(self, target: str) -> bool:
        """Check if this plugin should run against the target."""
        return True
    
    def get_payloads(self) -> List[str]:
        """Return a list of payloads this plugin uses."""
        return []
    
    # Utility methods for plugin authors
    def encode_payload(self, payload: str, encoding: str = 'url') -> str:
        """Encode a payload using various methods."""
        import urllib.parse
        
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'hex':
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == 'base64':
            import base64
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    def make_request(self, target: str, payload: str = None, method: str = 'GET',
                     headers: Dict[str, str] = None, session: Any = None, **kwargs) -> Any:
        """Make an HTTP request with the given parameters."""
        import requests
        
        s = session or requests.Session()
        
        if method.upper() == 'GET':
            return s.get(target, params={'payload': payload} if payload else None,
                        headers=headers, **kwargs)
        elif method.upper() == 'POST':
            return s.post(target, data={'payload': payload} if payload else None,
                         headers=headers, **kwargs)
        else:
            return s.request(method, target, headers=headers, **kwargs)
    
    def is_blocked(self, response: Any) -> bool:
        """Check if the response indicates WAF blocking."""
        if response is None:
            return True
        
        # Common WAF block indicators
        block_codes = [403, 406, 429, 503]
        block_phrases = [
            'blocked', 'forbidden', 'access denied', 'security',
            'firewall', 'waf', 'attack', 'malicious', 'not allowed'
        ]
        
        if response.status_code in block_codes:
            return True
        
        text_lower = response.text.lower()
        return any(phrase in text_lower for phrase in block_phrases)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert plugin metadata to dictionary."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'category': self.category,
            'tags': self.tags,
            'compatible_wafs': self.compatible_wafs,
            'enabled': self.enabled,
            'success_count': self.success_count,
            'fail_count': self.fail_count,
            'last_run': self.last_run.isoformat() if self.last_run else None
        }


class PluginManager:
    """Manages loading, running, and organizing plugins."""
    
    def __init__(self, db=None):
        self.plugins_dir = ensure_plugins_dir()
        self.plugins_dirs = self._get_plugin_dirs()
        self.plugins: Dict[str, BypassPlugin] = {}
        self.plugin_files: Dict[str, str] = {}
        self.load_errors: Dict[str, str] = {}
        self.db = db
        self._create_example_plugin()

    def _get_plugin_dirs(self) -> List[str]:
        """Get all plugin directories to search."""
        dirs = []

        # Primary user plugins directory
        dirs.append(ensure_plugins_dir())

        # Workspace-local plugin folders (common user expectation)
        try:
            module_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(module_dir)

            candidates = [
                os.path.join(module_dir, 'plugins'),
                os.path.join(project_root, 'plugins'),
                os.path.join(os.getcwd(), 'plugins'),
            ]
            dirs.extend(candidates)
        except Exception:
            pass

        unique_dirs = []
        seen = set()
        for d in dirs:
            if not d:
                continue
            norm = os.path.normcase(os.path.abspath(d))
            if norm in seen:
                continue
            seen.add(norm)
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                pass
            unique_dirs.append(d)

        return unique_dirs
    
    def _create_example_plugin(self):
        """Create an example plugin file if none exist."""
        example_path = os.path.join(self.plugins_dir, 'example_plugin.py')
        if not os.path.exists(example_path):
            example_code = '''"""
Example WAFPierce Plugin
This is a template for creating your own bypass plugins.
"""
try:
    from wafpierce.plugins import BypassPlugin
except ImportError:
    from plugins import BypassPlugin


class UnicodeBypassPlugin(BypassPlugin):
    """Example plugin that uses Unicode normalization for bypasses."""
    
    name = "Unicode Normalization Bypass"
    version = "1.0.0"
    author = "WAFPierce Community"
    description = "Uses Unicode character variations to bypass WAF filters"
    category = "encoding"
    tags = ["unicode", "encoding", "obfuscation"]
    compatible_wafs = ["cloudflare", "akamai", "imperva"]
    
    def execute(self, target, session, **kwargs):
        """Execute the Unicode bypass technique."""
        import requests
        
        payload = kwargs.get('payload', '<script>alert(1)</script>')
        
        # Unicode fullwidth characters
        unicode_payload = ''.join(
            chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
            for c in payload
        )
        
        try:
            resp = session.get(target, params={'q': unicode_payload}, timeout=10)
            
            bypassed = not self.is_blocked(resp)
            
            return {
                'success': True,
                'bypass': bypassed,
                'response': resp,
                'technique': self.name,
                'reason': 'Unicode fullwidth characters bypassed filter' if bypassed else 'Blocked',
                'severity': 'HIGH' if bypassed else 'INFO',
                'payload': unicode_payload
            }
        except Exception as e:
            return {
                'success': False,
                'bypass': False,
                'response': None,
                'technique': self.name,
                'reason': str(e),
                'severity': 'INFO'
            }


# Register the plugin (required)
PLUGIN_CLASS = UnicodeBypassPlugin
'''
            try:
                with open(example_path, 'w', encoding='utf-8') as f:
                    f.write(example_code)
            except Exception:
                pass
    
    def discover_plugins(self) -> List[str]:
        """Discover all plugin files in the plugins directory."""
        plugin_files = []
        seen = set()

        for plugins_dir in self.plugins_dirs:
            if not os.path.exists(plugins_dir):
                continue

            try:
                for filename in os.listdir(plugins_dir):
                    if not filename.endswith('.py') or filename.startswith('_'):
                        continue
                    path = os.path.abspath(os.path.join(plugins_dir, filename))
                    key = os.path.normcase(path)
                    if key in seen:
                        continue
                    seen.add(key)
                    plugin_files.append(path)
            except Exception:
                continue

        return sorted(plugin_files, key=lambda p: os.path.basename(p).lower())

    def _safe_module_name_for_path(self, file_path: str) -> str:
        """Build a unique import module name for a plugin file path."""
        base = os.path.splitext(os.path.basename(file_path))[0]
        safe = re.sub(r'[^0-9a-zA-Z_]', '_', base)
        digest = hashlib.sha1(os.path.abspath(file_path).encode('utf-8', errors='ignore')).hexdigest()[:10]
        return f"wafpierce_user_plugin_{safe}_{digest}"

    def _decode_plugin_source(self, source_bytes: bytes) -> str:
        """Decode plugin source bytes with robust encoding detection/fallbacks."""
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(source_bytes).readline)
            return source_bytes.decode(encoding)
        except Exception:
            pass

        for encoding in ('utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'cp1252', 'latin-1'):
            try:
                return source_bytes.decode(encoding)
            except Exception:
                continue

        raise ValueError('Unsupported text encoding for plugin file')

    def _get_bypass_bases(self) -> List[type]:
        """Return known BypassPlugin base class identities across import paths."""
        bases: List[type] = [BypassPlugin]
        for mod_name in ('wafpierce.plugins', 'plugins'):
            mod = sys.modules.get(mod_name)
            cls = getattr(mod, 'BypassPlugin', None) if mod else None
            if isinstance(cls, type) and cls not in bases:
                bases.append(cls)
        return bases

    def _is_valid_plugin_class(self, obj: Any) -> bool:
        """Check whether object is a valid plugin class."""
        if not isinstance(obj, type):
            return False
        for base in self._get_bypass_bases():
            try:
                if issubclass(obj, base) and obj is not base:
                    return True
            except TypeError:
                continue
        return False
    
    def load_plugin(self, file_path: str) -> Optional[BypassPlugin]:
        """Load a plugin from a file."""
        try:
            # Calculate checksum for integrity
            if not os.path.exists(file_path):
                self.load_errors[file_path] = 'File not found'
                return None

            with open(file_path, 'rb') as f:
                source_bytes = f.read()
                checksum = hashlib.sha256(source_bytes).hexdigest()
            
            # Load module directly from source to avoid stale .pyc / import cache issues.
            source_text = self._decode_plugin_source(source_bytes)
            module_name = self._safe_module_name_for_path(file_path)
            importlib.invalidate_caches()
            code = compile(source_text, file_path, 'exec')
            module = types.ModuleType(module_name)
            module.__file__ = os.path.abspath(file_path)
            module.__package__ = ''
            module.__loader__ = None
            sys.modules.pop(module_name, None)
            sys.modules[module_name] = module
            exec(code, module.__dict__)
            
            # Get the plugin class
            plugin_class = getattr(module, 'PLUGIN_CLASS', None)
            if plugin_class is None:
                # Fallback: auto-discover first BypassPlugin subclass in module
                candidates = []
                for obj in module.__dict__.values():
                    if self._is_valid_plugin_class(obj):
                        candidates.append(obj)
                if candidates:
                    plugin_class = candidates[0]

            if self._is_valid_plugin_class(plugin_class):
                plugin = plugin_class()
                self.plugins[plugin.name] = plugin
                self.plugin_files[plugin.name] = os.path.abspath(file_path)
                self.load_errors.pop(file_path, None)
                
                # Save to database
                if self.db:
                    self.db.save_plugin(
                        name=plugin.name,
                        version=plugin.version,
                        file_path=file_path,
                        author=plugin.author,
                        description=plugin.description,
                        category=plugin.category,
                        source='local',
                        checksum=checksum
                    )
                
                return plugin
            else:
                self.load_errors[file_path] = 'No valid BypassPlugin class found (PLUGIN_CLASS missing/invalid)'
        except SyntaxError as e:
            self.load_errors[file_path] = f"Syntax error at line {getattr(e, 'lineno', '?')}: {e.msg}"
        except UnicodeDecodeError:
            self.load_errors[file_path] = 'Could not decode plugin file text (save as UTF-8 or UTF-16)'
        except ValueError as e:
            self.load_errors[file_path] = str(e)
        except Exception as e:
            self.load_errors[file_path] = str(e)
        
        return None
    
    def load_all_plugins(self):
        """Load all discovered plugins."""
        # Rebuild from disk every refresh to avoid stale plugin state.
        self.plugins = {}
        self.plugin_files = {}
        self.load_errors = {}
        for file_path in self.discover_plugins():
            self.load_plugin(file_path)
    
    def get_plugin(self, name: str) -> Optional[BypassPlugin]:
        """Get a loaded plugin by name."""
        return self.plugins.get(name)
    
    def get_enabled_plugins(self) -> List[BypassPlugin]:
        """Get all enabled plugins."""
        return [p for p in self.plugins.values() if p.enabled]
    
    def get_plugins_by_category(self, category: str) -> List[BypassPlugin]:
        """Get plugins filtered by category."""
        return [p for p in self.plugins.values() if p.category == category]
    
    def get_plugins_for_waf(self, waf_type: str) -> List[BypassPlugin]:
        """Get plugins compatible with a specific WAF."""
        return [
            p for p in self.plugins.values()
            if not p.compatible_wafs or waf_type.lower() in [w.lower() for w in p.compatible_wafs]
        ]
    
    def run_plugin(self, plugin_name: str, target: str, session: Any, **kwargs) -> Dict[str, Any]:
        """Run a specific plugin."""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return {'success': False, 'reason': 'Plugin not found'}
        
        if not plugin.enabled:
            return {'success': False, 'reason': 'Plugin is disabled'}
        
        try:
            result = plugin.execute(target, session, **kwargs)
            plugin.last_run = datetime.now()
            
            if result.get('success'):
                plugin.success_count += 1
            else:
                plugin.fail_count += 1
            
            # Update database stats
            if self.db:
                self.db.update_plugin_stats(plugin_name, result.get('success', False))
            
            return result
        except Exception as e:
            plugin.fail_count += 1
            return {'success': False, 'reason': str(e)}
    
    def run_all_enabled(self, target: str, session: Any, **kwargs) -> List[Dict[str, Any]]:
        """Run all enabled plugins against a target."""
        results = []
        for plugin in self.get_enabled_plugins():
            if plugin.validate_target(target):
                result = self.run_plugin(plugin.name, target, session, **kwargs)
                result['plugin_name'] = plugin.name
                results.append(result)
        return results
    
    def enable_plugin(self, name: str):
        """Enable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = True
            if self.db:
                self.db.toggle_plugin(name, True)
    
    def disable_plugin(self, name: str):
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = False
            if self.db:
                self.db.toggle_plugin(name, False)
    
    def uninstall_plugin(self, name: str) -> bool:
        """Uninstall a plugin."""
        plugin = self.plugins.get(name)
        if not plugin:
            return False

        # Find and remove the plugin file
        file_path = self.plugin_files.get(name)
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        
        # Remove from memory
        del self.plugins[name]
        self.plugin_files.pop(name, None)
        
        # Remove from database
        if self.db:
            self.db.delete_plugin(name)
        
        return True
    
    def get_plugin_info(self) -> List[Dict[str, Any]]:
        """Get info about all plugins."""
        info = []
        for p in self.plugins.values():
            data = p.to_dict()
            data['file_path'] = self.plugin_files.get(p.name, '')
            info.append(data)
        return sorted(info, key=lambda p: p.get('name', '').lower())

    def get_discovered_files(self) -> List[str]:
        """Get all discovered plugin file paths."""
        return self.discover_plugins()

    def get_load_errors(self) -> Dict[str, str]:
        """Get plugin load errors keyed by file path."""
        return dict(self.load_errors)


def validate_plugin(plugin: BypassPlugin) -> List[str]:
    """
    Validate a plugin and return list of issues.
    
    Args:
        plugin: The plugin instance to validate
    
    Returns:
        List of validation issues (empty if valid)
    """
    issues = []
    
    # Check name
    if not plugin.name or plugin.name == "Unnamed Plugin":
        issues.append("Plugin must have a custom name")
    
    # Check version format
    if plugin.version:
        parts = plugin.version.split('.')
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            issues.append("Version should be in semver format (e.g., '1.0.0')")
    
    # Check execute method
    if not hasattr(plugin, 'execute') or not callable(getattr(plugin, 'execute', None)):
        issues.append("Plugin must implement execute method")
    
    # Check category
    valid_categories = ['bypass', 'encoding', 'header', 'injection', 'protocol', 'cloud', 'recon']
    if plugin.category not in valid_categories:
        issues.append(f"Category must be one of: {', '.join(valid_categories)}")
    
    return issues


# Community Plugin Marketplace (placeholder for future implementation)
class PluginMarketplace:
    """Interface to the WAFPierce community plugin marketplace."""
    
    MARKETPLACE_URL = "https://wafpierce.github.io/plugins"  # Placeholder
    
    def __init__(self, manager: PluginManager):
        self.manager = manager
        self.cache: Dict[str, Any] = {}
    
    def search(self, query: str = '', category: str = None) -> List[Dict[str, Any]]:
        """Search for plugins in the marketplace."""
        # Placeholder - would fetch from actual marketplace API
        return [
            {
                'name': 'Advanced SQL Bypass',
                'version': '2.0.0',
                'author': 'SecurityResearcher',
                'description': 'Advanced SQL injection bypass techniques',
                'category': 'injection',
                'downloads': 1250,
                'rating': 4.8,
                'compatible_wafs': ['cloudflare', 'aws_waf', 'imperva']
            },
            {
                'name': 'XSS Filter Evasion',
                'version': '1.5.0',
                'author': 'XSSHunter',
                'description': 'Comprehensive XSS filter bypass techniques',
                'category': 'encoding',
                'downloads': 890,
                'rating': 4.5,
                'compatible_wafs': ['akamai', 'cloudflare']
            },
            {
                'name': 'Request Smuggling Toolkit',
                'version': '1.0.0',
                'author': 'HTTPExpert',
                'description': 'HTTP Request Smuggling techniques',
                'category': 'protocol',
                'downloads': 450,
                'rating': 4.7,
                'compatible_wafs': ['aws_alb', 'nginx']
            }
        ]
    
    def get_plugin_details(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a marketplace plugin."""
        plugins = self.search()
        for p in plugins:
            if p['name'] == name:
                return p
        return None
    
    def install(self, name: str) -> bool:
        """Install a plugin from the marketplace."""
        # Placeholder - would download and install from marketplace
        print(f"[*] Installing plugin '{name}' from marketplace...")
        print("[!] Marketplace installation is not yet implemented.")
        print(f"[*] You can manually download plugins and place them in: {self.manager.plugins_dir}")
        return False
    
    def check_updates(self) -> List[Dict[str, Any]]:
        """Check for updates to installed plugins."""
        updates = []
        # Placeholder - would check each installed plugin against marketplace
        return updates
