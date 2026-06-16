#!/usr/bin/env python3
"""
Entry point for WAFPierce GUI application.
This file is used by PyInstaller to create the executable.
"""
import sys
import os
import multiprocessing
import json

# CRITICAL: Must be called at the very start for frozen Windows executables
# This prevents the exe from spawning infinite GUI instances
if __name__ == '__main__':
    multiprocessing.freeze_support()

# When running as a PyInstaller bundle, update paths for bundled resources
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    bundle_dir = sys._MEIPASS
    # Update working directory to bundle location
    os.chdir(bundle_dir)
    # Set environment variable so GUI knows we're frozen
    os.environ['WAFPIERCE_FROZEN'] = '1'
    os.environ['WAFPIERCE_BUNDLE_DIR'] = bundle_dir
    
    # Set Qt plugin paths for frozen executable
    # This ensures Qt can find its plugins (styles, platforms, etc.)
    qt_plugin_path = os.path.join(bundle_dir, 'PySide6', 'plugins')
    if os.path.exists(qt_plugin_path):
        os.environ['QT_PLUGIN_PATH'] = qt_plugin_path
    
    # Ensure Qt uses the bundled platform plugins
    platform_path = os.path.join(bundle_dir, 'PySide6', 'plugins', 'platforms')
    if os.path.exists(platform_path):
        os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = platform_path
    
    # Set style plugin path
    styles_path = os.path.join(bundle_dir, 'PySide6', 'plugins', 'styles')
    if os.path.exists(styles_path):
        os.environ['QT_STYLE_OVERRIDE'] = ''  # Let Qt choose the best available style
else:
    # Running as script
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    os.environ['WAFPIERCE_FROZEN'] = '0'

# Add the bundle directory to path
if bundle_dir not in sys.path:
    sys.path.insert(0, bundle_dir)

# Also add workspace root parent to help Python find the package reliably
package_dir = os.path.join(bundle_dir, 'wafpierce')
if os.path.isdir(package_dir):
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)

def main():
    """Launch the WAFPierce GUI."""
    try:
        from wafpierce.gui import main as gui_main
        gui_main()
        return
    except ModuleNotFoundError:
        # Fallback loader for unusual launch contexts
        import importlib.util
        gui_path = os.path.join(bundle_dir, 'wafpierce', 'gui.py')
        if not os.path.exists(gui_path):
            raise
        spec = importlib.util.spec_from_file_location('wafpierce.gui', gui_path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules['wafpierce.gui'] = module
        spec.loader.exec_module(module)
        module.main()


def _run_scan_worker() -> int:
    """Run scanner mode inside frozen executable for killable subprocess scans."""
    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--scan-worker', action='store_true')
    parser.add_argument('--target', required=True)
    parser.add_argument('--threads', type=int, default=5)
    parser.add_argument('--delay', type=float, default=0.2)
    parser.add_argument('--output', required=True)
    parser.add_argument('--categories', default='')
    args, _ = parser.parse_known_args()

    try:
        from wafpierce.pierce import create_scanner

        print(f"[*] Scanning {args.target}")
        # create_scanner pre-wires DB custom payloads / plugins / evasion profile and
        # enables crawling + schema discovery by default.
        scanner = create_scanner(args.target, threads=args.threads, delay=args.delay, timeout=5)
        selected_categories = [c.strip() for c in args.categories.split(',') if c.strip()]
        results = scanner.scan(selected_categories if selected_categories else None)

        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results or [], f, indent=2)

        print(f"[+] Scan complete: {len(results or [])} result(s)")
        return 0
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user")
        return 130
    except Exception as exc:
        print(f"[!] Scan error: {exc}")
        return 1

if __name__ == '__main__':
    if '--scan-worker' in sys.argv:
        raise SystemExit(_run_scan_worker())
    main()
