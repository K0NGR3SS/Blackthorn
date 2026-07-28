# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for the Blackthorn desktop application.
This bundles the entire application with all dependencies into a single executable.
"""

import os
import sys

block_cipher = None

# Get the project root directory
project_root = os.path.dirname(os.path.abspath(SPEC))

# Data files to include (wordlists, logo, etc.)
datas = [
    # Include wordlists folder
    (os.path.join(project_root, 'wordlists'), 'wordlists'),
    # Include the three supplied Blackthorn identity assets.
    (os.path.join(project_root, 'blackthorn-logo-transparent.png'), os.path.join('wafpierce', 'assets')),
    (os.path.join(project_root, 'blackthornlogo-background.jpg'), os.path.join('wafpierce', 'assets')),
    (os.path.join(project_root, 'blackthornlogo-nottransparent.jpg'), os.path.join('wafpierce', 'assets')),
    # Include categories file
    (os.path.join(project_root, 'categories.txt'), '.'),
]

# Try to find and include PySide6 plugins for proper styling
try:
    import PySide6
    pyside6_dir = os.path.dirname(PySide6.__file__)
    plugins_dir = os.path.join(pyside6_dir, 'plugins')
    if os.path.exists(plugins_dir):
        # Include platform plugins (essential for Qt to work)
        platforms_dir = os.path.join(plugins_dir, 'platforms')
        if os.path.exists(platforms_dir):
            datas.append((platforms_dir, os.path.join('PySide6', 'plugins', 'platforms')))
        # Include style plugins (for proper app appearance)
        styles_dir = os.path.join(plugins_dir, 'styles')
        if os.path.exists(styles_dir):
            datas.append((styles_dir, os.path.join('PySide6', 'plugins', 'styles')))
        # Include imageformats for icons
        imageformats_dir = os.path.join(plugins_dir, 'imageformats')
        if os.path.exists(imageformats_dir):
            datas.append((imageformats_dir, os.path.join('PySide6', 'plugins', 'imageformats')))
except ImportError:
    pass

# Hidden imports that PyInstaller might miss
hidden_imports = [
    # PySide6 core modules - only include what we actually use
    'PySide6',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'shiboken6',
    # Requests and networking
    'requests',
    'requests.adapters',
    'urllib3',
    'urllib3.util',
    'urllib3.util.retry',
    'urllib3.exceptions',
    'certifi',
    'charset_normalizer',
    'charset_normalizer.md',
    'charset_normalizer.md__mypyc',
    'idna',
    # Blackthorn internal modules
    'wafpierce',
    'wafpierce.gui',
    'wafpierce.theme',
    'wafpierce.pierce',
    'wafpierce.chain',
    'wafpierce.error_handler',
    'wafpierce.exceptions',
    'wafpierce.database',
    'wafpierce.plugins',
    # v1.5 modules (lazily imported — list explicitly so PyInstaller bundles them)
    'wafpierce.crawler',
    'wafpierce.schema_ingest',
    'wafpierce.exporters',
    'wafpierce.monitor',
    'wafpierce.ai_triage',
    'wafpierce.browser_tests',
    'wafpierce.mutations',
    'wafpierce.websocket_tests',
    'wafpierce.repro',
    'wafpierce.oob',
    'wafpierce.techniques_v16',
    'wafpierce.cvss',
    'wafpierce.importers',
    'wafpierce.integrations',
    'wafpierce.cli',
    'wafpierce.diagnostics',
    'wafpierce.recon',
    'wafpierce.recon_install',
    'wafpierce.redaction',
    'wafpierce.authorization',
    'wafpierce.configfile',
    # Optional native-dep features (lazily imported; degrade gracefully)
    'cryptography',
    'curl_cffi',
    'curl_cffi.requests',
    # Standard library modules
    'json',
    'threading',
    'subprocess',
    'tempfile',
    'concurrent.futures',
    'multiprocessing',
    'logging',
    'socket',
    'ssl',
    're',
    'hashlib',
    'functools',
    'typing',
    'io',
    'webbrowser',
]

# Collect native binaries/data PyInstaller can't trace from imports alone.
# curl_cffi bundles a libcurl-impersonate shared library; without this the
# --impersonate feature silently degrades inside the frozen build.
binaries = []
try:
    from PyInstaller.utils.hooks import collect_all
    for _pkg in ('certifi', 'curl_cffi', 'cryptography', 'reportlab'):
        try:
            _datas, _bins, _hidden = collect_all(_pkg)
            datas += _datas
            binaries += _bins
            hidden_imports += _hidden
        except Exception:
            pass
except Exception:
    pass

a = Analysis(
    [os.path.join(project_root, 'run_gui.py')],
    pathex=[project_root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary PySide6 modules to reduce size and build time
        'PySide6.Qt3DAnimation',
        'PySide6.Qt3DCore',
        'PySide6.Qt3DExtras',
        'PySide6.Qt3DInput',
        'PySide6.Qt3DLogic',
        'PySide6.Qt3DRender',
        'PySide6.QtBluetooth',
        'PySide6.QtCharts',
        'PySide6.QtConcurrent',
        'PySide6.QtDataVisualization',
        'PySide6.QtDesigner',
        'PySide6.QtHelp',
        'PySide6.QtMultimedia',
        'PySide6.QtMultimediaWidgets',
        'PySide6.QtNetworkAuth',
        'PySide6.QtNfc',
        'PySide6.QtOpenGL',
        'PySide6.QtOpenGLWidgets',
        'PySide6.QtPdf',
        'PySide6.QtPdfWidgets',
        'PySide6.QtPositioning',
        'PySide6.QtPrintSupport',
        'PySide6.QtQml',
        'PySide6.QtQuick',
        'PySide6.QtQuick3D',
        'PySide6.QtQuickControls2',
        'PySide6.QtQuickWidgets',
        'PySide6.QtRemoteObjects',
        'PySide6.QtScxml',
        'PySide6.QtSensors',
        'PySide6.QtSerialPort',
        'PySide6.QtSpatialAudio',
        'PySide6.QtSql',
        'PySide6.QtStateMachine',
        'PySide6.QtSvg',
        'PySide6.QtSvgWidgets',
        'PySide6.QtTest',
        'PySide6.QtUiTools',
        'PySide6.QtWebChannel',
        'PySide6.QtWebEngineCore',
        'PySide6.QtWebEngineQuick',
        'PySide6.QtWebEngineWidgets',
        'PySide6.QtWebSockets',
        'PySide6.QtXml',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Blackthorn',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to False for GUI app (no console window)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(project_root, 'blackthorn-logo-transparent.png') if os.path.exists(os.path.join(project_root, 'blackthorn-logo-transparent.png')) else None,
)
