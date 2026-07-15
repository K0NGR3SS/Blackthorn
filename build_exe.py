#!/usr/bin/env python3
"""
Build script for creating the Blackthorn executable.
Run this script to build the standalone executable.

Usage:
    python build_exe.py
"""
import subprocess
import sys
import os

# Fix encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def main():
    print("=" * 60)
    print("Blackthorn Executable Builder")
    print("=" * 60)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"[OK] PyInstaller found (version {PyInstaller.__version__})")
    except ImportError:
        print("[X] PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
        print("[OK] PyInstaller installed")
    
    # Install project dependencies
    print("\nInstalling project dependencies...")
    requirements_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_file):
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', requirements_file])
        print("[OK] Dependencies installed")
    
    # Build the executable
    print("\nBuilding executable...")
    print("-" * 60)
    
    spec_file = os.path.join(os.path.dirname(__file__), 'wafpierce.spec')
    
    result = subprocess.run([
        sys.executable, '-m', 'PyInstaller',
        '--clean',
        '--noconfirm',
        spec_file
    ], cwd=os.path.dirname(__file__))
    
    if result.returncode == 0:
        print("-" * 60)
        print("\n[OK] Build successful!")
        print(f"\nExecutable location: {os.path.join(os.path.dirname(__file__), 'dist', 'Blackthorn.exe')}")
        print("\nYou can distribute this single .exe file to users.")
    else:
        print("\n[X] Build failed. Check the output above for errors.")
        sys.exit(1)

if __name__ == '__main__':
    main()
