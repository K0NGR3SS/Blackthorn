import re
import pathlib

from setuptools import setup, find_packages


def _read_version() -> str:
    """Single-source the version from wafpierce/__init__.py without importing it
    (importing would pull in runtime deps that may not be installed at build time)."""
    init = pathlib.Path(__file__).parent / "wafpierce" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not m:
        raise RuntimeError("Unable to find __version__ in wafpierce/__init__.py")
    return m.group(1)


setup(
    name="wafpierce",
    version=_read_version(),
    packages=find_packages(),
    install_requires=['requests', 'urllib3', 'certifi', 'charset-normalizer', 'idna', 'cryptography', 'httpx[http2]>=0.27.0', 'curl_cffi>=0.7.0', 'reportlab>=4.0.0'],
    extras_require={
        'browser': ['playwright>=1.40.0'],
        'ai': ['anthropic>=0.40.0'],
        'dev': ['pytest>=8.0.0', 'ruff>=0.5.0'],
        'full': ['playwright>=1.40.0', 'anthropic>=0.40.0'],
    },
    entry_points={'console_scripts': ['wafpierce=wafpierce.cli:main']}
)
