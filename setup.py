import pathlib
import re

from setuptools import find_packages, setup


ROOT = pathlib.Path(__file__).parent


def _read_version() -> str:
    """Read the version without importing runtime dependencies."""
    text = (ROOT / "wafpierce" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not match:
        raise RuntimeError("Unable to find __version__ in wafpierce/__init__.py")
    return match.group(1)


setup(
    name="blackthorn",
    version=_read_version(),
    description="Threat hunting and bug bounty web security toolkit",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    packages=find_packages(),
    data_files=[
        ("share/blackthorn", [
            "blackthorn-logo-transparent.png",
            "blackthornlogo-background.jpg",
            "blackthornlogo-nottransparent.jpg",
        ]),
    ],
    install_requires=[
        "requests",
        "urllib3",
        "certifi",
        "charset-normalizer",
        "idna",
        "cryptography",
        "httpx[http2]>=0.27.0",
        "curl_cffi>=0.7.0",
        "reportlab>=4.0.0",
    ],
    extras_require={
        "browser": ["playwright>=1.40.0"],
        "ai": ["anthropic>=0.40.0"],
        "dev": ["pytest>=8.0.0", "ruff>=0.5.0"],
        "full": ["playwright>=1.40.0", "anthropic>=0.40.0"],
    },
    entry_points={
        "console_scripts": [
            "blackthorn=wafpierce.cli:main",
            "wafpierce=wafpierce.cli:main",
        ],
    },
)
