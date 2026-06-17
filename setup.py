from setuptools import setup, find_packages
setup(
    name="wafpierce",
    version="1.5",
    packages=find_packages(),
    install_requires=['requests', 'urllib3', 'certifi', 'charset-normalizer', 'idna', 'cryptography', 'httpx[http2]>=0.27.0', 'curl_cffi>=0.7.0'],
    extras_require={
        'browser': ['playwright>=1.40.0'],
        'ai': ['anthropic>=0.40.0'],
        'dev': ['pytest>=8.0.0', 'ruff>=0.5.0'],
        'full': ['playwright>=1.40.0', 'anthropic>=0.40.0'],
    },
    entry_points={'console_scripts': ['wafpierce=wafpierce.chain:main']}
)