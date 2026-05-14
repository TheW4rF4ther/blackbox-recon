#!/usr/bin/env python3
"""Setup script for Blackbox Recon."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="blackbox-recon",
    version="1.0.0",
    author="Blackbox Intelligence Group LLC",
    author_email="info@blackboxintelgroup.com",
    description="AI-Augmented Reconnaissance for Penetration Testers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/blackboxintel/blackbox-recon",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
        "click>=8.0.0",
        "pydantic>=2.0.0",
        "openai>=1.0.0",
        "anthropic>=0.18.0",
        "dnspython>=2.3.0",
        "python-nmap>=0.7.1",
        "beautifulsoup4>=4.12.0",
        "aiohttp>=3.8.0",
        "asyncio>=3.4.3",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "blackbox-recon=blackbox_recon.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
