#!/usr/bin/env python3
"""
Setup script for Reverse Engineering Automation Tool
NTRO Approved - Government of India Project
"""

from setuptools import setup, find_packages
import os

# Read README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="reverse-engineering-automation",
    version="1.0.0",
    author="NTRO - Government of India",
    author_email="contact@ntro.gov.in",
    description="Automated reverse engineering tool for security analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ntro/reverse-engineering-automation",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
        "ml": [
            "transformers>=4.30.0",
            "torch>=2.0.0",
            "tensorflow>=2.13.0",
        ],
        "advanced": [
            "yara-python>=4.3.0",
            "ssdeep>=3.4",
            "tlsh>=4.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "re-automation=rea:main",
            "re-install-tools=scripts.install_tools:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.md", "*.txt"],
    },
    zip_safe=False,
    keywords="reverse-engineering, malware-analysis, security, binary-analysis, NTRO",
    project_urls={
        "Bug Reports": "https://github.com/ntro/reverse-engineering-automation/issues",
        "Source": "https://github.com/ntro/reverse-engineering-automation",
        "Documentation": "https://github.com/ntro/reverse-engineering-automation/docs",
    },
)
