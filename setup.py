#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/config_extractor/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-config-extractor",
    version=version_info["__version__"],
    description="Static configuration extractor for the Karton framework",
    namespace_packages=["karton"],
    packages=["karton.config_extractor"],
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "karton-config-extractor=karton.config_extractor:ConfigExtractor.main"
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
