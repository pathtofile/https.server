"""
SimpleHTTPSServer
"""
import os
from setuptools import setup

setup(name="https.server",
      version="1.2.0",
      description="https.server - SimpleHTTPServer wrapped in TLS",
      author="/path/to/file",
      license="MIT",
      url="https://github.com/pathtofile/https.server",
      packages=["https"],
      entry_points={"console_scripts": ["https.server = https.server:main"]},
      include_package_data=True,
      install_requires=["pyOpenSSL>=19.0.0"],
      python_requires=">=3.6")
