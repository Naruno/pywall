#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from setuptools import setup


setup(
    name='pywall',
    version='0.1.0',
    description="""Python firewall framework.""",
    long_description="""
# pywall
Python firewall framework.
# Install
```
pip3 install pywall
```
# Using
## In another script
```python
from pywall import pywall
# pywall(iface="wlan0")
safe = pywall(iface="wlan0").control()
```
## In command line
```console
pywall
```
```console
usage: pywall [-h] [-i IFACE] [-t TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout
```
    """,
    long_description_content_type='text/markdown',
    url='https://github.com/Decentra-Network/pywall',
    author='Decentra Network Developers',
    author_email='onur@decentranetwork.org',
    license='MIT',
    packages=["pywall"],
    package_dir={'':'src'},
    install_requires=[
        "scapy==2.4.5",
        "cryptography==36.0.2"
    ],
    entry_points = {
        'console_scripts': ['pywall=pywall.pywall:arguments'],
    },
    python_requires=">=3.8",
    zip_safe=False
)
