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