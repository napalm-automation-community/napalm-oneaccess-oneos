# napalm-oneaccess-oneos

[![PyPI version](https://badge.fury.io/py/napalm-oneaccess-oneos.svg)](https://pypi.org/project/napalm-oneaccess-oneos/)
[![Python Tests](https://github.com/napalm-automation-community/napalm-oneaccess-oneos/actions/workflows/python-app.yml/badge.svg)](https://github.com/napalm-automation-community/napalm-oneaccess-oneos/actions/workflows/python-app.yml)

## NAPALM

[NAPALM](https://napalm.readthedocs.io/en/latest/) (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different router vendor devices using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configurations or to retrieve data.

## napalm-oneaccess-oneos

NAPALM driver for [Ekinops OneAccess](https://www.ekinops.com/products-services/products/oneaccess) devices
(OneAccess was acquired by Ekinops in 2017)

Connection to the device is done through a SSH or telnet connection using the netmiko librairy.

# Supported devices

All OneAccess devices running OneOS v5.x or OneOS v6.x
(CLI commands are mostly indentical between OS5 and OS6)

On your device you can check your OneOS version with the command "show version"


# Supported functions
- :white_check_mark: is_alive()
- :white_check_mark: get_facts()
- :white_check_mark: get_interfaces()
- :white_check_mark: get_interfaces_ip()
- :white_check_mark: get_environment()
- :white_check_mark: get_arp_table()
- :white_check_mark: get_config()
- :white_check_mark: get_users()
- :white_check_mark: cli()

Functions definition can be found [here](https://napalm.readthedocs.io/en/latest/base.html)

# Installation
You can install the driver using pip: 
```
pip install napalm-oneaccess-oneos
```

# Usage

You can use this driver like this:

```python
from napalm import get_network_driver

oneos_driver = get_network_driver("oneaccess_oneos")
device = oneos_driver("192.168.2.1", "admin", "password")
device.open()
print(device.get_facts())
```

If you want to custom some connection parameter, for example the transport protocol or the port connected to the device, you should use the `optional_args` argument (its attributes derivate from netmiko)

```python
from napalm import get_network_driver

oneos_driver = get_network_driver("oneaccess_oneos")
conn_args = {
    "port": 2333,
    "transport": "telnet"
}
device = oneos_driver("192.168.10.2", "admin", "password",optional_args=conn_args)
device.open()
print(device.get_interfaces_ip())
```

# Tests
You can execute the unit tests using Pytest:

### Run all tests
```
pytest
```

### Run a specific test (example)
```
pytest -sk test_get_environment[os6]
```
Notes: Tests only supported with NAPALM >= 4.0.0

# Contributing
If you would like to contribute to this project please contact Robin Guillat (robin@guillat.com)
