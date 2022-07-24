# napalm-oneaccess-oneos

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

On you can check your OneOS version with the command "show version" on your device


# Supported functions

- :white_check_mark: is_alive()
- :white_check_mark: get_facts()
- :white_check_mark: get_interfaces()
- :white_check_mark: get_interfaces_ip()
- :white_check_mark: get_environment()
- :white_check_mark: get_arp_table()
- :white_check_mark: get_config()
- :white_check_mark: cli()

# Installation
The driver is not yet integrated in napalm. 
To use it, simply copy the folder napalm-oneaccess-oneos/napalm_oneaccess_oneos
into your Python package repository, in the same location where you can find the napalm folder, e.g:

\<PATH>/Python/Python39/site-packages

From this location NAPALM will then be able to find the driver automatically when calling the
function get_network_driver()

# Usage

You can use this driver like this:

```python
from napalm import get_network_driver

oneos_driver = get_network_driver("oneaccess_oneos")
device = oneos_driver("192.168.2.1", "admin", "password",)
device.open()
print(device.get_facts())
```

If you want to custom some connection parameter, for example the transport protocol or the port connected to the device, you should use `optional_args`, it is exactly the same as `netmiko.

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
