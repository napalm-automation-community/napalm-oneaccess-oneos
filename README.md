# napalm-oneaccess-oneos

** UNDER CONSTRUCTION **

## NAPALM

[NAPALM](https://github.com/napalm-automation/napalm) (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different router vendor devices using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configurations or to retrieve data.

## napalm-oneaccess-oneos
NAPALM driver for <b>Ekinops OneAccess</b> devices
Connection to the device is done through a SSH or telnet connection using the netmiko librairy. 

# Supported devices

All OneAccess devices running OneOS 5 or OneOs 6
(CLI commands are mostly indentical between OS5 and OS6)

OS5 devices includes: One100, One420, One425, One540, One1540, One270, One700, One2515
OS6 devices includes: One421, One521, One531, One2501, One526, One2515, One2540, One3540, 1647, 1651, OneOS6-LIM and v600 virtual Router

# Supported functions

- :white_check_mark: is_alive()
- :white_check_mark: get_facts()
- :white_check_mark: get_interfaces_ip()
- :white_check_mark: get_arp_table()
- :white_check_mark: get_config()
- :white_check_mark: cli()


## Usage

You can use this driver like this:

```python
from napalm import get_network_driver

device = get_network_driver("oneaccess_oneos")
device = device("192.168.2.1", "admin", "password",)
device.open()
print(device.get_facts())
```

If you want to custom some connection parameter, example: the transport protocol or the port connected to the device, you should use `optional_args`, it is exactly the same as `netmiko.BaseConnection.__init__`:
optional_args = {'transport' : 'telnet'}
```python
from napalm import get_network_driver

device = get_network_driver("oneaccess_oneos")
conn_args = {
    "port": 2333,
    "transport": "telnet"
}
device = device("192.168.10.2", "admin", "password",optional_args=conn_args)
device.open()
print(device.get_interfaces_ip())
```
