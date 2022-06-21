# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Oneaccess_oneos.

Read https://napalm.readthedocs.io for more information.
"""

### temp 
import pprint
#####

import telnetlib
import netmiko
from napalm.base import NetworkDriver
import napalm.base.helpers
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
)

from napalm.base.netmiko_helpers import netmiko_args
import re

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = (
    r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:"
    "[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}"
)
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(
    IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3
)



class OneaccessOneosDriver(NetworkDriver):
    """Napalm driver for Oneaccess_oneos."""


    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Contructor for the class Oneaccess_oneosDriver

        :param hostname: The IP address or hostname of the device you want to connect to
        :param username: The username to use to login to the router
        :param password: The password to use for authentication
        :param timeout: The amount of time to wait for the device to respond to a command, defaults to 60
        (optional)
        :param optional_args: 
        """
      
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.oneos_gen = None  #OneOs generation OneOS5 or OneOS6

        if optional_args is None:
            optional_args = {}

        self.netmiko_optional_args = netmiko_args(optional_args)

        self.transport = optional_args.get("transport", "ssh")        
        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        #not sure if really needed
        if self.transport == "telnet":
            # Telnet only supports inline_transfer
            self.inline_transfer = True


    def open(self):
        """Open connection to device"""
        device_type = 'oneaccess_oneos'

        if self.transport == "telnet":
            device_type = 'oneaccess_oneos_telnet'

        self.device = self._netmiko_open(device_type, netmiko_optional_args=self.netmiko_optional_args)


    def close(self):
        """Implement the NAPALM method close (mandatory)"""
        self._netmiko_close()


    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "Incorrect usage" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
 


    @staticmethod
    def _send_command_postprocess(output):
        output = output.strip()
        return output


    def is_alive(self):
        # """Returns a flag with the state of the connection.
        #    Logic copied from cisco ios driver
        # """
        # null = chr(0)
        # if self.device is None:
        #     return {'is_alive': False}

        # if self.transport == "telnet":
        #     try:
        #         # Try sending IAC + NOP (IAC is telnet way of sending command
        #         # IAC = Interpret as Command (it comes before the NOP)
        #         self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
        #         return {"is_alive": True}
        #     except AttributeError:
        #         return {"is_alive": False}
        # else:
        # # SSH
        #     try:
        #         # Try sending ASCII null byte to maintain the connection alive
        #         self.device.write_channel(null)
        #         return {'is_alive': self.device.remote_conn.transport.is_active()}
        #     except (socket.error, EOFError):
        #         # If unable to send, we can tell for sure that the connection is unusable
        #         return {'is_alive': False}
        # return {'is_alive': False}
        # """Return flag with the state of the connection."""
        # print(self.device)
        # if self.device is None:
        #     return {"is_alive": False}
        # return {"is_alive": self.device._session.transport.is_active()}
        raise NotImplementedError()


    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.
        Example input:
        ['show clock', 'show calendar']
        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self._send_command(command)
            #OneOS error message if the command is not valid
            if ('Syntax error' or 'syntax error') in output:  
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_oneos_gen(self):
        """
        Return the OneOs generation version (OneOS5 or OneOS6).
        Since it's not something which can change on a device,
        we only send a command to the device the first time
        :return int: 5, 6 or -1 (if unknown)         
        """
        if self.oneos_gen != None:
            return self.oneos_gen

        version = self._send_command("show version | include version")
        if "-6." in version:
            self.oneos_gen = "OneOS6"
        elif "-V5." in version:
            self.oneos_gen = "OneOS5"
        else:
            self.oneos_gen = "Unknown" #OS generation version Unknown

        return self.oneos_gen


    def save_config(self):
        """
        ** Not a Napalm function **
        Saves the config of the device, uses the paramiko save_config() function        
        """
        try:
            output = self.device.save_config()
            return True
        except:
            return False


    def get_config(self, retrieve='all',full=False, sanitized=False):
        """
        Return the configuration of a device.
        Args:
        retrieve(string): Which configuration type you want to populate, default is all of them.
                          Note with OneAccess device there is no "candidate" show run.
                          so the value can only be "all" , "running" or "startup"
        full(bool): NOT IMPLEMENTED, concept not present on OneAccess
        sanitized(bool): NOT IMPLEMENTED (but could be done), Remove secret data. Default: ``False``.
        """
        configs = {'startup': '','running': '','candidate': ''}

        if retrieve in ('running', 'all'):
            command = [ 'show running-config' ]
            output = self._send_command(command)
            configs['running'] = output

        if retrieve in ('startup', 'all'):
            #method working for both OneOS5 and OneOs6
            command = [ 'cat /BSA/config/bsaStart.cfg' ] 
            output = self._send_command(command)
            configs['startup'] = output

        return configs


    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given OneAccess.
        Return the uptime in seconds as an integer

        credit @mwallraf 
        """
        # Initialize to zero
        (days, hours, minutes, seconds) = (0, 0, 0, 0)

        m = re.match(".*(?P<days>[0-9]+)d (?P<hours>[0-9]+)h (?P<minutes>[0-9]+)m (?P<seconds>[0-9]+)s.*", uptime_str)
        if m:
            days = int(m.groupdict()["days"])
            hours = int(m.groupdict()["hours"])
            minutes = int(m.groupdict()["minutes"])
            seconds = int(m.groupdict()["seconds"])

        uptime_sec = (days * DAY_SECONDS) + (hours * HOUR_SECONDS) \
                      + (minutes * 60) + seconds

        return uptime_sec

    def get_facts(self):
        """Return a set of facts from the device.        
        """        
        facts = {
            "vendor": "Ekinops OneAccess",
            "uptime": None,  #converted in seconds
            "os_version": None,
            "os_generation": self.get_oneos_gen(),
            "boot_version": None,
            "serial_number": None,
            "model": None,
            "hostname": None,
            "fqdn": None,
            "interface_list": []
        }

        # get output from device
        show_system_status = self._send_command('show system status')
        show_system_hardware = self._send_command('show system hardware')
        show_hostname = self._send_command('hostname')
        show_ip_int_brief = self._send_command('show ip int brief')                           

        for l in show_system_status.splitlines():
            if "System Information" in l:
                c = l.split()
                facts["serial_number"] = c[-1]
                continue
            if "Software version" in l:
                facts["os_version"] = l.split()[-1]
                continue
            if "Boot version" in l:
                facts["boot_version"] = l.split()[-1]
                continue
            if "Sys Up time" in l: 
                uptime_str = l.split(":")[-1]
                facts["uptime"] = self.parse_uptime(uptime_str)
                continue

        for l in show_system_hardware.splitlines():
            m = re.match(".*Device\s*:\s+(?P<MODEL>\S+).*", l)
            if m:
                facts["model"] = m.groupdict()["MODEL"]
                break
        
        for l in show_hostname.splitlines():
            if l:
                facts["hostname"] = l.strip()
                break
                
        for line in show_ip_int_brief.splitlines()[1:-1]:
            interface = line.split("  ")[0]
            if interface != "Null 0":
                facts["interface_list"].append(interface)                            

        #No local FQDN to retrieve on a OneAccess device
        facts["fqdn"] = "N/A" 

        return facts


    def get_interfaces_ip(self):
        """
        Get interface ip details.

        Returns a dict of dicts

        Example Output:

        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': 10}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """
        interfaces = {}

        command = "show interface"
        show_ip_interface = self._send_command(command)

        INTERNET_ADDRESS = r"\s+(?:Internet address is|Secondary address is)"
        INTERNET_ADDRESS += r" (?P<ip>{})/(?P<prefix>\d+)".format(IPV4_ADDR_REGEX)

        IPV6_ADDR = r"\s+(?:IPv6 address is)"
        IPV6_ADDR += r" (?P<ip>{})/(?P<prefix>\d+)".format(IPV6_ADDR_REGEX)

        interfaces = {}
        for line in show_ip_interface.splitlines():
            if len(line.strip()) == 0:
                continue
            if line[0] != " ": #Extract interface name
                ipv4 = {}
                ipv6 = {}
                interface_name = line.split(" is ")[0]
                continue

            #Extract IPv4 and prefix
            m = re.match(INTERNET_ADDRESS, line) 
            if m:
                ip, prefix = m.groups()
                ipv4.update({ip: {"prefix_length": int(prefix)}})
                interfaces[interface_name] = {"ipv4": ipv4}
                continue

            #Extract IPv6 and prefix
            m = re.match(IPV6_ADDR, line)                       
            if m:                
                ip, prefix = m.groups()                
                ipv6.update({ip: {"prefix_length": int(prefix)}})
                interfaces[interface_name] = {"ipv6": ipv6}
                
        return interfaces

    def get_arp_table(self, vrf=""):

        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)  -  ** Not specified in the base driver, so I assumed converted in second here **

        'vrf' of null-string will default to the non-vrf default domain. 

        In all cases the same data structure is returned and no reference to the VRF that was used
        is included in the output.

        Example::

            [
                {
                    'interface' : 'GigabitEthernet 1/0.5',
                    'mac'       : '5C:5E:AB:DA:3C:F0',
                    'ip'        : '172.17.17.1',
                    'age'       :  6596.0
                },
                {
                    'interface' : 'GigabitEthernet 0/0',
                    'mac'       : '5C:5E:AB:DA:3C:FF',
                    'ip'        : '172.17.17.2',
                    'age'       : 6923.0
                }
            ]
        """
        if vrf:
            command = "show arp vrf {}".format(vrf)
        else:
            command = "show arp"

        arp_table = []
        output = self._send_command(command)
        output = output.split("\n")
        output = output[1:] # Skip the first line which is a header      

        for line in output:                          
            arp_data = list(filter(None, line.split('  ')))             
            """for reference, here how our arp_data list will be like this:
            # dynamic: ['172.16.30.1', ' 6a:fc:8c:25:56:53', '01:59:06', ' GigabitEthernet 1/0.5', 'ARPA ']
            # static OS6: ['99.1.1.2', '70:fc:8c:16:99:92', '-']  (no interface and no age)
            # static OS5: ['99.1.1.1', '70:fc:8c:16:99:99', '-', 'Bvi 5', 'ARPA']
            """
            if len(line) == 0 or len(arp_data) < 3:                 
                continue   #skip lines which are not arp data

            #If no timeout/age, set it to -1
            if arp_data[2] == "-": 
                age_sec = -1.0
            else: #convert hh:mm:ss to seconds
                fields = arp_data[2].split(":")
                if len(fields) == 3:
                    try:
                        fields = [float(x) for x in fields]
                        hours, minutes, seconds = fields
                        age_sec = 3600 * hours + 60 * minutes + seconds
                    except ValueError:
                        age_sec = -1.0
                            
            if len(arp_data) < 4:
                 interface = '' #if no interface retrieve, set to empty string
            else:
                interface = arp_data[3]

            entry = {
                "interface": interface.strip(),
                "mac": arp_data[1].strip().upper(),
                "ip": arp_data[0],
                "age": age_sec,
            }
            arp_table.append(entry)

        return arp_table


    def get_environment(self):
        """
        Returns a dictionary where:

            * fans is a dictionary of dictionaries where the key is the location and the values:
                 * status (True/False) - True if it's ok, false if it's broken
            * temperature is a dict of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temp is above the critical threshold
            * power is a dictionary of dictionaries where the key is the PSU id and the values:
                 * status (True/False) - True if it's ok, false if it's broken
                 * capacity (float) - Capacity in W that the power supply can support
                 * output (float) - Watts drawn by the system
            * cpu is a dictionary of dictionaries where the key is the ID and the values
                 * %usage  - average CPU usage on the last minute
                 e.g. {'cpu': {'0': {'%usage': 9.0},'1': {'%usage': 1.0}},
            * memory is a dictionary with:
                 * available_ram (int) - Total amount of RAM installed in the device
                 * used_ram (int) - RAM in use in the device
        """

        environment = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}}

        if self.get_oneos_gen() == "OneOS6":
            cpu_status = self._send_command('show system status | begin "last 72 hours"')
            """
            FYI, you get an output like this on OS6 with this command:
            One2515#show system status | begin "last 72 hours"
            Core    Type     last sec  last min  last hour  last day  last 72 hours
            0     control      6.0 %    14.0 %      6.0 %     4.0 %      2.0 %
            1  forwarding      1.0 %     1.0 %      1.0 %     0.0 %      0.0 %
            One2515#
            """                        
            cpu_status = cpu_status.splitlines()[1:-1]
            for cpu in cpu_status: #for each cores (can be several)
                cpu = cpu.split()                               
                environment["cpu"][cpu[0]] = {}
                #Extract the CPU usage at 1min
                environment["cpu"][cpu[0]]["%usage"] = float(cpu[4])

        return environment