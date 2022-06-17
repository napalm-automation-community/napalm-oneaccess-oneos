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



class Oneaccess_oneosDriver(NetworkDriver):
    """Napalm driver for Oneaccess_oneos."""


    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor.
        You can Create an object as per below example:
        Oneaccess_oneosDriver('172.16.30.214', 'admin','admin',optional_args = {'transport' : 'telnet'})         
        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

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

        #Don't know the purpose
        # self.profile = [ "oneaccess_oneos_ssh" ]




    def open(self):
        """Implement the NAPALM method open (mandatory)"""
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
        return output.strip()

    def is_alive(self):
        """Returns a flag with the state of the connection.
           Logic copied from cisco ios driver
        """
        null = chr(0)
        if self.device is None:
            return {'is_alive': False}

        if self.transport == "telnet":
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {"is_alive": True}
            except AttributeError:
                return {"is_alive": False}
        else:
        # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {'is_alive': self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {'is_alive': False}
        return {'is_alive': False}


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


    def get_config(self, retrieve='all'):
        """Implementation of get_config for Cisco WLC.
        Returns the running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        configs = {
            'startup': '',
            'running': '',
            'candidate': '',
        }

        if retrieve in ('running', 'all'):
            command = [ 'show running-config' ]
            output = self._send_command(command)
            configs['running'] = output

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


    def get_tacacs_server(self):
        """Return output for 'get tacacs-server'"""

        tacacs_server = {
            "servers": []
        }

        rexSrv = re.compile('^\s*(?P<IP>\S+)\s+(?P<PORT>\S+)\s+(?P<KEY>\S+)(?:\s+(?P<INT>\S+ [0-9]\S*))?(?:\s+(?P<VRF>\S+))?$')
        # get output
        show_tacacs_server = self._send_command("show tacacs-server")

        start_parsing = False
        for l in show_tacacs_server.splitlines():
            l = l.strip()
            if 'Port' in l:
                start_parsing = True
                continue
            if not start_parsing:
                continue
            m = rexSrv.match(l)
            if m:
                tacacs_server["servers"].append({
                    "server": m.groupdict()["IP"],
                    "port": m.groupdict()["PORT"],
                    "key": m.groupdict()["KEY"],
                    "is_encrypted": True,
                    "source_interface": m.groupdict().get("INT", None) or None,
                    "vrf": m.groupdict().get("VRF", None) or None
                })

        return tacacs_server

    def get_facts(self):
        """Return a set of facts from the device.        
        """
        facts = {
            "vendor": "Ekinops OneAccess",
            "uptime": None,  #converted in seconds
            "os_version": None,
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


    def get_netflow(self):
        """
        Get Netflow facts:

        netwflow: {
            "cache_timeout_active": xx,
            "cahce_timeout_inactive": xx,
            "exporters": [
            ],
            monitors: [
            ],
            interfaces: [
            ]
        }

        """
        netflow = {
            "cache_timeout_active": None,
            "cache_timeout_inactive": None,
            "exporters": [],
            "monitors": [],
            "interfaces": []
        }

        cmd_stats = "show flow cache statistics"
        cmd_exporters = "show flow exporter"
        cmd_monitors = "show flow monitor"
        cmd_interfaces = "show flow interface"

        # get output from device
        show_stats = self._send_command(cmd_stats)
        show_exporters = self._send_command(cmd_exporters)
        show_monitors = self._send_command(cmd_monitors)
        show_interfaces = self._send_command(cmd_interfaces)

        for l in show_stats.splitlines():
            if 'Inactive' in l:
                netflow["cache_timeout_inactive"] = l.split()[-2]
                continue
            if 'Active timer' in l:
                netflow["cache_timeout_active"] = l.split()[2]
                continue

        exporter = None
        for l in show_exporters.splitlines():
            if l.startswith("Flow exporter"):
                if exporter:
                    netflow["exporters"].append(exporter)
                exporter = { 
                    "exporter": l.split()[-1].replace(":", ""),
                    "dest": None,
                    "dest_port": None,
                    "src": None
                }
                continue
            if exporter and "destination address" in l:
                c = l.split()[-1].split(":")
                exporter["dest"] = c[0]
                if len(c) > 1:
                    exporter["dest_port"] = c[1]
                continue
            if exporter and "source address" in l:
                exporter["src"] = l.split()[-1]
                continue
        if exporter:
            netflow["exporters"].append(exporter)

        monitor = None
        for l in show_monitors.splitlines():
            if l.startswith("Flow monitor"):
                if monitor:
                    netflow["monitors"].append(monitor)
                monitor = {
                    "monitor": l.split()[-1].replace(":", ""),
                    "exporter": None
                }
                continue
            if monitor and " exporter " in l:
                monitor["exporter"] = l.split()[-1]
                continue
        if monitor:
            netflow["monitors"].append(monitor)

        intf = None
        for l in show_interfaces.splitlines():
            if l and not l.startswith(" ") and l.endswith(":"):
                if intf:
                    netflow["interfaces"].append(intf)
                intf = {
                    "interface": l.replace(":", ""),
                    "monitor-in": None,
                    "monitor-out": None
                }
                continue
            if intf and "flow monitor input" in l:
                intf["monitor-in"] = l.split()[-1]
                continue
            if intf and "flow monitor output" in l:
                intf["monitor-out"] = l.split()[-1]
                continue
        if intf:
            netflow["interfaces"].append(intf)

        return netflow


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
        LINK_LOCAL_ADDRESS = (
            r"\s+IPv6 is enabled, link-local address is (?P<ip>[a-fA-F0-9:]+)"
        )
        GLOBAL_ADDRESS = (
            r"\s+(?P<ip>[a-fA-F0-9:]+), subnet is (?:[a-fA-F0-9:]+)/(?P<prefix>\d+)"
        )

        interfaces = {}
        for line in show_ip_interface.splitlines():
            if len(line.strip()) == 0:
                continue
            if line[0] != " ":
                ipv4 = {}
                interface_name = line.split(" is ")[0]
            m = re.match(INTERNET_ADDRESS, line)
            if m:
                ip, prefix = m.groups()
                ipv4.update({ip: {"prefix_length": int(prefix)}})
                interfaces[interface_name] = {"ipv4": ipv4}

        return interfaces


