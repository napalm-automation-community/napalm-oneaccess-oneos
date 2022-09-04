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

import re
from typing import Dict

from napalm.base import NetworkDriver
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args




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

"""
Misc notes:
OneOS5 and OneOS6 behavior difference observed:
- on ssh, the output of OneOS6 adds an extra line with the prompt
"""


class OneaccessOneosDriver(NetworkDriver):
    """Napalm driver for Oneaccess_oneos."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Contructor for the class Oneaccess_oneosDriver

        :param hostname: The IP address or hostname of the device you want to connect to
        :param username: The username to use to login to the router
        :param password: The password to use for authentication
        :param timeout: The amount of time to wait for the device to respond to a command,
                        defaults to 60
        (optional)
        :param optional_args:
        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.oneos_gen = None  # OneOs generation OneOS5 or OneOS6
        self.prompt_os6 = None

        if optional_args is None:
            optional_args = {}

        self.netmiko_optional_args = netmiko_args(optional_args)

        self.transport = optional_args.get("transport", "ssh")
        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        # not sure if really needed
        if self.transport == "telnet":
            # Telnet only supports inline_transfer
            self.inline_transfer = True


    def open(self):
        """Open connection to device"""
        device_type = 'oneaccess_oneos'

        if self.transport == "telnet":
            device_type = 'oneaccess_oneos_telnet'

        self.device = self._netmiko_open(device_type, netmiko_optional_args=self.netmiko_optional_args)

        """
        We extract the prompt of the device based on the hostname so that we can remove it from
        the output of the send_command if it appears (only for some commands on os6 with SSH we have an
        extra line returned in the cli output)
        Note we use the parent send_command() here and not _send_command()
        """
        self.prompt_os6 = re.findall('.+[^#]', self.device.send_command('hostname'))[0].replace('\n', '')
        self.prompt_os6 += "#"

        # We find out what is the device generation (OneOS6 or OneOS5) as somme cmds depends of it
        version = self._send_command("show version | include version")
        if "-6." in version:
            self.oneos_gen = "OneOS6"
        elif "-V5." in version:
            self.oneos_gen = "OneOS5"
        else:
            self.oneos_gen = "Unknown"  # OS generation version Unknown

        # disable show output pagination as it can causes issues for some commands in the send_command
        self._send_command("term len 0")

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

            output_lines = output.splitlines()
            if output_lines and output_lines[-1] == self.prompt_os6:
                output = output[:- len(self.prompt_os6)]

            return self._send_command_postprocess(output)
        except RuntimeError as e:  # don't think this exception is correct, to be fixed.
            raise "Error in _send_command() caught: " + str(e)



    @staticmethod
    def _send_command_postprocess(output):
        output = output.strip()

        return output


    def is_alive(self):
        """Returns a flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        return {"is_alive": self.device.is_alive()}


    def cli(self, commands, encoding="text"):
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
            # OneOS error message if the command is not valid
            if ('Syntax error' or 'syntax error') in output:
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output


    def get_config(self, retrieve='all', full=False, sanitized=False):
        """
        Return the configuration of a device.
        Args:
        retrieve(string): Which configuration type you want to populate, default is all of them.
                          Note with OneAccess device there is no "candidate" show run.
                          so the value can only be "all" , "running" or "startup"
        full(bool): NOT IMPLEMENTED, concept not present on OneAccess
        sanitized(bool): NOT IMPLEMENTED (but could be done), Remove secret data. Default: ``False``.
        """
        configs = {'startup': '', 'running': '', 'candidate': ''}

        if retrieve in ('running', 'all'):
            command = ['show running-config']
            output = self._send_command(command)


            if self.oneos_gen == "OneOS6":
                configs['running'] = output
            else:
                # in OS5 there is 3 added info line displayed as per below example that we remove here:
                """
                Building configuration...

                Current configuration:

                """
                configs['running'] = output[52:]

        if retrieve in ('startup', 'all'):
            # method working for both OneOS5 and OneOs6
            command = ['cat /BSA/config/bsaStart.cfg']
            output = self._send_command(command)
            configs['startup'] = output

        return configs


    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given OneAccess.
        Return the uptime in seconds as a float

        credit @mwallraf
        """
        # Initialize to zero
        (days, hours, minutes, seconds) = (0, 0, 0, 0)

        m = re.match(r"\s*(?P<days>[0-9]+)d (?P<hours>[0-9]+)h (?P<minutes>[0-9]+)m (?P<seconds>[0-9]+)s.*", uptime_str)
        if m:
            days = float(m.groupdict()["days"])
            hours = float(m.groupdict()["hours"])
            minutes = float(m.groupdict()["minutes"])
            seconds = float(m.groupdict()["seconds"])

        uptime_sec = (days * DAY_SECONDS) + (hours * HOUR_SECONDS) \
            + (minutes * 60) + seconds

        return uptime_sec

    def get_facts(self):
        """Return a set of facts from the device.
        """
        facts = {
            "vendor": "Ekinops OneAccess",
            "uptime": -1.0,  # converted in seconds, float
            "os_version": None,
            "serial_number": None,
            "model": None,
            "hostname": None,
            "fqdn": None,
            "interface_list": []
        }

        # get output from device, works for both OS5 and OS6
        show_system_status = self._send_command('show system status')
        show_system_hardware = self._send_command('show system hardware')
        show_hostname = self._send_command('hostname')
        show_ip_int_brief = self._send_command('show ip interface brief')

        for line_status in show_system_status.splitlines():
            if "System Information" in line_status:
                c = line_status.split()
                facts["serial_number"] = c[-1]
                continue
            if "Software version" in line_status:
                facts["os_version"] = line_status.split()[-1]
                continue
            if "Sys Up time" in line_status:
                uptime_str = line_status.split(":")[-1]
                facts["uptime"] = self.parse_uptime(uptime_str)
                continue

        for line_hw in show_system_hardware.splitlines():
            m = re.match(r".*Device\s*:\s+(?P<MODEL>\S+).*", line_hw)
            if m:
                facts["model"] = m.groupdict()["MODEL"]
                break

        for line_hostname in show_hostname.splitlines():
            if line_hostname:
                facts["hostname"] = line_hostname.strip()
                break

        for line in show_ip_int_brief.splitlines()[1:-1]:
            interface = line.split("  ")[0]
            if interface != "Null 0":
                facts["interface_list"].append(interface)

        # No local FQDN to retrieve on a OneAccess device
        facts["fqdn"] = ""

        return facts


    def get_interfaces(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the \
        interfaces in the devices. The inner dictionary will containing the following data for \
        each interface:

         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * last_flapped (float in seconds)
         * speed (float in Mbit)
         * MTU (in Bytes)
         * mac_address (string)
        Example::

        FastEthernet 1/0.100': {
                        'description': 'WAN Interface',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': 900.0,
                        'mac_address': '70:FC:8C:1C:96:7A',
                        'mtu': 1500,
                        'speed': 100.0},
        """
        interfaces = {}

        command = "show interfaces"
        show_interface = self._send_command(command)

        interfaces = {}
        for line in show_interface.splitlines():

            # Extract Interface name, is_enabled and is_up status
            interface_regex = r"^(.*?)\sis\s(up|down).+line\s+protocol\s+is\s(up|down)"
            interface_match = re.match(interface_regex, line)
            if interface_match:
                interface_name = interface_match.groups()[0]
                if interface_name == "Null 0":  # internal null interface not relevant
                    continue

                is_enabled = bool("up" in interface_match.groups()[1])
                interfaces[interface_name] = {}
                interfaces[interface_name]["is_enabled"] = is_enabled

                # create all the keys associated to the interface with empty values
                interfaces[interface_name]["description"] = ''
                interfaces[interface_name]["mac_address"] = ''
                interfaces[interface_name]["mtu"] = None
                interfaces[interface_name]["speed"] = -1.0
                interfaces[interface_name]["last_flapped"] = -1.0

                # if interface is not enabled then it's not up either
                if is_enabled is False:
                    interfaces[interface_name]["is_up"] = False
                    continue

                interfaces[interface_name]["is_up"] = bool("up" in interface_match.groups()[2])
                continue

            # we skip all lines associated to the Null interface (until we find another interface name)
            if interface_name == "Null 0":
                continue

            descr_regex = r"^\s+Description:\s+(.+)"
            descr_match = re.search(descr_regex, line)
            if descr_match:
                interfaces[interface_name]["description"] = descr_match.groups()[0].strip()
                continue

            mac_addr_regex = r"^\s+Hardware.+address\s+is\s(.+),"
            mac_addr_match = re.search(mac_addr_regex, line)
            if mac_addr_match:
                interfaces[interface_name]["mac_address"] = mac_addr_match.groups()[0].upper()
                continue


            """
            In OS6, MTU is shown as below in the command output:
              "Encapsulation: Ethernet v2, IPv4 MTU 1500 bytes, IPv6 MTU 1500 bytes"
            whereas for OS5 it will be like below:
              "Encapsulation: Ethernet v2, MTU 1500 bytes"
            """
            mtu_regex = r"(?:IPv4)?\sMTU\s(\d+)\sbytes"
            mtu_match = re.search(mtu_regex, line)
            if mtu_match:
                interfaces[interface_name]["mtu"] = int(mtu_match.groups()[0])
                continue

            """
            We have 3 possible type of output in the cli for the speed, e.g:
              Line speed 1000000 kbps, bandwidth limit 500000 kbps
              Line speed 1000000 kbps
              Line speed unknown, bandwidth limit 50000 kbps
            If a Bandwidth value is set it takes precedence over the line speed
            """
            speed_regex = r"^\s+Line\s+speed\s+(\d+|unknown)(?:.*bandwidth\s+limit\s+(\d+))?"
            speed_match = re.search(speed_regex, line)
            if speed_match:
                if speed_match.groups()[1]:  # if there is a bandwidth defined we use the bw value
                    interfaces[interface_name]["speed"] = float(float(speed_match.groups()[1]) / 1000)
                elif speed_match.groups()[0] != "unknown":
                    interfaces[interface_name]["speed"] = float(float(speed_match.groups()[0]) / 1000)
                continue

            """
            Example of possible uptime/downtime output line:
              Up-time 17d1h48m, status change count 3
              Down-time 00:05:41, status change count 0    !when less than 24h
            """
            last_flapped_regex = r"^\s+(?:Up|Down)-time\s(.+),"
            last_flapped_match = re.search(last_flapped_regex, line)
            if last_flapped_match:
                last_flapped_seconds = 0
                last_flapped = last_flapped_match.groups()[0]
                if 'd' in last_flapped:  # format like DDdHHhMMm
                    days = int(last_flapped.split('d')[0])
                    hours = int(last_flapped.split('d')[1].split('h')[0])
                    minutes = int(last_flapped.split('h')[1][:-1])
                else:  # format like HH:MM:SS
                    t = last_flapped.split(':')
                    days = 0
                    hours = int(t[0])
                    minutes = int(t[1])
                    last_flapped_seconds += int(t[2])

                last_flapped_seconds += days * 86400
                last_flapped_seconds += hours * 3600
                last_flapped_seconds += minutes * 60
                interfaces[interface_name]["last_flapped"] = float(last_flapped_seconds)
                continue

        return interfaces







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

        command = "show interfaces"
        show_ip_interface = self._send_command(command)

        INTERNET_ADDRESS = r"\s+(?:Internet address is|Secondary address is)"
        INTERNET_ADDRESS += r" (?P<ip>{})/(?P<prefix>\d+)".format(IPV4_ADDR_REGEX)

        IPV6_ADDR = r"\s+(?:IPv6 address is)"
        IPV6_ADDR += r" (?P<ip>{})/(?P<prefix>\d+)".format(IPV6_ADDR_REGEX)

        interfaces = {}
        for line in show_ip_interface.splitlines():
            if len(line.strip()) == 0:
                continue
            if line[0] != " ":  # Extract interface name
                ipv4 = {}
                ipv6 = {}
                interface_name = line.split(" is ")[0]
                continue

            # Extract IPv4 and prefix
            m = re.match(INTERNET_ADDRESS, line)
            if m:
                ip, prefix = m.groups()
                ipv4.update({ip: {"prefix_length": int(prefix)}})
                interfaces[interface_name] = {"ipv4": ipv4}
                continue

            # Extract IPv6 and prefix
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
        output = output[1:]  # Skip the first line which is a header

        for line in output:
            arp_data = list(filter(None, line.split('  ')))
            """for reference, here how our arp_data list will be like this:
            # dynamic: ['172.16.30.1', ' 6a:fc:8c:25:56:53', '01:59:06', ' GigabitEthernet 1/0.5', 'ARPA ']
            # static OS6: ['99.1.1.2', '70:fc:8c:16:99:92', '-']  (no interface and no age)
            # static OS5: ['99.1.1.1', '70:fc:8c:16:99:99', '-', 'Bvi 5', 'ARPA']
            """
            if len(line) == 0 or len(arp_data) < 3:
                continue   # skip lines which are not arp data

            # If no timeout/age, set it to -1
            if arp_data[2] == "-":
                age_sec = -1.0
            else:  # convert hh:mm:ss to seconds
                fields = arp_data[2].split(":")
                if len(fields) == 3:
                    try:
                        fields = [float(x) for x in fields]
                        hours, minutes, seconds = fields
                        age_sec = 3600 * hours + 60 * minutes + seconds
                    except ValueError:
                        age_sec = -1.0

            if len(arp_data) < 4:
                interface = ''  # if no interface retrieve, set to empty string
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
                 ** Not Implemented **
            * temperature is a dict of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temp is above the critical threshold
                Data only available for some OneOS6 Hardware
            * power
                 ** Not implemented **
            * cpu is a dictionary of dictionaries where the key is the ID and the values
                 * %usage  - In OS6 the average for the last 1min is retrieve wheread for OS5 is
                             for the last 5min
                 e.g. {'cpu': {'0': {'%usage': 9.0},'1': {'%usage': 1.0}},
            * memory is a dictionary with:
                 * available_ram (int) - Total amount of RAM in Kbytes installed in the device
                 * used_ram (int) - RAM in Kbytes in use in the device
        """

        environment = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}, "memory": {}}

        if self.oneos_gen == "OneOS6":
            # ###### CPU stats ########
            cpu_status = self._send_command('show system cpu')
            """
            FYI, you get an output like this on OS6 with this command:
            One2515#show system cpu

            Core    Type     last sec  last min  last hour  last day  last 72 hours
            0     control      6.0 %    14.0 %      6.0 %     4.0 %      2.0 %
            1  forwarding      1.0 %     1.0 %      1.0 %     0.0 %      0.0 %
            One2515#
            """
            cpu_status = cpu_status.splitlines()[1:]
            for cpu in cpu_status:  # for each cores (can be several)
                cpu = cpu.split()
                if (len(cpu)) < 3:  # exit loop if not a valid cpu line
                    continue

                environment["cpu"][int(cpu[0])] = {}
                # Extract the CPU usage at 1min
                environment["cpu"][int(cpu[0])]["%usage"] = float(cpu[4])

            # ###### RAM Memory ########
            ram_info = self._send_command('show expert system ram-usage | include Mem')
            ram_info = ram_info.split()

            # convert Mb returned value to Kb
            environment["memory"]["available_ram"] = int(ram_info[6]) * 1000
            environment["memory"]["used_ram"] = int(ram_info[2]) * 1000


            # ###### Temperatures ########
            temperatures = self._send_command('show system status | include "alarm level:"')
            """ Output example;
            One2515#show system status | include "alarm level:
              CPU     normal   86.25 C (alarm level: 100.00 C)
              board sensor 1     normal   49.75 C (alarm level:  80.00 C)
            """
            # Only a some hardware have Temperatures values available
            if temperatures:
                temperatures = temperatures.splitlines()
                for temp_line in temperatures:

                    sensor_name = temp_line.strip().split("  ")[0]
                    temp_line = re.findall(r"\d+\.\d. C", temp_line)
                    if not temp_line:  # exit loop if not a valid temp line
                        continue
                    current_temp = float(temp_line[0].replace('C', ''))
                    temp_alert = float(temp_line[1].replace('C', ''))

                    # Let's considere a critical temperature as 10% above the alarm threshold
                    temp_critical = round(temp_alert * 1.1, 2)
                    environment["temperature"][sensor_name] = {}
                    environment["temperature"][sensor_name]["temperature"] = current_temp
                    environment["temperature"][sensor_name]["is_alert"] = current_temp >= temp_alert
                    environment["temperature"][sensor_name]["is_critical"] = current_temp >= temp_critical

        else:  # OneOS5
            # ###### CPU stats ########
            cpu_status = self._send_command('show system status | include Average CPU load')
            """FYI, you get an output like this (only 1 core shown, and for 5min average stats):
            Average CPU load (5 / 60 Minutes)         : 8.2% / 7.5%
            """
            cpu_status = re.findall(r"\d*.\d*%", cpu_status)[0].replace('%', '')
            environment["cpu"][0] = {}
            environment["cpu"][0]["%usage"] = float(cpu_status)

            # ###### RAM Memory ########
            ram_info = self._send_command('show memory | begin Dynamic').splitlines()[1:3]
            environment["memory"]["used_ram"] = int(ram_info[0].split('|')[2].replace(' ', ''))
            environment["memory"]["available_ram"] = int(ram_info[1].split('|')[2].replace(' ', ''))

            # ###### no temperature data implemented for OS5 ########

        return environment


    def get_users(self) -> Dict[str, models.UsersDict]:
        """
        Returns a dictionary with the configured users.
        The keys of the main dictionary represents the username. The values represent the details
        of the user, represented by the following keys:

            * level (int)
            * password (str)
            * sshkeys (list)   ### NOT SUPPORTED

        The level is an integer between 0 and 15, where 0 is the lowest access and 15 represents
        full access to the device.

        In OneAccess the password hashs are generated with a random SALT value.
        The passwords are stored in the file /password as per below example:
        9496e639c29d09b473b601644f94a941$0acd45bc016f1fb4aa12018824ee45cd
        The part before the $ is the password hash and the part after the $ is the salt

        Example::
            {
                'admin': {
                    'level': 15,
                    'password': '9496e639c29d09b473b601644f94a941$0acd45bc016f1fb4aa12018824ee45cd',
                    'sshkeys': []
                }
            }
        """
        users = {}

        cat_password_file = self._send_command('cat /password')

        """
        OneOS6 devices will not have a /passsword file for the two following scenarios:
        1- only the default admin/admin user is present
        2- The users are saved in the running config instead of in the file
        """
        # if no user in /password file then users are in the show run
        if "No such file or directory" in cat_password_file:
            show_username = self._send_command('show run username')
            if "% No entries found." in show_username:  # default admin/admin password
                users['admin'] = {
                    'level': 15,
                    'password': "9496e639c29d09b473b601644f94a941$0acd45bc016f1fb4aa12018824ee45cd",
                    'sshkeys': []
                }
            else:
                for user_line in show_username.splitlines():
                    user_info = user_line.split(' ')
                    if len(user_info) < 5:  # ignore empty lines
                        continue

                    # priviledge level can be set as its int value or by one of the three priviledge name
                    if len(user_info[4]) <= 2:
                        level = int(user_info[4])
                    elif user_info[4] == "administrator":
                        level = 15
                    elif user_info[4] == "manager":
                        level = 7
                    elif user_info[4] == "user":
                        level = 0

                    password = user_info[3]
                    # If the password is encrypted, we add the SALT hash to our data
                    if len(user_info) > 5:
                        password += '$' + user_info[9]

                    users[user_info[1]] = {
                        'level': level,
                        'password': password,
                        'sshkeys': []  # not supported
                    }
        else:  # users to be retrieved from /password file
            for user_line in cat_password_file.splitlines():
                if len(user_line) < 3:  # pass empty lines
                    continue
                user_info = user_line.split(':')
                users[user_info[0]] = {
                    'level': int(user_info[2]),
                    'password': user_info[1],
                    'sshkeys': []  # no supported
                }
        return users