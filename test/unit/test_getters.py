"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters
from napalm.base.test.getters import wrap_test_cases 
from napalm.base.test import models
from napalm.base.test import helpers
import pytest
import functools
import json
from napalm.base.test import conftest

from pprint import pprint

"""
Here we import the test functions already present in the base Napalm
"""

# def OneOsDecorator(decorator):
#     def setOneOs(cls):
#         self.device.oneos_gen = "OneOS6"
#     return setOneOs

@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    """    
    TLDR ---------------------------------------------------------------------- 
    for each test-case, copy the original test function from the base 
    and add following line at the beginning of the function:
        self.device.select_os_from_testcase(test_case) 

    (explanation why below)
    ---------------------------------------------------------------------------

    Here to manage the different scenario between OneOS5 and OneOS6 (different output for some functions)
    we have named all the test cases with a name prefixed by "os5" or "os6"
    Then based on the test-case name we will changet he OneOsDriver object variable oneos_gen to 
    OneOS5 or OneOS6 via the method "select_os_from_testcase()" defined in the patchedOneOsDriver
    
    To do this we would ideally directly run the "select_os_from_testcase()" function at the beginning
    of each inherited napalm getter test functions. 
    An elegant way would be to do as per following example:
        # @wrap_test_cases
        # def test_get_config(self, test_case):
        #     self.device.select_os_from_testcase(test_case)  
        #     return super().test_get_config(test_case)
    But here this type of method doesn't work.
    When calling the test method like this the mocked_file data for the result comparaison is not 
    properly loaded (full file path is not properly generated)
    Some data seems to be getting lost in the operation.

    As a result since i am not able to use the inheritance
    the only way I found to make it work is to copy paste the full getters function
    from the base/test/getters napalm module file (very ugly)

    So here all method are just copy paste from the BaseTestGetters with just the adition of
    "select_os_from_testcase()" call at the beginning
    """

    @wrap_test_cases
    def test_get_config(self, test_case):
        """Test get_config method."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        ####   

        get_config = self.device.get_config()
        print(get_config)
        assert isinstance(get_config, dict)       
        assert helpers.test_model(models.config, get_config)
        
        return get_config


    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        """Test get_arp_table."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 

        get_arp_table = self.device.get_arp_table()

        assert len(get_arp_table) > 0        

        for arp_entry in get_arp_table:
            assert helpers.test_model(models.arp_table, arp_entry)

        return get_arp_table

    
    @wrap_test_cases
    def test_get_arp_table_with_vrf(self, test_case):
        """Test get_arp_table."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 

        get_arp_table = self.device.get_arp_table(vrf="TEST")
        assert len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            assert helpers.test_model(models.arp_table, arp_entry)

        return get_arp_table


    @pytest.mark.skip(reason="Not supported")
    def test_get_config_filtered(self, test_case):
        pass

    @pytest.mark.skip(reason="Not supported")
    def test_get_config_sanitized(self, test_case):
        pass


    @wrap_test_cases
    def test_get_environment(self, test_case):
        """Test get_environment."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 

        environment = self.device.get_environment()
        assert len(environment) > 0

        for fan, fan_data in environment["fans"].items():
            assert helpers.test_model(models.fan, fan_data)

        for power, power_data in environment["power"].items():
            assert helpers.test_model(models.power, power_data)

        for temperature, temperature_data in environment["temperature"].items():
            assert helpers.test_model(models.temperature, temperature_data)

        for cpu, cpu_data in environment["cpu"].items():
            assert helpers.test_model(models.cpu, cpu_data)

        assert helpers.test_model(models.memory, environment["memory"])

        return environment

    

    @wrap_test_cases
    def test_get_facts(self, test_case):
        """Test get_facts method."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 

        facts = self.device.get_facts()
        assert helpers.test_model(models.facts, facts)
        return facts

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 
        get_interfaces = self.device.get_interfaces()
        print("ICI GET_INTERFACE_TEST")
        print(get_interfaces)
        print("END")
        print(get_interfaces.items())
        print("******************")
        print(models.interface)
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.items():
            print("####### ICI in loop")
            print(models.interface)
            print("################")
            print(interface_data)
            print("####-------------")
            assert helpers.test_model(models.interface, interface_data)

        return get_interfaces