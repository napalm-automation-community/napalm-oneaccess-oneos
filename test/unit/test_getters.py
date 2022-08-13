"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters
from napalm.base.test.getters import wrap_test_cases 
from napalm.base.test.getters import models
from napalm.base.test.getters import helpers
import pytest

from napalm.base.test import conftest

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict


#we use a cusom Facts dict for OneOs to support custom values additions
oneos_facts_model = TypedDict(
    "facts",
    {
        "os_version": str,
        "os_generation":str,    #custom oneos
        "boot_version":str,     #custom oneos
        "uptime": int,
        "interface_list": list,
        "vendor": str,
        "serial_number": str,
        "model": str,
        "hostname": str,
        "fqdn": str,
    },
)



@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    """    
    ------- Notes OneOS Driver:    
    for each test-case having an OS5 variant, copy the original test function from the base 
    and add following line at the beginning of the function:
        self.device.select_os_from_testcase(test_case) 

    This is very ugly and not flexible if the original base method change.
    A better way would be to insert this select_os_from_testcase to all inherited method 
    automatically but I couldn't find a way to do it.
    (I loose access to some variables if I try to decorate the method here)

    This limitation makes the testing uncompatible with NAPALM < 4.0.0 due to a change
    in the models class and definition
    ---------------------------------------------------------------------------
    """

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
            assert helpers.test_model(models.FanDict, fan_data)

        for power, power_data in environment["power"].items():
            assert helpers.test_model(models.PowerDict, power_data)

        for temperature, temperature_data in environment["temperature"].items():
            assert helpers.test_model(models.TemperatureDict, temperature_data)

        for cpu, cpu_data in environment["cpu"].items():
            assert helpers.test_model(models.CPUDict, cpu_data)

        assert helpers.test_model(models.MemoryDict, environment["memory"])

        return environment

    

    @wrap_test_cases
    def test_get_facts(self, test_case):
        """Test get_facts method."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 

        facts = self.device.get_facts()
        
        #we compare to our custom OneOs Fact model
        assert helpers.test_model(oneos_facts_model, facts)
        return facts



    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""

        ####set the OneOs version matching the test_case name
        self.device.select_os_from_testcase(test_case)  
        #### 
        get_interfaces = self.device.get_interfaces()
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.items():
            assert helpers.test_model(models.InterfaceDict, interface_data)

        return get_interfaces
