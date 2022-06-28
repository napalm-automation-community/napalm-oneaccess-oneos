"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters


import pytest



"""
Tests component KO at the moment, 
couldn't understand how the test-framework is to be used.

When running pytest we get a netmiko error. It seems the test tries to connect to
a device at 127.0.0.1.

"""

@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""
    NAPALM_TEST_MOCK = 1
        
    def test_is_alive(self, test_case):
        """Test is_alive method."""
        alive = self.device.is_alive()
        assert helpers.test_model(models.alive, alive)
        return alive


    # def test_get_facts(self, test_case):
    #     """Test get_facts method."""
    #     print(os.getenv("NAPALM_TEST_MOCK"))
    #     facts = self.device.get_facts()
    #     assert helpers.test_model(models.facts, facts)
        # assert True
        # return facts

    # def test_get_interfaces_ip(self, test_case):
    #     """Test get_interfaces_ip."""
    #     assert True
        # get_interfaces_ip = self.device.get_interfaces_ip()
        # assert len(get_interfaces_ip) > 0

        # for interface, interface_details in get_interfaces_ip.items():
        #     ipv4 = interface_details.get("ipv4", {})
        #     ipv6 = interface_details.get("ipv6", {})
        #     for ip, ip_details in ipv4.items():
        #         assert helpers.test_model(models.interfaces_ip, ip_details)
        #     for ip, ip_details in ipv6.items():
        #         assert helpers.test_model(models.interfaces_ip, ip_details)
    
        # return get_interfaces_ip
        