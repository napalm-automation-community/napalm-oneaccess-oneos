"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters


import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""


    # def test_get_facts(self, test_case):
    #     """Test get_facts method."""
    #     print(os.getenv("NAPALM_TEST_MOCK"))
        # facts = self.device.get_facts()
        # assert helpers.test_model(models.facts, facts)
        # assert True
        # return facts

    def test_get_interfaces_ip(self, test_case):
        """Test get_interfaces_ip."""
        get_interfaces_ip = self.device.get_interfaces_ip()
        assert len(get_interfaces_ip) > 0

        for interface, interface_details in get_interfaces_ip.items():
            ipv4 = interface_details.get("ipv4", {})
            ipv6 = interface_details.get("ipv6", {})
            for ip, ip_details in ipv4.items():
                assert helpers.test_model(models.interfaces_ip, ip_details)
            for ip, ip_details in ipv6.items():
                assert helpers.test_model(models.interfaces_ip, ip_details)
    
        return get_interfaces_ip
        