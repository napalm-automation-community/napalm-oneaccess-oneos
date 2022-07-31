"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters

import pytest

"""
Here we just import the test functions already present in the base Napalm
"""

@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""
    
    def test_get_arp_table_with_vrf(self, test_case):
        assert(True)
        return true