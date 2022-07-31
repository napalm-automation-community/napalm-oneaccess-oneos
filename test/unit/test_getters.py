"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters
from napalm.base.test.getters import wrap_test_cases
from napalm.base.test import helpers
from napalm.base.test import models
import pytest
import functools
import json
from napalm.base.test import conftest

"""
Here we just import the test functions already present in the base Napalm
"""

# def wrap_test_cases(func):
#     """Wrap test cases."""
#     func.__dict__["build_test_cases"] = True

#     @functools.wraps(func)
#     def mock_wrapper(cls, test_case):

#         print("\n ### wrap_test_cases")
#         if "os6" in test_case: 
#             print("\n OS6")
#             cls.device.oneos_gen = "OneOS6"
#         else:
#             print("\n OS5")
#             cls.device.oneos_gen = "OneOS5"


#         for patched_attr in cls.device.patched_attrs:
#             attr = getattr(cls.device, patched_attr)
#             attr.current_test = func.__name__
#             attr.current_test_case = test_case

#         try:
#             # This is an ugly, ugly, ugly hack because some python objects don't load
#             # as expected. For example, dicts where integers are strings
#             result = json.loads(json.dumps(func(cls, test_case)))
#         except IOError:
#             if test_case == "no_test_case_found":
#                 pytest.fail("No test case for '{}' found".format(func.__name__))
#             else:
#                 raise
#         except NotImplementedError:
#             pytest.skip("Method not implemented")
#             return

#         # This is an ugly, ugly, ugly hack because some python objects don't load
#         # as expected. For example, dicts where integers are strings
#         try:
#             expected_result = attr.expected_result
#         except IOError as e:
#             raise Exception("{}. Actual result was: {}".format(e, json.dumps(result)))
#         if isinstance(result, list):
#             diff = list_dicts_diff(result, # 
#             expected_result)
#         else:
#             diff = dict_diff(result, expected_result)
#         if diff:
#             print("Resulting JSON object was: {}".format(json.dumps(result)))
#             raise AssertionError(
#                 "Expected result varies on some keys {}".format(json.dumps(diff))
#             )

#         for patched_attr in cls.device.patched_attrs:
#             attr = getattr(cls.device, patched_attr)
#             attr.current_test = ""  # Empty them to avoid side effects
#             attr.current_test_case = ""  # Empty them to avoid side effects

#         return result

#     @functools.wraps(func)
#     def real_wrapper(cls, test_case):
#         try:
#             return func(cls, test_case)
#         except NotImplementedError:
#             pytest.skip("Method not implemented")
#             return

#     if conftest.NAPALM_TEST_MOCK:
#         return mock_wrapper
#     else:
#         return real_wrapper




@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    def set_oneos_test_version(self, test_case):
        if "os6" in test_case: 
            print("\n OS6")
            self.device.oneos_gen = "OneOS6"
        else:
            print("\n OS5")
            self.device.oneos_gen = "OneOS5"


    # @wrap_test_cases
    # def test_get_config(self, test_case):
    #     self.set_oneos_test_version(test_case)
    #     # return BaseTestGetters.test_get_config(self, test_case)
    #     return super().test_get_config(self, test_case)


    @wrap_test_cases
    def test_get_config(self, test_case):
        self.set_oneos_test_version(test_case)
        """Test get_config method."""
        get_config = self.device.get_config()
        assert isinstance(get_config, dict)
        assert helpers.test_model(models.config, get_config)

        return get_config