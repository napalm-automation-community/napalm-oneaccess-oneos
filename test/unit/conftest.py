"""Test fixtures."""
from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest
from napalm.base.test.double import BaseTestDouble

from napalm_oneaccess_oneos import oneaccess_oneos


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = oneaccess_oneos.OneaccessOneosDriver
    request.cls.patched_driver = PatchedOneaccessOneosDriver
    request.cls.vendor = 'oneaccess_oneos'

    parent_conftest.set_device_parameters(request)

def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)
    



class PatchedOneaccessOneosDriver(oneaccess_oneos.OneaccessOneosDriver):
    """
    Patched OneaccessOneos Driver which will simulate all the elements requiring I/O
    
    """

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):        
        """Patched OneaccessOneos Driver constructor."""
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        
        self.device = FakeOneaccessOneosDevice()
        print(" CONSTRUCTOR CONSTRUCTOR")
        # self.oneos_gen = "OneOS6"
    
    def select_os_from_testcase(self, test_case):
        if "os6" in test_case: 
            print("\n OS6")
            self.oneos_gen = "OneOS6"
        else:
            print("\n OS5")
            self.oneos_gen = "OneOS5"

    def close(self):
        pass

    def is_alive(self):
        return {"is_alive": True}

    def open(self):
        pass
        
        
        


class FakeOneaccessOneosDevice(BaseTestDouble):
    """OneaccessOneos device test double.
       Here we overwrite the functions needed for the simulation of a Device
       e.g: the send_command() will read the command in a file instead of a real device
    """
   

    def send_command(self, command):
        """Fake run_commands."""
        
        #we create the filename based on the command sent.
        # The spaces and the non-standard characters (like | ) are replaced by underscore _ in the filename
        filename = '{}.txt'.format(self.sanitize_text(command))
        #find_file will look for the file named as per the command in the folder test/unit/mocked_data/
        full_path = self.find_file(filename)

        return self.read_txt_file(full_path)
        