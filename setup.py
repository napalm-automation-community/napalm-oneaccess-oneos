"""setup.py file."""

# import uuid

from setuptools import setup, find_packages

__author__ = 'Robin Guillat <robin@guillat.com>'

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

setup(
    name="napalm-oneaccess-oneos",
    version="0.1.3",
    packages=find_packages(),
    author="Robin Guillat",
    author_email="robin@guillat.com",
    description="NAPALM driver for Ekinops OneAccess devices over Telnet or SSH",
    long_description="NAPALM driver for Ekinops OneAccess devices" 
            "Connection to the device is done through a SSH or telnet connection using the netmiko librairy.",    
    classifiers=[
        'Topic :: Utilities',
        "Topic :: System :: Networking",
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        "Operating System :: Microsoft :: Windows"
    ],
    url="https://github.com/napalm-automation/napalm-oneaccess_oneos",
    include_package_data=True,
    install_requires=reqs,
)
