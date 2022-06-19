"""setup.py file."""

import uuid

from setuptools import setup, find_packages

__author__ = 'Robin Guillat <robin@guillat.com>'

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

setup(
    name="napalm-oneaccess-oneos",
    version="0.1.0",
    packages=find_packages(),
    author="Robin Guillat",
    author_email="robin@guillat.com",
    description="NAPALM driver for OneAccess devices over Telnet or SSH",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-oneaccess_oneos",
    include_package_data=True,
    install_requires=reqs,
)
   