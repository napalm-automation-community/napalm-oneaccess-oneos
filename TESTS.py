
from pprint import pprint
from napalm_oneaccess_oneos import Oneaccess_oneosDriver
# from napalm.base.test.base import TestConfigNetworkDriver
# from napalm import get_network_driver

# driver = get_network_driver('oneaccess_oneos')

import ncclient

def checklan():
    """
    Function that checks the LAN interfaces
    """
    # Use above detail to connect to our device
    with ncclient.manager.connect(
        host='172.16.30.214',
        port=830,
        username='admin',
        password='admin',
        hostkey_verify=False,
    ) as my_session:

        # prepare our RPC with clirpc function. CLI command will only display underlay interface
        showlan = ncclient.clirpc("show ip int brief | include t:lan | nomore")

        # Send the RPC to the device
        try:
            rpc_reply = my_session.dispatch(to_ele(showlan))
        except NCClientError as err:
            print("RPC error: " + str(err))

        lan = parsexmllan(rpc_reply, debug)
    
    return lan



"""
Resources: 
https://napalm.readthedocs.io/en/latest/base.html

"""



def test():    
    router = Oneaccess_oneosDriver('172.16.30.214', 'admin','admin',optional_args = {'transport' : 'telnet'})
    router.open()

    pprint(router.get_facts())
    # pprint(router.get_interfaces_ip())

    # pprint(router.cli(["show system status"]))


if __name__ == "__main__":
    # test()
    # print(checklan())

    router = Oneaccess_oneosDriver('172.16.30.214', 'admin','admin',30, optional_args = {'transport' : 'ssh'})
    try:
        router.open()
    except Exception as e:
        pprint (e)

    pprint(router.get_facts())

    print('\n')
    print('\n')
    #os5
    router2 = Oneaccess_oneosDriver('172.16.30.111', 'admin','admin',30, optional_args = {'transport' : 'ssh'})
    router2.open()
    pprint(router2.get_facts())