from osm_rovim_kubevim.vimconn_kubevim import vimconnector
from pprint import pprint
import time
conn = vimconnector("1", "test", "t1", "tname", "192.168.33.149:30081")

netid_overlay, items = conn.new_network(
        net_name="ro-test-overlay-1",
        net_type="bridge",
        ip_profile={
            "ip_version": "IPv4",
            "subnet_address": "172.18.5.0/24",
            "gateway_address": "172.18.5.1",
            "dhcp_enabled": True
        }, shared=False)
print(netid_overlay, items)
time.sleep(2)
pprint(conn.get_network(netid_overlay))

print("\n\n")
net_list = conn.get_network_list()
pprint(net_list)

net_ids = [net["id"] for net in net_list]
net_ids.pop()

print("\n\n")
pprint(conn.refresh_nets_status(net_ids))

print(conn.delete_network(net_id=netid_overlay))
