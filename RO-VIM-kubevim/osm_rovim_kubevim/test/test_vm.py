from osm_ro_plugin import vimconn
from osm_rovim_kubevim.vimconn_kubevim import vimconnector
from pprint import pprint
import time
import traceback

conn = vimconnector("1", "test", "t1", "tname", "192.168.33.149:30081")

img_id = conn.new_image({
    "name": "osm-test-vm",
    "location": "https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img"
})
pprint(img_id)

flavor_id = conn.new_flavor({
    "name": "osm-test-flavour",
    "ram": 1024,
    "vcpus": 2,
    "disk": 10,
})
pprint(flavor_id)

net_id, net_items = conn.new_network(
        net_name="osm-net",
        net_type="bridge",
        ip_profile={
            "ip_version": "IPv4",
            "subnet_address": "172.18.10.0/24",
            "gateway_address": "172.18.10.1",
            "dhcp_enabled": True
        }, shared=False)
pprint(net_id)

time.sleep(2)
vm_id, vm_items = conn.new_vminstance(
        name="test",
        description="Test VM Instance",
        start=True,
        image_id=img_id,
        flavor_id=flavor_id,
        affinity_group_list=[],
        net_list=[{
            "name": "osm-test-iface",
            "net_id": net_id,
            "type": "virtual",
            }],
        cloud_config=None,
        disk_list=None,
)
pprint(vm_id)

time.sleep(2)


vm_info = conn.get_vminstance(vm_id)
print(vm_info)

def watch_vm_status(conn, vm_id, poll_interval=5):
    last_status = None

    try:
        while True:
            try:
                vms_status = conn.refresh_vms_status([vm_id])
                vm_info = vms_status.get(vm_id)

                if not vm_info:
                    print(f"No status found for VM {vm_id}")
                    break

                current_status = vm_info.get("status")

                if current_status != last_status:
                    print(f"VM {vm_id} status changed: {last_status} → {current_status}")
                    pprint(vm_info)
                    last_status = current_status

                time.sleep(poll_interval)

            except Exception:
                traceback.print_exc()
                pprint(conn.get_vminstance(vm_id))
                time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\nStopped watching VM status.")

watch_vm_status(conn, vm_id, poll_interval=15)

print("==== Cleanup ====")

conn.delete_vminstance(vm_id)

while True:
    try:
        conn.get_vminstance(vm_id)
        print(f"Vm instance still exists: {vm_id}")
        time.sleep(5)
    except vimconn.VimConnNotFoundException:
        print(f"Vm {vm_id} deleted")
        break

conn.delete_network(net_id)
conn.delete_flavor(flavor_id)
