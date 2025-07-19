from osm_rovim_kubevim.vimconn_kubevim import vimconnector
from pprint import pprint
conn = vimconnector("1", "test", "t1", "tname", "192.168.33.149:30081")

flavor_id = conn.new_flavor({
    "name": "test",
    "ram": 100,
    "vcpus": 4,
    "disk": 10,
})
print(flavor_id)

pprint(conn.get_flavor(flavor_id=flavor_id, flavor_name=None))
pprint(conn.get_flavor(flavor_id=None, flavor_name="test"))

pprint(conn.get_flavor_id_from_data({
    "ram": 100,
    "vcpus": 4,
    "disk": 10,
}))

flavor_id = conn.delete_flavor(flavor_id)
print(flavor_id)
