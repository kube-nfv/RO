from osm_rovim_kubevim.vimconn_kubevim import vimconnector
from pprint import pprint
conn = vimconnector("1", "test", "t1", "tname", "192.168.33.149:30081")

conn.new_image({
    "name": "test",
    "location": 'https://download.cirros-cloud.net/0.6.0/cirros-0.6.0-x86_64-disk.img',
})
conn.new_image({
    "name": "test2",
    "location": 'https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img',
})

pprint(conn.get_image_list())
