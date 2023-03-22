#######################################################################################
# Copyright ETSI Contributors and Others.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################
# The variables that are used in the monitoring tests
db_vim_collection = "vim_accounts"
vim_type = "openstack"
ro_task_collection = "ro_tasks"
plugin_name = "rovim_openstack"
mac1_addr = "d0:94:66:ed:fc:e2"
mac2_addr = "fa:16:3e:0b:84:08"
ip1_addr = "192.168.22.13"
vm1_id = "ebd39f37-e607-4bce-9f10-ea4c5635f726"
vm2_id = "f4404a39-51d5-4cf8-9058-95001e69fdb3"
vim1_id = target_id = "55b2219a-7bb9-4644-9612-980dada84e83"
vim2_id = "77b2219a-8bb9-9644-9612-680dada84e83"
vim3_id = "33b2219a-7bb9-4644-9612-280dada84e83"
vim4_id = "f239ed93-756b-408e-89f8-fcbf47a9d8f7"
file_name = "/app/osm_ro/certs/55b2219a-7bb9-4644-9612-980dada84e83:23242"
net1_id = "21ea5d92-24f1-40ab-8d28-83230e277a49"
vnfr_id = "35c034cc-8c5b-48c4-bfa2-17a71577ef19"
db_vim_cacert = "/app/osm_ro/certs/55b2219a-7bb9-4644-9612-980dada84e83:23242/ca_cert"
vdur_path = "vdur.0"
vims_to_monitor = []
vim_info_path = "vdur.0.vim_info.vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7"
server_other_info = {
    "admin_state_up": "true",
    "binding:host_id": "nfvisrv11",
    "binding:profile": {},
    "binding:vif_type": "ovs",
    "binding:vnic_type": "normal",
    "created_at": "2023-02-22T05:35:46Z",
}
deleted_externally = {
    "vim_status": "DELETED",
    "vim_message": "Deleted externally",
    "vim_id": None,
    "vim_name": None,
    "interfaces": None,
}
interface_with_binding = {
    "binding:profile": {
        "physical_network": "physnet1",
        "pci_slot": "0000:86:17.4",
    },
    "binding:vif_details": {
        "vlan": 400,
    },
}
target_record = "vnfrs:35c034cc-8c5b-48c4-bfa2-17a71577ef19:vdur.0.vim_info.vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7"
target_record2 = "vnfrs:41e16909-a519-4897-b481-f386e5022425:vdur.0.vim_info.vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7"
serialized_server_info = "{admin_state_up: true, binding:host_id: nfvisrv11, binding:profile: {}, binding:vif_type: ovs, binding:vnic_type: normal, created_at: 2023-02-22T05:35:46Z}"
serialized_interface_info = "{fixed_ips: [{ip_address: 192.168.22.13}], mac_address: 'd0:94:66:ed:fc:e2', network_id: 21ea5d92-24f1-40ab-8d28-83230e277a49}"
config = {
    "period": {
        "refresh_active": 60,
        "refresh_build": 15,
        "refresh_image": "3600 * 10",
        "refresh_error": 600,
        "queue_size": 100,
    },
    "database": {"driver": "mongo", "uri": "mongodb://mongo:27017", "name": "osm"},
    "storage": {"driver": "None", "path": "/app/storage", "loglevel": "DEBUG"},
}
old_interface = {
    "vim_info": "{admin_state_up: true, allowed_address_pairs: [], 'binding:host_id': nfvisrv12, 'binding:profile': {}, 'binding:vif_details': {bridge_name: br-int, connectivity: l2, datapath_type: system, ovs_hybrid_plug: true, port_filter: true}, 'binding:vif_type': ovs, 'binding:vnic_type': normal,\n  created_at: '2023-02-18T21:28:52Z', description: '', device_id: ebd39f37-e607-4bce-9f10-ea4c5635f726, device_owner: 'compute:nova', extra_dhcp_opts: [], fixed_ips: [{ip_address: 192.168.251.15, subnet_id: bf950890-8d50-40cc-81ba-afa35db69a19}], id: 4d081f50-e13a-4306-a67e-1edb28d76013,\n  mac_address: 'fa:16:3e:85:6c:02', name: vdu-eth0, network_id: 327f5e8e-a383-47c9-80a3-ed45b71d24ca, port_security_enabled: true, project_id: 71c7971a7cab4b72bd5c10dbe6617f1e, revision_number: 4, security_groups: [1de4b2c2-e4be-4e91-985c-d887e2715949], status: ACTIVE,\n  tags: [], tenant_id: 71c7971a7cab4b72bd5c10dbe6617f1e, updated_at: '2023-02-18T21:28:59Z'}\n",
    "mac_address": "fa:16:3e:85:6c:02",
    "vim_net_id": "327f5e8e-a383-47c9-80a3-ed45b71d24ca",
    "vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013",
    "compute_node": "nfvisrv12",
    "pci": None,
    "vlan": None,
    "ip_address": "192.168.251.15",
    "mgmt_vnf_interface": True,
    "mgmt_vdu_interface": True,
}
old_interface2 = {
    "mgmt_vdu_interface": True,
    "mgmt_vnf_interface": True,
}
interface_info2 = {
    "fixed_ips": [{"ip_address": ip1_addr}],
    "mac_address": mac2_addr,
    "network_id": net1_id,
}
sample_vim_info = {
    "interfaces": [
        old_interface,
    ],
    "interfaces_backup": [
        {
            "vim_info": "{admin_state_up: true, allowed_address_pairs: [], 'binding:host_id': nfvisrv12, 'binding:profile': {}, 'binding:vif_details': {bridge_name: br-int, connectivity: l2, datapath_type: system, ovs_hybrid_plug: true, port_filter: true}, 'binding:vif_type': ovs, 'binding:vnic_type': normal,\n  created_at: '2023-02-18T21:28:52Z', description: '', device_id: ebd39f37-e607-4bce-9f10-ea4c5635f726, device_owner: 'compute:nova', extra_dhcp_opts: [], fixed_ips: [{ip_address: 192.168.251.15, subnet_id: bf950890-8d50-40cc-81ba-afa35db69a19}], id: 4d081f50-e13a-4306-a67e-1edb28d76013,\n  mac_address: 'fa:16:3e:85:6c:02', name: vdu-eth0, network_id: 327f5e8e-a383-47c9-80a3-ed45b71d24ca, port_security_enabled: true, project_id: 71c7971a7cab4b72bd5c10dbe6617f1e, revision_number: 4, security_groups: [1de4b2c2-e4be-4e91-985c-d887e2715949], status: ACTIVE,\n  tags: [], tenant_id: 71c7971a7cab4b72bd5c10dbe6617f1e, updated_at: '2023-02-18T21:28:59Z'}\n",
            "mac_address": "fa:16:3e:85:6c:02",
            "vim_net_id": "327f5e8e-a383-47c9-80a3-ed45b71d24ca",
            "vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013",
            "compute_node": "nfvisrv12",
            "pci": None,
            "vlan": None,
            "ip_address": "192.168.251.15",
            "mgmt_vnf_interface": True,
            "mgmt_vdu_interface": True,
        }
    ],
    "vim_details": "{'OS-DCF:diskConfig': MANUAL, 'OS-EXT-AZ:availability_zone': nova, 'OS-EXT-SRV-ATTR:host': nfvisrv12, 'OS-EXT-SRV-ATTR:hypervisor_hostname': nfvisrv12, 'OS-EXT-SRV-ATTR:instance_name': instance-000400a6, 'OS-EXT-STS:power_state': 1, 'OS-EXT-STS:task_state': null,\n  'OS-EXT-STS:vm_state': active, 'OS-SRV-USG:launched_at': '2023-02-18T21:28:59.000000', 'OS-SRV-USG:terminated_at': null, accessIPv4: '', accessIPv6: '', addresses: {mgmtnet: [{'OS-EXT-IPS-MAC:mac_addr': 'fa:16:3e:85:6c:02', 'OS-EXT-IPS:type': fixed, addr: 192.168.251.15,\n        version: 4}]}, config_drive: '', created: '2023-02-18T21:28:54Z', flavor: {id: 367fc1eb-bd22-40f8-a519-ed2fb4e5976b, links: [{href: 'http://172.21.247.1:8774/flavors/367fc1eb-bd22-40f8-a519-ed2fb4e5976b', rel: bookmark}]}, hostId: e72dec159231b67a5d4fa37fae67e97051ce9aee003516dadb6a25e4,\n  id: ebd39f37-e607-4bce-9f10-ea4c5635f726, image: {id: 919fc71a-6acd-4ee3-8123-739a9abbc2e7, links: [{href: 'http://172.21.247.1:8774/images/919fc71a-6acd-4ee3-8123-739a9abbc2e7', rel: bookmark}]}, key_name: null, links: [{href: 'http://172.21.247.1:8774/v2.1/servers/ebd39f37-e607-4bce-9f10-ea4c5635f726',\n      rel: self}, {href: 'http://172.21.247.1:8774/servers/ebd39f37-e607-4bce-9f10-ea4c5635f726', rel: bookmark}], metadata: {}, name: test7-vnf-hackfest_basic-VM-000000, 'os-extended-volumes:volumes_attached': [], progress: 0, security_groups: [{name: default}],\n  status: ACTIVE, tenant_id: 71c7971a7cab4b72bd5c10dbe6617f1e, updated: '2023-02-19T21:09:09Z', user_id: f043c84f940b4fc8a01a98714ea97c80}\n",
    "vim_id": "ebd39f37-e607-4bce-9f10-ea4c5635f726",
    "vim_message": "Interface 4d081f50-e13a-4306-a67e-1edb28d76013 status: DOWN",
    "vim_status": "ACTIVE",
    "vim_name": "test7-vnf-hackfest_basic-VM-000000",
}
sample_vnfr = {
    "_id": "35c034cc-8c5b-48c4-bfa2-17a71577ef19",
    "id": "35c034cc-8c5b-48c4-bfa2-17a71577ef19",
    "nsr-id-ref": "ee46620f-cba3-4245-b8be-183ff483bb7e",
    "created-time": 1676755692.20987,
    "vnfd-ref": "hackfest_basic-vnf",
    "vnfd-id": "f1401992-83f4-43cc-ac37-1ad7c1370d03",
    "vim-account-id": vim4_id,
    "vca-id": None,
    "vdur": [
        {
            "_id": "faa21fc1-7f27-4a95-93dd-87535ce6b59c",
            "additionalParams": {
                "OSM": {
                    "count_index": 0,
                    "member_vnf_index": "vnf",
                    "ns_id": "ee46620f-cba3-4245-b8be-183ff483bb7e",
                    "vdu": {
                        "hackfest_basic-VM-0": {
                            "count_index": 0,
                            "interfaces": {"vdu-eth0": {"name": "vdu-eth0"}},
                            "vdu_id": "hackfest_basic-VM",
                        }
                    },
                    "vdu_id": "hackfest_basic-VM",
                    "vim_account_id": vim4_id,
                    "vnf_id": "35c034cc-8c5b-48c4-bfa2-17a71577ef19",
                    "vnfd_id": "f1401992-83f4-43cc-ac37-1ad7c1370d03",
                    "vnfd_ref": "hackfest_basic-vnf",
                }
            },
            "affinity-or-anti-affinity-group-id": [],
            "count-index": 0,
            "id": "faa21fc1-7f27-4a95-93dd-87535ce6b59c",
            "interfaces": [
                {
                    "external-connection-point-ref": "vnf-cp0-ext",
                    "internal-connection-point-ref": "vdu-eth0-int",
                    "mgmt-interface": True,
                    "mgmt-vnf": True,
                    "name": "vdu-eth0",
                    "ns-vld-id": "mgmtnet",
                    "type": "PARAVIRT",
                    "compute_node": "nfvisrv12",
                    "ip-address": "192.168.251.15",
                    "mac-address": "fa:16:3e:85:6c:02",
                    "pci": None,
                    "vlan": None,
                }
            ],
            "internal-connection-point": [
                {
                    "connection-point-id": "vdu-eth0-int",
                    "id": "vdu-eth0-int",
                    "name": "vdu-eth0-int",
                }
            ],
            "ip-address": "192.168.251.15",
            "ns-flavor-id": "0",
            "ns-image-id": "0",
            "vdu-id-ref": "hackfest_basic-VM",
            "vdu-name": "hackfest_basic-VM",
            "vim_info": {"vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7": sample_vim_info},
            "virtual-storages": [
                {"id": "hackfest_basic-VM-storage", "size-of-storage": "10"}
            ],
            "status": "ACTIVE",
            "vim-id": "ebd39f37-e607-4bce-9f10-ea4c5635f726",
            "name": "test7-vnf-hackfest_basic-VM-000000",
        }
    ],
    "connection-point": [
        {
            "name": "vnf-cp0-ext",
            "connection-point-id": "vdu-eth0-int",
            "connection-point-vdu-id": "hackfest_basic-VM",
            "id": "vnf-cp0-ext",
        }
    ],
    "ip-address": "192.168.251.15",
    "revision": 1,
    "_admin": {
        "created": 1676755692.21059,
        "modified": 1676755692.21059,
        "projects_read": ["9a61dad6cbc744879344e5b84d842578"],
        "projects_write": ["9a61dad6cbc744879344e5b84d842578"],
        "nsState": "INSTANTIATED",
    },
}
vims = [
    {
        "_id": vim1_id,
        "name": "openstackETSI1",
        "vim_type": "openstack",
    },
    {
        "_id": vim2_id,
        "name": "openstackETSI2",
        "vim_type": "openstack",
    },
]
sample_vim = {
    "_id": vim1_id,
    "name": "openstackETSI1",
    "vim_type": "openstack",
    "description": None,
    "vim_url": "http://172.21.223.1:5000/v3",
    "vim_user": "myuser",
    "vim_password": "mypassword",
    "vim_tenant_name": "mytenant",
    "_admin": {
        "created": 1675758291.0110583,
        "modified": 1675758291.0110583,
        "operationalState": "ENABLED",
        "current_operation": None,
        "detailed-status": "",
    },
    "schema_version": "1.11",
    "admin": {"current_operation": 0},
}
ro_task1 = {
    "_id": "6659675b-b6a4-4c0c-ad40-47dae476a961:3",
    "target_id": f"vim:{vim1_id}",
    "vim_info": {
        "created": True,
        "created_items": {"port:4d081f50-e13a-4306-a67e-1edb28d76013": True},
        "vim_id": vm1_id,
        "vim_name": "test7-vnf-hackfest_basic-VM-0",
        "vim_status": "ACTIVE",
        "refresh_at": -1,
        "interfaces": [
            {
                "mac_address": "fa:16:3e:85:6c:02",
                "vim_net_id": "327f5e8e-a383-47c9-80a3-ed45b71d24ca",
                "vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013",
                "compute_node": "nfvisrv12",
                "pci": None,
                "vlan": None,
                "ip_address": "192.168.251.15",
                "mgmt_vnf_interface": True,
                "mgmt_vdu_interface": True,
            }
        ],
        "interfaces_vim_ids": ["4d081f50-e13a-4306-a67e-1edb28d76013"],
    },
    "modified_at": 1676755752.49715,
    "created_at": 1676755693.91547,
    "to_check_at": -1,
    "tasks": [
        {
            "action_id": "6659675b-b6a4-4c0c-ad40-47dae476a961",
            "nsr_id": "ee46620f-cba3-4245-b8be-183ff483bb7e",
            "task_id": "6659675b-b6a4-4c0c-ad40-47dae476a961:3",
            "status": "DONE",
            "action": "CREATE",
            "item": "vdu",
            "target_record": target_record,
            "mgmt_vnf_interface": 0,
        }
    ],
}
ro_task2 = {
    "_id": "7b05fd30-f128-4486-a1ba-56fcf7387967:3",
    "target_id": f"vim:{vim2_id}",
    "vim_info": {
        "created": True,
        "created_items": {
            "port:4d2faa64-3f10-42ec-a5db-0291600d0692": True,
        },
        "vim_id": vm2_id,
        "vim_name": "test7-vnf-hackfest_basic-VM-0",
        "vim_status": "ACTIVE",
        "refresh_at": -1,
        "interfaces": [
            {
                "mac_address": "fa:16:3e:2c:2d:21",
                "vim_net_id": "327f5e8e-a383-47c9-80a3-ed45b71d24ca",
                "vim_interface_id": "4d2faa64-3f10-42ec-a5db-0291600d0692",
                "compute_node": "nfvisrv12",
                "pci": None,
                "vlan": None,
                "ip_address": "192.168.251.197",
                "mgmt_vnf_interface": True,
                "mgmt_vdu_interface": True,
            }
        ],
        "interfaces_vim_ids": ["4d2faa64-3f10-42ec-a5db-0291600d0692"],
    },
    "modified_at": 1676839542.4801,
    "created_at": 1676839494.78525,
    "to_check_at": -1,
    "tasks": [
        {
            "action_id": "7b05fd30-f128-4486-a1ba-56fcf7387967",
            "nsr_id": "ddf8c820-4cfa-47fb-8de3-e0afbe039efb",
            "task_id": "7b05fd30-f128-4486-a1ba-56fcf7387967:3",
            "status": "FAILED",
            "action": "CREATE",
            "item": "vdu",
            "target_record": "vnfrs:41e16909-a519-4897-b481-f386e5022425:vdur.0.vim_info.vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7",
            "mgmt_vnf_interface": 0,
        }
    ],
}
wrong_ro_task = {
    "_id": "6659675b-b6a4-4c0c-ad40-47dae476a961:3",
    "target_id": "vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7",
}
port1 = {
    "id": "4d081f50-e13a-4306-a67e-1edb28d76013",
    "network_id": net1_id,
    "tenant_id": "34a71bb7d82f4ec691d8cc11045ae83e",
    "mac_address": mac2_addr,
    "admin_state_up": True,
    "status": "ACTIVE",
    "device_id": vm1_id,
    "device_owner": "compute:nova",
    "fixed_ips": [],
}
port2 = {
    "id": "5d081f50-e13a-4306-a67e-1edb28d76013",
    "network_id": net1_id,
    "tenant_id": "34a71bb7d82f4ec691d8cc11045ae83e",
    "mac_address": mac2_addr,
    "admin_state_up": True,
    "status": "ACTIVE",
    "device_id": vm1_id,
    "device_owner": "compute:nova",
    "fixed_ips": [],
}
