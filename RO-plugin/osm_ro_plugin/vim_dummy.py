# -*- coding: utf-8 -*-

##
# Copyright 2020 Telefonica Investigacion y Desarrollo, S.A.U.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
##

"""
Implements a Dummy vim plugin.
"""

import yaml
from osm_ro_plugin import vimconn
from uuid import uuid4
from copy import deepcopy

__author__ = "Alfonso Tierno"
__date__ = "2020-04-20"


class VimDummyConnector(vimconn.VimConnector):
    """Dummy vim connector that does nothing
    Provide config with:
        vm_ip: ip address to provide at VM creation. For some tests must be a valid reachable VM
        ssh_key: private ssh key to use for inserting an authorized ssh key
    """
    def __init__(self, uuid, name, tenant_id, tenant_name, url, url_admin=None, user=None, passwd=None, log_level=None,
                 config={}, persistent_info={}):
        super().__init__(uuid, name, tenant_id, tenant_name, url, url_admin, user, passwd, log_level,
                         config, persistent_info)
        self.nets = {
            "mgmt": {
                "id": "mgmt",
                "name": "mgmt",
                "status": "ACTIVE",
                "vim_info": '{status: ACTIVE}'
            }
        }
        self.vms = {}
        self.flavors = {}
        self.tenants = {}
        # preload some images
        self.images = {
            "90681b39-dc09-49b7-ba2e-2c00c6b33b76": {
                "id": "90681b39-dc09-49b7-ba2e-2c00c6b33b76",
                "name": "cirros034",
                "checksum": "ee1eca47dc88f4879d8a229cc70a07c6"
            },
            "83a39656-65db-47dc-af03-b55289115a53": {
                "id": "",
                "name": "cirros040",
                "checksum": "443b7623e27ecf03dc9e01ee93f67afe"
            },
            "208314f2-8eb6-4101-965d-fe2ffbaedf3c": {
                "id": "208314f2-8eb6-4101-965d-fe2ffbaedf3c",
                "name": "ubuntu18.04",
                "checksum": "b6fc7b9b91bca32e989e1edbcdeecb95"
            },
            "c03321f8-4b6e-4045-a309-1b3878bd32c1": {
                "id": "c03321f8-4b6e-4045-a309-1b3878bd32c1",
                "name": "ubuntu16.04",
                "checksum": "8f08442faebad2d4a99fedb22fca11b5"
            },
            "4f6399a2-3554-457e-916e-ada01f8b950b": {
                "id": "4f6399a2-3554-457e-916e-ada01f8b950b",
                "name": "ubuntu1604",
                "checksum": "8f08442faebad2d4a99fedb22fca11b5"
            },
            "59ac0b79-5c7d-4e83-b517-4c6c6a8ac1d3": {
                "id": "59ac0b79-5c7d-4e83-b517-4c6c6a8ac1d3",
                "name": "hackfest3-mgmt",
                "checksum": "acec1e5d5ad7be9be7e6342a16bcf66a"
            },
            "f8818a03-f099-4c18-b1c7-26b1324203c1": {
                "id": "f8818a03-f099-4c18-b1c7-26b1324203c1",
                "name": "hackfest-pktgen",
                "checksum": "f8818a03-f099-4c18-b1c7-26b1324203c1"
            },
        }

    def new_network(self, net_name, net_type, ip_profile=None, shared=False, provider_network_profile=None):
        net_id = str(uuid4())
        net = {
            "id": net_id,
            "name": net_name,
            "net_type": net_type,
            "status": "ACTIVE",
        }
        self.nets[net_id] = net
        return net_id, net

    def get_network_list(self, filter_dict=None):
        nets = []
        for net_id, net in self.nets.items():
            if filter_dict and filter_dict.get("name"):
                if net["name"] != filter_dict.get("name"):
                    continue
            if filter_dict and filter_dict.get("id"):
                if net_id != filter_dict.get("id"):
                    continue
            nets.append(net)
        return nets

    def get_network(self, net_id):
        if net_id not in self.nets:
            raise vimconn.VimConnNotFoundException("network with id {} not found".format(net_id))
        return self.nets[net_id]

    def delete_network(self, net_id, created_items=None):
        if net_id not in self.nets:
            raise vimconn.VimConnNotFoundException("network with id {} not found".format(net_id))
        self.nets.pop(net_id)
        return net_id

    def refresh_nets_status(self, net_list):
        nets = {}
        for net_id in net_list:
            if net_id not in self.nets:
                net = {"status": "DELETED"}
            else:
                net = self.nets[net_id].copy()
                net["vim_info"] = yaml.dump({"status": "ACTIVE", "name": net["name"]},
                                            default_flow_style=True, width=256)
            nets[net_id] = net

        return nets

    def get_flavor(self, flavor_id):
        if flavor_id not in self.flavors:
            raise vimconn.VimConnNotFoundException("flavor with id {} not found".format(flavor_id))
        return self.flavors[flavor_id]

    def new_flavor(self, flavor_data):
        flavor_id = str(uuid4())
        flavor = deepcopy(flavor_data)
        flavor["id"] = flavor_id
        if "name" not in flavor:
            flavor["name"] = flavor_id
        self.flavors[flavor_id] = flavor
        return flavor_id

    def delete_flavor(self, flavor_id):
        if flavor_id not in self.flavors:
            raise vimconn.VimConnNotFoundException("flavor with id {} not found".format(flavor_id))
        return flavor_id
        self.flavors.pop(flavor_id)

    def get_flavor_id_from_data(self, flavor_dict):
        for flavor_id, flavor_data in self.flavors.items():
            for k in ("ram", "vcpus", "disk", "extended"):
                if flavor_data.get(k) != flavor_dict.get(k):
                    break
            else:
                return flavor_id
        raise vimconn.VimConnNotFoundException("flavor with ram={}  cpu={} disk={} {} not found".format(
            flavor_dict["ram"], flavor_dict["vcpus"], flavor_dict["disk"],
            "and extended" if flavor_dict.get("extended") else ""))

    def new_tenant(self, tenant_name, tenant_description):
        tenant_id = str(uuid4())
        tenant = {'name': tenant_name, 'description': tenant_description, 'id': tenant_id}
        self.tenants[tenant_id] = tenant
        return tenant_id

    def delete_tenant(self, tenant_id):
        if tenant_id not in self.tenants:
            raise vimconn.VimConnNotFoundException("tenant with id {} not found".format(tenant_id))
        return tenant_id
        self.tenants.pop(tenant_id)

    def get_tenant_list(self, filter_dict=None):
        tenants = []
        for tenant_id, tenant in self.tenants.items():
            if filter_dict and filter_dict.get("name"):
                if tenant["name"] != filter_dict.get("name"):
                    continue
            if filter_dict and filter_dict.get("id"):
                if tenant_id != filter_dict.get("id"):
                    continue
            tenants.append(tenant)
        return tenants

    def new_image(self, image_dict):
        image_id = str(uuid4())
        image = deepcopy(image_dict)
        image["id"] = image_id
        if "name" not in image:
            image["id"] = image_id
        self.images[image_id] = image
        return image_id

    def delete_image(self, image_id):
        if image_id not in self.images:
            raise vimconn.VimConnNotFoundException("image with id {} not found".format(image_id))
        return image_id
        self.images.pop(image_id)

    def get_image_list(self, filter_dict=None):
        images = []
        for image_id, image in self.images.items():
            if filter_dict and filter_dict.get("name"):
                if image["name"] != filter_dict.get("name"):
                    continue
            if filter_dict and filter_dict.get("checksum"):
                if image["checksum"] != filter_dict.get("checksum"):
                    continue
            if filter_dict and filter_dict.get("id"):
                if image_id != filter_dict.get("id"):
                    continue
            images.append(image)
        return images

    def new_vminstance(self, name, description, start, image_id, flavor_id, net_list, cloud_config=None, disk_list=None,
                       availability_zone_index=None, availability_zone_list=None):
        vm_id = str(uuid4())
        interfaces = []
        for iface_index, iface in enumerate(net_list):
            iface["vim_id"] = str(iface_index)
            interface = {
                "ip_address": self.config.get("vm_ip") or "192.168.4.2",
                "vim_interface_id": str(iface_index),
                "vim_net_id": iface["net_id"],
            }
            interfaces.append(interface)
        vm = {
            "id": vm_id,
            "name": name,
            "status": "ACTIVE",
            "description": description,
            "interfaces": interfaces,
            "image_id": image_id,
            "flavor_id": flavor_id,
        }
        if image_id not in self.images:
            self.logger.error("vm create, image_id '{}' not found. Skip".format(image_id))
        if flavor_id not in self.flavors:
            self.logger.error("vm create flavor_id '{}' not found. Skip".format(flavor_id))
        self.vms[vm_id] = vm
        return vm_id, vm

    def get_vminstance(self, vm_id):
        if vm_id not in self.vms:
            raise vimconn.VimConnNotFoundException("vm with id {} not found".format(vm_id))
        return self.vms[vm_id]

    def delete_vminstance(self, vm_id, created_items=None):
        if vm_id not in self.vms:
            raise vimconn.VimConnNotFoundException("vm with id {} not found".format(vm_id))
        return vm_id
        self.vms.pop(vm_id)

    def refresh_vms_status(self, vm_list):
        vms = {}
        for vm_id in vm_list:
            if vm_id not in self.vms:
                vm = {"status": "DELETED"}
            else:
                vm = deepcopy(self.vms[vm_id])
                vm["vim_info"] = yaml.dump({"status": "ACTIVE", "name": vm["name"]},
                                           default_flow_style=True, width=256)
            vms[vm_id] = vm
        return vms

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        return None

    def inject_user_key(self, ip_addr=None, user=None, key=None, ro_key=None, password=None):
        if self.config.get("ssh_key"):
            ro_key = self.config.get("ssh_key")
        return super().inject_user_key(ip_addr=ip_addr, user=user, key=key, ro_key=ro_key, password=password)
