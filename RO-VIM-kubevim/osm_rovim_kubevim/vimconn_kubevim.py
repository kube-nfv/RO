# -*- coding: utf-8 -*-
##
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
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact with: saboor.ahmad@xflowresearch.com
##

"""
TODO:
"""

from copy import deepcopy
import logging
from random import SystemRandom
from uuid import uuid4

from osm_ro_plugin import vimconn
import yaml

from kubevim_vivnfm_client.configuration import Configuration
from kubevim_vivnfm_client.api_client import ApiClient
from kubevim_vivnfm_client.api import vi_vnfm_api
from kubevim_vivnfm_client.exceptions import ApiException, BadRequestException, ConflictException, NotFoundException, UnauthorizedException

from kubevim_vivnfm_client.models.pb_create_compute_flavour_request import PbCreateComputeFlavourRequest

__author__ = "Dmytro Malovanyi"
__date__ = "2024-12-20"

class vimconnector(vimconn.VimConnector):
    def __init__(
        self,
        uuid,
        name,
        tenant_id,
        tenant_name,
        url,
        url_admin=None,
        user=None,
        passwd=None,
        log_level=None,
        config={},
        persistent_info={},
    ):
        super().__init__(
            uuid,
            name,
            tenant_id,
            tenant_name,
            url,
            url_admin,
            user,
            passwd,
            log_level,
            config,
            persistent_info,
        )
        self.logger = logging.getLogger("ro.vim.kubevim")
        self.headers_req = {"content-type": "application/json"}
        self.persistent_info = persistent_info
        self.configuration = Configuration(
                host=url
        )
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))
        
        # Contains flavor_id -> flavor_name dict. 
        # ETSI GS NFV-IFA 006 8.4.2 spec doesn't contains flavor name information
        # but it is required by the RO.
        self.flavors = dict()

        self.images = dict()

    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):
        pass

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

        # if no network is returned and search by name create a new one
        if not nets and filter_dict and filter_dict.get("name"):
            net_id, net = self.new_network(filter_dict.get("name"), "mgmt")
            nets.append(net)

        return nets

    def get_network(self, net_id):
        if net_id not in self.nets:
            raise vimconn.VimConnNotFoundException(
                "network with id {} not found".format(net_id)
            )

        return self.nets[net_id]

    def delete_network(self, net_id, created_items=None):
        if net_id not in self.nets:
            raise vimconn.VimConnNotFoundException(
                "network with id {} not found".format(net_id)
            )

        self.logger.debug(
            "delete network id={}, created_items={}".format(net_id, created_items)
        )
        self.nets.pop(net_id)

        return net_id

    def refresh_nets_status(self, net_list):
        nets = {}

        for net_id in net_list:
            if net_id not in self.nets:
                net = {"status": "DELETED"}
            else:
                net = self.nets[net_id].copy()
                net["vim_info"] = yaml.dump(
                    {"status": "ACTIVE", "name": net["name"]},
                    default_flow_style=True,
                    width=256,
                )

            nets[net_id] = net

        return nets

    # Implemented
    def get_flavor(self, flavor_id, flavor_name):
        self.logger.debug(f"Flavour {flavor_id} get request")
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            query_filter=f'filter=(eq,flavourId/value,{flavor_id})'
            try:
                api_response = api_instance.vi_vnfm_query_compute_flavour(query_compute_flavour_filter_value=query_filter)
                if api_response is None or api_response.flavours is None:
                    raise vimconn.VimConnNotFoundException(f"failed to find flavor with id: {flavor_id}")
                flavors = api_response.flavours
                if len(flavors) == 0:
                    raise vimconn.VimConnNotFoundException(f"failed to find flavor with id: {flavor_id}")
                if len(flavors) > 1:
                    raise vimconn.VimConnUnexpectedResponse(f"more that one flavor found with id: {flavor_id}")
                flavor = flavors[0]
                if flavor.flavour_id is None or flavor.flavour_id.value is None:
                    raise vimconn.VimConnUnexpectedResponse(f"flavor_id can't be empty in flavor query response")
                rsp_flavor_id = flavor.flavour_id.value
                if rsp_flavor_id not in self.flavors:
                    raise vimconn.VimConnUnexpectedResponse(f"flavor with id {rsp_flavor_id} name is missed in local storage. Probably flavor was not created by the RO")
                flavor_name = self.flavors[rsp_flavor_id]
                resp = {
                    "id": rsp_flavor_id,
                    "name": flavor_name
                }
                return resp
            except ApiException as e:
                self._format_exception(e)

    # Implemented
    def new_flavor(self, flavor_data):
        self.logger.debug(f"new flavour creation with data {flavor_data} requested")
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client=api_client)
            body = PbCreateComputeFlavourRequest.from_dict({
                "flavour": {
                    "virtualCpu": {
                        "numVirtualCpu": flavor_data["vcpus"] 
                    },
                    "virtualMemory": {
                        "virtualMemSize": flavor_data["ram"] # In Mbytes
                    },
                    "storageAttributes": [
                        {
                            "typeOfStorage": "volume",
                            "sizeOfStorage": flavor_data.disk
                        }
                    ]
                }
            })
            if body is None:
                raise vimconn.VimConnConnectionException(f"incorrect body format for flavor creation") 
            try:
                api_response = api_instance.vi_vnfm_create_compute_flavour(body)
                flavor_id = api_response.flavour_id
                if flavor_id is None or flavor_id.value is None:
                    raise vimconn.VimConnUnexpectedResponse("flavor_id in flavor creation response can't be empty")
                flavor_id = flavor_id.value
                self.flavos[flavor_id] = flavor_data.name
                return flavor_id
            except ApiException as e:
                self._format_exception(e)

    # Not Implemented
    def delete_flavor(self, flavor_id):
        raise vimconn.VimConnNotImplemented("flavor deletion not implemented yet")

    # Implemented
    def get_flavor_id_from_data(self, flavor_dict):
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            query_filter=f'filter=(eq,virtualMemory/virtualMemSize,{flavor_dict["ram"]});(eq,virtualCpu/numVirtualCpu,{flavor_dict["vcpus"]};(eq,storageAttributes/sizeOfStorage,{flavor_dict["disk"]}'
            try:
                api_response = api_instance.vi_vnfm_query_compute_flavour(query_compute_flavour_filter_value=query_filter)
                if api_response.flavours is None or len(api_response.flavours) == 0:
                    raise vimconn.VimConnNotFoundException(
                        "flavor with ram={}  cpu={} disk={} {} not found".format(
                            flavor_dict["ram"],
                            flavor_dict["vcpus"],
                            flavor_dict["disk"],
                            "and extended" if flavor_dict.get("extended") else "",
                        )
                    )
                flavor = api_response.flavours[0]
                if flavor.flavour_id is None or flavor.flavour_id.value is None:
                    raise vimconn.VimConnUnexpectedResponse(f"flavor_id can't be empty in flavor query response")
                return flavor.flavour_id.value
            except ApiException as e:
                self._format_exception(e)

    # Implemented
    def new_image(self, image_dict):
        new_image_dict = {"name": image_dict["name"]}
        if image_dict.get("description"):
            new_image_dict["description"] = image_dict["description"]
        if image_dict.get("metadata"):
            new_image_dict["metadata"] = yaml.load(
                image_dict["metadata"], Loader=yaml.SafeLoader,
            )
        if image_dict.get("location"):
            new_image_dict["path"] = image_dict["location"]
        else:
            raise vimconn.VimConnException("image_dict should have location for the image")
        try:
            with ApiClient(self.configuration) as api_client:
                api_instance = vi_vnfm_api.ViVnfmApi(api_client=api_client)
                api_response = api_instance.vi_vnfm_query_image(software_image_id_value=new_image_dict["path"])
                if api_response.software_image_information is None:
                    raise vimconn.VimConnException("empty image creation response")
                sw_img_id = api_response.software_image_information.software_image_id.value
                self.images[sw_img_id] = new_image_dict
                return sw_img_id
        except ApiException as e:
            self._format_exception(e)

    def delete_image(self, image_id):
        raise vimconn.VimConnNotImplemented("image deletion not implemented yet")

    def get_image_list(self, filter_dict=None):

    def new_vminstance(
        self,
        name,
        description,
        start,
        image_id,
        flavor_id,
        affinity_group_list,
        net_list,
        cloud_config=None,
        disk_list=None,
        availability_zone_index=None,
        availability_zone_list=None,
    ):
        vm_id = str(uuid4())
        interfaces = []
        self.logger.debug(
            "new vm id={}, name={}, image_id={}, flavor_id={}, net_list={}, cloud_config={}".format(
                vm_id, name, image_id, flavor_id, net_list, cloud_config
            )
        )

        for iface_index, iface in enumerate(net_list):
            iface["vim_id"] = str(iface_index)
            interface = {
                "ip_address": iface.get("ip_address")
                or self.config.get("vm_ip")
                or "192.168.4.2",
                "mac_address": iface.get("mac_address")
                or self.config.get("vm_mac")
                or "00:11:22:33:44:55",
                "vim_interface_id": str(iface_index),
                "vim_net_id": iface["net_id"],
            }

            if iface.get("type") in ("SR-IOV", "PCI-PASSTHROUGH") and self.config.get(
                "sdn-port-mapping"
            ):
                compute_index = SystemRandom().randrange(
                    len(self.config["sdn-port-mapping"])
                )
                port_index = SystemRandom().randrange(
                    len(self.config["sdn-port-mapping"][compute_index]["ports"])
                )
                interface["compute_node"] = self.config["sdn-port-mapping"][
                    compute_index
                ]["compute_node"]
                interface["pci"] = self.config["sdn-port-mapping"][compute_index][
                    "ports"
                ][port_index]["pci"]

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
            self.logger.error(
                "vm create, image_id '{}' not found. Skip".format(image_id)
            )

        if flavor_id not in self.flavors:
            self.logger.error(
                "vm create flavor_id '{}' not found. Skip".format(flavor_id)
            )

        self.vms[vm_id] = vm

        return vm_id, vm

    def get_vminstance(self, vm_id):
        if vm_id not in self.vms:
            raise vimconn.VimConnNotFoundException(
                "vm with id {} not found".format(vm_id)
            )

        return self.vms[vm_id]

    def delete_vminstance(self, vm_id, created_items=None, volumes_to_hold=None):
        if vm_id not in self.vms:
            raise vimconn.VimConnNotFoundException(
                "vm with id {} not found".format(vm_id)
            )

        self.vms.pop(vm_id)
        self.logger.debug(
            "delete vm id={}, created_items={}".format(vm_id, created_items)
        )

        return vm_id

    def refresh_vms_status(self, vm_list):
        vms = {}

        for vm_id in vm_list:
            if vm_id not in self.vms:
                vm = {"status": "DELETED"}
            else:
                vm = deepcopy(self.vms[vm_id])
                vm["vim_info"] = yaml.dump(
                    {"status": "ACTIVE", "name": vm["name"]},
                    default_flow_style=True,
                    width=256,
                )

            vms[vm_id] = vm

        return vms

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        return None

    def inject_user_key(
        self, ip_addr=None, user=None, key=None, ro_key=None, password=None
    ):
        if self.config.get("ssh_key"):
            ro_key = self.config.get("ssh_key")

        return super().inject_user_key(
            ip_addr=ip_addr, user=user, key=key, ro_key=ro_key, password=password
        )

    def _format_exception(self, exception: ApiException):
        """Raises a vimconn exception if the requests to the api is not OK"""
        if isinstance(exception, UnauthorizedException):
            raise vimconn.VimConnAuthException(exception)
        elif isinstance(exception, NotFoundException):
            raise vimconn.VimConnNotFoundException(exception)
        elif isinstance(exception, ConflictException):
            raise vimconn.VimConnConflictException(exception)
        elif isinstance(exception, BadRequestException):
            raise vimconn.VimConnException(exception)
        else:
            raise vimconn.VimConnConnectionException(exception)


