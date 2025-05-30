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
from kubevim_vivnfm_client.models.pb_allocate_network_request import PbAllocateNetworkRequest
from kubevim_vivnfm_client.models.virtual_network_data import VirtualNetworkData
from kubevim_vivnfm_client.models.network_type import NetworkType
from kubevim_vivnfm_client.models.virtual_network import VirtualNetwork
from kubevim_vivnfm_client.models.virtual_network_interface_data import VirtualNetworkInterfaceData
from kubevim_vivnfm_client.models.virtual_network_interface_ipam import VirtualNetworkInterfaceIPAM
from kubevim_vivnfm_client.models.virtual_network_interface_data_type_virtual_nic import VirtualNetworkInterfaceDataTypeVirtualNic
from kubevim_vivnfm_client.models.network_resource_type import NetworkResourceType
from kubevim_vivnfm_client.models.network_subnet_data import NetworkSubnetData
from kubevim_vivnfm_client.models.ip_version import IPVersion
from kubevim_vivnfm_client.models.ip_address import IPAddress
from kubevim_vivnfm_client.models.ip_subnet_cidr import IPSubnetCIDR
from kubevim_vivnfm_client.models.operational_state import OperationalState
from kubevim_vivnfm_client.models.identifier import Identifier
from kubevim_vivnfm_client.models.pb_query_image_request import PbQueryImageRequest
from kubevim_vivnfm_client.models.pb_allocate_compute_request import PbAllocateComputeRequest


__author__ = "Dmytro Malovanyi"
__date__ = "2024-12-20"

def network_from_virtual_network_response(net: VirtualNetwork):
    res = {}
    res["id"] = net.network_resource_id.value
    res["name"] = net.network_resource_name
    state = net.operational_state
    if state == OperationalState.ENABLED:
        res["status"] = "ACTIVE"
    elif state == OperationalState.DISABLED:
        res["status"] = "INACTIVE"
    else:
        res["status"] = "OTHER"
        res["error_msg"] = f"Undefined state {state}"
    net_type = net.network_type
    if net_type == "OVERLAY":
        res["network_type"] = "vxlan"
        # NOTE: kube-vim use ovn as a network soltion, while
        # ovn (might) use vxlan for the overlays it is lacks of the
        # specific "segmentation_id" for the network.
        res["segmentation_id"] = 0
    elif net_type == "UNDERLAY":
        if net.segmentation_id is None or net.segmentation_id == "0":
            res["network_type"] = "flat"
        else:
            res["network_type"] = "vlan"
            res["segmentation_id"] = int(net.segmentation_id)
    res["shared"] = net.is_shared
    res = {**res, **net.to_dict()}
    del res["connectedNetworks"]
    del res["networkResourceId"]
    del res["networkResourceName"]
    del res["networkType"]
    del res["operationalState"]
    return res

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

    # Implemented
    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):
        self.logger.debug(f"Network {net_name} create request")
        req = PbAllocateNetworkRequest(networkResourceType=NetworkResourceType("NETWORK"))

        req.network_resource_name = net_name
        bandwidth = 100 # Mbps
        net = VirtualNetworkData(bandwidth=bandwidth)
        net.is_shared = shared
        subnet = NetworkSubnetData()
        if ip_profile is not None:
            if ip_profile["ip_version"] == "IPv4":
                subnet.ip_version = IPVersion("IPV4")
            elif ip_profile.ip_version == "IPv6":
                subnet.ip_version = IPVersion("IPV6")
            subnet.is_dhcp_enabled = ip_profile["dhcp_enabled"]
            if "gateway_address" in ip_profile:
                subnet.gateway_ip = IPAddress(ip=ip_profile["gateway_address"])
            subnet.cidr = IPSubnetCIDR(cidr=ip_profile["subnet_address"])
            # TODO: Add dhcp pool
        if net_type == "bridge":
            net.network_type = NetworkType("OVERLAY")
        if net_type in ["data", "ptp"]:
            net.network_type = NetworkType("UNDERLAY")
            if provider_network_profile is None:
                raise vimconn.VimConnNotSupportedException(f"provider network should be defined for the {net_type} network type")
            net.provider_network = provider_network_profile["provider_network"]
            net.segmentation_id = provider_network_profile["segmentation-id"]

        net.layer3_attributes = [subnet]
        req.type_network_data = net
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            try:
                api_response = api_instance.vi_vnfm_allocate_virtualised_network_resource(body=req)
                if api_response is None or api_response.network_data is None:
                    raise vimconn.VimConnUnexpectedResponse("received empty response")
                net_id = api_response.network_data.network_resource_id.value
                return net_id, {}
            except ApiException as ex:
                self._format_exception(ex)

    # Implemented
    def get_network_list(self, filter_dict=None):
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            query_filter = ""
            try:
                api_response = api_instance.vi_vnfm_query_virtualised_network_resource("NETWORK", query_filter)
                res = []
                if api_response is None or api_response.query_network_result is None:
                    raise vimconn.VimConnUnexpectedResponse("response can't be empty")
                for net in api_response.query_network_result:
                    res.append(network_from_virtual_network_response(net))
                return res
            except ApiException as ex:
                self._format_exception(ex)

    # Implemented
    def get_network(self, net_id):
        self.logger.debug(f"Network {net_id} get request")
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            query_filter = f'filter=(eq,networkResourceId/value,{net_id})'
            try:
                api_response = api_instance.vi_vnfm_query_virtualised_network_resource( "NETWORK", query_filter)
                if api_response is None or api_response.query_network_result is None:
                    raise vimconn.VimConnUnexpectedResponse("received empty response")
                net_data_lst = api_response.query_network_result
                if len(net_data_lst) == 0:
                    raise vimconn.VimConnNotFoundException(f"network with id {net_id} not found")
                if len(net_data_lst) > 1:
                    raise vimconn.VimConnUnexpectedResponse(f"More that one network found by the id {net_id}")
                net_data = net_data_lst[0]
                return network_from_virtual_network_response(net_data)
            except ApiException as ex:
                self._format_exception(ex)

    # Implemented
    def delete_network(self, net_id, created_items=None):
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            try:
                api_response = api_instance.vi_vnfm_terminate_virtualised_network_resource(net_id)
                if api_response is None or api_response.network_resource_id is None:
                    raise vimconn.VimConnUnexpectedResponse("received empty response")
                return api_response.network_resource_id.value
            except ApiException as ex:
                self._format_exception(ex)

    # Implemented
    def refresh_nets_status(self, net_list):
        """Get the status of the networks
        Params:
            'net_list': a list with the VIM network id to be get the status
        Returns a dictionary with:
            'net_id':         #VIM id of this network
                status:     #Mandatory. Text with one of:
                    #  DELETED (not found at vim)
                    #  VIM_ERROR (Cannot connect to VIM, authentication problems, VIM response error, ...)
                    #  OTHER (Vim reported other status not understood)
                    #  ERROR (VIM indicates an ERROR status)
                    #  ACTIVE, INACTIVE, DOWN (admin down),
                    #  BUILD (on building process)
                error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
                vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
            'net_id2': ...
        """
        res = {}
        try:
            nets = self.get_network_list()
            by_id = {net["id"]: net for net in nets}
            for net_id in net_list:
                if net_id in by_id:
                    net = by_id[net_id]
                    res[net_id] = {
                        "status": net["status"],
                        "vim_info": yaml.safe_dump(net)
                    }
                else:
                    res[net_id] = {
                        "status": "DELETED"
                    }
        except vimconn.VimConnException as ex:
            for net_id in net_list:
                res[net_id] = {
                    "status": "VIM_ERROR",
                    "error_msg": ex.__str__()
                }
        return res

    # Implemented
    def get_flavor(self, flavor_id, flavor_name):
        self.logger.debug(f"Flavour id: {flavor_id}, name: {flavor_name} get request")
        if flavor_name is not None and flavor_id is None:
            for fid, fname in self.flavors.items():
                if fname == flavor_name:
                    flavor_id = fid
                    break
            if flavor_id is None:
                raise vimconn.VimConnConflictException("flavor with name {flavor_name} doesn't exists")
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
                if flavor.flavour_id is None:
                    raise vimconn.VimConnUnexpectedResponse("flavor id can't be empty in response")
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
                            "sizeOfStorage": flavor_data["disk"]
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
                self.flavors[flavor_id] = flavor_data["name"]
                return flavor_id
            except ApiException as e:
                self._format_exception(e)

    # Implemented
    def delete_flavor(self, flavor_id):
        self.logger.debug(f"Flavour {flavor_id} delete request")
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            try:
                api_instance.vi_vnfm_delete_compute_flavour(compute_flavour_id_value=flavor_id)
                return flavor_id
            except ApiException as ex:
                self._format_exception(ex)

    # Implemented
    def get_flavor_id_from_data(self, flavor_dict):
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            query_filter=f'filter=(eq,virtualMemory/virtualMemSize,{flavor_dict["ram"]});(eq,virtualCpu/numVirtualCpu,{flavor_dict["vcpus"]});(eq,storageAttributes/sizeOfStorage,{flavor_dict["disk"]})'
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

                api_response = api_instance.vi_vnfm_query_image2(PbQueryImageRequest(softwareImageId=Identifier(value=new_image_dict["path"])))
                if api_response.software_image_information is None:
                    raise vimconn.VimConnException("empty image creation response")
                sw_img_id = api_response.software_image_information.software_image_id.value
                self.images[sw_img_id] = new_image_dict
                return sw_img_id
        except ApiException as e:
            self._format_exception(e)

    def delete_image(self, image_id):
        # TODO: Implement this
        return image_id

    # Implemented
    def get_image_list(self, filter_dict={}):
        self.logger.debug(f"Image list request: {filter_dict}")
        img_filter = ""
        if filter_dict is not None and len(filter_dict) != 0:
            img_filter = "filter="
        for filter_name, filter_val in filter_dict:
            if filter_name == "id":
                img_filter += f"(eq,flavourId/value,{filter_val});"
            elif filter_name == "name":
                img_id = next((k for k, v in self.images.items() if v == filter_val), None)
                if img_id is None:
                    raise vimconn.VimConnConflictException(f"There is no image with name {filter_val}")
                img_filter += f"(eq,flavourId/value,{img_id});"
            elif filter_name == "location":
                raise vimconn.VimConnNotImplemented("list images by the location is not supported yet")
            elif filter_name == "checksum":
                raise vimconn.VimConnNotImplemented("list images by the checksum is not supported yet")
        # remove trailing ;
        img_filter = img_filter[:-1]
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            try:
                api_response = api_instance.vi_vnfm_query_images(img_filter)
                if api_response == None or api_response.software_images_information == None:
                    raise vimconn.VimConnNotFoundException(f"images with filter {filter_dict} not found")
                resp = []
                for img in api_response.software_images_information:
                    imgId = img.software_image_id.value
                    if imgId not in self.images:
                        continue
                    img_dict = img.to_dict()
                    img_dict["id"] = imgId
                    img_dict["name"] = self.images[imgId]["name"]
                    img_dict["checksum"] = "none"
                    location_key = "image.kubevim.kubenfv.io/source-url"
                    if img.metadata and img.metadata.fields and location_key in img.metadata.fields:
                        img_dict["location"] = img.metadata.fields[location_key]
                    else:
                        img_dict["location"] = "None"
                    resp.append(img_dict)
                return resp
            except ApiException as e:
                self._format_exception(e)

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
        self.logger.debug(f"Compute create request: {locals()}")
        req = PbAllocateComputeRequest(
                computeFlavourId=Identifier(value=flavor_id),
                computeName=name,
                vcImageId=Identifier(value=image_id),
            )
        req.meta_data = {
            "kubernetes.io/description": description,
        }
        for net in net_list:
            nic_type = None
            if net["type"] == "virtual":
                nic_type = VirtualNetworkInterfaceDataTypeVirtualNic.BRIDGE
            elif net["type"] == "PCI_PASSTHROUGH" or net["type"] == "PF":
                nic_type = VirtualNetworkInterfaceDataTypeVirtualNic.PATHTHROUGH
            # TODO: Differentiate shared and not shared VF's
            elif net["type"] == "SR-IOV" or net["type"] == "VF" or net["type"] == "VFnotShared":
                nic_type = VirtualNetworkInterfaceDataTypeVirtualNic.SRIOV
            else:
                raise vimconn.VimConnNotSupportedException(f'unknown network type: {net["type"]}')
            net_data = VirtualNetworkInterfaceData(typeVirtualNic=nic_type)
            if net["bw"]:
                net_data.bandwidth = int(net["bw"]) * 1000
            if "net_id" in net:
                net_data.network_id = Identifier(value=net["net_id"])

        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            try:
               vm_data =  api_instance.vi_vnfm_allocate_virtualised_compute_resource(body=req)
            except ApiException as ex:
                self._format_exception(ex)

    def get_vminstance(self, vm_id):
        with ApiClient(self.configuration) as api_client:
            api_instance = vi_vnfm_api.ViVnfmApi(api_client)
            try:
                ...
            except ApiException as ex:
                self._format_exception(ex)

    def delete_vminstance(self, vm_id, created_items=None, volumes_to_hold=None):
        return None

    def refresh_vms_status(self, vm_list):
        return None

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

