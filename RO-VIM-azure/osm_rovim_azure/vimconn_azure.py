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
##

import base64
import logging
from os import getenv
import re

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import DiskCreateOption
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.profiles import ProfileDefinition
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from msrest.exceptions import AuthenticationError
from msrestazure.azure_exceptions import CloudError
import msrestazure.tools as azure_tools
import netaddr
from osm_ro_plugin import vimconn
from requests.exceptions import ConnectionError

__author__ = "Isabel Lloret, Sergio Gonzalez, Alfonso Tierno, Gerardo Garcia"
__date__ = "$18-apr-2019 23:59:59$"


if getenv("OSMRO_PDB_DEBUG"):
    import sys

    print(sys.path)
    import pdb

    pdb.set_trace()


def find_in_list(the_list, condition_lambda):
    for item in the_list:
        if condition_lambda(item):
            return item
    else:
        return None


class vimconnector(vimconn.VimConnector):

    # Translate azure provisioning state to OSM provision state
    # The first three ones are the transitional status once a user initiated action has been requested
    # Once the operation is complete, it will transition into the states Succeeded or Failed
    # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/states-lifecycle
    provision_state2osm = {
        "Creating": "BUILD",
        "Updating": "BUILD",
        "Deleting": "INACTIVE",
        "Succeeded": "ACTIVE",
        "Failed": "ERROR",
    }

    # Translate azure power state to OSM provision state
    power_state2osm = {
        "starting": "INACTIVE",
        "running": "ACTIVE",
        "stopping": "INACTIVE",
        "stopped": "INACTIVE",
        "unknown": "OTHER",
        "deallocated": "BUILD",
        "deallocating": "BUILD",
    }

    # TODO - review availability zones
    AZURE_ZONES = ["1", "2", "3"]

    AZURE_COMPUTE_MGMT_CLIENT_API_VERSION = "2021-03-01"
    AZURE_COMPUTE_MGMT_PROFILE_TAG = "azure.mgmt.compute.ComputeManagementClient"
    AZURE_COMPUTE_MGMT_PROFILE = ProfileDefinition(
        {
            AZURE_COMPUTE_MGMT_PROFILE_TAG: {
                None: AZURE_COMPUTE_MGMT_CLIENT_API_VERSION,
                "availability_sets": "2020-12-01",
                "dedicated_host_groups": "2020-12-01",
                "dedicated_hosts": "2020-12-01",
                "disk_accesses": "2020-12-01",
                "disk_encryption_sets": "2020-12-01",
                "disk_restore_point": "2020-12-01",
                "disks": "2020-12-01",
                "galleries": "2020-09-30",
                "gallery_application_versions": "2020-09-30",
                "gallery_applications": "2020-09-30",
                "gallery_image_versions": "2020-09-30",
                "gallery_images": "2020-09-30",
                "gallery_sharing_profile": "2020-09-30",
                "images": "2020-12-01",
                "log_analytics": "2020-12-01",
                "operations": "2020-12-01",
                "proximity_placement_groups": "2020-12-01",
                "resource_skus": "2019-04-01",
                "shared_galleries": "2020-09-30",
                "shared_gallery_image_versions": "2020-09-30",
                "shared_gallery_images": "2020-09-30",
                "snapshots": "2020-12-01",
                "ssh_public_keys": "2020-12-01",
                "usage": "2020-12-01",
                "virtual_machine_extension_images": "2020-12-01",
                "virtual_machine_extensions": "2020-12-01",
                "virtual_machine_images": "2020-12-01",
                "virtual_machine_images_edge_zone": "2020-12-01",
                "virtual_machine_run_commands": "2020-12-01",
                "virtual_machine_scale_set_extensions": "2020-12-01",
                "virtual_machine_scale_set_rolling_upgrades": "2020-12-01",
                "virtual_machine_scale_set_vm_extensions": "2020-12-01",
                "virtual_machine_scale_set_vm_run_commands": "2020-12-01",
                "virtual_machine_scale_set_vms": "2020-12-01",
                "virtual_machine_scale_sets": "2020-12-01",
                "virtual_machine_sizes": "2020-12-01",
                "virtual_machines": "2020-12-01",
            }
        },
        AZURE_COMPUTE_MGMT_PROFILE_TAG + " osm",
    )

    AZURE_RESOURCE_MGMT_CLIENT_API_VERSION = "2020-10-01"
    AZURE_RESOURCE_MGMT_PROFILE_TAG = (
        "azure.mgmt.resource.resources.ResourceManagementClient"
    )
    AZURE_RESOURCE_MGMT_PROFILE = ProfileDefinition(
        {
            AZURE_RESOURCE_MGMT_PROFILE_TAG: {
                None: AZURE_RESOURCE_MGMT_CLIENT_API_VERSION,
            }
        },
        AZURE_RESOURCE_MGMT_PROFILE_TAG + " osm",
    )

    AZURE_NETWORK_MGMT_CLIENT_API_VERSION = "2020-11-01"
    AZURE_NETWORK_MGMT_PROFILE_TAG = "azure.mgmt.network.NetworkManagementClient"
    AZURE_NETWORK_MGMT_PROFILE = ProfileDefinition(
        {
            AZURE_NETWORK_MGMT_PROFILE_TAG: {
                None: AZURE_NETWORK_MGMT_CLIENT_API_VERSION,
                "firewall_policy_rule_groups": "2020-04-01",
                "interface_endpoints": "2019-02-01",
                "p2_svpn_server_configurations": "2019-07-01",
            }
        },
        AZURE_NETWORK_MGMT_PROFILE_TAG + " osm",
    )

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
        """
        Constructor of VIM. Raise an exception is some needed parameter is missing, but it must not do any connectivity
        checking against the VIM
        Using common constructor parameters.
        In this case: config must include the following parameters:
        subscription_id: assigned azure subscription identifier
        region_name: current region for azure network
        resource_group: used for all azure created resources
        vnet_name: base vnet for azure, created networks will be subnets from this base network
        config may also include the following parameter:
        flavors_pattern: pattern that will be used to select a range of vm sizes, for example
            "^((?!Standard_B).)*$" will filter out Standard_B range that is cheap but is very overused
            "^Standard_B" will select a serie B maybe for test environment
        """
        vimconn.VimConnector.__init__(
            self,
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

        # Variable that indicates if client must be reloaded or initialized
        self.reload_client = True

        self.vnet_address_space = None

        # LOGGER
        self.logger = logging.getLogger("ro.vim.azure")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

        self.tenant = tenant_id or tenant_name

        # Store config to create azure subscription later
        self._config = {
            "user": user,
            "passwd": passwd,
            "tenant": tenant_id or tenant_name,
        }

        # SUBSCRIPTION
        if "subscription_id" in config:
            self._config["subscription_id"] = config.get("subscription_id")
            # self.logger.debug("Setting subscription to: %s", self.config["subscription_id"])
        else:
            raise vimconn.VimConnException("Subscription not specified")

        # RESOURCE_GROUP
        if "resource_group" in config:
            self.resource_group = config.get("resource_group")
        else:
            raise vimconn.VimConnException(
                "Azure resource_group is not specified at config"
            )

        # REGION
        if "region_name" in config:
            self.region = config.get("region_name")
        else:
            raise vimconn.VimConnException(
                "Azure region_name is not specified at config"
            )

        # VNET_NAME
        if "vnet_name" in config:
            self.vnet_name = config["vnet_name"]

        # TODO - not used, do anything about it?
        # public ssh key
        self.pub_key = config.get("pub_key")

        # TODO - check default user for azure
        # default admin user
        self._default_admin_user = "azureuser"

        # flavor pattern regex
        if "flavors_pattern" in config:
            self._config["flavors_pattern"] = config["flavors_pattern"]

    def _find_in_capabilities(self, capabilities, name):
        cap = find_in_list(capabilities, lambda c: c["name"] == name)
        if cap:
            return cap.get("value")
        else:
            return None

    def _reload_connection(self):
        """
        Called before any operation, checks python azure clients
        """
        if self.reload_client:
            self.logger.debug("reloading azure client")

            try:
                self.credentials = ClientSecretCredential(
                    client_id=self._config["user"],
                    client_secret=self._config["passwd"],
                    tenant_id=self._config["tenant"],
                )
                self.conn = ResourceManagementClient(
                    self.credentials,
                    self._config["subscription_id"],
                    profile=self.AZURE_RESOURCE_MGMT_PROFILE,
                )
                self.conn_compute = ComputeManagementClient(
                    self.credentials,
                    self._config["subscription_id"],
                    profile=self.AZURE_COMPUTE_MGMT_PROFILE,
                )
                self.conn_vnet = NetworkManagementClient(
                    self.credentials,
                    self._config["subscription_id"],
                    profile=self.AZURE_NETWORK_MGMT_PROFILE,
                )
                self._check_or_create_resource_group()
                self._check_or_create_vnet()

                # Set to client created
                self.reload_client = False
            except Exception as e:
                self._format_vimconn_exception(e)

    def _get_resource_name_from_resource_id(self, resource_id):
        """
        Obtains resource_name from the azure complete identifier: resource_name will always be last item
        """
        try:
            resource = str(resource_id.split("/")[-1])

            return resource
        except Exception as e:
            raise vimconn.VimConnException(
                "Unable to get resource name from resource_id '{}' Error: '{}'".format(
                    resource_id, e
                )
            )

    def _get_location_from_resource_group(self, resource_group_name):
        try:
            location = self.conn.resource_groups.get(resource_group_name).location

            return location
        except Exception:
            raise vimconn.VimConnNotFoundException(
                "Location '{}' not found".format(resource_group_name)
            )

    def _get_resource_group_name_from_resource_id(self, resource_id):
        try:
            rg = str(resource_id.split("/")[4])

            return rg
        except Exception:
            raise vimconn.VimConnException(
                "Unable to get resource group from invalid resource_id format '{}'".format(
                    resource_id
                )
            )

    def _get_net_name_from_resource_id(self, resource_id):
        try:
            net_name = str(resource_id.split("/")[8])

            return net_name
        except Exception:
            raise vimconn.VimConnException(
                "Unable to get azure net_name from invalid resource_id format '{}'".format(
                    resource_id
                )
            )

    def _check_subnets_for_vm(self, net_list):
        # All subnets must belong to the same resource group and vnet
        # All subnets must belong to the same resource group anded vnet
        rg_vnet = set(
            self._get_resource_group_name_from_resource_id(net["net_id"])
            + self._get_net_name_from_resource_id(net["net_id"])
            for net in net_list
        )

        if len(rg_vnet) != 1:
            raise self._format_vimconn_exception(
                "Azure VMs can only attach to subnets in same VNET"
            )

    def _format_vimconn_exception(self, e):
        """
        Transforms a generic or azure exception to a vimcommException
        """
        self.logger.error("Azure plugin error: {}".format(e))
        if isinstance(e, vimconn.VimConnException):
            raise e
        elif isinstance(e, AuthenticationError):
            raise vimconn.VimConnAuthException(type(e).__name__ + ": " + str(e))
        elif isinstance(e, ConnectionError):
            raise vimconn.VimConnConnectionException(type(e).__name__ + ": " + str(e))
        else:
            # In case of generic error recreate client
            self.reload_client = True

            raise vimconn.VimConnException(type(e).__name__ + ": " + str(e))

    def _check_or_create_resource_group(self):
        """
        Creates the base resource group if it does not exist
        """
        try:
            rg_exists = self.conn.resource_groups.check_existence(self.resource_group)

            if not rg_exists:
                self.logger.debug("create base rgroup: %s", self.resource_group)
                self.conn.resource_groups.create_or_update(
                    self.resource_group, {"location": self.region}
                )
        except Exception as e:
            self._format_vimconn_exception(e)

    def _check_or_create_vnet(self):
        """
        Try to get existent base vnet, in case it does not exist it creates it
        """
        try:
            vnet = self.conn_vnet.virtual_networks.get(
                self.resource_group, self.vnet_name
            )
            self.vnet_address_space = vnet.address_space.address_prefixes[0]
            self.vnet_id = vnet.id

            return
        except CloudError as e:
            if e.error.error and "notfound" in e.error.error.lower():
                pass
                # continue and create it
            else:
                self._format_vimconn_exception(e)

        # if it does not exist, create it
        try:
            vnet_params = {
                "location": self.region,
                "address_space": {"address_prefixes": ["10.0.0.0/8"]},
            }
            self.vnet_address_space = "10.0.0.0/8"

            self.logger.debug("create base vnet: %s", self.vnet_name)
            self.conn_vnet.virtual_networks.begin_create_or_update(
                self.resource_group, self.vnet_name, vnet_params
            )
            vnet = self.conn_vnet.virtual_networks.get(
                self.resource_group, self.vnet_name
            )
            self.vnet_id = vnet.id
        except Exception as e:
            self._format_vimconn_exception(e)

    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):
        """
        Adds a tenant network to VIM
        :param net_name: name of the network
        :param net_type: not used for azure networks
        :param ip_profile: is a dict containing the IP parameters of the network (Currently only IPv4 is implemented)
                'ip-version': can be one of ['IPv4','IPv6']
                'subnet-address': ip_prefix_schema, that is X.X.X.X/Y
                'gateway-address': (Optional) ip_schema, that is X.X.X.X, not implemented for azure connector
                'dns-address': (Optional) ip_schema, not implemented for azure connector
                'dhcp': (Optional) dict containing, not implemented for azure connector
                    'enabled': {'type': 'boolean'},
                    'start-address': ip_schema, first IP to grant
                    'count': number of IPs to grant.
        :param shared: Not allowed for Azure Connector
        :param provider_network_profile: (optional) contains {segmentation-id: vlan, provider-network: vim_netowrk}
        :return: a tuple with the network identifier and created_items, or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_network. Can be used to store created segments, created l2gw connections, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        return self._new_subnet(net_name, ip_profile)

    def _new_subnet(self, net_name, ip_profile):
        """
        Adds a tenant network to VIM. It creates a new subnet at existing base vnet
        :param net_name: subnet name
        :param ip_profile:
                subnet-address: if it is not provided a subnet/24 in the default vnet is created,
                otherwise it creates a subnet in the indicated address
        :return: a tuple with the network identifier and created_items, or raises an exception on error
        """
        self.logger.debug("create subnet name %s, ip_profile %s", net_name, ip_profile)
        self._reload_connection()

        if ip_profile is None:
            # get a non used vnet ip range /24 and allocate automatically inside the range self.vnet_address_space
            used_subnets = self.get_network_list()
            for ip_range in netaddr.IPNetwork(self.vnet_address_space).subnet(24):
                for used_subnet in used_subnets:
                    subnet_range = netaddr.IPNetwork(used_subnet["cidr_block"])

                    if subnet_range in ip_range or ip_range in subnet_range:
                        # this range overlaps with an existing subnet ip range. Breaks and look for another
                        break
                else:
                    ip_profile = {"subnet_address": str(ip_range)}
                    self.logger.debug("dinamically obtained ip_profile: %s", ip_range)
                    break
            else:
                raise vimconn.VimConnException(
                    "Cannot find a non-used subnet range in {}".format(
                        self.vnet_address_space
                    )
                )
        else:
            ip_profile = {"subnet_address": ip_profile["subnet_address"]}

        try:
            # subnet_name = "{}-{}".format(net_name[:24], uuid4())
            subnet_params = {"address_prefix": ip_profile["subnet_address"]}
            # Assign a not duplicated net name
            subnet_name = self._get_unused_subnet_name(net_name)

            self.logger.debug("creating subnet_name: {}".format(subnet_name))
            async_creation = self.conn_vnet.subnets.begin_create_or_update(
                self.resource_group, self.vnet_name, subnet_name, subnet_params
            )
            async_creation.wait()
            # TODO - do not wait here, check where it is used
            self.logger.debug("created subnet_name: {}".format(subnet_name))

            return "{}/subnets/{}".format(self.vnet_id, subnet_name), None
        except Exception as e:
            self._format_vimconn_exception(e)

    def _get_unused_subnet_name(self, subnet_name):
        """
        Adds a prefix to the subnet_name with a number in case the indicated name is repeated
        Checks subnets with the indicated name (without suffix) and adds a suffix with a number
        """
        all_subnets = self.conn_vnet.subnets.list(self.resource_group, self.vnet_name)
        # Filter to subnets starting with the indicated name
        subnets = list(
            filter(lambda subnet: (subnet.name.startswith(subnet_name)), all_subnets)
        )
        net_names = [str(subnet.name) for subnet in subnets]

        # get the name with the first not used suffix
        name_suffix = 0
        # name = subnet_name + "-" + str(name_suffix)
        name = subnet_name  # first subnet created will have no prefix
        while name in net_names:
            name_suffix += 1
            name = subnet_name + "-" + str(name_suffix)

        return name

    def _create_nic(self, net, nic_name, region=None, static_ip=None, created_items={}):
        self.logger.debug("create nic name %s, net_name %s", nic_name, net)
        self._reload_connection()

        subnet_id = net["net_id"]
        location = self.region or self._get_location_from_resource_group(
            self.resource_group
        )
        try:
            net_ifz = {"location": location}
            net_ip_config = {
                "name": nic_name + "-ipconfiguration",
                "subnet": {"id": subnet_id},
            }

            if static_ip:
                net_ip_config["privateIPAddress"] = static_ip
                net_ip_config["privateIPAllocationMethod"] = "Static"

            net_ifz["ip_configurations"] = [net_ip_config]
            mac_address = net.get("mac_address")

            if mac_address:
                net_ifz["mac_address"] = mac_address

            async_nic_creation = (
                self.conn_vnet.network_interfaces.begin_create_or_update(
                    self.resource_group, nic_name, net_ifz
                )
            )
            nic_data = async_nic_creation.result()
            created_items[nic_data.id] = True
            self.logger.debug("created nic name %s", nic_name)

            public_ip = net.get("floating_ip")
            if public_ip:
                public_ip_address_params = {
                    "location": location,
                    "public_ip_allocation_method": "Dynamic",
                }
                public_ip_name = nic_name + "-public-ip"
                async_public_ip = (
                    self.conn_vnet.public_ip_addresses.begin_create_or_update(
                        self.resource_group, public_ip_name, public_ip_address_params
                    )
                )
                public_ip = async_public_ip.result()
                self.logger.debug("created public IP: {}".format(public_ip))

                # Associate NIC to Public IP
                nic_data = self.conn_vnet.network_interfaces.get(
                    self.resource_group, nic_name
                )

                nic_data.ip_configurations[0].public_ip_address = public_ip
                created_items[public_ip.id] = True

                self.conn_vnet.network_interfaces.begin_create_or_update(
                    self.resource_group, nic_name, nic_data
                )

        except Exception as e:
            self._format_vimconn_exception(e)

        return nic_data, created_items

    def new_flavor(self, flavor_data):
        """
        It is not allowed to create new flavors in Azure, must always use an existing one
        """
        raise vimconn.VimConnAuthException(
            "It is not possible to create new flavors in AZURE"
        )

    def new_tenant(self, tenant_name, tenant_description):
        """
        It is not allowed to create new tenants in azure
        """
        raise vimconn.VimConnAuthException(
            "It is not possible to create a TENANT in AZURE"
        )

    def new_image(self, image_dict):
        """
        It is not allowed to create new images in Azure, must always use an existing one
        """
        raise vimconn.VimConnAuthException(
            "It is not possible to create new images in AZURE"
        )

    def get_image_id_from_path(self, path):
        """Get the image id from image path in the VIM database.
        Returns the image_id or raises a vimconnNotFoundException
        """
        raise vimconn.VimConnAuthException(
            "It is not possible to obtain image from path in AZURE"
        )

    def get_image_list(self, filter_dict={}):
        """Obtain tenant images from VIM
        Filter_dict can be:
            name: image name with the format: publisher:offer:sku:version
            If some part of the name is provide ex: publisher:offer it will search all availables skus and version
            for the provided publisher and offer
            id: image uuid, currently not supported for azure
        Returns the image list of dictionaries:
            [{<the fields at Filter_dict plus some VIM specific>}, ...]
            List can be empty
        """
        self.logger.debug("get_image_list filter {}".format(filter_dict))

        self._reload_connection()
        try:
            image_list = []
            if filter_dict.get("name"):
                # name will have the format "publisher:offer:sku:version"
                # publisher is required, offer sku and version will be searched if not provided
                params = filter_dict["name"].split(":")
                publisher = params[0]
                if publisher:
                    # obtain offer list
                    offer_list = self._get_offer_list(params, publisher)

                    for offer in offer_list:
                        # obtain skus
                        sku_list = self._get_sku_list(params, publisher, offer)

                        for sku in sku_list:
                            # if version is defined get directly version, else list images
                            if len(params) == 4 and params[3]:
                                version = params[3]
                                if version == "latest":
                                    image_list = self._get_sku_image_list(
                                        publisher, offer, sku
                                    )
                                    image_list = [image_list[-1]]
                                else:
                                    image_list = self._get_version_image_list(
                                        publisher, offer, sku, version
                                    )
                            else:
                                image_list = self._get_sku_image_list(
                                    publisher, offer, sku
                                )
                else:
                    raise vimconn.VimConnAuthException(
                        "List images in Azure must include name param with at least publisher"
                    )
            else:
                raise vimconn.VimConnAuthException(
                    "List images in Azure must include name param with at"
                    " least publisher"
                )

            return image_list
        except Exception as e:
            self._format_vimconn_exception(e)

    def _get_offer_list(self, params, publisher):
        """
        Helper method to obtain offer list for defined publisher
        """
        if len(params) >= 2 and params[1]:
            return [params[1]]
        else:
            try:
                # get list of offers from azure
                result_offers = self.conn_compute.virtual_machine_images.list_offers(
                    self.region, publisher
                )

                return [offer.name for offer in result_offers]
            except CloudError as e:
                # azure raises CloudError when not found
                self.logger.info(
                    "error listing offers for publisher {}, Error: {}".format(
                        publisher, e
                    )
                )

                return []

    def _get_sku_list(self, params, publisher, offer):
        """
        Helper method to obtain sku list for defined publisher and offer
        """
        if len(params) >= 3 and params[2]:
            return [params[2]]
        else:
            try:
                # get list of skus from azure
                result_skus = self.conn_compute.virtual_machine_images.list_skus(
                    self.region, publisher, offer
                )

                return [sku.name for sku in result_skus]
            except CloudError as e:
                # azure raises CloudError when not found
                self.logger.info(
                    "error listing skus for publisher {}, offer {}, Error: {}".format(
                        publisher, offer, e
                    )
                )

                return []

    def _get_sku_image_list(self, publisher, offer, sku):
        """
        Helper method to obtain image list for publisher, offer and sku
        """
        image_list = []
        try:
            result_images = self.conn_compute.virtual_machine_images.list(
                self.region, publisher, offer, sku
            )
            for result_image in result_images:
                image_list.append(
                    {
                        "id": str(result_image.id),
                        "name": ":".join([publisher, offer, sku, result_image.name]),
                    }
                )
        except CloudError as e:
            self.logger.info(
                "error listing skus for publisher {}, offer {}, Error: {}".format(
                    publisher, offer, e
                )
            )
            image_list = []

        return image_list

    def _get_version_image_list(self, publisher, offer, sku, version):
        image_list = []
        try:
            result_image = self.conn_compute.virtual_machine_images.get(
                self.region, publisher, offer, sku, version
            )

            if result_image:
                image_list.append(
                    {
                        "id": str(result_image.id),
                        "name": ":".join([publisher, offer, sku, version]),
                    }
                )
        except CloudError as e:
            # azure gives CloudError when not found
            self.logger.info(
                "error listing images for publisher {}, offer {}, sku {}, version {} Error: {}".format(
                    publisher, offer, sku, version, e
                )
            )
            image_list = []

        return image_list

    def get_network_list(self, filter_dict={}):
        """Obtain tenant networks of VIM
        Filter_dict can be:
            name: network name
            id: network id
            shared: boolean, not implemented in Azure
            tenant_id: tenant, not used in Azure, all networks same tenants
            admin_state_up: boolean, not implemented in Azure
            status: 'ACTIVE', not implemented in Azure #
        Returns the network list of dictionaries
        """
        # self.logger.debug("getting network list for vim, filter %s", filter_dict)
        try:
            self._reload_connection()

            vnet = self.conn_vnet.virtual_networks.get(
                self.resource_group, self.vnet_name
            )
            subnet_list = []

            for subnet in vnet.subnets:
                if filter_dict:
                    if filter_dict.get("id") and str(subnet.id) != filter_dict["id"]:
                        continue

                    if (
                        filter_dict.get("name")
                        and str(subnet.name) != filter_dict["name"]
                    ):
                        continue

                name = self._get_resource_name_from_resource_id(subnet.id)

                subnet_list.append(
                    {
                        "id": str(subnet.id),
                        "name": name,
                        "status": self.provision_state2osm[subnet.provisioning_state],
                        "cidr_block": str(subnet.address_prefix),
                        "type": "bridge",
                        "shared": False,
                    }
                )

            return subnet_list
        except Exception as e:
            self._format_vimconn_exception(e)

    def new_vminstance(
        self,
        name,
        description,
        start,
        image_id,
        flavor_id,
        net_list,
        cloud_config=None,
        disk_list=None,
        availability_zone_index=None,
        availability_zone_list=None,
    ):
        self.logger.debug(
            "new vm instance name: %s, image_id: %s, flavor_id: %s, net_list: %s, cloud_config: %s, "
            "disk_list: %s, availability_zone_index: %s, availability_zone_list: %s",
            name,
            image_id,
            flavor_id,
            net_list,
            cloud_config,
            disk_list,
            availability_zone_index,
            availability_zone_list,
        )
        self._reload_connection()

        # Validate input data is valid
        # The virtual machine name must have less or 64 characters and it can not have the following
        # characters: (~ ! @ # $ % ^ & * ( ) = + _ [ ] { } \ | ; : ' " , < > / ?.)
        vm_name = self._check_vm_name(name)
        # Obtain vm unused name
        vm_name = self._get_unused_vm_name(vm_name)

        # At least one network must be provided
        if not net_list:
            raise vimconn.VimConnException(
                "At least one net must be provided to create a new VM"
            )

        # image_id are several fields of the image_id
        image_reference = self._get_image_reference(image_id)

        try:
            virtual_machine = None
            created_items = {}

            # Create nics for each subnet
            self._check_subnets_for_vm(net_list)
            vm_nics = []

            for idx, net in enumerate(net_list):
                # Fault with subnet_id
                # subnet_id=net["subnet_id"]
                # subnet_id=net["net_id"]
                nic_name = vm_name + "-nic-" + str(idx)
                vm_nic, nic_items = self._create_nic(
                    net, nic_name, self.region, net.get("ip_address"), created_items
                )
                vm_nics.append({"id": str(vm_nic.id)})
                net["vim_id"] = vm_nic.id

            vm_parameters = {
                "location": self.region,
                "os_profile": self._build_os_profile(vm_name, cloud_config, image_id),
                "hardware_profile": {"vm_size": flavor_id},
                "storage_profile": {"image_reference": image_reference},
            }

            # If the machine has several networks one must be marked as primary
            # As it is not indicated in the interface the first interface will be marked as primary
            if len(vm_nics) > 1:
                for idx, vm_nic in enumerate(vm_nics):
                    if idx == 0:
                        vm_nics[0]["Primary"] = True
                    else:
                        vm_nics[idx]["Primary"] = False

            vm_parameters["network_profile"] = {"network_interfaces": vm_nics}

            # Obtain zone information
            vm_zone = self._get_vm_zone(availability_zone_index, availability_zone_list)
            if vm_zone:
                vm_parameters["zones"] = [vm_zone]

            self.logger.debug("create vm name: %s", vm_name)
            creation_result = self.conn_compute.virtual_machines.begin_create_or_update(
                self.resource_group, vm_name, vm_parameters, polling=False
            )
            self.logger.debug("obtained creation result: %s", creation_result)
            virtual_machine = creation_result.result()
            self.logger.debug("created vm name: %s", vm_name)

            """ Por ahora no hacer polling para ver si tarda menos
            # Add disks if they are provided
            if disk_list:
                for disk_index, disk in enumerate(disk_list):
                    self.logger.debug(
                        "add disk size: %s, image: %s",
                        disk.get("size"),
                        disk.get("image"),
                    )
                    self._add_newvm_disk(
                        virtual_machine, vm_name, disk_index, disk, created_items
                    )

            if start:
                self.conn_compute.virtual_machines.start(self.resource_group, vm_name)
            # start_result.wait()
            """

            return virtual_machine.id, created_items

            # run_command_parameters = {
            #     "command_id": "RunShellScript", # For linux, don't change it
            #     "script": [
            #     "date > /tmp/test.txt"
            #     ]
            # }
        except Exception as e:
            # Rollback vm creacion
            vm_id = None

            if virtual_machine:
                vm_id = virtual_machine.id

            try:
                self.logger.debug("exception creating vm try to rollback")
                self.delete_vminstance(vm_id, created_items)
            except Exception as e2:
                self.logger.error("new_vminstance rollback fail {}".format(e2))

            self.logger.debug("Exception creating new vminstance: %s", e, exc_info=True)
            self._format_vimconn_exception(e)

    def _build_os_profile(self, vm_name, cloud_config, image_id):

        # initial os_profile
        os_profile = {"computer_name": vm_name}

        # for azure os_profile admin_username is required
        if cloud_config and cloud_config.get("users"):
            admin_username = cloud_config.get("users")[0].get(
                "name", self._get_default_admin_user(image_id)
            )
        else:
            admin_username = self._get_default_admin_user(image_id)
        os_profile["admin_username"] = admin_username

        # if there is a cloud-init load it
        if cloud_config:
            _, userdata = self._create_user_data(cloud_config)
            custom_data = base64.b64encode(userdata.encode("utf-8")).decode("latin-1")
            os_profile["custom_data"] = custom_data

        # either password of ssh-keys are required
        # we will always use ssh-keys, in case it is not available we will generate it
        if cloud_config and cloud_config.get("key-pairs"):
            key_data = cloud_config.get("key-pairs")[0]
        else:
            _, key_data = self._generate_keys()

        os_profile["linux_configuration"] = {
            "ssh": {
                "public_keys": [
                    {
                        "path": "/home/{}/.ssh/authorized_keys".format(admin_username),
                        "key_data": key_data,
                    }
                ]
            },
        }

        return os_profile

    def _generate_keys(self):
        """Method used to generate a pair of private/public keys.
        This method is used because to create a vm in Azure we always need a key or a password
        In some cases we may have a password in a cloud-init file but it may not be available
        """
        key = rsa.generate_private_key(
            backend=crypto_default_backend(), public_exponent=65537, key_size=2048
        )
        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption(),
        )
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH,
        )
        private_key = private_key.decode("utf8")
        # Change first line because Paramiko needs a explicit start with 'BEGIN RSA PRIVATE KEY'
        i = private_key.find("\n")
        private_key = "-----BEGIN RSA PRIVATE KEY-----" + private_key[i:]
        public_key = public_key.decode("utf8")

        return private_key, public_key

    def _get_unused_vm_name(self, vm_name):
        """
        Checks the vm name and in case it is used adds a suffix to the name to allow creation
        :return:
        """
        all_vms = self.conn_compute.virtual_machines.list(self.resource_group)
        # Filter to vms starting with the indicated name
        vms = list(filter(lambda vm: (vm.name.startswith(vm_name)), all_vms))
        vm_names = [str(vm.name) for vm in vms]

        # get the name with the first not used suffix
        name_suffix = 0
        # name = subnet_name + "-" + str(name_suffix)
        name = vm_name  # first subnet created will have no prefix

        while name in vm_names:
            name_suffix += 1
            name = vm_name + "-" + str(name_suffix)

        return name

    def _get_vm_zone(self, availability_zone_index, availability_zone_list):
        if availability_zone_index is None:
            return None

        vim_availability_zones = self._get_azure_availability_zones()
        # check if VIM offer enough availability zones describe in the VNFD
        if vim_availability_zones and len(availability_zone_list) <= len(
            vim_availability_zones
        ):
            # check if all the names of NFV AV match VIM AV names
            match_by_index = False

            if not availability_zone_list:
                match_by_index = True
            else:
                for av in availability_zone_list:
                    if av not in vim_availability_zones:
                        match_by_index = True
                        break

            if match_by_index:
                return vim_availability_zones[availability_zone_index]
            else:
                return availability_zone_list[availability_zone_index]
        else:
            raise vimconn.VimConnConflictException(
                "No enough availability zones at VIM for this deployment"
            )

    def _get_azure_availability_zones(self):
        return self.AZURE_ZONES

    def _add_newvm_disk(
        self, virtual_machine, vm_name, disk_index, disk, created_items={}
    ):
        disk_name = None
        data_disk = None

        # Check if must create empty disk or from image
        if disk.get("vim_id"):
            # disk already exists, just get
            parsed_id = azure_tools.parse_resource_id(disk.get("vim_id"))
            disk_name = parsed_id.get("name")
            data_disk = self.conn_compute.disks.get(self.resource_group, disk_name)
        else:
            disk_name = vm_name + "_DataDisk_" + str(disk_index)
            if not disk.get("image_id"):
                self.logger.debug("create new data disk name: %s", disk_name)
                async_disk_creation = self.conn_compute.disks.begin_create_or_update(
                    self.resource_group,
                    disk_name,
                    {
                        "location": self.region,
                        "disk_size_gb": disk.get("size"),
                        "creation_data": {"create_option": DiskCreateOption.empty},
                    },
                )
                data_disk = async_disk_creation.result()
                created_items[data_disk.id] = True
            else:
                image_id = disk.get("image_id")

                if azure_tools.is_valid_resource_id(image_id):
                    parsed_id = azure_tools.parse_resource_id(image_id)

                    # Check if image is snapshot or disk
                    image_name = parsed_id.get("name")
                    type = parsed_id.get("resource_type")

                    if type == "snapshots" or type == "disks":
                        self.logger.debug("create disk from copy name: %s", image_name)
                        # ¿Should check that snapshot exists?
                        async_disk_creation = (
                            self.conn_compute.disks.begin_create_or_update(
                                self.resource_group,
                                disk_name,
                                {
                                    "location": self.region,
                                    "creation_data": {
                                        "create_option": "Copy",
                                        "source_uri": image_id,
                                    },
                                },
                            )
                        )
                        data_disk = async_disk_creation.result()
                        created_items[data_disk.id] = True
                    else:
                        raise vimconn.VimConnNotFoundException(
                            "Invalid image_id: %s ", image_id
                        )
                else:
                    raise vimconn.VimConnNotFoundException(
                        "Invalid image_id: %s ", image_id
                    )

        # Attach the disk created
        virtual_machine.storage_profile.data_disks.append(
            {
                "lun": disk_index,
                "name": disk_name,
                "create_option": DiskCreateOption.attach,
                "managed_disk": {"id": data_disk.id},
                "disk_size_gb": disk.get("size"),
            }
        )
        self.logger.debug("attach disk name: %s", disk_name)
        self.conn_compute.virtual_machines.begin_create_or_update(
            self.resource_group, virtual_machine.name, virtual_machine
        )

    # It is necesary extract from image_id data to create the VM with this format
    #        "image_reference": {
    #           "publisher": vm_reference["publisher"],
    #           "offer": vm_reference["offer"],
    #           "sku": vm_reference["sku"],
    #           "version": vm_reference["version"]
    #        },
    def _get_image_reference(self, image_id):
        try:
            # The data input format example:
            # /Subscriptions/ca3d18ab-d373-4afb-a5d6-7c44f098d16a/Providers/Microsoft.Compute/Locations/westeurope/
            # Publishers/Canonical/ArtifactTypes/VMImage/
            # Offers/UbuntuServer/
            # Skus/18.04-LTS/
            # Versions/18.04.201809110
            publisher = str(image_id.split("/")[8])
            offer = str(image_id.split("/")[12])
            sku = str(image_id.split("/")[14])
            version = str(image_id.split("/")[16])

            return {
                "publisher": publisher,
                "offer": offer,
                "sku": sku,
                "version": version,
            }
        except Exception:
            raise vimconn.VimConnException(
                "Unable to get image_reference from invalid image_id format: '{}'".format(
                    image_id
                )
            )

    # Azure VM names can not have some special characters
    def _check_vm_name(self, vm_name):
        """
        Checks vm name, in case the vm has not allowed characters they are removed, not error raised
        """
        chars_not_allowed_list = "~!@#$%^&*()=+_[]{}|;:<>/?."

        # First: the VM name max length is 64 characters
        vm_name_aux = vm_name[:64]

        # Second: replace not allowed characters
        for elem in chars_not_allowed_list:
            # Check if string is in the main string
            if elem in vm_name_aux:
                # self.logger.debug("Dentro del IF")
                # Replace the string
                vm_name_aux = vm_name_aux.replace(elem, "-")

        return vm_name_aux

    def get_flavor_id_from_data(self, flavor_dict):
        self.logger.debug("getting flavor id from data, flavor_dict: %s", flavor_dict)
        filter_dict = flavor_dict or {}

        try:
            self._reload_connection()
            vm_sizes_list = [
                vm_size.as_dict()
                for vm_size in self.conn_compute.resource_skus.list(
                    "location eq '{}'".format(self.region)
                )
            ]

            cpus = filter_dict.get("vcpus") or 0
            memMB = filter_dict.get("ram") or 0
            numberInterfaces = len(filter_dict.get("interfaces", [])) or 0

            # Filter
            filtered_sizes = []
            for size in vm_sizes_list:
                if size["resource_type"] == "virtualMachines":
                    size_cpus = int(
                        self._find_in_capabilities(size["capabilities"], "vCPUs")
                    )
                    size_memory = float(
                        self._find_in_capabilities(size["capabilities"], "MemoryGB")
                    )
                    size_interfaces = self._find_in_capabilities(
                        size["capabilities"], "MaxNetworkInterfaces"
                    )
                    if size_interfaces:
                        size_interfaces = int(size_interfaces)
                    else:
                        self.logger.debug(
                            "Flavor with no defined MaxNetworkInterfaces: {}".format(
                                size["name"]
                            )
                        )
                        continue
                    if (
                        size_cpus >= cpus
                        and size_memory >= memMB / 1024
                        and size_interfaces >= numberInterfaces
                    ):
                        if self._config.get("flavors_pattern"):
                            if re.search(
                                self._config.get("flavors_pattern"), size["name"]
                            ):
                                new_size = {
                                    e["name"]: e["value"] for e in size["capabilities"]
                                }
                                new_size["name"] = size["name"]
                                filtered_sizes.append(new_size)
                        else:
                            new_size = {
                                e["name"]: e["value"] for e in size["capabilities"]
                            }
                            new_size["name"] = size["name"]
                            filtered_sizes.append(new_size)

            # Sort
            listedFilteredSizes = sorted(
                filtered_sizes,
                key=lambda k: (
                    int(k["vCPUs"]),
                    float(k["MemoryGB"]),
                    int(k["MaxNetworkInterfaces"]),
                    int(k["MaxResourceVolumeMB"]),
                ),
            )

            if listedFilteredSizes:
                return listedFilteredSizes[0]["name"]

            raise vimconn.VimConnNotFoundException(
                "Cannot find any flavor matching '{}'".format(str(flavor_dict))
            )
        except Exception as e:
            self._format_vimconn_exception(e)

    def _get_flavor_id_from_flavor_name(self, flavor_name):
        # self.logger.debug("getting flavor id from flavor name {}".format(flavor_name))
        try:
            self._reload_connection()
            vm_sizes_list = [
                vm_size.as_dict()
                for vm_size in self.conn_compute.resource_skus.list(
                    "location eq '{}'".format(self.region)
                )
            ]

            output_flavor = None
            for size in vm_sizes_list:
                if size["name"] == flavor_name:
                    output_flavor = size

            # None is returned if not found anything
            return output_flavor
        except Exception as e:
            self._format_vimconn_exception(e)

    def check_vim_connectivity(self):
        try:
            self._reload_connection()
            return True
        except Exception as e:
            raise vimconn.VimConnException(
                "Connectivity issue with Azure API: {}".format(e)
            )

    def get_network(self, net_id):
        # self.logger.debug("get network id: {}".format(net_id))
        # res_name = self._get_resource_name_from_resource_id(net_id)
        self._reload_connection()

        filter_dict = {"name": net_id}
        network_list = self.get_network_list(filter_dict)

        if not network_list:
            raise vimconn.VimConnNotFoundException(
                "network '{}' not found".format(net_id)
            )
        else:
            return network_list[0]

    def delete_network(self, net_id, created_items=None):
        self.logger.debug(
            "deleting network {} - {}".format(self.resource_group, net_id)
        )

        self._reload_connection()
        res_name = self._get_resource_name_from_resource_id(net_id)

        try:
            # Obtain subnets ant try to delete nic first
            subnet = self.conn_vnet.subnets.get(
                self.resource_group, self.vnet_name, res_name
            )
            if not subnet:
                raise vimconn.VimConnNotFoundException(
                    "network '{}' not found".format(net_id)
                )

            # TODO - for a quick-fix delete nics sequentially but should not wait
            # for each in turn
            if subnet.ip_configurations:
                for ip_configuration in subnet.ip_configurations:
                    # obtain nic_name from ip_configuration
                    parsed_id = azure_tools.parse_resource_id(ip_configuration.id)
                    nic_name = parsed_id["name"]
                    self.delete_inuse_nic(nic_name)

            # Subnet API fails (CloudError: Azure Error: ResourceNotFound)
            # Put the initial virtual_network API
            async_delete = self.conn_vnet.subnets.begin_delete(
                self.resource_group, self.vnet_name, res_name
            )
            async_delete.wait()

            return net_id

        except ResourceNotFoundError:
            raise vimconn.VimConnNotFoundException(
                "network '{}' not found".format(net_id)
            )
        except CloudError as e:
            if e.error.error and "notfound" in e.error.error.lower():
                raise vimconn.VimConnNotFoundException(
                    "network '{}' not found".format(net_id)
                )
            else:
                self._format_vimconn_exception(e)
        except Exception as e:
            self._format_vimconn_exception(e)

    def delete_inuse_nic(self, nic_name):

        # Obtain nic data
        nic_data = self.conn_vnet.network_interfaces.get(self.resource_group, nic_name)

        # Obtain vm associated to nic in case it exists
        if nic_data.virtual_machine:
            vm_name = azure_tools.parse_resource_id(nic_data.virtual_machine.id)["name"]
            self.logger.debug("vm_name: {}".format(vm_name))
            virtual_machine = self.conn_compute.virtual_machines.get(
                self.resource_group, vm_name
            )
            self.logger.debug("obtained vm")

            # Deattach nic from vm if it has netwolk machines attached
            network_interfaces = virtual_machine.network_profile.network_interfaces
            network_interfaces[:] = [
                interface
                for interface in network_interfaces
                if self._get_resource_name_from_resource_id(interface.id) != nic_name
            ]

            # TODO - check if there is a public ip to delete and delete it
            if network_interfaces:

                # Deallocate the vm
                async_vm_deallocate = (
                    self.conn_compute.virtual_machines.begin_deallocate(
                        self.resource_group, vm_name
                    )
                )
                self.logger.debug("deallocating vm")
                async_vm_deallocate.wait()
                self.logger.debug("vm deallocated")

                async_vm_update = (
                    self.conn_compute.virtual_machines.begin_create_or_update(
                        self.resource_group, vm_name, virtual_machine
                    )
                )
                virtual_machine = async_vm_update.result()
                self.logger.debug("nic removed from interface")

            else:
                self.logger.debug("There are no interfaces left, delete vm")
                self.delete_vminstance(virtual_machine.id)
                self.logger.debug("Delete vm")

        # Delete nic
        self.logger.debug("delete NIC name: %s", nic_name)
        nic_delete = self.conn_vnet.network_interfaces.begin_delete(
            self.resource_group, nic_name
        )
        nic_delete.wait()
        self.logger.debug("deleted NIC name: %s", nic_name)

    def delete_vminstance(self, vm_id, created_items=None):
        """Deletes a vm instance from the vim."""
        self.logger.debug(
            "deleting VM instance {} - {}".format(self.resource_group, vm_id)
        )
        self._reload_connection()

        created_items = created_items or {}
        try:
            # Check vm exists, we can call delete_vm to clean created_items
            if vm_id:
                res_name = self._get_resource_name_from_resource_id(vm_id)
                vm = self.conn_compute.virtual_machines.get(
                    self.resource_group, res_name
                )

                # Shuts down the virtual machine and releases the compute resources
                # vm_stop = self.conn_compute.virtual_machines.power_off(self.resource_group, resName)
                # vm_stop.wait()

                vm_delete = self.conn_compute.virtual_machines.begin_delete(
                    self.resource_group, res_name
                )
                vm_delete.wait()
                self.logger.debug("deleted VM name: %s", res_name)

                # Delete OS Disk, check if exists, in case of error creating
                # it may not be fully created
                if vm.storage_profile.os_disk:
                    os_disk_name = vm.storage_profile.os_disk.name
                    self.logger.debug("delete OS DISK: %s", os_disk_name)
                    async_disk_delete = self.conn_compute.disks.begin_delete(
                        self.resource_group, os_disk_name
                    )
                    async_disk_delete.wait()
                    # os disks are created always with the machine
                    self.logger.debug("deleted OS DISK name: %s", os_disk_name)

                for data_disk in vm.storage_profile.data_disks:
                    self.logger.debug("delete data_disk: %s", data_disk.name)
                    async_disk_delete = self.conn_compute.disks.begin_delete(
                        self.resource_group, data_disk.name
                    )
                    async_disk_delete.wait()
                    self._markdel_created_item(data_disk.managed_disk.id, created_items)
                    self.logger.debug("deleted OS DISK name: %s", data_disk.name)

                # After deleting VM, it is necessary to delete NIC, because if is not deleted delete_network
                # does not work because Azure says that is in use the subnet
                network_interfaces = vm.network_profile.network_interfaces

                for network_interface in network_interfaces:
                    nic_name = self._get_resource_name_from_resource_id(
                        network_interface.id
                    )
                    nic_data = self.conn_vnet.network_interfaces.get(
                        self.resource_group, nic_name
                    )

                    public_ip_name = None
                    exist_public_ip = nic_data.ip_configurations[0].public_ip_address
                    if exist_public_ip:
                        public_ip_id = nic_data.ip_configurations[
                            0
                        ].public_ip_address.id

                        # Delete public_ip
                        public_ip_name = self._get_resource_name_from_resource_id(
                            public_ip_id
                        )

                        # Public ip must be deleted afterwards of nic that is attached

                    self.logger.debug("delete NIC name: %s", nic_name)
                    nic_delete = self.conn_vnet.network_interfaces.begin_delete(
                        self.resource_group, nic_name
                    )
                    nic_delete.wait()
                    self._markdel_created_item(network_interface.id, created_items)
                    self.logger.debug("deleted NIC name: %s", nic_name)

                    # Delete list of public ips
                    if public_ip_name:
                        self.logger.debug("delete PUBLIC IP - " + public_ip_name)
                        ip_delete = self.conn_vnet.public_ip_addresses.begin_delete(
                            self.resource_group, public_ip_name
                        )
                        ip_delete.wait()
                        self._markdel_created_item(public_ip_id, created_items)

            # Delete created items
            self._delete_created_items(created_items)

        except ResourceNotFoundError:
            raise vimconn.VimConnNotFoundException(
                "No vm instance found '{}'".format(vm_id)
            )
        except CloudError as e:
            if e.error.error and "notfound" in e.error.error.lower():
                raise vimconn.VimConnNotFoundException(
                    "No vm instance found '{}'".format(vm_id)
                )
            else:
                self._format_vimconn_exception(e)
        except Exception as e:
            self._format_vimconn_exception(e)

    def _markdel_created_item(self, item_id, created_items):
        if item_id in created_items:
            created_items[item_id] = False

    def _delete_created_items(self, created_items):
        """Delete created_items elements that have not been deleted with the virtual machine
        Created_items may not be deleted correctly with the created machine if the
        virtual machine fails creating or in other cases of error
        """
        self.logger.debug("Created items: %s", created_items)
        # TODO - optimize - should not wait until it is deleted
        # Must delete in order first nics, then public_ips
        # As dictionaries don't preserve order, first get items to be deleted then delete them
        nics_to_delete = []
        publics_ip_to_delete = []
        disks_to_delete = []
        for item_id, v in created_items.items():
            if not v:  # skip already deleted
                continue

            # self.logger.debug("Must delete item id: %s", item_id)
            # Obtain type, supported nic, disk or public ip
            parsed_id = azure_tools.parse_resource_id(item_id)
            resource_type = parsed_id.get("resource_type")
            name = parsed_id.get("name")

            if resource_type == "networkInterfaces":
                nics_to_delete.append(name)
            elif resource_type == "publicIPAddresses":
                publics_ip_to_delete.append(name)
            elif resource_type == "disks":
                disks_to_delete.append(name)

        # Now delete
        for item_name in nics_to_delete:
            try:
                self.logger.debug("deleting nic name %s:", item_name)
                nic_delete = self.conn_vnet.network_interfaces.begin_delete(
                    self.resource_group, item_name
                )
                nic_delete.wait()
                self.logger.debug("deleted nic name %s:", item_name)
            except Exception as e:
                self.logger.error(
                    "Error deleting item: {}: {}".format(type(e).__name__, e)
                )

        for item_name in publics_ip_to_delete:
            try:
                self.logger.debug("deleting public ip name %s:", item_name)
                ip_delete = self.conn_vnet.public_ip_addresses.begin_delete(
                    self.resource_group, name
                )
                ip_delete.wait()
                self.logger.debug("deleted public ip name %s:", item_name)
            except Exception as e:
                self.logger.error(
                    "Error deleting item: {}: {}".format(type(e).__name__, e)
                )

        for item_name in disks_to_delete:
            try:
                self.logger.debug("deleting data disk name %s:", name)
                async_disk_delete = self.conn_compute.disks.begin_delete(
                    self.resource_group, item_name
                )
                async_disk_delete.wait()
                self.logger.debug("deleted data disk name %s:", name)
            except Exception as e:
                self.logger.error(
                    "Error deleting item: {}: {}".format(type(e).__name__, e)
                )

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        """Send and action over a VM instance from VIM
        Returns the vm_id if the action was successfully sent to the VIM
        """
        self.logger.debug("Action over VM '%s': %s", vm_id, str(action_dict))

        try:
            self._reload_connection()
            resName = self._get_resource_name_from_resource_id(vm_id)

            if "start" in action_dict:
                self.conn_compute.virtual_machines.begin_start(
                    self.resource_group, resName
                )
            elif (
                "stop" in action_dict
                or "shutdown" in action_dict
                or "shutoff" in action_dict
            ):
                self.conn_compute.virtual_machines.begin_power_off(
                    self.resource_group, resName
                )
            elif "terminate" in action_dict:
                self.conn_compute.virtual_machines.begin_delete(
                    self.resource_group, resName
                )
            elif "reboot" in action_dict:
                self.conn_compute.virtual_machines.begin_restart(
                    self.resource_group, resName
                )

            return None
        except ResourceNotFoundError:
            raise vimconn.VimConnNotFoundException("No vm found '{}'".format(vm_id))
        except CloudError as e:
            if e.error.error and "notfound" in e.error.error.lower():
                raise vimconn.VimConnNotFoundException("No vm found '{}'".format(vm_id))
            else:
                self._format_vimconn_exception(e)
        except Exception as e:
            self._format_vimconn_exception(e)

    def delete_flavor(self, flavor_id):
        raise vimconn.VimConnAuthException(
            "It is not possible to delete a FLAVOR in AZURE"
        )

    def delete_tenant(self, tenant_id):
        raise vimconn.VimConnAuthException(
            "It is not possible to delete a TENANT in AZURE"
        )

    def delete_image(self, image_id):
        raise vimconn.VimConnAuthException(
            "It is not possible to delete a IMAGE in AZURE"
        )

    def get_vminstance(self, vm_id):
        """
        Obtaing the vm instance data from v_id
        """
        self.logger.debug("get vm instance: %s", vm_id)
        self._reload_connection()
        try:
            resName = self._get_resource_name_from_resource_id(vm_id)
            vm = self.conn_compute.virtual_machines.get(self.resource_group, resName)
        except ResourceNotFoundError:
            raise vimconn.VimConnNotFoundException(
                "No vminstance found '{}'".format(vm_id)
            )
        except CloudError as e:
            if e.error.error and "notfound" in e.error.error.lower():
                raise vimconn.VimConnNotFoundException(
                    "No vminstance found '{}'".format(vm_id)
                )
            else:
                self._format_vimconn_exception(e)
        except Exception as e:
            self._format_vimconn_exception(e)

        return vm

    def get_flavor(self, flavor_id):
        """
        Obtains the flavor_data from the flavor_id
        """
        self._reload_connection()
        self.logger.debug("get flavor from id: %s", flavor_id)
        flavor_data = self._get_flavor_id_from_flavor_name(flavor_id)

        if flavor_data:
            flavor = {
                "id": flavor_id,
                "name": flavor_id,
                "ram": flavor_data["memoryInMB"],
                "vcpus": flavor_data["numberOfCores"],
                "disk": flavor_data["resourceDiskSizeInMB"] / 1024,
            }

            return flavor
        else:
            raise vimconn.VimConnNotFoundException(
                "flavor '{}' not found".format(flavor_id)
            )

    def get_tenant_list(self, filter_dict={}):
        """Obtains the list of tenants
        For the azure connector only the azure tenant will be returned if it is compatible
        with filter_dict
        """
        tenants_azure = [{"name": self.tenant, "id": self.tenant}]
        tenant_list = []

        self.logger.debug("get tenant list: %s", filter_dict)
        for tenant_azure in tenants_azure:
            if filter_dict:
                if (
                    filter_dict.get("id")
                    and str(tenant_azure.get("id")) != filter_dict["id"]
                ):
                    continue

                if (
                    filter_dict.get("name")
                    and str(tenant_azure.get("name")) != filter_dict["name"]
                ):
                    continue

            tenant_list.append(tenant_azure)

        return tenant_list

    def refresh_nets_status(self, net_list):
        """Get the status of the networks
        Params: the list of network identifiers
        Returns a dictionary with:
            net_id:  #VIM id of this network
            status:  #Mandatory. Text with one of:
                     #  DELETED (not found at vim)
                     #  VIM_ERROR (Cannot connect to VIM, VIM response error, ...)
                     #  OTHER (Vim reported other status not understood)
                     #  ERROR (VIM indicates an ERROR status)
                     #  ACTIVE, INACTIVE, DOWN (admin down),
                     #  BUILD (on building process)
                     #
            error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
             vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
        """
        out_nets = {}
        self._reload_connection()

        self.logger.debug("reload nets status net_list: %s", net_list)
        for net_id in net_list:
            try:
                netName = self._get_net_name_from_resource_id(net_id)
                resName = self._get_resource_name_from_resource_id(net_id)

                net = self.conn_vnet.subnets.get(self.resource_group, netName, resName)

                out_nets[net_id] = {
                    "status": self.provision_state2osm[net.provisioning_state],
                    "vim_info": str(net),
                }
            except CloudError as e:
                if e.error.error and "notfound" in e.error.error.lower():
                    self.logger.info(
                        "Not found subnet net_name: %s, subnet_name: %s",
                        netName,
                        resName,
                    )
                    out_nets[net_id] = {"status": "DELETED", "error_msg": str(e)}
                else:
                    self.logger.error(
                        "CloudError Exception %s when searching subnet", e
                    )
                    out_nets[net_id] = {
                        "status": "VIM_ERROR",
                        "error_msg": str(e),
                    }
            except vimconn.VimConnNotFoundException as e:
                self.logger.error(
                    "VimConnNotFoundException %s when searching subnet", e
                )
                out_nets[net_id] = {
                    "status": "DELETED",
                    "error_msg": str(e),
                }
            except Exception as e:
                self.logger.error(
                    "Exception %s when searching subnet", e, exc_info=True
                )
                out_nets[net_id] = {
                    "status": "VIM_ERROR",
                    "error_msg": str(e),
                }

        return out_nets

    def refresh_vms_status(self, vm_list):
        """Get the status of the virtual machines and their interfaces/ports
        Params: the list of VM identifiers
        Returns a dictionary with:
            vm_id:          # VIM id of this Virtual Machine
                status:     # Mandatory. Text with one of:
                            #  DELETED (not found at vim)
                            #  VIM_ERROR (Cannot connect to VIM, VIM response error, ...)
                            #  OTHER (Vim reported other status not understood)
                            #  ERROR (VIM indicates an ERROR status)
                            #  ACTIVE, PAUSED, SUSPENDED, INACTIVE (not running),
                            #  BUILD (on building process), ERROR
                            #  ACTIVE:NoMgmtIP (Active but none of its interfaces has an IP address
                            #     (ACTIVE:NoMgmtIP is not returned for Azure)
                            #
                error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
                vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
                interfaces: list with interface info. Each item a dictionary with:
                    vim_interface_id -  The ID of the interface
                    mac_address - The MAC address of the interface.
                    ip_address - The IP address of the interface within the subnet.
        """
        out_vms = {}
        self._reload_connection()

        self.logger.debug("refresh vm status vm_list: %s", vm_list)
        search_vm_list = vm_list or {}

        for vm_id in search_vm_list:
            out_vm = {}
            try:
                res_name = self._get_resource_name_from_resource_id(vm_id)

                vm = self.conn_compute.virtual_machines.get(
                    self.resource_group, res_name
                )
                out_vm["vim_info"] = str(vm)
                out_vm["status"] = self.provision_state2osm.get(
                    vm.provisioning_state, "OTHER"
                )

                if vm.provisioning_state == "Succeeded":
                    # check if machine is running or stopped
                    instance_view = self.conn_compute.virtual_machines.instance_view(
                        self.resource_group, res_name
                    )

                    for status in instance_view.statuses:
                        splitted_status = status.code.split("/")
                        if (
                            len(splitted_status) == 2
                            and splitted_status[0] == "PowerState"
                        ):
                            out_vm["status"] = self.power_state2osm.get(
                                splitted_status[1], "OTHER"
                            )

                network_interfaces = vm.network_profile.network_interfaces
                out_vm["interfaces"] = self._get_vm_interfaces_status(
                    vm_id, network_interfaces
                )

            except CloudError as e:
                if e.error.error and "notfound" in e.error.error.lower():
                    self.logger.debug("Not found vm id: %s", vm_id)
                    out_vm["status"] = "DELETED"
                    out_vm["error_msg"] = str(e)
                    out_vm["vim_info"] = None
                else:
                    # maybe connection error or another type of error, return vim error
                    self.logger.error("Exception %s refreshing vm_status", e)
                    out_vm["status"] = "VIM_ERROR"
                    out_vm["error_msg"] = str(e)
                    out_vm["vim_info"] = None
            except Exception as e:
                self.logger.error("Exception %s refreshing vm_status", e, exc_info=True)
                out_vm["status"] = "VIM_ERROR"
                out_vm["error_msg"] = str(e)
                out_vm["vim_info"] = None

            out_vms[vm_id] = out_vm

        return out_vms

    def _get_vm_interfaces_status(self, vm_id, interfaces):
        """
        Gets the interfaces detail for a vm
        :param interfaces: List of interfaces.
        :return: Dictionary with list of interfaces including, vim_interface_id, mac_address and ip_address
        """
        try:
            interface_list = []
            for network_interface in interfaces:
                interface_dict = {}
                nic_name = self._get_resource_name_from_resource_id(
                    network_interface.id
                )
                interface_dict["vim_interface_id"] = network_interface.id

                nic_data = self.conn_vnet.network_interfaces.get(
                    self.resource_group,
                    nic_name,
                )

                ips = []
                if nic_data.ip_configurations[0].public_ip_address:
                    self.logger.debug("Obtain public ip address")
                    public_ip_name = self._get_resource_name_from_resource_id(
                        nic_data.ip_configurations[0].public_ip_address.id
                    )
                    public_ip = self.conn_vnet.public_ip_addresses.get(
                        self.resource_group, public_ip_name
                    )
                    self.logger.debug("Public ip address is: %s", public_ip.ip_address)
                    ips.append(public_ip.ip_address)

                private_ip = nic_data.ip_configurations[0].private_ip_address
                ips.append(private_ip)

                interface_dict["mac_address"] = nic_data.mac_address
                interface_dict["ip_address"] = ";".join(ips)
                interface_list.append(interface_dict)

            return interface_list
        except Exception as e:
            self.logger.error(
                "Exception %s obtaining interface data for vm: %s",
                e,
                vm_id,
                exc_info=True,
            )
            self._format_vimconn_exception(e)

    def _get_default_admin_user(self, image_id):
        if "ubuntu" in image_id.lower():
            return "ubuntu"
        else:
            return self._default_admin_user


if __name__ == "__main__":
    # Init logger
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    log_formatter = logging.Formatter(log_format, datefmt="%Y-%m-%dT%H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(log_formatter)
    logger = logging.getLogger("ro.vim.azure")
    # logger.setLevel(level=logging.ERROR)
    # logger.setLevel(level=logging.INFO)
    logger.setLevel(level=logging.DEBUG)
    logger.addHandler(handler)

    # Making some basic test
    vim_id = "azure"
    vim_name = "azure"
    needed_test_params = {
        "client_id": "AZURE_CLIENT_ID",
        "secret": "AZURE_SECRET",
        "tenant": "AZURE_TENANT",
        "resource_group": "AZURE_RESOURCE_GROUP",
        "subscription_id": "AZURE_SUBSCRIPTION_ID",
        "vnet_name": "AZURE_VNET_NAME",
    }
    test_params = {}

    for param, env_var in needed_test_params.items():
        value = getenv(env_var)

        if not value:
            raise Exception("Provide a valid value for env '{}'".format(env_var))

        test_params[param] = value

    config = {
        "region_name": getenv("AZURE_REGION_NAME", "northeurope"),
        "resource_group": getenv("AZURE_RESOURCE_GROUP"),
        "subscription_id": getenv("AZURE_SUBSCRIPTION_ID"),
        "pub_key": getenv("AZURE_PUB_KEY", None),
        "vnet_name": getenv("AZURE_VNET_NAME", "osm_vnet"),
    }

    azure = vimconnector(
        vim_id,
        vim_name,
        tenant_id=test_params["tenant"],
        tenant_name=None,
        url=None,
        url_admin=None,
        user=test_params["client_id"],
        passwd=test_params["secret"],
        log_level=None,
        config=config,
    )

    """
    logger.debug("List images")
    image = azure.get_image_list({"name": "Canonical:UbuntuServer:18.04-LTS:18.04.201809110"})
    logger.debug("image: {}".format(image))

    logger.debug("List networks")
    network_list = azure.get_network_list({"name": "internal"})
    logger.debug("Network_list: {}".format(network_list))

    logger.debug("List flavors")
    flavors = azure.get_flavor_id_from_data({"vcpus": 2})
    logger.debug("flavors: {}".format(flavors))
    """

    """
    # Create network and test machine
    #new_network_id, _ = azure.new_network("testnet1", "data")
    new_network_id = ("/subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}/providers")
                      "/Microsoft.Network/virtualNetworks/osm_vnet/subnets/testnet1"
                      ).format(test_params["resource_group"])
    logger.debug("new_network_id: {}".format(new_network_id))

    logger.debug("Delete network")
    new_network_id = azure.delete_network(new_network_id)
    logger.debug("deleted network_id: {}".format(new_network_id))
    """

    """
    logger.debug("List networks")
    network_list = azure.get_network_list({"name": "internal"})
    logger.debug("Network_list: {}".format(network_list))
    
    logger.debug("Show machine isabelvm")
    vmachine = azure.get_vminstance( ("/subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}"
                                      "/providers/Microsoft.Compute/virtualMachines/isabelVM"
                                      ).format(test_params["resource_group"])
                                    )
    logger.debug("Vmachine: {}".format(vmachine))
    """

    """
    logger.debug("List images")
    image = azure.get_image_list({"name": "Canonical:UbuntuServer:16.04"})
    # image = azure.get_image_list({"name": "Canonical:UbuntuServer:18.04-LTS"})
    logger.debug("image: {}".format(image))
    """

    """
    # Create network and test machine
    new_network_id, _ = azure.new_network("testnet1", "data")
    image_id = ("/Subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/Providers/Microsoft.Compute"
                "/Locations/northeurope/Publishers/Canonical/ArtifactTypes/VMImage/Offers/UbuntuServer"
                "/Skus/18.04-LTS/Versions/18.04.201809110")
    """
    """
    
    network_id = ("subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}
                  "/providers/Microsoft.Network/virtualNetworks/osm_vnet/subnets/internal"
                 ).format(test_params["resource_group"])
    """

    """
    logger.debug("Create machine")
    image_id = ("/Subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/Providers/Microsoft.Compute/Locations"
                "/northeurope/Publishers/Canonical/ArtifactTypes/VMImage/Offers/UbuntuServer/Skus/18.04-LTS"
                "/Versions/18.04.202103151")
    cloud_config = {"user-data": (
                    "#cloud-config\n"
                    "password: osm4u\n"
                    "chpasswd: { expire: False }\n"
                    "ssh_pwauth: True\n\n"
                    "write_files:\n"
                    "-   content: |\n"
                    "        # My new helloworld file\n\n"
                    "    owner: root:root\n"
                    "    permissions: '0644'\n"
                    "    path: /root/helloworld.txt",
                    "key-pairs": [
                        ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/p7fuw/W0+6uhx9XNPY4dN/K2cXZweDfjJN8W/sQ1AhKvn"
                         "j0MF+dbBdsd2tfq6XUhx5LiKoGTunRpRonOw249ivH7pSyNN7FYpdLaij7Krn3K+QRNEOahMI4eoqdglVftA3"
                         "vlw4Oe/aZOU9BXPdRLxfr9hRKzg5zkK91/LBkEViAijpCwK6ODPZLDDUwY4iihYK9R5eZ3fmM4+3k3Jd0hPRk"
                         "B5YbtDQOu8ASWRZ9iTAWqr1OwQmvNc6ohSVg1tbq3wSxj/5bbz0J24A7TTpY0giWctne8Qkl/F2e0ZSErvbBB"
                         "GXKxfnq7sc23OK1hPxMAuS+ufzyXsnL1+fB4t2iF azureuser@osm-test-client\n"
                        )]
    }
    network_id = ("subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}/providers"
                  "/Microsoft.Network/virtualNetworks/osm_vnet/subnets/internal"
                 ).format(test_params["resource_group"])
    vm = azure.new_vminstance(name="isabelvm",
                            description="testvm",
                            start=True,
                            image_id=image_id,
                            flavor_id="Standard_B1ls",
                            net_list = [{"net_id": network_id, "name": "internal", "use": "mgmt", "floating_ip":True}],
                            cloud_config = cloud_config)
    logger.debug("vm: {}".format(vm))
    """

    """
    # Delete nonexistent vm
    try:
        logger.debug("Delete machine")
        vm_id = ("/subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}/providers/Microsoft.Compute/"
                "virtualMachines/isabelvm"
                ).format(test_params["resource_group"])
        created_items = {
            ("/subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}/providers/Microsoft.Network"
             "/networkInterfaces/isabelvm-nic-0"
            ).format(test_params["resource_group"]): True,
            ("/subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}/providers/Microsoft.Network"
             "/publicIPAddresses/isabelvm-nic-0-public-ip"
            ).format(test_params["resource_group"]): True
        }
        azure.delete_vminstance(vm_id, created_items)
    except vimconn.VimConnNotFoundException as e:
        print("Ok: excepcion no encontrada")
    """

    """
    network_id = ("/subscriptions/5c1a2458-dfde-4adf-a4e3-08fa0e21d171/resourceGroups/{}/providers/Microsoft.Network"
                  "/virtualNetworks/osm_vnet/subnets/hfcloudinit-internal-1"
                 ).format(test_params["resource_group"])
    azure.delete_network(network_id)
    """
