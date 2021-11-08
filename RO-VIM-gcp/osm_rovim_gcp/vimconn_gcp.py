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
from osm_ro_plugin import vimconn
import logging
import time
import random
from random import choice as random_choice
from os import getenv

from google.api_core.exceptions import NotFound
import googleapiclient.discovery
from google.oauth2 import service_account

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

import logging

__author__ = "Sergio Gallardo Ruiz"
__date__ = "$11-aug-2021 08:30:00$"


if getenv("OSMRO_PDB_DEBUG"):
    import sys

    print(sys.path)
    import pdb

    pdb.set_trace()


class vimconnector(vimconn.VimConnector):

    # Translate Google Cloud provisioning state to OSM provision state
    # The first three ones are the transitional status once a user initiated action has been requested
    # Once the operation is complete, it will transition into the states Succeeded or Failed
    # https://cloud.google.com/compute/docs/instances/instance-life-cycle
    provision_state2osm = {
        "PROVISIONING": "BUILD",
        "REPAIRING": "ERROR",
    }

    # Translate azure power state to OSM provision state
    power_state2osm = {
        "STAGING": "BUILD",
        "RUNNING": "ACTIVE",
        "STOPPING": "INACTIVE",
        "SUSPENDING": "INACTIVE",
        "SUSPENDED": "INACTIVE",
        "TERMINATED": "INACTIVE",
    }

    # If a net or subnet is tried to be deleted and it has an associated resource, the net is marked "to be deleted"
    # (incluid it's name in the following list). When the instance is deleted, its associated net will be deleted if
    # they are present in that list
    nets_to_be_deleted = []

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
        subscription_id: assigned subscription identifier
        region_name: current region for network
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
        self.reload_client = False

        # LOGGER

        log_format_simple = (
            "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(message)s"
        )
        log_format_complete = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
        log_formatter_simple = logging.Formatter(
            log_format_simple, datefmt="%Y-%m-%dT%H:%M:%S"
        )
        self.handler = logging.StreamHandler()
        self.handler.setFormatter(log_formatter_simple)

        self.logger = logging.getLogger("ro.vim.gcp")
        self.logger.addHandler(self.handler)
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

        if self.logger.getEffectiveLevel() == logging.DEBUG:
            log_formatter = logging.Formatter(
                log_format_complete, datefmt="%Y-%m-%dT%H:%M:%S"
            )
            self.handler.setFormatter(log_formatter)

        self.logger.debug("Google Cloud connection init")

        self.project = tenant_id or tenant_name

        # REGION - Google Cloud considers regions and zones. A specific region can have more than one zone
        # (for instance: region us-west1 with the zones us-west1-a, us-west1-b and us-west1-c)
        # So the region name specified in the config will be considered as a specific zone for GC and
        # the region will be calculated from that without the preffix.
        if "region_name" in config:
            self.zone = config.get("region_name")
            self.region = self.zone.rsplit("-", 1)[0]
        else:
            raise vimconn.VimConnException(
                "Google Cloud region_name is not specified at config"
            )

        # Credentials
        self.logger.debug("Config: %s", config)
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        self.credentials = None
        if (
            "credentials" in config
        ):
            self.logger.debug("Setting credentials")
            # Settings Google Cloud credentials dict
            credentials_body = config["credentials"]
            # self.logger.debug("Credentials filtered: %s", credentials_body)
            credentials = service_account.Credentials.from_service_account_info(
                credentials_body
            )
            if "sa_file" in config:
                credentials = service_account.Credentials.from_service_account_file(
                    config.get("sa_file"), scopes=scopes
                )
                self.logger.debug("Credentials: %s", credentials)
            # Construct a Resource for interacting with an API.
            self.credentials = credentials
            try:
                self.conn_compute = googleapiclient.discovery.build(
                    "compute", "v1", credentials=credentials
                )
            except Exception as e:
                self._format_vimconn_exception(e)
        else:
            raise vimconn.VimConnException(
                "It is not possible to init GCP with no credentials"
            )

    def _reload_connection(self):
        """
        Called before any operation, checks python Google Cloud clientsself.reload_client
        """
        if self.reload_client:
            self.logger.debug("reloading google cloud client")

            try:
                # Set to client created
                self.conn_compute = googleapiclient.discovery.build("compute", "v1")
            except Exception as e:
                self._format_vimconn_exception(e)

    def _format_vimconn_exception(self, e):
        """
        Transforms a generic exception to a vimConnException
        """
        self.logger.error("Google Cloud plugin error: {}".format(e))
        if isinstance(e, vimconn.VimConnException):
            raise e
        else:
            # In case of generic error recreate client
            self.reload_client = True
            raise vimconn.VimConnException(type(e).__name__ + ": " + str(e))

    def _wait_for_global_operation(self, operation):
        """
        Waits for the end of the specific operation
        :operation: operation name
        """

        self.logger.debug("Waiting for operation %s", operation)

        while True:
            result = (
                self.conn_compute.globalOperations()
                .get(project=self.project, operation=operation)
                .execute()
            )

            if result["status"] == "DONE":
                if "error" in result:
                    raise vimconn.VimConnException(result["error"])
                return result

            time.sleep(1)

    def _wait_for_zone_operation(self, operation):
        """
        Waits for the end of the specific operation
        :operation: operation name
        """

        self.logger.debug("Waiting for operation %s", operation)

        while True:
            result = (
                self.conn_compute.zoneOperations()
                .get(project=self.project, operation=operation, zone=self.zone)
                .execute()
            )

            if result["status"] == "DONE":
                if "error" in result:
                    raise vimconn.VimConnException(result["error"])
                return result

            time.sleep(1)

    def _wait_for_region_operation(self, operation):
        """
        Waits for the end of the specific operation
        :operation: operation name
        """

        self.logger.debug("Waiting for operation %s", operation)

        while True:
            result = (
                self.conn_compute.regionOperations()
                .get(project=self.project, operation=operation, region=self.region)
                .execute()
            )

            if result["status"] == "DONE":
                if "error" in result:
                    raise vimconn.VimConnException(result["error"])
                return result

            time.sleep(1)

    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):
        """
        Adds a network to VIM
        :param net_name: name of the network
        :param net_type: not used for Google Cloud networks
        :param ip_profile: not used for Google Cloud networks
        :param shared: Not allowed for Google Cloud Connector
        :param provider_network_profile: (optional)

         contains {segmentation-id: vlan, provider-network: vim_netowrk}
        :return: a tuple with the network identifier and created_items, or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_network. Can be used to store created segments, created l2gw connections, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """

        self.logger.debug(
            "new_network begin: net_name %s net_type %s ip_profile %s shared %s provider_network_profile %s",
            net_name,
            net_type,
            ip_profile,
            shared,
            provider_network_profile,
        )
        net_name = self._check_vm_name(net_name)
        net_name = self._randomize_name(net_name)
        self.logger.debug("create network name %s, ip_profile %s", net_name, ip_profile)

        try:

            self.logger.debug("creating network_name: {}".format(net_name))

            network = "projects/{}/global/networks/default".format(self.project)
            subnet_address = ""
            if ip_profile is not None:
                if "subnet_address" in ip_profile:
                    subnet_address = ip_profile["subnet_address"]
            network_body = {
                "name": str(net_name),
                "description": net_name,
                "network": network,
                "ipCidrRange": subnet_address,
                # "autoCreateSubnetworks": True, # The network is created in AUTO mode (one subnet per region is created)
                "autoCreateSubnetworks": False,
            }

            operation = (
                self.conn_compute.networks()
                .insert(project=self.project, body=network_body)
                .execute()
            )
            self._wait_for_global_operation(operation["name"])
            self.logger.debug("created network_name: {}".format(net_name))

            # Adding firewall rules to allow the traffic in the network:
            rules_list = self._create_firewall_rules(net_name)

            # create subnetwork, even if there is no profile

            if not ip_profile:
                ip_profile = {}

            if not ip_profile.get("subnet_address"):
                # Fake subnet is required
                subnet_rand = random.randint(0, 255)
                ip_profile["subnet_address"] = "192.168.{}.0/24".format(subnet_rand)

            subnet_name = net_name + "-subnet"
            subnet_id = self._new_subnet(
                subnet_name, ip_profile, operation["targetLink"]
            )

            self.logger.debug("new_network Return: subnet_id: %s", subnet_id)
            return subnet_id
        except Exception as e:
            self._format_vimconn_exception(e)

    def _new_subnet(self, subnet_name, ip_profile, network):
        """
        Adds a tenant network to VIM. It creates a new subnet at existing base vnet
        :param net_name: subnet name
        :param ip_profile:
                subnet-address: if it is not provided a subnet/24 in the default vnet is created,
                otherwise it creates a subnet in the indicated address
        :return: a tuple with the network identifier and created_items, or raises an exception on error
        """
        self.logger.debug(
            "_new_subnet begin: subnet_name %s ip_profile %s network %s",
            subnet_name,
            ip_profile,
            network,
        )
        self.logger.debug(
            "create subnet name %s, ip_profile %s", subnet_name, ip_profile
        )

        try:

            self.logger.debug("creating subnet_name: {}".format(subnet_name))

            subnetwork_body = {
                "name": str(subnet_name),
                "description": subnet_name,
                "network": network,
                "ipCidrRange": ip_profile["subnet_address"],
            }

            operation = (
                self.conn_compute.subnetworks()
                .insert(
                    project=self.project,
                    region=self.region,
                    body=subnetwork_body,
                )
                .execute()
            )
            self._wait_for_region_operation(operation["name"])

            self.logger.debug("created subnet_name: {}".format(subnet_name))

            self.logger.debug(
                "_new_subnet Return: (%s,%s)",
                "regions/%s/subnetworks/%s" % (self.region, subnet_name),
                None,
            )
            return "regions/%s/subnetworks/%s" % (self.region, subnet_name), None
        except Exception as e:
            self._format_vimconn_exception(e)

    def get_network_list(self, filter_dict={}):
        """Obtain tenant networks of VIM
        Filter_dict can be:
            name: network name
            id: network id
            shared: boolean, not implemented in GC
            tenant_id: tenant, not used in GC, all networks same tenants
            admin_state_up: boolean, not implemented in GC
            status: 'ACTIVE', not implemented in GC #
        Returns the network list of dictionaries
        """
        self.logger.debug("get_network_list begin: filter_dict %s", filter_dict)
        self.logger.debug(
            "Getting network (subnetwork) from VIM filter: {}".format(str(filter_dict))
        )

        try:

            if self.reload_client:
                self._reload_connection()

            net_list = []

            request = self.conn_compute.subnetworks().list(
                project=self.project, region=self.region
            )

            while request is not None:
                response = request.execute()
                self.logger.debug("Network list: %s", response)
                for net in response["items"]:
                    self.logger.debug("Network in list: {}".format(str(net["name"])))
                    if filter_dict is not None:
                        if "name" in filter_dict.keys():
                            if (
                                filter_dict["name"] == net["name"]
                                or filter_dict["name"] == net["selfLink"]
                            ):
                                self.logger.debug("Network found: %s", net["name"])
                                net_list.append(
                                    {
                                        "id": str(net["selfLink"]),
                                        "name": str(net["name"]),
                                        "network": str(net["network"]),
                                    }
                                )
                    else:
                        net_list.append(
                            {
                                "id": str(net["selfLink"]),
                                "name": str(net["name"]),
                                "network": str(net["network"]),
                            }
                        )
                request = self.conn_compute.subnetworks().list_next(
                    previous_request=request, previous_response=response
                )

            self.logger.debug("get_network_list Return: net_list %s", net_list)
            return net_list

        except Exception as e:
            self.logger.error("Error in get_network_list()", exc_info=True)
            raise vimconn.VimConnException(e)

    def get_network(self, net_id):
        self.logger.debug("get_network begin: net_id %s", net_id)
        # res_name = self._get_resource_name_from_resource_id(net_id)
        self._reload_connection()

        self.logger.debug("Get network: %s", net_id)
        filter_dict = {"name": net_id}
        network_list = self.get_network_list(filter_dict)
        self.logger.debug("Network list: %s", network_list)

        if not network_list:
            return []
        else:
            self.logger.debug(
                "get_network Return: network_list[0] %s", network_list[0]
            )
            return network_list[0]

    def delete_network(self, net_id, created_items=None):
        """
        Removes a tenant network from VIM and its associated elements
        :param net_id: VIM identifier of the network, provided by method new_network
        :param created_items: dictionary with extra items to be deleted. provided by method new_network
        Returns the network identifier or raises an exception upon error or when network is not found
        """

        self.logger.debug(
            "delete_network begin: net_id %s created_items %s",
            net_id,
            created_items,
        )
        self.logger.debug("Deleting network: {}".format(str(net_id)))

        try:

            net_name = self._get_resource_name_from_resource_id(net_id)

            # Check associated VMs
            vms = (
                self.conn_compute.instances()
                .list(project=self.project, zone=self.zone)
                .execute()
            )

            net_id = self.delete_subnet(net_name, created_items)

            self.logger.debug("delete_network Return: net_id %s", net_id)
            return net_id

        except Exception as e:
            self.logger.error("Error in delete_network()", exc_info=True)
            raise vimconn.VimConnException(e)

    def delete_subnet(self, net_id, created_items=None):
        """
        Removes a tenant network from VIM and its associated elements
        :param net_id: VIM identifier of the network, provided by method new_network
        :param created_items: dictionary with extra items to be deleted. provided by method new_network
        Returns the network identifier or raises an exception upon error or when network is not found
        """

        self.logger.debug(
            "delete_subnet begin: net_id %s created_items %s",
            net_id,
            created_items,
        )
        self.logger.debug("Deleting subnetwork: {}".format(str(net_id)))

        try:
            # If the network has no more subnets, it will be deleted too
            net_info = self.get_network(net_id)
            # If the subnet is in use by another resource, the deletion will be retried N times before abort the operation
            created_items = created_items or {}
            created_items[net_id] = False

            try:
                operation = (
                    self.conn_compute.subnetworks()
                    .delete(
                        project=self.project,
                        region=self.region,
                        subnetwork=net_id,
                    )
                    .execute()
                )
                self._wait_for_region_operation(operation["name"])
                if net_id in self.nets_to_be_deleted:
                    self.nets_to_be_deleted.remove(net_id)
            except Exception as e:
                if (
                    e.args[0]["status"] == "400"
                ):  # Resource in use, so the net is marked to be deleted
                    self.logger.debug("Subnet still in use")
                    self.nets_to_be_deleted.append(net_id)
                else:
                    raise vimconn.VimConnException(e)

            self.logger.debug("nets_to_be_deleted: %s", self.nets_to_be_deleted)

            # If the network has no more subnets, it will be deleted too
            # if "network" in net_info and net_id not in self.nets_to_be_deleted:
            if "network" in net_info:
                network_name = self._get_resource_name_from_resource_id(
                    net_info["network"]
                )

                try:
                    # Deletion of the associated firewall rules:
                    rules_list = self._delete_firewall_rules(network_name)

                    operation = (
                        self.conn_compute.networks()
                        .delete(
                            project=self.project,
                            network=network_name,
                        )
                        .execute()
                    )
                    self._wait_for_global_operation(operation["name"])
                except Exception as e:
                    self.logger.debug("error deleting associated network %s", e)

            self.logger.debug("delete_subnet Return: net_id %s", net_id)
            return net_id

        except Exception as e:
            self.logger.error("Error in delete_network()", exc_info=True)
            raise vimconn.VimConnException(e)

    def new_flavor(self, flavor_data):
        """
        It is not allowed to create new flavors (machine types) in Google Cloud, must always use an existing one
        """
        raise vimconn.VimConnNotImplemented(
            "It is not possible to create new flavors in Google Cloud"
        )

    def new_tenant(self, tenant_name, tenant_description):
        """
        It is not allowed to create new tenants in Google Cloud
        """
        raise vimconn.VimConnNotImplemented(
            "It is not possible to create a TENANT in Google Cloud"
        )

    def get_flavor(self, flavor_id):
        """
        Obtains the flavor_data from the flavor_id/machine type id
        """
        self.logger.debug("get_flavor begin: flavor_id %s", flavor_id)

        try:
            response = (
                self.conn_compute.machineTypes()
                .get(project=self.project, zone=self.zone, machineType=flavor_id)
                .execute()
            )
            flavor_data = response
            self.logger.debug("Machine type data: %s", flavor_data)

            if flavor_data:
                flavor = {
                    "id": flavor_data["id"],
                    "name": flavor_id,
                    "id_complete": flavor_data["selfLink"],
                    "ram": flavor_data["memoryMb"],
                    "vcpus": flavor_data["guestCpus"],
                    "disk": flavor_data["maximumPersistentDisksSizeGb"],
                }

                self.logger.debug("get_flavor Return: flavor %s", flavor)
                return flavor
            else:
                raise vimconn.VimConnNotFoundException(
                    "flavor '{}' not found".format(flavor_id)
                )
        except Exception as e:
            self._format_vimconn_exception(e)

    # Google Cloud VM names can not have some special characters
    def _check_vm_name(self, vm_name):
        """
        Checks vm name, in case the vm has not allowed characters they are removed, not error raised
        Only lowercase and hyphens are allowed
        """
        chars_not_allowed_list = "~!@#$%^&*()=+_[]{}|;:<>/?."

        # First: the VM name max length is 64 characters
        vm_name_aux = vm_name[:62]

        # Second: replace not allowed characters
        for elem in chars_not_allowed_list:
            # Check if string is in the main string
            if elem in vm_name_aux:
                # self.logger.debug("Dentro del IF")
                # Replace the string
                vm_name_aux = vm_name_aux.replace(elem, "-")

        return vm_name_aux.lower()

    def get_flavor_id_from_data(self, flavor_dict):
        self.logger.debug(
            "get_flavor_id_from_data begin: flavor_dict %s", flavor_dict
        )
        filter_dict = flavor_dict or {}

        try:
            response = (
                self.conn_compute.machineTypes()
                .list(project=self.project, zone=self.zone)
                .execute()
            )
            machine_types_list = response["items"]
            # self.logger.debug("List of machine types: %s", machine_types_list)

            cpus = filter_dict.get("vcpus") or 0
            memMB = filter_dict.get("ram") or 0
            numberInterfaces = len(filter_dict.get("interfaces", [])) or 4 # Workaround (it should be 0)

            # Filter
            filtered_machines = []
            for machine_type in machine_types_list:
                if (
                    machine_type["guestCpus"] >= cpus
                    and machine_type["memoryMb"] >= memMB
                    # In Google Cloud the number of virtual network interfaces scales with
                    # the number of virtual CPUs with a minimum of 2 and a maximum of 8:
                    # https://cloud.google.com/vpc/docs/create-use-multiple-interfaces#max-interfaces
                    and machine_type["guestCpus"] >= numberInterfaces
                ):
                    filtered_machines.append(machine_type)

            # self.logger.debug("Filtered machines: %s", filtered_machines)

            # Sort
            listedFilteredMachines = sorted(
                filtered_machines,
                key=lambda k: (
                    int(k["guestCpus"]),
                    float(k["memoryMb"]),
                    int(k["maximumPersistentDisksSizeGb"]),
                    k["name"],
                ),
            )
            # self.logger.debug("Sorted filtered machines: %s", listedFilteredMachines)

            if listedFilteredMachines:
                self.logger.debug(
                    "get_flavor_id_from_data Return: listedFilteredMachines[0][name] %s",
                    listedFilteredMachines[0]["name"],
                )
                return listedFilteredMachines[0]["name"]

            raise vimconn.VimConnNotFoundException(
                "Cannot find any flavor matching '{}'".format(str(flavor_dict))
            )

        except Exception as e:
            self._format_vimconn_exception(e)

    def delete_flavor(self, flavor_id):
        raise vimconn.VimConnNotImplemented(
            "It is not possible to delete a flavor in Google Cloud"
        )

    def delete_tenant(self, tenant_id):
        raise vimconn.VimConnNotImplemented(
            "It is not possible to delete a TENANT in Google Cloud"
        )

    def new_image(self, image_dict):
        """
        This function comes from the early days when we though the image could be embedded in the package.
        Unless OSM manages VM images E2E from NBI to RO, this function does not make sense to be implemented.
        """
        raise vimconn.VimConnNotImplemented("Not implemented")

    def get_image_id_from_path(self, path):
        """
        This function comes from the early days when we though the image could be embedded in the package.
        Unless OSM manages VM images E2E from NBI to RO, this function does not make sense to be implemented.
        """
        raise vimconn.VimConnNotImplemented("Not implemented")

    def get_image_list(self, filter_dict={}):
        """Obtain tenant images from VIM
        Filter_dict can be:
            name: image name with the format: image project:image family:image version
            If some part of the name is provide ex: publisher:offer it will search all availables skus and version
            for the provided publisher and offer
            id: image uuid, currently not supported for azure
        Returns the image list of dictionaries:
            [{<the fields at Filter_dict plus some VIM specific>}, ...]
            List can be empty
        """
        self.logger.debug("get_image_list begin: filter_dict %s", filter_dict)

        try:
            image_list = []
            # Get image id from parameter image_id:
            #    <image Project>:image-family:<family> => Latest version of the family
            #    <image Project>:image:<image>         => Specific image
            #    <image Project>:<image>               => Specific image

            image_info = filter_dict["name"].split(":")
            image_project = image_info[0]
            if len(image_info) == 2:
                image_type = "image"
                image_item = image_info[1]
            if len(image_info) == 3:
                image_type = image_info[1]
                image_item = image_info[2]
            else:
                raise vimconn.VimConnNotFoundException("Wrong format for image")

            image_response = {}
            if image_type == "image-family":
                image_response = (
                    self.conn_compute.images()
                    .getFromFamily(project=image_project, family=image_item)
                    .execute()
                )
            elif image_type == "image":
                image_response = (
                    self.conn_compute.images()
                    .get(project=image_project, image=image_item)
                    .execute()
                )
            else:
                raise vimconn.VimConnNotFoundException("Wrong format for image")
            image_list.append(
                {
                    "id": "projects/%s/global/images/%s"
                    % (image_project, image_response["name"]),
                    "name": ":".join(
                        [image_project, image_item, image_response["name"]]
                    ),
                }
            )

            self.logger.debug("get_image_list Return: image_list %s", image_list)
            return image_list

        except Exception as e:
            self._format_vimconn_exception(e)

    def delete_inuse_nic(self, nic_name):
        raise vimconn.VimConnNotImplemented("Not necessary")

    def delete_image(self, image_id):
        raise vimconn.VimConnNotImplemented("Not implemented")

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        """Send and action over a VM instance from VIM
        Returns the vm_id if the action was successfully sent to the VIM
        """
        raise vimconn.VimConnNotImplemented("Not necessary")

    def _randomize_name(self, name):
        """Adds a random string to allow requests with the same VM name
        Returns the name with an additional random string (if the total size is bigger
        than 62 the original name will be truncated)
        """
        random_name = name

        while True:
            try:
                random_name = (
                    name[:49]
                    + "-"
                    + "".join(random_choice("0123456789abcdef") for _ in range(12))
                )
                response = (
                    self.conn_compute.instances()
                    .get(project=self.project, zone=self.zone, instance=random_name)
                    .execute()
                )
                # If no exception is arisen, the random name exists for an instance, so a new random name must be generated

            except Exception as e:
                if e.args[0]["status"] == "404":
                    self.logger.debug("New random name: %s", random_name)
                    break
                else:
                    self.logger.error("Exception generating random name (%s) for the instance", name)
                    self._format_vimconn_exception(e)

        return random_name

    def new_vminstance(
        self,
        name,
        description,
        start,
        image_id=None,  # <image project>:(image|image-family):<image/family id>
        flavor_id=None,
        net_list=None,
        cloud_config=None,
        disk_list=None,
        availability_zone_index=None,
        availability_zone_list=None,
    ):
        self.logger.debug(
            "new_vminstance begin: name: %s, image_id: %s, flavor_id: %s, net_list: %s, cloud_config: %s, "
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

        if self.reload_client:
            self._reload_connection()

        # Validate input data is valid
        # # First of all, the name must be adapted because Google Cloud only allows names consist of
        # lowercase letters (a-z), numbers and hyphens (?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)
        vm_name = self._check_vm_name(name)
        vm_name = self._randomize_name(vm_name)
        vm_id = None

        # At least one network must be provided
        if not net_list:
            raise vimconn.VimConnException(
                "At least one net must be provided to create a new VM"
            )

        try:
            created_items = {}
            metadata = self._build_metadata(vm_name, cloud_config)

            # Building network interfaces list
            network_interfaces = []
            for net in net_list:
                net_iface = {}
                if not net.get("net_id"):
                    if not net.get("name"):
                        continue
                    else:
                        net_iface[
                            "subnetwork"
                        ] = "regions/%s/subnetworks/" % self.region + net.get("name")
                else:
                    net_iface["subnetwork"] = net.get("net_id")
                # In order to get an external IP address, the key "accessConfigs" must be used
                # in the interace. It has to be of type "ONE_TO_ONE_NAT" and name "External NAT"
                if net.get("floating_ip", False) or (net["use"] == "mgmt" and self.config.get("use_floating_ip")):
                    net_iface["accessConfigs"] = [
                        {"type": "ONE_TO_ONE_NAT", "name": "External NAT"}
                    ]

                network_interfaces.append(net_iface)

            self.logger.debug("Network interfaces: %s", network_interfaces)

            self.logger.debug("Source image: %s", image_id)

            vm_parameters = {
                "name": vm_name,
                "machineType": self.get_flavor(flavor_id)["id_complete"],
                # Specify the boot disk and the image to use as a source.
                "disks": [
                    {
                        "boot": True,
                        "autoDelete": True,
                        "initializeParams": {
                            "sourceImage": image_id,
                        },
                    }
                ],
                # Specify the network interfaces
                "networkInterfaces": network_interfaces,
                "metadata": metadata,
            }

            response = (
                self.conn_compute.instances()
                .insert(project=self.project, zone=self.zone, body=vm_parameters)
                .execute()
            )
            self._wait_for_zone_operation(response["name"])

            # The created instance info is obtained to get the name of the generated network interfaces (nic0, nic1...)
            response = (
                self.conn_compute.instances()
                .get(project=self.project, zone=self.zone, instance=vm_name)
                .execute()
            )
            self.logger.debug("instance get: %s", response)
            vm_id = response["name"]

            # The generated network interfaces in the instance are include in net_list:
            for _, net in enumerate(net_list):
                for net_ifaces in response["networkInterfaces"]:
                    network_id = ""
                    if "net_id" in net:
                        network_id = self._get_resource_name_from_resource_id(
                            net["net_id"]
                        )
                    else:
                        network_id = self._get_resource_name_from_resource_id(
                            net["name"]
                        )
                    if network_id == self._get_resource_name_from_resource_id(
                        net_ifaces["subnetwork"]
                    ):
                        net["vim_id"] = net_ifaces["name"]

            self.logger.debug(
                "new_vminstance Return: (name %s, created_items %s)",
                vm_name,
                created_items,
            )
            return vm_name, created_items

        except Exception as e:
            # Rollback vm creacion
            if vm_id is not None:
                try:
                    self.logger.debug("exception creating vm try to rollback")
                    self.delete_vminstance(vm_id, created_items)
                except Exception as e2:
                    self.logger.error("new_vminstance rollback fail {}".format(e2))

            else:
                self.logger.debug("Exception creating new vminstance: %s", e, exc_info=True)
                self._format_vimconn_exception(e)


    def _build_metadata(self, vm_name, cloud_config):

        # initial metadata
        metadata = {}
        metadata["items"] = []
        key_pairs = {}

        # if there is a cloud-init load it
        if cloud_config:
            self.logger.debug("cloud config: %s", cloud_config)
            _, userdata = self._create_user_data(cloud_config)
            metadata["items"].append(
                {"key": "user-data", "value": userdata}
            )

        # either password of ssh-keys are required
        # we will always use ssh-keys, in case it is not available we will generate it
        """
        if cloud_config and cloud_config.get("key-pairs"):
            key_data = ""
            key_pairs = {}
            if cloud_config.get("key-pairs"):
                if isinstance(cloud_config["key-pairs"], list):
                    # Transform the format "<key> <user@host>" into "<user>:<key>"
                    key_data = ""
                    for key in cloud_config.get("key-pairs"):
                        key_data = key_data + key + "\n"
                    key_pairs = {
                        "key": "ssh-keys",
                        "value": key_data
                    }
        else:
            # If there is no ssh key in cloud config, a new key is generated:
            _, key_data = self._generate_keys()
            key_pairs = {
                "key": "ssh-keys",
                "value": "" + key_data
            }
            self.logger.debug("generated keys: %s", key_data)

        metadata["items"].append(key_pairs)
        """
        self.logger.debug("metadata: %s", metadata)

        return metadata


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
        all_vms = (
            self.conn_compute.instances()
            .list(project=self.project, zone=self.zone)
            .execute()
        )
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

    def get_vminstance(self, vm_id):
        """
        Obtaing the vm instance data from v_id
        """
        self.logger.debug("get_vminstance begin: vm_id %s", vm_id)
        self._reload_connection()
        response = {}
        try:
            response = (
                self.conn_compute.instances()
                .get(project=self.project, zone=self.zone, instance=vm_id)
                .execute()
            )
            # vm = response["source"]
        except Exception as e:
            self._format_vimconn_exception(e)

        self.logger.debug("get_vminstance Return: response %s", response)
        return response

    def delete_vminstance(self, vm_id, created_items=None):
        """Deletes a vm instance from the vim."""
        self.logger.debug(
            "delete_vminstance begin: vm_id %s created_items %s",
            vm_id,
            created_items,
        )
        if self.reload_client:
            self._reload_connection()

        created_items = created_items or {}
        try:
            vm = self.get_vminstance(vm_id)

            operation = (
                self.conn_compute.instances()
                .delete(project=self.project, zone=self.zone, instance=vm_id)
                .execute()
            )
            self._wait_for_zone_operation(operation["name"])

            # The associated subnets must be checked if they are marked to be deleted
            for netIface in vm["networkInterfaces"]:
                if (
                    self._get_resource_name_from_resource_id(netIface["subnetwork"])
                    in self.nets_to_be_deleted
                ):
                    net_id = self._get_resource_name_from_resource_id(
                        self.delete_network(netIface["subnetwork"])
                    )

            self.logger.debug("delete_vminstance end")

        except Exception as e:
            # The VM can be deleted previously during network deletion
            if e.args[0]["status"] == "404":
                self.logger.debug("The VM doesn't exist or has been deleted")
            else:
                self._format_vimconn_exception(e)

    def _get_net_name_from_resource_id(self, resource_id):
        try:
            net_name = str(resource_id.split("/")[-1])

            return net_name
        except Exception:
            raise vimconn.VimConnException(
                "Unable to get google cloud net_name from invalid resource_id format '{}'".format(
                    resource_id
                )
            )

    def _get_resource_name_from_resource_id(self, resource_id):
        """
        Obtains resource_name from the google cloud complete identifier: resource_name will always be last item
        """
        self.logger.debug(
            "_get_resource_name_from_resource_id begin: resource_id %s",
            resource_id,
        )
        try:
            resource = str(resource_id.split("/")[-1])

            self.logger.debug(
                "_get_resource_name_from_resource_id Return: resource %s",
                resource,
            )
            return resource
        except Exception as e:
            raise vimconn.VimConnException(
                "Unable to get resource name from resource_id '{}' Error: '{}'".format(
                    resource_id, e
                )
            )

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
        self.logger.debug("refresh_nets_status begin: net_list %s", net_list)
        out_nets = {}
        self._reload_connection()

        for net_id in net_list:
            try:
                netName = self._get_net_name_from_resource_id(net_id)
                resName = self._get_resource_name_from_resource_id(net_id)

                net = (
                    self.conn_compute.subnetworks()
                    .get(project=self.project, region=self.region, subnetwork=resName)
                    .execute()
                )
                self.logger.debug("get subnetwork: %s", net)

                out_nets[net_id] = {
                    "status": "ACTIVE",  # Google Cloud does not provide the status in subnetworks getting
                    "vim_info": str(net),
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

        self.logger.debug("refresh_nets_status Return: out_nets %s", out_nets)
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
        self.logger.debug("refresh_vms_status begin: vm_list %s", vm_list)
        out_vms = {}
        self._reload_connection()

        search_vm_list = vm_list or {}

        for vm_id in search_vm_list:
            out_vm = {}
            try:
                res_name = self._get_resource_name_from_resource_id(vm_id)

                vm = (
                    self.conn_compute.instances()
                    .get(project=self.project, zone=self.zone, instance=res_name)
                    .execute()
                )

                out_vm["vim_info"] = str(vm["name"])
                out_vm["status"] = self.provision_state2osm.get(vm["status"], "OTHER")

                # In Google Cloud the there is no difference between provision or power status,
                # so if provision status method doesn't return a specific state (OTHER), the
                # power method is called
                if out_vm["status"] == "OTHER":
                    out_vm["status"] = self.power_state2osm.get(vm["status"], "OTHER")

                network_interfaces = vm["networkInterfaces"]
                out_vm["interfaces"] = self._get_vm_interfaces_status(
                    vm_id, network_interfaces
                )
            except Exception as e:
                self.logger.error("Exception %s refreshing vm_status", e, exc_info=True)
                out_vm["status"] = "VIM_ERROR"
                out_vm["error_msg"] = str(e)
                out_vm["vim_info"] = None

            out_vms[vm_id] = out_vm

        self.logger.debug("refresh_vms_status Return: out_vms %s", out_vms)
        return out_vms

    def _get_vm_interfaces_status(self, vm_id, interfaces):
        """
        Gets the interfaces detail for a vm
        :param interfaces: List of interfaces.
        :return: Dictionary with list of interfaces including, vim_interface_id, mac_address and ip_address
        """
        self.logger.debug(
            "_get_vm_interfaces_status begin: vm_id %s interfaces %s",
            vm_id,
            interfaces,
        )
        try:
            interface_list = []
            for network_interface in interfaces:
                interface_dict = {}
                nic_name = network_interface["name"]
                interface_dict["vim_interface_id"] = network_interface["name"]

                ips = []
                ips.append(network_interface["networkIP"])
                interface_dict["ip_address"] = ";".join(ips)
                interface_list.append(interface_dict)

            self.logger.debug(
                "_get_vm_interfaces_status Return: interface_list %s",
                interface_list,
            )
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

    def _create_firewall_rules(self, network):
        """
        Creates the necessary firewall rules to allow the traffic in the network
        (https://cloud.google.com/vpc/docs/firewalls)
        :param network.
        :return: a list with the names of the firewall rules
        """
        self.logger.debug("_create_firewall_rules begin: network %s", network)
        try:
            rules_list = []

            # Adding firewall rule to allow http:
            self.logger.debug("creating firewall rule to allow http")
            firewall_rule_body = {
                "name": "fw-rule-http-" + network,
                "network": "global/networks/" + network,
                "allowed": [{"IPProtocol": "tcp", "ports": ["80"]}],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            # Adding firewall rule to allow ssh:
            self.logger.debug("creating firewall rule to allow ssh")
            firewall_rule_body = {
                "name": "fw-rule-ssh-" + network,
                "network": "global/networks/" + network,
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            # Adding firewall rule to allow ping:
            self.logger.debug("creating firewall rule to allow ping")
            firewall_rule_body = {
                "name": "fw-rule-icmp-" + network,
                "network": "global/networks/" + network,
                "allowed": [{"IPProtocol": "icmp"}],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            # Adding firewall rule to allow internal:
            self.logger.debug("creating firewall rule to allow internal")
            firewall_rule_body = {
                "name": "fw-rule-internal-" + network,
                "network": "global/networks/" + network,
                "allowed": [
                    {"IPProtocol": "tcp", "ports": ["0-65535"]},
                    {"IPProtocol": "udp", "ports": ["0-65535"]},
                    {"IPProtocol": "icmp"},
                ],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            # Adding firewall rule to allow microk8s:
            self.logger.debug("creating firewall rule to allow microk8s")
            firewall_rule_body = {
                "name": "fw-rule-microk8s-" + network,
                "network": "global/networks/" + network,
                "allowed": [{"IPProtocol": "tcp", "ports": ["16443"]}],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            # Adding firewall rule to allow rdp:
            self.logger.debug("creating firewall rule to allow rdp")
            firewall_rule_body = {
                "name": "fw-rule-rdp-" + network,
                "network": "global/networks/" + network,
                "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            # Adding firewall rule to allow osm:
            self.logger.debug("creating firewall rule to allow osm")
            firewall_rule_body = {
                "name": "fw-rule-osm-" + network,
                "network": "global/networks/" + network,
                "allowed": [{"IPProtocol": "tcp", "ports": ["9001", "9999"]}],
            }
            operation_firewall = (
                self.conn_compute.firewalls()
                .insert(project=self.project, body=firewall_rule_body)
                .execute()
            )

            self.logger.debug(
                "_create_firewall_rules Return: list_rules %s", rules_list
            )
            return rules_list
        except Exception as e:
            self.logger.error(
                "Unable to create google cloud firewall rules for network '{}'".format(
                    network
                )
            )
            self._format_vimconn_exception(e)

    def _delete_firewall_rules(self, network):
        """
        Deletes the associated firewall rules to the network
        :param network.
        :return: a list with the names of the firewall rules
        """
        self.logger.debug("_delete_firewall_rules begin: network %s", network)
        try:
            rules_list = []

            rules_list = (
                self.conn_compute.firewalls().list(project=self.project).execute()
            )
            for item in rules_list["items"]:
                if network == self._get_resource_name_from_resource_id(item["network"]):
                    operation_firewall = (
                        self.conn_compute.firewalls()
                        .delete(project=self.project, firewall=item["name"])
                        .execute()
                    )

            self.logger.debug("_delete_firewall_rules Return: list_rules %s", 0)
            return rules_list
        except Exception as e:
            self.logger.error(
                "Unable to delete google cloud firewall rules for network '{}'".format(
                    network
                )
            )
            self._format_vimconn_exception(e)

