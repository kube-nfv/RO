# -*- coding: utf-8 -*-

##
# Copyright 2017 xFlow Research Pvt. Ltd
# This file is part of openmano
# All Rights Reserved.
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
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact with: saboor.ahmad@xflowresearch.com
##

"""
AWS-connector implements all the methods to interact with AWS using the BOTO client
"""
import logging
import random
import time
import traceback

import boto
import boto.ec2
from boto.exception import BotoServerError, EC2ResponseError
import boto.vpc
from ipconflict import check_conflicts
import netaddr
from osm_ro_plugin import vimconn
import yaml

__author__ = "Saboor Ahmad"
__date__ = "10-Apr-2017"


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
        """Params:
        uuid - id asigned to this VIM
        name - name assigned to this VIM, can be used for logging
        tenant_id - ID to be used for tenant
        tenant_name - name of tenant to be used VIM tenant to be used
        url_admin - optional, url used for administrative tasks
        user - credentials of the VIM user
        passwd - credentials of the VIM user
        log_level - if must use a different log_level than the general one
        config - dictionary with misc VIM information
            region_name - name of region to deploy the instances
            vpc_cidr_block - default CIDR block for VPC
            security_groups - default security group to specify this instance
        persistent_info - dict where the class can store information that will be available among class
            destroy/creation cycles. This info is unique per VIM/credential. At first call it will contain an
            empty dict. Useful to store login/tokens information for speed up communication
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

        self.persistent_info = persistent_info
        self.a_creds = {}

        if user:
            self.a_creds["aws_access_key_id"] = user
        else:
            raise vimconn.VimConnAuthException("Username is not specified")

        if passwd:
            self.a_creds["aws_secret_access_key"] = passwd
        else:
            raise vimconn.VimConnAuthException("Password is not specified")

        if "region_name" in config:
            self.region = config.get("region_name")
        else:
            raise vimconn.VimConnException("AWS region_name is not specified at config")

        self.vpc_data = {}
        self.subnet_data = {}
        self.conn = None
        self.conn_vpc = None
        self.account_id = None
        self.network_delete_on_termination = []
        self.server_timeout = 180

        self.vpc_id = self.get_tenant_list()[0]["id"]
        # we take VPC CIDR block if specified, otherwise we use the default CIDR
        # block suggested by AWS while creating instance
        self.vpc_cidr_block = "10.0.0.0/24"

        if tenant_name:
            self.vpc_id = tenant_name

        if "vpc_cidr_block" in config:
            self.vpc_cidr_block = config["vpc_cidr_block"]

        self.security_groups = None
        if "security_groups" in config:
            self.security_groups = config["security_groups"]

        self.key_pair = None
        if "key_pair" in config:
            self.key_pair = config["key_pair"]

        self.flavor_info = None
        if "flavor_info" in config:
            flavor_data = config.get("flavor_info")
            if isinstance(flavor_data, str):
                try:
                    if flavor_data[0] == "@":  # read from a file
                        with open(flavor_data[1:], "r") as stream:
                            self.flavor_info = yaml.safe_load(stream)
                    else:
                        self.flavor_info = yaml.safe_load(flavor_data)
                except yaml.YAMLError as e:
                    self.flavor_info = None

                    raise vimconn.VimConnException(
                        "Bad format at file '{}': {}".format(flavor_data[1:], e)
                    )
                except IOError as e:
                    raise vimconn.VimConnException(
                        "Error reading file '{}': {}".format(flavor_data[1:], e)
                    )
            elif isinstance(flavor_data, dict):
                self.flavor_info = flavor_data

        self.logger = logging.getLogger("ro.vim.aws")

        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

    def __setitem__(self, index, value):
        """Params:
        index - name of value of set
        value - value to set
        """
        if index == "user":
            self.a_creds["aws_access_key_id"] = value
        elif index == "passwd":
            self.a_creds["aws_secret_access_key"] = value
        elif index == "region":
            self.region = value
        else:
            vimconn.VimConnector.__setitem__(self, index, value)

    def _reload_connection(self):
        """Returns: sets boto.EC2 and boto.VPC connection to work with AWS services"""
        try:
            self.conn = boto.ec2.connect_to_region(
                self.region,
                aws_access_key_id=self.a_creds["aws_access_key_id"],
                aws_secret_access_key=self.a_creds["aws_secret_access_key"],
            )
            self.conn_vpc = boto.vpc.connect_to_region(
                self.region,
                aws_access_key_id=self.a_creds["aws_access_key_id"],
                aws_secret_access_key=self.a_creds["aws_secret_access_key"],
            )
            # client = boto3.client("sts", aws_access_key_id=self.a_creds['aws_access_key_id'],
            # aws_secret_access_key=self.a_creds['aws_secret_access_key'])
            # self.account_id = client.get_caller_identity()["Account"]
        except Exception as e:
            self.format_vimconn_exception(e)

    def format_vimconn_exception(self, e):
        """Params: an Exception object
        Returns: Raises the exception 'e' passed in mehtod parameters
        """
        self.conn = None
        self.conn_vpc = None

        raise vimconn.VimConnConnectionException(type(e).__name__ + ": " + str(e))

    def get_tenant_list(self, filter_dict={}):
        """Obtain tenants of VIM
        filter_dict dictionary that can contain the following keys:
            name: filter by tenant name
            id: filter by tenant uuid/id
            <other VIM specific>
        Returns the tenant list of dictionaries, and empty list if no tenant match all the filers:
            [{'name':'<name>, 'id':'<id>, ...}, ...]
        """
        try:
            self._reload_connection()
            vpc_ids = []

            if filter_dict != {}:
                if "id" in filter_dict:
                    vpc_ids.append(filter_dict["id"])

            tenants = self.conn_vpc.get_all_vpcs(vpc_ids, None)
            tenant_list = []

            for tenant in tenants:
                tenant_list.append(
                    {
                        "id": str(tenant.id),
                        "name": str(tenant.id),
                        "status": str(tenant.state),
                        "cidr_block": str(tenant.cidr_block),
                    }
                )

            return tenant_list
        except Exception as e:
            self.format_vimconn_exception(e)

    def new_tenant(self, tenant_name, tenant_description):
        """Adds a new tenant to VIM with this name and description, this is done using admin_url if provided
        "tenant_name": string max lenght 64
        "tenant_description": string max length 256
        returns the tenant identifier or raise exception
        """
        self.logger.debug("Adding a new VPC")

        try:
            self._reload_connection()
            vpc = self.conn_vpc.create_vpc(self.vpc_cidr_block)
            self.conn_vpc.modify_vpc_attribute(vpc.id, enable_dns_support=True)
            self.conn_vpc.modify_vpc_attribute(vpc.id, enable_dns_hostnames=True)

            gateway = self.conn_vpc.create_internet_gateway()
            self.conn_vpc.attach_internet_gateway(gateway.id, vpc.id)
            route_table = self.conn_vpc.create_route_table(vpc.id)
            self.conn_vpc.create_route(route_table.id, "0.0.0.0/0", gateway.id)

            self.vpc_data[vpc.id] = {
                "gateway": gateway.id,
                "route_table": route_table.id,
                "subnets": self.subnet_sizes(self.vpc_cidr_block),
            }

            return vpc.id
        except Exception as e:
            self.format_vimconn_exception(e)

    def delete_tenant(self, tenant_id):
        """Delete a tenant from VIM
        tenant_id: returned VIM tenant_id on "new_tenant"
        Returns None on success. Raises and exception of failure. If tenant is not found raises vimconnNotFoundException
        """
        self.logger.debug("Deleting specified VPC")

        try:
            self._reload_connection()
            vpc = self.vpc_data.get(tenant_id)

            if "gateway" in vpc and "route_table" in vpc:
                gateway_id, route_table_id = vpc["gateway"], vpc["route_table"]
                self.conn_vpc.detach_internet_gateway(gateway_id, tenant_id)
                self.conn_vpc.delete_vpc(tenant_id)
                self.conn_vpc.delete_route(route_table_id, "0.0.0.0/0")
            else:
                self.conn_vpc.delete_vpc(tenant_id)
        except Exception as e:
            self.format_vimconn_exception(e)

    def subnet_sizes(self, cidr):
        """Calculates possible subnets given CIDR value of VPC"""
        netmasks = (
            "255.255.0.0",
            "255.255.128.0",
            "255.255.192.0",
            "255.255.224.0",
            "255.255.240.0",
            "255.255.248.0",
        )

        ip = netaddr.IPNetwork(cidr)
        mask = ip.netmask
        pub_split = ()

        for netmask in netmasks:
            if str(mask) == netmask:
                pub_split = list(ip.subnet(24))
                break

        subnets = pub_split if pub_split else (list(ip.subnet(28)))

        return map(str, subnets)

    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):
        """Adds a tenant network to VIM
        Params:
            'net_name': name of the network
            'net_type': one of:
                'bridge': overlay isolated network
                'data':   underlay E-LAN network for Passthrough and SRIOV interfaces
                'ptp':    underlay E-LINE network for Passthrough and SRIOV interfaces.
            'ip_profile': is a dict containing the IP parameters of the network (Currently only IPv4 is implemented)
                'ip-version': can be one of ["IPv4","IPv6"]
                'subnet-address': ip_prefix_schema, that is X.X.X.X/Y
                'gateway-address': (Optional) ip_schema, that is X.X.X.X
                'dns-address': (Optional) ip_schema,
                'dhcp': (Optional) dict containing
                    'enabled': {"type": "boolean"},
                    'start-address': ip_schema, first IP to grant
                    'count': number of IPs to grant.
            'shared': if this network can be seen/use by other tenants/organization
        Returns a tuple with the network identifier and created_items, or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_network. Can be used to store created segments, created l2gw connections, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        self.logger.debug("Adding a subnet to VPC")

        try:
            created_items = {}
            self._reload_connection()
            subnet = None
            vpc_id = self.vpc_id
            if self.conn_vpc.get_all_subnets():
                existing_subnet = self.conn_vpc.get_all_subnets()[0]
                if not self.availability_zone:
                    self.availability_zone = str(existing_subnet.availability_zone)

            if self.vpc_data.get(vpc_id, None):
                cidr_block = list(
                    set(self.vpc_data[vpc_id]["subnets"])
                    - set(
                        self.get_network_details(
                            {"tenant_id": vpc_id}, detail="cidr_block"
                        )
                    )
                )
            else:
                vpc = self.get_tenant_list({"id": vpc_id})[0]
                subnet_list = self.subnet_sizes(vpc["cidr_block"])
                cidr_block = list(
                    set(subnet_list)
                    - set(
                        self.get_network_details(
                            {"tenant_id": vpc["id"]}, detail="cidr_block"
                        )
                    )
                )

            try:
                selected_cidr_block = random.choice(cidr_block)
                retry = 15
                while retry > 0:
                    all_subnets = [
                        subnet.cidr_block for subnet in self.conn_vpc.get_all_subnets()
                    ]
                    all_subnets.append(selected_cidr_block)
                    conflict = check_conflicts(all_subnets)
                    if not conflict:
                        subnet = self.conn_vpc.create_subnet(
                            vpc_id, selected_cidr_block, self.availability_zone
                        )
                        break
                    retry -= 1
                    selected_cidr_block = random.choice(cidr_block)
                else:
                    raise vimconn.VimConnException(
                        "Failed to find a proper CIDR which does not overlap"
                        "with existing subnets",
                        http_code=vimconn.HTTP_Request_Timeout,
                    )

            except (EC2ResponseError, BotoServerError) as error:
                self.format_vimconn_exception(error)

            created_items["net:" + str(subnet.id)] = True

            return subnet.id, created_items
        except Exception as e:
            self.format_vimconn_exception(e)

    def get_network_details(self, filters, detail):
        """Get specified details related to a subnet"""
        detail_list = []
        subnet_list = self.get_network_list(filters)

        for net in subnet_list:
            detail_list.append(net[detail])

        return detail_list

    def get_network_list(self, filter_dict={}):
        """Obtain tenant networks of VIM
        Params:
            'filter_dict' (optional) contains entries to return only networks that matches ALL entries:
                name: string  => returns only networks with this name
                id:   string  => returns networks with this VIM id, this imply returns one network at most
                shared: boolean >= returns only networks that are (or are not) shared
                tenant_id: sting => returns only networks that belong to this tenant/project
                ,#(not used yet) admin_state_up: boolean => returns only networks that are (or are not) in admin
                    state active
                #(not used yet) status: 'ACTIVE','ERROR',... => filter networks that are on this status
        Returns the network list of dictionaries. each dictionary contains:
            'id': (mandatory) VIM network id
            'name': (mandatory) VIM network name
            'status': (mandatory) can be 'ACTIVE', 'INACTIVE', 'DOWN', 'BUILD', 'ERROR', 'VIM_ERROR', 'OTHER'
            'error_msg': (optional) text that explains the ERROR status
            other VIM specific fields: (optional) whenever possible using the same naming of filter_dict param
        List can be empty if no network map the filter_dict. Raise an exception only upon VIM connectivity,
            authorization, or some other unspecific error
        """
        self.logger.debug("Getting all subnets from VIM")

        try:
            self._reload_connection()
            tfilters = {}

            if filter_dict != {}:
                if "tenant_id" in filter_dict:
                    tfilters["vpcId"] = filter_dict.get("tenant_id")

            subnets = self.conn_vpc.get_all_subnets(
                subnet_ids=filter_dict.get("SubnetId", None), filters=tfilters
            )

            net_list = []

            for net in subnets:
                if net.id == filter_dict.get("name"):
                    self.availability_zone = str(net.availability_zone)
                    net_list.append(
                        {
                            "id": str(net.id),
                            "name": str(net.id),
                            "status": str(net.state),
                            "vpc_id": str(net.vpc_id),
                            "cidr_block": str(net.cidr_block),
                            "type": "bridge",
                        }
                    )

            return net_list
        except Exception as e:
            self.format_vimconn_exception(e)

    def get_network(self, net_id):
        """Obtain network details from the 'net_id' VIM network
        Return a dict that contains:
            'id': (mandatory) VIM network id, that is, net_id
            'name': (mandatory) VIM network name
            'status': (mandatory) can be 'ACTIVE', 'INACTIVE', 'DOWN', 'BUILD', 'ERROR', 'VIM_ERROR', 'OTHER'
            'error_msg': (optional) text that explains the ERROR status
            other VIM specific fields: (optional) whenever possible using the same naming of filter_dict param
        Raises an exception upon error or when network is not found
        """
        self.logger.debug("Getting Subnet from VIM")

        try:
            self._reload_connection()
            subnet = self.conn_vpc.get_all_subnets(net_id)[0]
            return {
                "id": str(subnet.id),
                "name": str(subnet.id),
                "status": str(subnet.state),
                "vpc_id": str(subnet.vpc_id),
                "cidr_block": str(subnet.cidr_block),
                "availability_zone": str(subnet.availability_zone),
            }
        except Exception as e:
            self.format_vimconn_exception(e)

    def delete_network(self, net_id, created_items=None):
        """
        Removes a tenant network from VIM and its associated elements
        :param net_id: VIM identifier of the network, provided by method new_network
        :param created_items: dictionary with extra items to be deleted. provided by method new_network
        Returns the network identifier or raises an exception upon error or when network is not found
        """
        self.logger.debug("Deleting subnet from VIM")

        try:
            self._reload_connection()
            self.logger.debug("DELETING NET_ID: " + str(net_id))
            self.conn_vpc.delete_subnet(net_id)

            return net_id

        except Exception as e:
            if isinstance(e, EC2ResponseError):
                self.network_delete_on_termination.append(net_id)
                self.logger.warning(
                    f"{net_id} could not be deleted, deletion will retry after dependencies resolved"
                )
            else:
                self.format_vimconn_exception(e)

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
        self._reload_connection()

        try:
            dict_entry = {}

            for net_id in net_list:
                subnet_dict = {}
                subnet = None

                try:
                    subnet = self.conn_vpc.get_all_subnets(net_id)[0]

                    if subnet.state == "pending":
                        subnet_dict["status"] = "BUILD"
                    elif subnet.state == "available":
                        subnet_dict["status"] = "ACTIVE"
                    else:
                        subnet_dict["status"] = "ERROR"
                    subnet_dict["error_msg"] = ""
                except Exception:
                    subnet_dict["status"] = "DELETED"
                    subnet_dict["error_msg"] = "Network not found"
                finally:
                    subnet_dictionary = vars(subnet)
                    cleared_subnet_dict = {
                        key: subnet_dictionary[key]
                        for key in subnet_dictionary
                        if not isinstance(subnet_dictionary[key], object)
                    }
                    subnet_dict["vim_info"] = cleared_subnet_dict
                dict_entry[net_id] = subnet_dict

            return dict_entry
        except Exception as e:
            self.format_vimconn_exception(e)

    def get_flavor(self, flavor_id):
        """Obtain flavor details from the VIM
        Returns the flavor dict details {'id':<>, 'name':<>, other vim specific }
        Raises an exception upon error or if not found
        """
        self.logger.debug("Getting instance type")

        try:
            if flavor_id in self.flavor_info:
                return self.flavor_info[flavor_id]
            else:
                raise vimconn.VimConnNotFoundException(
                    "Cannot find flavor with this flavor ID/Name"
                )
        except Exception as e:
            self.format_vimconn_exception(e)

    def new_image(self, image_dict):
        """Adds a tenant image to VIM
        Params: image_dict
            name (string) - The name of the AMI. Valid only for EBS-based images.
            description (string) - The description of the AMI.
            image_location (string) - Full path to your AMI manifest in Amazon S3 storage. Only used for S3-based AMI’s.
            architecture (string) - The architecture of the AMI. Valid choices are: * i386 * x86_64
            kernel_id (string) -  The ID of the kernel with which to launch the instances
            root_device_name (string) - The root device name (e.g. /dev/sdh)
            block_device_map (boto.ec2.blockdevicemapping.BlockDeviceMapping) - A BlockDeviceMapping data structure
                describing the EBS volumes associated with the Image.
            virtualization_type (string) - The virutalization_type of the image. Valid choices are: * paravirtual * hvm
            sriov_net_support (string) - Advanced networking support. Valid choices are: * simple
            snapshot_id (string) - A snapshot ID for the snapshot to be used as root device for the image. Mutually
                exclusive with block_device_map, requires root_device_name
            delete_root_volume_on_termination (bool) - Whether to delete the root volume of the image after instance
                termination. Only applies when creating image from snapshot_id. Defaults to False. Note that leaving
                    volumes behind after instance termination is not free
        Returns: image_id - image ID of the newly created image
        """
        try:
            self._reload_connection()
            image_location = image_dict.get("image_location", None)

            if image_location:
                image_location = str(self.account_id) + str(image_location)

            image_id = self.conn.register_image(
                image_dict.get("name", None),
                image_dict.get("description", None),
                image_location,
                image_dict.get("architecture", None),
                image_dict.get("kernel_id", None),
                image_dict.get("root_device_name", None),
                image_dict.get("block_device_map", None),
                image_dict.get("virtualization_type", None),
                image_dict.get("sriov_net_support", None),
                image_dict.get("snapshot_id", None),
                image_dict.get("delete_root_volume_on_termination", None),
            )

            return image_id
        except Exception as e:
            self.format_vimconn_exception(e)

    def delete_image(self, image_id):
        """Deletes a tenant image from VIM
        Returns the image_id if image is deleted or raises an exception on error"""

        try:
            self._reload_connection()
            self.conn.deregister_image(image_id)

            return image_id
        except Exception as e:
            self.format_vimconn_exception(e)

    def get_image_id_from_path(self, path):
        """
        Params: path - location of the image
        Returns: image_id - ID of the matching image
        """
        self._reload_connection()
        try:
            filters = {}

            if path:
                tokens = path.split("/")
                filters["owner_id"] = tokens[0]
                filters["name"] = "/".join(tokens[1:])

            image = self.conn.get_all_images(filters=filters)[0]

            return image.id
        except Exception as e:
            self.format_vimconn_exception(e)

    def get_image_list(self, filter_dict={}):
        """Obtain tenant images from VIM
        Filter_dict can be:
            name: image name
            id: image uuid
            checksum: image checksum
            location: image path
        Returns the image list of dictionaries:
            [{<the fields at Filter_dict plus some VIM specific>}, ...]
            List can be empty
        """
        self.logger.debug("Getting image list from VIM")

        try:
            self._reload_connection()
            image_id = None
            filters = {}

            if "id" in filter_dict:
                image_id = filter_dict["id"]

            if "name" in filter_dict:
                filters["name"] = filter_dict["name"]

            if "location" in filter_dict:
                filters["location"] = filter_dict["location"]

            # filters['image_type'] = 'machine'
            # filter_dict['owner_id'] = self.account_id
            images = self.conn.get_all_images(image_id, filters=filters)
            image_list = []

            for image in images:
                image_list.append(
                    {
                        "id": str(image.id),
                        "name": str(image.name),
                        "status": str(image.state),
                        "owner": str(image.owner_id),
                        "location": str(image.location),
                        "is_public": str(image.is_public),
                        "architecture": str(image.architecture),
                        "platform": str(image.platform),
                    }
                )

            return image_list
        except Exception as e:
            self.format_vimconn_exception(e)

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
        """Create a new VM/instance in AWS
        Params: name
                decription
                start: (boolean) indicates if VM must start or created in pause mode.
                image_id - image ID in AWS
                flavor_id - instance type ID in AWS
                net_list
                    name
                    net_id - subnet_id from AWS
                    vpci - (optional) virtual vPCI address to assign at the VM. Can be ignored depending on VIM
                         capabilities
                    model: (optional and only have sense for type==virtual) interface model: virtio, e1000, ...
                    mac_address: (optional) mac address to assign to this interface
                    type: (mandatory) can be one of:
                        virtual, in this case always connected to a network of type 'net_type=bridge'
                        'PCI-PASSTHROUGH' or 'PF' (passthrough): depending on VIM capabilities it can be connected to a
                             data/ptp network ot it
                           can created unconnected
                        'SR-IOV' or 'VF' (SRIOV with VLAN tag): same as PF for network connectivity.
                        VFnotShared - (SRIOV without VLAN tag) same as PF for network connectivity. VF where no other
                            VFs are allocated on the same physical NIC
                    bw': (optional) only for PF/VF/VFnotShared. Minimal Bandwidth required for the interface in GBPS
                    port_security': (optional) If False it must avoid any traffic filtering at this interface.
                         If missing or True, it must apply the default VIM behaviour
                    vim_id': must be filled/added by this method with the VIM identifier generated by the VIM for this
                         interface. 'net_list' is modified
                    elastic_ip - True/False to define if an elastic_ip is required
                cloud_config': (optional) dictionary with:
                    key-pairs': (optional) list of strings with the public key to be inserted to the default user
                    users': (optional) list of users to be inserted, each item is a dict with:
                        name': (mandatory) user name,
                        key-pairs': (optional) list of strings with the public key to be inserted to the user
                    user-data': (optional) string is a text script to be passed directly to cloud-init
                    config-files': (optional). List of files to be transferred. Each item is a dict with:
                        dest': (mandatory) string with the destination absolute path
                        encoding': (optional, by default text). Can be one of:
                            b64', 'base64', 'gz', 'gz+b64', 'gz+base64', 'gzip+b64', 'gzip+base64'
                        content' (mandatory): string with the content of the file
                        permissions': (optional) string with file permissions, typically octal notation '0644'
                        owner: (optional) file owner, string with the format 'owner:group'
                    boot-data-drive: boolean to indicate if user-data must be passed using a boot drive (hard disk)
                    security-groups:
                        subnet_id
                        security_group_id
                disk_list': (optional) list with additional disks to the VM. Each item is a dict with:
                    image_id': (optional). VIM id of an existing image. If not provided an empty disk must be mounted
                    size': (mandatory) string with the size of the disk in GB
        Returns a tuple with the instance identifier and created_items or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_vminstance and action_vminstance. Can be used to store created ports, volumes, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        self.logger.debug("Creating a new VM instance")

        try:
            created_items = {}
            self._reload_connection()
            reservation = None
            _, userdata = self._create_user_data(cloud_config)

            if not net_list:
                reservation = self.conn.run_instances(
                    image_id,
                    key_name=self.key_pair,
                    instance_type=flavor_id,
                    security_groups=self.security_groups,
                    user_data=userdata,
                )

            else:
                for index, subnet in enumerate(net_list):
                    net_intr = self.conn_vpc.create_network_interface(
                        subnet_id=subnet.get("net_id"),
                        groups=None,
                    )

                    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
                        network_interface_id=net_intr.id,
                        device_index=index,
                    )

                    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(
                        interface
                    )

                    if subnet.get("elastic_ip"):
                        eip = self.conn.allocate_address()
                        self.conn.associate_address(
                            allocation_id=eip.allocation_id,
                            network_interface_id=net_intr.id,
                        )

                    if index == 0:
                        try:
                            reservation = self.conn.run_instances(
                                image_id,
                                key_name=self.key_pair,
                                instance_type=flavor_id,
                                security_groups=self.security_groups,
                                network_interfaces=interfaces,
                                user_data=userdata,
                            )
                        except Exception as instance_create_error:
                            self.logger.debug(traceback.format_exc())
                            self.format_vimconn_exception(instance_create_error)

                    if index > 0:
                        try:
                            if reservation:
                                instance_id = self.wait_for_instance_id(reservation)
                                if instance_id and self.wait_for_vm(
                                    instance_id, "running"
                                ):
                                    self.conn.attach_network_interface(
                                        network_interface_id=net_intr.id,
                                        instance_id=instance_id,
                                        device_index=index,
                                    )
                        except Exception as attach_network_error:
                            self.logger.debug(traceback.format_exc())
                            self.format_vimconn_exception(attach_network_error)

                    if instance_id := self.wait_for_instance_id(reservation):
                        time.sleep(30)
                        instance_status = self.refresh_vms_status(instance_id)
                        refreshed_instance_status = instance_status.get(instance_id)
                        instance_interfaces = refreshed_instance_status.get(
                            "interfaces"
                        )
                        for idx, interface in enumerate(instance_interfaces):
                            if idx == index:
                                net_list[index]["vim_id"] = instance_interfaces[
                                    idx
                                ].get("vim_interface_id")

            instance_id = self.wait_for_instance_id(reservation)
            created_items["vm_id:" + str(instance_id)] = True

            return instance_id, created_items
        except Exception as e:
            self.logger.debug(traceback.format_exc())
            self.format_vimconn_exception(e)

    def get_vminstance(self, vm_id):
        """Returns the VM instance information from VIM"""
        try:
            self._reload_connection()
            reservation = self.conn.get_all_instances(vm_id)

            return reservation[0].instances[0].__dict__
        except Exception as e:
            self.format_vimconn_exception(e)

    def delete_vminstance(self, vm_id, created_items=None, volumes_to_hold=None):
        """Removes a VM instance from VIM
        Returns the instance identifier"""
        try:
            self._reload_connection()
            self.logger.debug("DELETING VM_ID: " + str(vm_id))
            reservation = self.conn.get_all_instances(vm_id)[0]
            if hasattr(reservation, "instances"):
                instance = reservation.instances[0]

                self.conn.terminate_instances(vm_id)
                if self.wait_for_vm(vm_id, "terminated"):
                    for interface in instance.interfaces:
                        self.conn_vpc.delete_network_interface(
                            network_interface_id=interface.id,
                        )
                if self.network_delete_on_termination:
                    for net in self.network_delete_on_termination:
                        try:
                            self.conn_vpc.delete_subnet(net)
                        except Exception as net_delete_error:
                            if isinstance(net_delete_error, EC2ResponseError):
                                self.logger.warning(f"Deleting network {net}: failed")
                            else:
                                self.format_vimconn_exception(net_delete_error)

                return vm_id
        except Exception as e:
            self.format_vimconn_exception(e)

    def wait_for_instance_id(self, reservation):
        if not reservation:
            return False

        self._reload_connection()
        elapsed_time = 0
        while elapsed_time < 30:
            if reservation.instances:
                instance_id = reservation.instances[0].id
                return instance_id
            time.sleep(5)
            elapsed_time += 5
        else:
            raise vimconn.VimConnException(
                "Failed to get instance_id for reservation",
                http_code=vimconn.HTTP_Request_Timeout,
            )

    def wait_for_vm(self, vm_id, status):
        """wait until vm is in the desired status and return True.
        If the timeout is reached generate an exception"""

        self._reload_connection()

        elapsed_time = 0
        while elapsed_time < self.server_timeout:
            if self.conn.get_all_instances(vm_id):
                reservation = self.conn.get_all_instances(vm_id)[0]
                if hasattr(reservation, "instances"):
                    instance = reservation.instances[0]
                    if instance.state == status:
                        return True
            time.sleep(5)
            elapsed_time += 5

        # if we exceeded the timeout
        else:
            raise vimconn.VimConnException(
                "Timeout waiting for instance " + vm_id + " to get " + status,
                http_code=vimconn.HTTP_Request_Timeout,
            )

    def refresh_vms_status(self, vm_list):
        """Get the status of the virtual machines and their interfaces/ports
        Params: the list of VM identifiers
        Returns a dictionary with:
            vm_id:          #VIM id of this Virtual Machine
                status:     #Mandatory. Text with one of:
                            #  DELETED (not found at vim)
                            #  VIM_ERROR (Cannot connect to VIM, VIM response error, ...)
                            #  OTHER (Vim reported other status not understood)
                            #  ERROR (VIM indicates an ERROR status)
                            #  ACTIVE, PAUSED, SUSPENDED, INACTIVE (not running),
                            #  BUILD (on building process), ERROR
                            #  ACTIVE:NoMgmtIP (Active but any of its interface has an IP address
                            #
                error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
                vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
                interfaces: list with interface info. Each item a dictionary with:
                    vim_interface_id -  The ID of the ENI.
                    vim_net_id - The ID of the VPC subnet.
                    mac_address - The MAC address of the interface.
                    ip_address - The IP address of the interface within the subnet.
        """
        self.logger.debug("Getting VM instance information from VIM")

        try:
            self._reload_connection()
            elapsed_time = 0
            while elapsed_time < self.server_timeout:
                reservation = self.conn.get_all_instances(vm_list)[0]
                if reservation:
                    break
                time.sleep(5)
                elapsed_time += 5

            # if we exceeded the timeout
            else:
                raise vimconn.VimConnException(
                    vm_list + "could not be gathered, refresh vm status failed",
                    http_code=vimconn.HTTP_Request_Timeout,
                )

            instances = {}
            instance_dict = {}

            for instance in reservation.instances:
                if hasattr(instance, "id"):
                    try:
                        if instance.state in ("pending"):
                            instance_dict["status"] = "BUILD"
                        elif instance.state in ("available", "running", "up"):
                            instance_dict["status"] = "ACTIVE"
                        else:
                            instance_dict["status"] = "ERROR"

                        instance_dict["error_msg"] = ""
                        instance_dict["interfaces"] = []

                        for interface in instance.interfaces:
                            interface_dict = {
                                "vim_interface_id": interface.id,
                                "vim_net_id": interface.subnet_id,
                                "mac_address": interface.mac_address,
                            }

                            if (
                                hasattr(interface, "publicIp")
                                and interface.publicIp is not None
                            ):
                                interface_dict["ip_address"] = (
                                    interface.publicIp
                                    + ";"
                                    + interface.private_ip_address
                                )
                            else:
                                interface_dict["ip_address"] = (
                                    interface.private_ip_address
                                )

                            instance_dict["interfaces"].append(interface_dict)
                    except Exception as e:
                        self.logger.error(
                            "Exception getting vm status: %s", str(e), exc_info=True
                        )
                        instance_dict["status"] = "DELETED"
                        instance_dict["error_msg"] = str(e)
                    finally:
                        instance_dictionary = vars(instance)
                        cleared_instance_dict = {
                            key: instance_dictionary[key]
                            for key in instance_dictionary
                            if not (isinstance(instance_dictionary[key], object))
                        }
                        instance_dict["vim_info"] = cleared_instance_dict

                    instances[instance.id] = instance_dict

            return instances
        except Exception as e:
            self.logger.error("Exception getting vm status: %s", str(e), exc_info=True)
            self.format_vimconn_exception(e)

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        """Send and action over a VM instance from VIM
        Returns the vm_id if the action was successfully sent to the VIM"""

        self.logger.debug("Action over VM '%s': %s", vm_id, str(action_dict))
        try:
            self._reload_connection()
            if "start" in action_dict:
                self.conn.start_instances(vm_id)
            elif "stop" in action_dict or "stop" in action_dict:
                self.conn.stop_instances(vm_id)
            elif "terminate" in action_dict:
                self.conn.terminate_instances(vm_id)
            elif "reboot" in action_dict:
                self.conn.reboot_instances(vm_id)

            return None
        except Exception as e:
            self.format_vimconn_exception(e)

    def migrate_instance(self, vm_id, compute_host=None):
        """
        Migrate a vdu
        param:
            vm_id: ID of an instance
            compute_host: Host to migrate the vdu to
        """
        # TODO: Add support for migration
        raise vimconn.VimConnNotImplemented("Not implemented")

    def resize_instance(self, vm_id, flavor_id=None):
        """
        resize a vdu
        param:
            vm_id: ID of an instance
            flavor_id: flavor to resize the vdu
        """
        # TODO: Add support for resize
        raise vimconn.VimConnNotImplemented("Not implemented")
