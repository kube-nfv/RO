# -*- coding: utf-8 -*-

# #
# Copyright 2016-2019 VMware Inc.
# This file is part of ETSI OSM
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
# contact:  osslegalrouting@vmware.com
# #

"""
vimconn_vmware implementation an Abstract class in order to interact with VMware  vCloud Director.
"""

import atexit
import hashlib
import json
import logging
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import traceback
import uuid
from xml.etree import ElementTree as XmlElementTree
from xml.sax.saxutils import escape

from lxml import etree as lxmlElementTree
import netaddr
from osm_ro_plugin import vimconn
from progressbar import Bar, ETA, FileTransferSpeed, Percentage, ProgressBar
from pyvcloud.vcd.client import BasicLoginCredentials, Client
from pyvcloud.vcd.org import Org
from pyvcloud.vcd.vapp import VApp
from pyvcloud.vcd.vdc import VDC
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl  # @UnresolvedImport
import requests
import yaml

# global variable for vcd connector type
STANDALONE = "standalone"

# key for flavor dicts
FLAVOR_RAM_KEY = "ram"
FLAVOR_VCPUS_KEY = "vcpus"
FLAVOR_DISK_KEY = "disk"
DEFAULT_IP_PROFILE = {"dhcp_count": 50, "dhcp_enabled": True, "ip_version": "IPv4"}
# global variable for wait time
INTERVAL_TIME = 5
MAX_WAIT_TIME = 1800

API_VERSION = "27.0"

#     -1: "Could not be created",
#     0: "Unresolved",
#     1: "Resolved",
#     2: "Deployed",
#     3: "Suspended",
#     4: "Powered on",
#     5: "Waiting for user input",
#     6: "Unknown state",
#     7: "Unrecognized state",
#     8: "Powered off",
#     9: "Inconsistent state",
#     10: "Children do not all have the same status",
#     11: "Upload initiated, OVF descriptor pending",
#     12: "Upload initiated, copying contents",
#     13: "Upload initiated , disk contents pending",
#     14: "Upload has been quarantined",
#     15: "Upload quarantine period has expired"

# mapping vCD status to MANO
vcdStatusCode2manoFormat = {
    4: "ACTIVE",
    7: "PAUSED",
    3: "SUSPENDED",
    8: "INACTIVE",
    12: "BUILD",
    -1: "ERROR",
    14: "DELETED",
}

#
netStatus2manoFormat = {
    "ACTIVE": "ACTIVE",
    "PAUSED": "PAUSED",
    "INACTIVE": "INACTIVE",
    "BUILD": "BUILD",
    "ERROR": "ERROR",
    "DELETED": "DELETED",
}


class vimconnector(vimconn.VimConnector):
    # dict used to store flavor in memory
    flavorlist = {}

    def __init__(
        self,
        uuid=None,
        name=None,
        tenant_id=None,
        tenant_name=None,
        url=None,
        url_admin=None,
        user=None,
        passwd=None,
        log_level=None,
        config={},
        persistent_info={},
    ):
        """
        Constructor create vmware connector to vCloud director.

        By default construct doesn't validate connection state. So client can create object with None arguments.
        If client specified username , password and host and VDC name.  Connector initialize other missing attributes.

        a) It initialize organization UUID
        b) Initialize tenant_id/vdc ID.   (This information derived from tenant name)

        Args:
            uuid - is organization uuid.
            name - is organization name that must be presented in vCloud director.
            tenant_id - is VDC uuid it must be presented in vCloud director
            tenant_name - is VDC name.
            url - is hostname or ip address of vCloud director
            url_admin - same as above.
            user - is user that administrator for organization. Caller must make sure that
                    username has right privileges.

            password - is password for a user.

            VMware connector also requires PVDC administrative privileges and separate account.
            This variables must be passed via config argument dict contains keys

            dict['admin_username']
            dict['admin_password']
            config - Provide NSX and vCenter information

            Returns:
                Nothing.
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
        )

        self.logger = logging.getLogger("ro.vim.vmware")
        self.logger.setLevel(10)
        self.persistent_info = persistent_info

        self.name = name
        self.id = uuid
        self.url = url
        self.url_admin = url_admin
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.user = user
        self.passwd = passwd
        self.config = config
        self.admin_password = None
        self.admin_user = None
        self.org_name = ""
        self.nsx_manager = None
        self.nsx_user = None
        self.nsx_password = None
        self.availability_zone = None

        # Disable warnings from self-signed certificates.
        requests.packages.urllib3.disable_warnings()

        if tenant_name is not None:
            orgnameandtenant = tenant_name.split(":")

            if len(orgnameandtenant) == 2:
                self.tenant_name = orgnameandtenant[1]
                self.org_name = orgnameandtenant[0]
            else:
                self.tenant_name = tenant_name

        if "orgname" in config:
            self.org_name = config["orgname"]

        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

        try:
            self.admin_user = config["admin_username"]
            self.admin_password = config["admin_password"]
        except KeyError:
            raise vimconn.VimConnException(
                message="Error admin username or admin password is empty."
            )

        try:
            self.nsx_manager = config["nsx_manager"]
            self.nsx_user = config["nsx_user"]
            self.nsx_password = config["nsx_password"]
        except KeyError:
            raise vimconn.VimConnException(
                message="Error: nsx manager or nsx user or nsx password is empty in Config"
            )

        self.vcenter_ip = config.get("vcenter_ip", None)
        self.vcenter_port = config.get("vcenter_port", None)
        self.vcenter_user = config.get("vcenter_user", None)
        self.vcenter_password = config.get("vcenter_password", None)

        # Set availability zone for Affinity rules
        self.availability_zone = self.set_availability_zones()

        # ############# Stub code for SRIOV #################
        #         try:
        #             self.dvs_name = config['dv_switch_name']
        #         except KeyError:
        #             raise vimconn.VimConnException(message="Error:
        #             distributed virtaul switch name is empty in Config")
        #
        #         self.vlanID_range = config.get("vlanID_range", None)

        self.org_uuid = None
        self.client = None

        if not url:
            raise vimconn.VimConnException("url param can not be NoneType")

        if not self.url_admin:  # try to use normal url
            self.url_admin = self.url

        logging.debug(
            "UUID: {} name: {} tenant_id: {} tenant name {}".format(
                self.id, self.org_name, self.tenant_id, self.tenant_name
            )
        )
        logging.debug(
            "vcd url {} vcd username: {} vcd password: {}".format(
                self.url, self.user, self.passwd
            )
        )
        logging.debug(
            "vcd admin username {} vcd admin passowrd {}".format(
                self.admin_user, self.admin_password
            )
        )

        # initialize organization
        if self.user is not None and self.passwd is not None and self.url:
            self.init_organization()

    def __getitem__(self, index):
        if index == "name":
            return self.name

        if index == "tenant_id":
            return self.tenant_id

        if index == "tenant_name":
            return self.tenant_name
        elif index == "id":
            return self.id
        elif index == "org_name":
            return self.org_name
        elif index == "org_uuid":
            return self.org_uuid
        elif index == "user":
            return self.user
        elif index == "passwd":
            return self.passwd
        elif index == "url":
            return self.url
        elif index == "url_admin":
            return self.url_admin
        elif index == "config":
            return self.config
        else:
            raise KeyError("Invalid key '{}'".format(index))

    def __setitem__(self, index, value):
        if index == "name":
            self.name = value

        if index == "tenant_id":
            self.tenant_id = value

        if index == "tenant_name":
            self.tenant_name = value
        elif index == "id":
            self.id = value
        elif index == "org_name":
            self.org_name = value
        elif index == "org_uuid":
            self.org_uuid = value
        elif index == "user":
            self.user = value
        elif index == "passwd":
            self.passwd = value
        elif index == "url":
            self.url = value
        elif index == "url_admin":
            self.url_admin = value
        else:
            raise KeyError("Invalid key '{}'".format(index))

    def connect_as_admin(self):
        """Method connect as pvdc admin user to vCloud director.
        There are certain action that can be done only by provider vdc admin user.
        Organization creation / provider network creation etc.

        Returns:
            The return client object that latter can be used to connect to vcloud director as admin for provider vdc
        """
        self.logger.debug("Logging into vCD {} as admin.".format(self.org_name))

        try:
            host = self.url
            org = "System"
            client_as_admin = Client(
                host, verify_ssl_certs=False, api_version=API_VERSION
            )
            client_as_admin.set_credentials(
                BasicLoginCredentials(self.admin_user, org, self.admin_password)
            )
        except Exception as e:
            raise vimconn.VimConnException(
                "Can't connect to vCloud director as: {} with exception {}".format(
                    self.admin_user, e
                )
            )

        return client_as_admin

    def connect(self):
        """Method connect as normal user to vCloud director.

        Returns:
            The return client object that latter can be used to connect to vCloud director as admin for VDC
        """
        try:
            self.logger.debug(
                "Logging into vCD {} as {} to datacenter {}.".format(
                    self.org_name, self.user, self.org_name
                )
            )
            host = self.url
            client = Client(host, verify_ssl_certs=False, api_version=API_VERSION)
            client.set_credentials(
                BasicLoginCredentials(self.user, self.org_name, self.passwd)
            )
        except Exception as e:
            raise vimconn.VimConnConnectionException(
                "Can't connect to vCloud director org: "
                "{} as user {} with exception: {}".format(self.org_name, self.user, e)
            )

        return client

    def init_organization(self):
        """Method initialize organization UUID and VDC parameters.

        At bare minimum client must provide organization name that present in vCloud director and VDC.

        The VDC - UUID ( tenant_id) will be initialized at the run time if client didn't call constructor.
        The Org - UUID will be initialized at the run time if data center present in vCloud director.

        Returns:
            The return vca object that letter can be used to connect to vcloud direct as admin
        """
        client = self.connect()

        if not client:
            raise vimconn.VimConnConnectionException("Failed to connect vCD.")

        self.client = client
        try:
            if self.org_uuid is None:
                org_list = client.get_org_list()
                for org in org_list.Org:
                    # we set org UUID at the init phase but we can do it only when we have valid credential.
                    if org.get("name") == self.org_name:
                        self.org_uuid = org.get("href").split("/")[-1]
                        self.logger.debug(
                            "Setting organization UUID {}".format(self.org_uuid)
                        )
                        break
                else:
                    raise vimconn.VimConnException(
                        "Vcloud director organization {} not found".format(
                            self.org_name
                        )
                    )

                # if well good we require for org details
                org_details_dict = self.get_org(org_uuid=self.org_uuid)

                # we have two case if we want to initialize VDC ID or VDC name at run time
                # tenant_name provided but no tenant id
                if (
                    self.tenant_id is None
                    and self.tenant_name is not None
                    and "vdcs" in org_details_dict
                ):
                    vdcs_dict = org_details_dict["vdcs"]
                    for vdc in vdcs_dict:
                        if vdcs_dict[vdc] == self.tenant_name:
                            self.tenant_id = vdc
                            self.logger.debug(
                                "Setting vdc uuid {} for organization UUID {}".format(
                                    self.tenant_id, self.org_name
                                )
                            )
                            break
                    else:
                        raise vimconn.VimConnException(
                            "Tenant name indicated but not present in vcloud director."
                        )

                    # case two we have tenant_id but we don't have tenant name so we find and set it.
                    if (
                        self.tenant_id is not None
                        and self.tenant_name is None
                        and "vdcs" in org_details_dict
                    ):
                        vdcs_dict = org_details_dict["vdcs"]
                        for vdc in vdcs_dict:
                            if vdc == self.tenant_id:
                                self.tenant_name = vdcs_dict[vdc]
                                self.logger.debug(
                                    "Setting vdc uuid {} for organization UUID {}".format(
                                        self.tenant_id, self.org_name
                                    )
                                )
                                break
                        else:
                            raise vimconn.VimConnException(
                                "Tenant id indicated but not present in vcloud director"
                            )

            self.logger.debug("Setting organization uuid {}".format(self.org_uuid))
        except Exception as e:
            self.logger.debug(
                "Failed initialize organization UUID for org {}: {}".format(
                    self.org_name, e
                ),
            )
            self.logger.debug(traceback.format_exc())
            self.org_uuid = None

    def new_tenant(self, tenant_name=None, tenant_description=None):
        """Method adds a new tenant to VIM with this name.
        This action requires access to create VDC action in vCloud director.

        Args:
            tenant_name is tenant_name to be created.
            tenant_description not used for this call

        Return:
            returns the tenant identifier in UUID format.
            If action is failed method will throw vimconn.VimConnException method
        """
        vdc_task = self.create_vdc(vdc_name=tenant_name)
        if vdc_task is not None:
            vdc_uuid, _ = vdc_task.popitem()
            self.logger.info(
                "Created new vdc {} and uuid: {}".format(tenant_name, vdc_uuid)
            )

            return vdc_uuid
        else:
            raise vimconn.VimConnException(
                "Failed create tenant {}".format(tenant_name)
            )

    def delete_tenant(self, tenant_id=None):
        """Delete a tenant from VIM
         Args:
            tenant_id is tenant_id to be deleted.

        Return:
            returns the tenant identifier in UUID format.
            If action is failed method will throw exception
        """
        vca = self.connect_as_admin()
        if not vca:
            raise vimconn.VimConnConnectionException("Failed to connect vCD")

        if tenant_id is not None:
            if vca._session:
                # Get OrgVDC
                url_list = [self.url, "/api/vdc/", tenant_id]
                orgvdc_herf = "".join(url_list)

                headers = {
                    "Accept": "application/*+xml;version=" + API_VERSION,
                    "x-vcloud-authorization": vca._session.headers[
                        "x-vcloud-authorization"
                    ],
                }
                response = self.perform_request(
                    req_type="GET", url=orgvdc_herf, headers=headers
                )

                if response.status_code != requests.codes.ok:
                    self.logger.debug(
                        "delete_tenant():GET REST API call {} failed. "
                        "Return status code {}".format(
                            orgvdc_herf, response.status_code
                        )
                    )

                    raise vimconn.VimConnNotFoundException(
                        "Fail to get tenant {}".format(tenant_id)
                    )

                lxmlroot_respond = lxmlElementTree.fromstring(response.content)
                namespaces = {
                    prefix: uri
                    for prefix, uri in lxmlroot_respond.nsmap.items()
                    if prefix
                }
                namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"
                vdc_remove_href = lxmlroot_respond.find(
                    "xmlns:Link[@rel='remove']", namespaces
                ).attrib["href"]
                vdc_remove_href = vdc_remove_href + "?recursive=true&force=true"

                response = self.perform_request(
                    req_type="DELETE", url=vdc_remove_href, headers=headers
                )

                if response.status_code == 202:
                    time.sleep(5)

                    return tenant_id
                else:
                    self.logger.debug(
                        "delete_tenant(): DELETE REST API call {} failed. "
                        "Return status code {}".format(
                            vdc_remove_href, response.status_code
                        )
                    )

                    raise vimconn.VimConnException(
                        "Fail to delete tenant with ID {}".format(tenant_id)
                    )
        else:
            self.logger.debug(
                "delete_tenant():Incorrect tenant ID  {}".format(tenant_id)
            )

            raise vimconn.VimConnNotFoundException(
                "Fail to get tenant {}".format(tenant_id)
            )

    def get_tenant_list(self, filter_dict={}):
        """Obtain tenants of VIM
        filter_dict can contain the following keys:
            name: filter by tenant name
            id: filter by tenant uuid/id
            <other VIM specific>
        Returns the tenant list of dictionaries:
            [{'name':'<name>, 'id':'<id>, ...}, ...]

        """
        org_dict = self.get_org(self.org_uuid)
        vdcs_dict = org_dict["vdcs"]

        vdclist = []
        try:
            for k in vdcs_dict:
                entry = {"name": vdcs_dict[k], "id": k}
                # if caller didn't specify dictionary we return all tenants.

                if filter_dict is not None and filter_dict:
                    filtered_entry = entry.copy()
                    filtered_dict = set(entry.keys()) - set(filter_dict)

                    for unwanted_key in filtered_dict:
                        del entry[unwanted_key]

                    if filter_dict == entry:
                        vdclist.append(filtered_entry)
                else:
                    vdclist.append(entry)
        except Exception:
            self.logger.debug("Error in get_tenant_list()")
            self.logger.debug(traceback.format_exc())

            raise vimconn.VimConnException("Incorrect state. {}")

        return vdclist

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
            'ip_profile': is a dict containing the IP parameters of the network
                'ip_version': can be "IPv4" or "IPv6" (Currently only IPv4 is implemented)
                'subnet_address': ip_prefix_schema, that is X.X.X.X/Y
                'gateway_address': (Optional) ip_schema, that is X.X.X.X
                'dns_address': (Optional) comma separated list of ip_schema, e.g. X.X.X.X[,X,X,X,X]
                'dhcp_enabled': True or False
                'dhcp_start_address': ip_schema, first IP to grant
                'dhcp_count': number of IPs to grant.
            'shared': if this network can be seen/use by other tenants/organization
            'provider_network_profile': (optional) contains {segmentation-id: vlan, provider-network: vim_netowrk}
        Returns a tuple with the network identifier and created_items, or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_network. Can be used to store created segments, created l2gw connections, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """

        self.logger.debug(
            "new_network tenant {} net_type {} ip_profile {} shared {} provider_network_profile {}".format(
                net_name, net_type, ip_profile, shared, provider_network_profile
            )
        )
        #        vlan = None
        #        if provider_network_profile:
        #            vlan = provider_network_profile.get("segmentation-id")

        created_items = {}
        isshared = "false"

        if shared:
            isshared = "true"

        # ############# Stub code for SRIOV #################
        #         if net_type == "data" or net_type == "ptp":
        #             if self.config.get('dv_switch_name') == None:
        #                  raise vimconn.VimConnConflictException("You must provide 'dv_switch_name' at config value")
        #             network_uuid = self.create_dvPort_group(net_name)
        parent_network_uuid = None

        if provider_network_profile is not None:
            for k, v in provider_network_profile.items():
                if k == "physical_network":
                    parent_network_uuid = self.get_physical_network_by_name(v)

        network_uuid = self.create_network(
            network_name=net_name,
            net_type=net_type,
            ip_profile=ip_profile,
            isshared=isshared,
            parent_network_uuid=parent_network_uuid,
        )

        if network_uuid is not None:
            return network_uuid, created_items
        else:
            raise vimconn.VimConnUnexpectedResponse(
                "Failed create a new network {}".format(net_name)
            )

    def get_network_list(self, filter_dict={}):
        """Obtain tenant networks of VIM
        Filter_dict can be:
            name: network name  OR/AND
            id: network uuid    OR/AND
            shared: boolean     OR/AND
            tenant_id: tenant   OR/AND
            admin_state_up: boolean
            status: 'ACTIVE'

        [{key : value , key : value}]

        Returns the network list of dictionaries:
            [{<the fields at Filter_dict plus some VIM specific>}, ...]
            List can be empty
        """

        self.logger.debug(
            "get_network_list(): retrieving network list for vcd {}".format(
                self.tenant_name
            )
        )

        if not self.tenant_name:
            raise vimconn.VimConnConnectionException("Tenant name is empty.")

        _, vdc = self.get_vdc_details()
        if vdc is None:
            raise vimconn.VimConnConnectionException(
                "Can't retrieve information for a VDC {}.".format(self.tenant_name)
            )

        try:
            vdcid = vdc.get("id").split(":")[3]

            if self.client._session:
                headers = {
                    "Accept": "application/*+xml;version=" + API_VERSION,
                    "x-vcloud-authorization": self.client._session.headers[
                        "x-vcloud-authorization"
                    ],
                }
                response = self.perform_request(
                    req_type="GET", url=vdc.get("href"), headers=headers
                )

            if response.status_code != 200:
                self.logger.error("Failed to get vdc content")
                raise vimconn.VimConnNotFoundException("Failed to get vdc content")
            else:
                content = XmlElementTree.fromstring(response.text)

            network_list = []
            for item in content:
                if item.tag.split("}")[-1] == "AvailableNetworks":
                    for net in item:
                        response = self.perform_request(
                            req_type="GET", url=net.get("href"), headers=headers
                        )

                        if response.status_code != 200:
                            self.logger.error("Failed to get network content")
                            raise vimconn.VimConnNotFoundException(
                                "Failed to get network content"
                            )
                        else:
                            net_details = XmlElementTree.fromstring(response.text)

                            filter_entry = {}
                            net_uuid = net_details.get("id").split(":")

                            if len(net_uuid) != 4:
                                continue
                            else:
                                net_uuid = net_uuid[3]
                                # create dict entry
                                self.logger.debug(
                                    "get_network_list(): Adding net {}"
                                    " to a list vcd id {} network {}".format(
                                        net_uuid, vdcid, net_details.get("name")
                                    )
                                )
                                filter_entry["name"] = net_details.get("name")
                                filter_entry["id"] = net_uuid

                                if [
                                    i.text
                                    for i in net_details
                                    if i.tag.split("}")[-1] == "IsShared"
                                ][0] == "true":
                                    shared = True
                                else:
                                    shared = False

                                filter_entry["shared"] = shared
                                filter_entry["tenant_id"] = vdcid

                                if int(net_details.get("status")) == 1:
                                    filter_entry["admin_state_up"] = True
                                else:
                                    filter_entry["admin_state_up"] = False

                                filter_entry["status"] = "ACTIVE"
                                filter_entry["type"] = "bridge"
                                filtered_entry = filter_entry.copy()

                                if filter_dict is not None and filter_dict:
                                    # we remove all the key : value we don't care and match only
                                    # respected field
                                    filtered_dict = set(filter_entry.keys()) - set(
                                        filter_dict
                                    )

                                    for unwanted_key in filtered_dict:
                                        del filter_entry[unwanted_key]

                                    if filter_dict == filter_entry:
                                        network_list.append(filtered_entry)
                                else:
                                    network_list.append(filtered_entry)
        except Exception as e:
            self.logger.debug("Error in get_network_list", exc_info=True)

            if isinstance(e, vimconn.VimConnException):
                raise
            else:
                raise vimconn.VimConnNotFoundException(
                    "Failed : Networks list not found {} ".format(e)
                )

        self.logger.debug("Returning {}".format(network_list))

        return network_list

    def get_network(self, net_id):
        """Method obtains network details of net_id VIM network
        Return a dict with  the fields at filter_dict (see get_network_list) plus some VIM specific>}, ...]
        """
        try:
            _, vdc = self.get_vdc_details()
            vdc_id = vdc.get("id").split(":")[3]

            if self.client._session:
                headers = {
                    "Accept": "application/*+xml;version=" + API_VERSION,
                    "x-vcloud-authorization": self.client._session.headers[
                        "x-vcloud-authorization"
                    ],
                }
                response = self.perform_request(
                    req_type="GET", url=vdc.get("href"), headers=headers
                )

            if response.status_code != 200:
                self.logger.error("Failed to get vdc content")
                raise vimconn.VimConnNotFoundException("Failed to get vdc content")
            else:
                content = XmlElementTree.fromstring(response.text)

            filter_dict = {}

            for item in content:
                if item.tag.split("}")[-1] == "AvailableNetworks":
                    for net in item:
                        response = self.perform_request(
                            req_type="GET", url=net.get("href"), headers=headers
                        )

                        if response.status_code != 200:
                            self.logger.error("Failed to get network content")
                            raise vimconn.VimConnNotFoundException(
                                "Failed to get network content"
                            )
                        else:
                            net_details = XmlElementTree.fromstring(response.text)

                            vdc_network_id = net_details.get("id").split(":")
                            if len(vdc_network_id) == 4 and vdc_network_id[3] == net_id:
                                filter_dict["name"] = net_details.get("name")
                                filter_dict["id"] = vdc_network_id[3]

                                if [
                                    i.text
                                    for i in net_details
                                    if i.tag.split("}")[-1] == "IsShared"
                                ][0] == "true":
                                    shared = True
                                else:
                                    shared = False

                                filter_dict["shared"] = shared
                                filter_dict["tenant_id"] = vdc_id

                                if int(net_details.get("status")) == 1:
                                    filter_dict["admin_state_up"] = True
                                else:
                                    filter_dict["admin_state_up"] = False

                                filter_dict["status"] = "ACTIVE"
                                filter_dict["type"] = "bridge"
                                self.logger.debug("Returning {}".format(filter_dict))

                                return filter_dict
                    else:
                        raise vimconn.VimConnNotFoundException(
                            "Network {} not found".format(net_id)
                        )
        except Exception as e:
            self.logger.debug("Error in get_network")
            self.logger.debug(traceback.format_exc())

            if isinstance(e, vimconn.VimConnException):
                raise
            else:
                raise vimconn.VimConnNotFoundException(
                    "Failed : Network not found {} ".format(e)
                )

        return filter_dict

    def delete_network(self, net_id, created_items=None):
        """
        Removes a tenant network from VIM and its associated elements
        :param net_id: VIM identifier of the network, provided by method new_network
        :param created_items: dictionary with extra items to be deleted. provided by method new_network
        Returns the network identifier or raises an exception upon error or when network is not found
        """
        vcd_network = self.get_vcd_network(network_uuid=net_id)
        if vcd_network is not None and vcd_network:
            if self.delete_network_action(network_uuid=net_id):
                return net_id
        else:
            raise vimconn.VimConnNotFoundException(
                "Network {} not found".format(net_id)
            )

    def refresh_nets_status(self, net_list):
        """Get the status of the networks
        Params: the list of network identifiers
        Returns a dictionary with:
             net_id:         #VIM id of this network
                 status:     #Mandatory. Text with one of:
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
        dict_entry = {}
        try:
            for net in net_list:
                errormsg = ""
                vcd_network = self.get_vcd_network(network_uuid=net)
                if vcd_network is not None and vcd_network:
                    if vcd_network["status"] == "1":
                        status = "ACTIVE"
                    else:
                        status = "DOWN"
                else:
                    status = "DELETED"
                    errormsg = "Network not found."

                dict_entry[net] = {
                    "status": status,
                    "error_msg": errormsg,
                    "vim_info": yaml.safe_dump(vcd_network),
                }
        except Exception:
            self.logger.debug("Error in refresh_nets_status")
            self.logger.debug(traceback.format_exc())

        return dict_entry

    def get_flavor(self, flavor_id):
        """Obtain flavor details from the  VIM
        Returns the flavor dict details {'id':<>, 'name':<>, other vim specific } #TODO to concrete
        """
        if flavor_id not in vimconnector.flavorlist:
            raise vimconn.VimConnNotFoundException("Flavor not found.")

        return vimconnector.flavorlist[flavor_id]

    def new_flavor(self, flavor_data):
        """Adds a tenant flavor to VIM
            flavor_data contains a dictionary with information, keys:
                name: flavor name
                ram: memory (cloud type) in MBytes
                vpcus: cpus (cloud type)
                extended: EPA parameters
                  - numas: #items requested in same NUMA
                        memory: number of 1G huge pages memory
                        paired-threads|cores|threads: number of paired hyperthreads, complete cores OR individual
                            threads
                        interfaces: # passthrough(PT) or SRIOV interfaces attached to this numa
                          - name: interface name
                            dedicated: yes|no|yes:sriov;  for PT, SRIOV or only one SRIOV for the physical NIC
                            bandwidth: X Gbps; requested guarantee bandwidth
                            vpci: requested virtual PCI address
                disk: disk size
                is_public:
                 #TODO to concrete
        Returns the flavor identifier"""

        # generate a new uuid put to internal dict and return it.
        self.logger.debug("Creating new flavor - flavor_data: {}".format(flavor_data))
        new_flavor = flavor_data
        ram = flavor_data.get(FLAVOR_RAM_KEY, 1024)
        cpu = flavor_data.get(FLAVOR_VCPUS_KEY, 1)
        disk = flavor_data.get(FLAVOR_DISK_KEY, 0)

        if not isinstance(ram, int):
            raise vimconn.VimConnException("Non-integer value for ram")
        elif not isinstance(cpu, int):
            raise vimconn.VimConnException("Non-integer value for cpu")
        elif not isinstance(disk, int):
            raise vimconn.VimConnException("Non-integer value for disk")

        extended_flv = flavor_data.get("extended")
        if extended_flv:
            numas = extended_flv.get("numas")
            if numas:
                for numa in numas:
                    # overwrite ram and vcpus
                    if "memory" in numa:
                        ram = numa["memory"] * 1024

                    if "paired-threads" in numa:
                        cpu = numa["paired-threads"] * 2
                    elif "cores" in numa:
                        cpu = numa["cores"]
                    elif "threads" in numa:
                        cpu = numa["threads"]

        new_flavor[FLAVOR_RAM_KEY] = ram
        new_flavor[FLAVOR_VCPUS_KEY] = cpu
        new_flavor[FLAVOR_DISK_KEY] = disk
        # generate a new uuid put to internal dict and return it.
        flavor_id = uuid.uuid4()
        vimconnector.flavorlist[str(flavor_id)] = new_flavor
        self.logger.debug("Created flavor - {} : {}".format(flavor_id, new_flavor))

        return str(flavor_id)

    def delete_flavor(self, flavor_id):
        """Deletes a tenant flavor from VIM identify by its id

        Returns the used id or raise an exception
        """
        if flavor_id not in vimconnector.flavorlist:
            raise vimconn.VimConnNotFoundException("Flavor not found.")

        vimconnector.flavorlist.pop(flavor_id, None)

        return flavor_id

    def new_image(self, image_dict):
        """
        Adds a tenant image to VIM
        Returns:
            200, image-id        if the image is created
            <0, message          if there is an error
        """
        return self.get_image_id_from_path(image_dict["location"])

    def delete_image(self, image_id):
        """
        Deletes a tenant image from VIM
        Args:
            image_id is ID of Image to be deleted
        Return:
            returns the image identifier in UUID format or raises an exception on error
        """
        conn = self.connect_as_admin()

        if not conn:
            raise vimconn.VimConnConnectionException("Failed to connect vCD")

        # Get Catalog details
        url_list = [self.url, "/api/catalog/", image_id]
        catalog_herf = "".join(url_list)

        headers = {
            "Accept": "application/*+xml;version=" + API_VERSION,
            "x-vcloud-authorization": conn._session.headers["x-vcloud-authorization"],
        }

        response = self.perform_request(
            req_type="GET", url=catalog_herf, headers=headers
        )

        if response.status_code != requests.codes.ok:
            self.logger.debug(
                "delete_image():GET REST API call {} failed. "
                "Return status code {}".format(catalog_herf, response.status_code)
            )

            raise vimconn.VimConnNotFoundException(
                "Fail to get image {}".format(image_id)
            )

        lxmlroot_respond = lxmlElementTree.fromstring(response.content)
        namespaces = {
            prefix: uri for prefix, uri in lxmlroot_respond.nsmap.items() if prefix
        }
        namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"

        catalogItems_section = lxmlroot_respond.find("xmlns:CatalogItems", namespaces)
        catalogItems = catalogItems_section.iterfind("xmlns:CatalogItem", namespaces)

        for catalogItem in catalogItems:
            catalogItem_href = catalogItem.attrib["href"]

            response = self.perform_request(
                req_type="GET", url=catalogItem_href, headers=headers
            )

            if response.status_code != requests.codes.ok:
                self.logger.debug(
                    "delete_image():GET REST API call {} failed. "
                    "Return status code {}".format(catalog_herf, response.status_code)
                )
                raise vimconn.VimConnNotFoundException(
                    "Fail to get catalogItem {} for catalog {}".format(
                        catalogItem, image_id
                    )
                )

            lxmlroot_respond = lxmlElementTree.fromstring(response.content)
            namespaces = {
                prefix: uri for prefix, uri in lxmlroot_respond.nsmap.items() if prefix
            }
            namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"
            catalogitem_remove_href = lxmlroot_respond.find(
                "xmlns:Link[@rel='remove']", namespaces
            ).attrib["href"]

            # Remove catalogItem
            response = self.perform_request(
                req_type="DELETE", url=catalogitem_remove_href, headers=headers
            )

            if response.status_code == requests.codes.no_content:
                self.logger.debug("Deleted Catalog item {}".format(catalogItem))
            else:
                raise vimconn.VimConnException(
                    "Fail to delete Catalog Item {}".format(catalogItem)
                )

        # Remove catalog
        url_list = [self.url, "/api/admin/catalog/", image_id]
        catalog_remove_herf = "".join(url_list)
        response = self.perform_request(
            req_type="DELETE", url=catalog_remove_herf, headers=headers
        )

        if response.status_code == requests.codes.no_content:
            self.logger.debug("Deleted Catalog {}".format(image_id))

            return image_id
        else:
            raise vimconn.VimConnException("Fail to delete Catalog {}".format(image_id))

    def catalog_exists(self, catalog_name, catalogs):
        """

        :param catalog_name:
        :param catalogs:
        :return:
        """
        for catalog in catalogs:
            if catalog["name"] == catalog_name:
                return catalog["id"]

    def create_vimcatalog(self, vca=None, catalog_name=None):
        """Create new catalog entry in vCloud director.

        Args
            vca:  vCloud director.
            catalog_name catalog that client wish to create.   Note no validation done for a name.
            Client must make sure that provide valid string representation.

         Returns catalog id if catalog created else None.

        """
        try:
            lxml_catalog_element = vca.create_catalog(catalog_name, catalog_name)

            if lxml_catalog_element:
                id_attr_value = lxml_catalog_element.get("id")
                return id_attr_value.split(":")[-1]

            catalogs = vca.list_catalogs()
        except Exception as ex:
            self.logger.error(
                'create_vimcatalog(): Creation of catalog "{}" failed with error: {}'.format(
                    catalog_name, ex
                )
            )
            raise
        return self.catalog_exists(catalog_name, catalogs)

    # noinspection PyIncorrectDocstring
    def upload_ovf(
        self,
        vca=None,
        catalog_name=None,
        image_name=None,
        media_file_name=None,
        description="",
        progress=False,
        chunk_bytes=128 * 1024,
    ):
        """
        Uploads a OVF file to a vCloud catalog

        :param chunk_bytes:
        :param progress:
        :param description:
        :param image_name:
        :param vca:
        :param catalog_name: (str): The name of the catalog to upload the media.
        :param media_file_name: (str): The name of the local media file to upload.
        :return: (bool) True if the media file was successfully uploaded, false otherwise.
        """
        os.path.isfile(media_file_name)
        statinfo = os.stat(media_file_name)

        #  find a catalog entry where we upload OVF.
        #  create vApp Template and check the status if vCD able to read OVF it will respond with appropirate
        #  status change.
        #  if VCD can parse OVF we upload VMDK file
        try:
            for catalog in vca.list_catalogs():
                if catalog_name != catalog["name"]:
                    continue
                catalog_href = "{}/api/catalog/{}/action/upload".format(
                    self.url, catalog["id"]
                )
                data = """
                <UploadVAppTemplateParams name="{}"
                  xmlns="http://www.vmware.com/vcloud/v1.5"
                  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1">
                  <Description>{} vApp Template</Description>
                </UploadVAppTemplateParams>
                """.format(
                    catalog_name, description
                )

                if self.client:
                    headers = {
                        "Accept": "application/*+xml;version=" + API_VERSION,
                        "x-vcloud-authorization": self.client._session.headers[
                            "x-vcloud-authorization"
                        ],
                    }
                    headers["Content-Type"] = (
                        "application/vnd.vmware.vcloud.uploadVAppTemplateParams+xml"
                    )

                response = self.perform_request(
                    req_type="POST", url=catalog_href, headers=headers, data=data
                )

                if response.status_code == requests.codes.created:
                    catalogItem = XmlElementTree.fromstring(response.text)
                    entity = [
                        child
                        for child in catalogItem
                        if child.get("type")
                        == "application/vnd.vmware.vcloud.vAppTemplate+xml"
                    ][0]
                    href = entity.get("href")
                    template = href

                    response = self.perform_request(
                        req_type="GET", url=href, headers=headers
                    )

                    if response.status_code == requests.codes.ok:
                        headers["Content-Type"] = "Content-Type text/xml"
                        result = re.search(
                            'rel="upload:default"\shref="(.*?\/descriptor.ovf)"',
                            response.text,
                        )

                        if result:
                            transfer_href = result.group(1)

                        response = self.perform_request(
                            req_type="PUT",
                            url=transfer_href,
                            headers=headers,
                            data=open(media_file_name, "rb"),
                        )

                        if response.status_code != requests.codes.ok:
                            self.logger.debug(
                                "Failed create vApp template for catalog name {} and image {}".format(
                                    catalog_name, media_file_name
                                )
                            )
                            return False

                    # TODO fix this with aync block
                    time.sleep(5)

                    self.logger.debug(
                        "vApp template for catalog name {} and image {}".format(
                            catalog_name, media_file_name
                        )
                    )

                    # uploading VMDK file
                    # check status of OVF upload and upload remaining files.
                    response = self.perform_request(
                        req_type="GET", url=template, headers=headers
                    )

                    if response.status_code == requests.codes.ok:
                        result = re.search(
                            'rel="upload:default"\s*href="(.*?vmdk)"', response.text
                        )

                        if result:
                            link_href = result.group(1)

                        # we skip ovf since it already uploaded.
                        if "ovf" in link_href:
                            continue

                        # The OVF file and VMDK must be in a same directory
                        head, _ = os.path.split(media_file_name)
                        file_vmdk = head + "/" + link_href.split("/")[-1]

                        if not os.path.isfile(file_vmdk):
                            return False

                        statinfo = os.stat(file_vmdk)
                        if statinfo.st_size == 0:
                            return False

                        hrefvmdk = link_href

                        if progress:
                            widgets = [
                                "Uploading file: ",
                                Percentage(),
                                " ",
                                Bar(),
                                " ",
                                ETA(),
                                " ",
                                FileTransferSpeed(),
                            ]
                            progress_bar = ProgressBar(
                                widgets=widgets, maxval=statinfo.st_size
                            ).start()

                        bytes_transferred = 0
                        f = open(file_vmdk, "rb")

                        while bytes_transferred < statinfo.st_size:
                            my_bytes = f.read(chunk_bytes)
                            if len(my_bytes) <= chunk_bytes:
                                headers["Content-Range"] = "bytes {}-{}/{}".format(
                                    bytes_transferred,
                                    len(my_bytes) - 1,
                                    statinfo.st_size,
                                )
                                headers["Content-Length"] = str(len(my_bytes))
                                response = requests.put(
                                    url=hrefvmdk,
                                    headers=headers,
                                    data=my_bytes,
                                    verify=False,
                                )

                                if response.status_code == requests.codes.ok:
                                    bytes_transferred += len(my_bytes)
                                    if progress:
                                        progress_bar.update(bytes_transferred)
                                else:
                                    self.logger.debug(
                                        "file upload failed with error: [{}] {}".format(
                                            response.status_code, response.text
                                        )
                                    )

                                    f.close()

                                    return False

                        f.close()
                        if progress:
                            progress_bar.finish()
                            time.sleep(10)

                    return True
                else:
                    self.logger.debug(
                        "Failed retrieve vApp template for catalog name {} for OVF {}".format(
                            catalog_name, media_file_name
                        )
                    )
                    return False
        except Exception as exp:
            self.logger.debug(
                "Failed while uploading OVF to catalog {} for OVF file {} with Exception {}".format(
                    catalog_name, media_file_name, exp
                )
            )

            raise vimconn.VimConnException(
                "Failed while uploading OVF to catalog {} for OVF file {} with Exception {}".format(
                    catalog_name, media_file_name, exp
                )
            )

        self.logger.debug(
            "Failed retrieve catalog name {} for OVF file {}".format(
                catalog_name, media_file_name
            )
        )

        return False

    def upload_vimimage(
        self,
        vca=None,
        catalog_name=None,
        media_name=None,
        medial_file_name=None,
        progress=False,
    ):
        """Upload media file"""
        # TODO add named parameters for readability
        return self.upload_ovf(
            vca=vca,
            catalog_name=catalog_name,
            image_name=media_name.split(".")[0],
            media_file_name=medial_file_name,
            description="medial_file_name",
            progress=progress,
        )

    def validate_uuid4(self, uuid_string=None):
        """Method validate correct format of UUID.

        Return: true if string represent valid uuid
        """
        try:
            uuid.UUID(uuid_string, version=4)
        except ValueError:
            return False

        return True

    def get_catalogid(self, catalog_name=None, catalogs=None):
        """Method check catalog and return catalog ID in UUID format.

        Args
            catalog_name: catalog name as string
            catalogs:  list of catalogs.

        Return: catalogs uuid
        """
        for catalog in catalogs:
            if catalog["name"] == catalog_name:
                catalog_id = catalog["id"]
                return catalog_id

        return None

    def get_catalogbyid(self, catalog_uuid=None, catalogs=None):
        """Method check catalog and return catalog name lookup done by catalog UUID.

        Args
            catalog_name: catalog name as string
            catalogs:  list of catalogs.

        Return: catalogs name or None
        """
        if not self.validate_uuid4(uuid_string=catalog_uuid):
            return None

        for catalog in catalogs:
            catalog_id = catalog.get("id")

            if catalog_id == catalog_uuid:
                return catalog.get("name")

        return None

    def get_catalog_obj(self, catalog_uuid=None, catalogs=None):
        """Method check catalog and return catalog name lookup done by catalog UUID.

        Args
            catalog_name: catalog name as string
            catalogs:  list of catalogs.

        Return: catalogs name or None
        """
        if not self.validate_uuid4(uuid_string=catalog_uuid):
            return None

        for catalog in catalogs:
            catalog_id = catalog.get("id")

            if catalog_id == catalog_uuid:
                return catalog

        return None

    def get_image_id_from_path(self, path=None, progress=False):
        """Method upload OVF image to vCloud director.

        Each OVF image represented as single catalog entry in vcloud director.
        The method check for existing catalog entry.  The check done by file name without file extension.

        if given catalog name already present method will respond with existing catalog uuid otherwise
        it will create new catalog entry and upload OVF file to newly created catalog.

        If method can't create catalog entry or upload a file it will throw exception.

        Method accept boolean flag progress that will output progress bar. It useful method
        for standalone upload use case. In case to test large file upload.

        Args
            path: - valid path to OVF file.
            progress - boolean progress bar show progress bar.

        Return: if image uploaded correct method will provide image catalog UUID.
        """
        if not path:
            raise vimconn.VimConnException("Image path can't be None.")

        if not os.path.isfile(path):
            raise vimconn.VimConnException("Can't read file. File not found.")

        if not os.access(path, os.R_OK):
            raise vimconn.VimConnException(
                "Can't read file. Check file permission to read."
            )

        self.logger.debug("get_image_id_from_path() client requesting {} ".format(path))

        _, filename = os.path.split(path)
        _, file_extension = os.path.splitext(path)
        if file_extension != ".ovf":
            self.logger.debug(
                "Wrong file extension {} connector support only OVF container.".format(
                    file_extension
                )
            )

            raise vimconn.VimConnException(
                "Wrong container.  vCloud director supports only OVF."
            )

        catalog_name = os.path.splitext(filename)[0]
        catalog_md5_name = hashlib.md5(path.encode("utf-8")).hexdigest()
        self.logger.debug(
            "File name {} Catalog Name {} file path {} "
            "vdc catalog name {}".format(filename, catalog_name, path, catalog_md5_name)
        )

        try:
            org, _ = self.get_vdc_details()
            catalogs = org.list_catalogs()
        except Exception as exp:
            self.logger.debug("Failed get catalogs() with Exception {} ".format(exp))

            raise vimconn.VimConnException(
                "Failed get catalogs() with Exception {} ".format(exp)
            )

        if len(catalogs) == 0:
            self.logger.info(
                "Creating a new catalog entry {} in vcloud director".format(
                    catalog_name
                )
            )

            if self.create_vimcatalog(org, catalog_md5_name) is None:
                raise vimconn.VimConnException(
                    "Failed create new catalog {} ".format(catalog_md5_name)
                )

            result = self.upload_vimimage(
                vca=org,
                catalog_name=catalog_md5_name,
                media_name=filename,
                medial_file_name=path,
                progress=progress,
            )

            if not result:
                raise vimconn.VimConnException(
                    "Failed create vApp template for catalog {} ".format(catalog_name)
                )

            return self.get_catalogid(catalog_name, catalogs)
        else:
            for catalog in catalogs:
                # search for existing catalog if we find same name we return ID
                # TODO optimize this
                if catalog["name"] == catalog_md5_name:
                    self.logger.debug(
                        "Found existing catalog entry for {} "
                        "catalog id {}".format(
                            catalog_name, self.get_catalogid(catalog_md5_name, catalogs)
                        )
                    )

                    return self.get_catalogid(catalog_md5_name, catalogs)

        # if we didn't find existing catalog we create a new one and upload image.
        self.logger.debug(
            "Creating new catalog entry {} - {}".format(catalog_name, catalog_md5_name)
        )
        if self.create_vimcatalog(org, catalog_md5_name) is None:
            raise vimconn.VimConnException(
                "Failed create new catalog {} ".format(catalog_md5_name)
            )

        result = self.upload_vimimage(
            vca=org,
            catalog_name=catalog_md5_name,
            media_name=filename,
            medial_file_name=path,
            progress=progress,
        )
        if not result:
            raise vimconn.VimConnException(
                "Failed create vApp template for catalog {} ".format(catalog_md5_name)
            )

        return self.get_catalogid(catalog_md5_name, org.list_catalogs())

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
        try:
            org, _ = self.get_vdc_details()
            image_list = []
            catalogs = org.list_catalogs()

            if len(catalogs) == 0:
                return image_list
            else:
                for catalog in catalogs:
                    catalog_uuid = catalog.get("id")
                    name = catalog.get("name")
                    filtered_dict = {}

                    if filter_dict.get("name") and filter_dict["name"] != name:
                        continue

                    if filter_dict.get("id") and filter_dict["id"] != catalog_uuid:
                        continue

                    filtered_dict["name"] = name
                    filtered_dict["id"] = catalog_uuid
                    image_list.append(filtered_dict)

                self.logger.debug(
                    "List of already created catalog items: {}".format(image_list)
                )

                return image_list
        except Exception as exp:
            raise vimconn.VimConnException(
                "Exception occured while retriving catalog items {}".format(exp)
            )

    def get_namebyvappid(self, vapp_uuid=None):
        """Method returns vApp name from vCD and lookup done by vapp_id.

        Args:
            vapp_uuid: vappid is application identifier

        Returns:
            The return vApp name otherwise None
        """
        try:
            if self.client and vapp_uuid:
                vapp_call = "{}/api/vApp/vapp-{}".format(self.url, vapp_uuid)
                headers = {
                    "Accept": "application/*+xml;version=" + API_VERSION,
                    "x-vcloud-authorization": self.client._session.headers[
                        "x-vcloud-authorization"
                    ],
                }

                response = self.perform_request(
                    req_type="GET", url=vapp_call, headers=headers
                )

                # Retry login if session expired & retry sending request
                if response.status_code == 403:
                    response = self.retry_rest("GET", vapp_call)

                tree = XmlElementTree.fromstring(response.text)

                return tree.attrib["name"] if "name" in tree.attrib else None
        except Exception as e:
            self.logger.exception(e)

            return None

        return None

    def new_vminstance(
        self,
        name=None,
        description="",
        start=False,
        image_id=None,
        flavor_id=None,
        affinity_group_list=[],
        net_list=[],
        cloud_config=None,
        disk_list=None,
        availability_zone_index=None,
        availability_zone_list=None,
    ):
        """Adds a VM instance to VIM
        Params:
            'start': (boolean) indicates if VM must start or created in pause mode.
            'image_id','flavor_id': image and flavor VIM id to use for the VM
            'net_list': list of interfaces, each one is a dictionary with:
                'name': (optional) name for the interface.
                'net_id': VIM network id where this interface must be connect to. Mandatory for type==virtual
                'vpci': (optional) virtual vPCI address to assign at the VM. Can be ignored depending on VIM
                    capabilities
                'model': (optional and only have sense for type==virtual) interface model: virtio, e1000, ...
                'mac_address': (optional) mac address to assign to this interface
                #TODO: CHECK if an optional 'vlan' parameter is needed for VIMs when type if VF and net_id is not
                    provided, the VLAN tag to be used. In case net_id is provided, the internal network vlan is used
                    for tagging VF
                'type': (mandatory) can be one of:
                    'virtual', in this case always connected to a network of type 'net_type=bridge'
                     'PCI-PASSTHROUGH' or 'PF' (passthrough): depending on VIM capabilities it can be connected to a
                           data/ptp network or it can created unconnected
                     'SR-IOV' or 'VF' (SRIOV with VLAN tag): same as PF for network connectivity.
                     'VFnotShared'(SRIOV without VLAN tag) same as PF for network connectivity. VF where no other VFs
                            are allocated on the same physical NIC
                'bw': (optional) only for PF/VF/VFnotShared. Minimal Bandwidth required for the interface in GBPS
                'port_security': (optional) If False it must avoid any traffic filtering at this interface. If missing
                                or True, it must apply the default VIM behaviour
                After execution the method will add the key:
                'vim_id': must be filled/added by this method with the VIM identifier generated by the VIM for this
                        interface. 'net_list' is modified
            'cloud_config': (optional) dictionary with:
                'key-pairs': (optional) list of strings with the public key to be inserted to the default user
                'users': (optional) list of users to be inserted, each item is a dict with:
                    'name': (mandatory) user name,
                    'key-pairs': (optional) list of strings with the public key to be inserted to the user
                'user-data': (optional) can be a string with the text script to be passed directly to cloud-init,
                    or a list of strings, each one contains a script to be passed, usually with a MIMEmultipart file
                'config-files': (optional). List of files to be transferred. Each item is a dict with:
                    'dest': (mandatory) string with the destination absolute path
                    'encoding': (optional, by default text). Can be one of:
                        'b64', 'base64', 'gz', 'gz+b64', 'gz+base64', 'gzip+b64', 'gzip+base64'
                    'content' (mandatory): string with the content of the file
                    'permissions': (optional) string with file permissions, typically octal notation '0644'
                    'owner': (optional) file owner, string with the format 'owner:group'
                'boot-data-drive': boolean to indicate if user-data must be passed using a boot drive (hard disk)
            'disk_list': (optional) list with additional disks to the VM. Each item is a dict with:
                'image_id': (optional). VIM id of an existing image. If not provided an empty disk must be mounted
                'size': (mandatory) string with the size of the disk in GB
            availability_zone_index: Index of availability_zone_list to use for this this VM. None if not AV required
            availability_zone_list: list of availability zones given by user in the VNFD descriptor.  Ignore if
                availability_zone_index is None
        Returns a tuple with the instance identifier and created_items or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_vminstance and action_vminstance. Can be used to store created ports, volumes, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        self.logger.info("Creating new instance for entry {}".format(name))
        self.logger.debug(
            "desc {} boot {} image_id: {} flavor_id: {} net_list: {} cloud_config {} disk_list {} "
            "availability_zone_index {} availability_zone_list {}".format(
                description,
                start,
                image_id,
                flavor_id,
                net_list,
                cloud_config,
                disk_list,
                availability_zone_index,
                availability_zone_list,
            )
        )

        # new vm name = vmname + tenant_id + uuid
        new_vm_name = [name, "-", str(uuid.uuid4())]
        vmname_andid = "".join(new_vm_name)

        for net in net_list:
            if net["type"] == "PCI-PASSTHROUGH":
                raise vimconn.VimConnNotSupportedException(
                    "Current vCD version does not support type : {}".format(net["type"])
                )

        if len(net_list) > 10:
            raise vimconn.VimConnNotSupportedException(
                "The VM hardware versions 7 and above support upto 10 NICs only"
            )

        # if vm already deployed we return existing uuid
        # we check for presence of VDC, Catalog entry and Flavor.
        org, vdc = self.get_vdc_details()
        if vdc is None:
            raise vimconn.VimConnNotFoundException(
                "new_vminstance(): Failed create vApp {}: (Failed retrieve VDC information)".format(
                    name
                )
            )

        catalogs = org.list_catalogs()
        if catalogs is None:
            # Retry once, if failed by refreshing token
            self.get_token()
            org = Org(self.client, resource=self.client.get_org())
            catalogs = org.list_catalogs()

        if catalogs is None:
            raise vimconn.VimConnNotFoundException(
                "new_vminstance(): Failed create vApp {}: (Failed retrieve catalogs list)".format(
                    name
                )
            )

        catalog_hash_name = self.get_catalogbyid(
            catalog_uuid=image_id, catalogs=catalogs
        )
        if catalog_hash_name:
            self.logger.info(
                "Found catalog entry {} for image id {}".format(
                    catalog_hash_name, image_id
                )
            )
        else:
            raise vimconn.VimConnNotFoundException(
                "new_vminstance(): Failed create vApp {}: "
                "(Failed retrieve catalog information {})".format(name, image_id)
            )

        # Set vCPU and Memory based on flavor.
        vm_cpus = None
        vm_memory = None
        vm_disk = None
        numas = None

        if flavor_id is not None:
            if flavor_id not in vimconnector.flavorlist:
                raise vimconn.VimConnNotFoundException(
                    "new_vminstance(): Failed create vApp {}: "
                    "Failed retrieve flavor information "
                    "flavor id {}".format(name, flavor_id)
                )
            else:
                try:
                    flavor = vimconnector.flavorlist[flavor_id]
                    vm_cpus = flavor[FLAVOR_VCPUS_KEY]
                    vm_memory = flavor[FLAVOR_RAM_KEY]
                    vm_disk = flavor[FLAVOR_DISK_KEY]
                    extended = flavor.get("extended", None)

                    if extended:
                        numas = extended.get("numas", None)
                except Exception as exp:
                    raise vimconn.VimConnException(
                        "Corrupted flavor. {}.Exception: {}".format(flavor_id, exp)
                    )

        # image upload creates template name as catalog name space Template.
        templateName = self.get_catalogbyid(catalog_uuid=image_id, catalogs=catalogs)
        # power_on = 'false'
        # if start:
        #    power_on = 'true'

        # client must provide at least one entry in net_list if not we report error
        # If net type is mgmt, then configure it as primary net & use its NIC index as primary NIC
        # If no mgmt, then the 1st NN in netlist is considered as primary net.
        primary_net = None
        primary_netname = None
        primary_net_href = None
        # network_mode = 'bridged'
        if net_list is not None and len(net_list) > 0:
            for net in net_list:
                if "use" in net and net["use"] == "mgmt" and not primary_net:
                    primary_net = net

            if primary_net is None:
                primary_net = net_list[0]

            try:
                primary_net_id = primary_net["net_id"]
                url_list = [self.url, "/api/network/", primary_net_id]
                primary_net_href = "".join(url_list)
                network_dict = self.get_vcd_network(network_uuid=primary_net_id)

                if "name" in network_dict:
                    primary_netname = network_dict["name"]
            except KeyError:
                raise vimconn.VimConnException(
                    "Corrupted flavor. {}".format(primary_net)
                )
        else:
            raise vimconn.VimConnUnexpectedResponse(
                "new_vminstance(): Failed network list is empty."
            )

        # use: 'data', 'bridge', 'mgmt'
        # create vApp.  Set vcpu and ram based on flavor id.
        try:
            vdc_obj = VDC(self.client, resource=org.get_vdc(self.tenant_name))
            if not vdc_obj:
                raise vimconn.VimConnNotFoundException(
                    "new_vminstance(): Failed to get VDC object"
                )

            for retry in (1, 2):
                items = org.get_catalog_item(catalog_hash_name, catalog_hash_name)
                catalog_items = [items.attrib]

                if len(catalog_items) == 1:
                    if self.client:
                        headers = {
                            "Accept": "application/*+xml;version=" + API_VERSION,
                            "x-vcloud-authorization": self.client._session.headers[
                                "x-vcloud-authorization"
                            ],
                        }

                    response = self.perform_request(
                        req_type="GET",
                        url=catalog_items[0].get("href"),
                        headers=headers,
                    )
                    catalogItem = XmlElementTree.fromstring(response.text)
                    entity = [
                        child
                        for child in catalogItem
                        if child.get("type")
                        == "application/vnd.vmware.vcloud.vAppTemplate+xml"
                    ][0]
                    vapp_tempalte_href = entity.get("href")

                response = self.perform_request(
                    req_type="GET", url=vapp_tempalte_href, headers=headers
                )

                if response.status_code != requests.codes.ok:
                    self.logger.debug(
                        "REST API call {} failed. Return status code {}".format(
                            vapp_tempalte_href, response.status_code
                        )
                    )
                else:
                    result = (response.text).replace("\n", " ")

                vapp_template_tree = XmlElementTree.fromstring(response.text)
                children_element = [
                    child for child in vapp_template_tree if "Children" in child.tag
                ][0]
                vm_element = [child for child in children_element if "Vm" in child.tag][
                    0
                ]
                vm_name = vm_element.get("name")
                vm_id = vm_element.get("id")
                vm_href = vm_element.get("href")

                # cpus = re.search('<rasd:Description>Number of Virtual CPUs</.*?>(\d+)</rasd:VirtualQuantity>',
                # result).group(1)
                memory_mb = re.search(
                    "<rasd:Description>Memory Size</.*?>(\d+)</rasd:VirtualQuantity>",
                    result,
                ).group(1)
                # cores = re.search('<vmw:CoresPerSocket ovf:required.*?>(\d+)</vmw:CoresPerSocket>', result).group(1)

                headers["Content-Type"] = (
                    "application/vnd.vmware.vcloud.instantiateVAppTemplateParams+xml"
                )
                vdc_id = vdc.get("id").split(":")[-1]
                instantiate_vapp_href = (
                    "{}/api/vdc/{}/action/instantiateVAppTemplate".format(
                        self.url, vdc_id
                    )
                )

                with open(
                    os.path.join(
                        os.path.dirname(__file__), "InstantiateVAppTemplateParams.xml"
                    ),
                    "r",
                ) as f:
                    template = f.read()

                data = template.format(
                    vmname_andid,
                    primary_netname,
                    primary_net_href,
                    vapp_tempalte_href,
                    vm_href,
                    vm_id,
                    vm_name,
                    primary_netname,
                    cpu=vm_cpus,
                    core=1,
                    memory=vm_memory,
                )

                response = self.perform_request(
                    req_type="POST",
                    url=instantiate_vapp_href,
                    headers=headers,
                    data=data,
                )

                if response.status_code != 201:
                    self.logger.error(
                        "REST call {} failed reason : {}"
                        "status code : {}".format(
                            instantiate_vapp_href, response.text, response.status_code
                        )
                    )
                    raise vimconn.VimConnException(
                        "new_vminstance(): Failed to create"
                        "vAapp {}".format(vmname_andid)
                    )
                else:
                    vapptask = self.get_task_from_response(response.text)

                if vapptask is None and retry == 1:
                    self.get_token()  # Retry getting token
                    continue
                else:
                    break

            if vapptask is None or vapptask is False:
                raise vimconn.VimConnUnexpectedResponse(
                    "new_vminstance(): failed to create vApp {}".format(vmname_andid)
                )

            # wait for task to complete
            result = self.client.get_task_monitor().wait_for_success(task=vapptask)

            if result.get("status") == "success":
                self.logger.debug(
                    "new_vminstance(): Sucessfully created Vapp {}".format(vmname_andid)
                )
            else:
                raise vimconn.VimConnUnexpectedResponse(
                    "new_vminstance(): failed to create vApp {}".format(vmname_andid)
                )
        except Exception as exp:
            raise vimconn.VimConnUnexpectedResponse(
                "new_vminstance(): failed to create vApp {} with Exception:{}".format(
                    vmname_andid, exp
                )
            )

        # we should have now vapp in undeployed state.
        try:
            vdc_obj = VDC(self.client, href=vdc.get("href"))
            vapp_resource = vdc_obj.get_vapp(vmname_andid)
            vapp_uuid = vapp_resource.get("id").split(":")[-1]
            vapp = VApp(self.client, resource=vapp_resource)
        except Exception as exp:
            raise vimconn.VimConnUnexpectedResponse(
                "new_vminstance(): Failed to retrieve vApp {} after creation: Exception:{}".format(
                    vmname_andid, exp
                )
            )

        if vapp_uuid is None:
            raise vimconn.VimConnUnexpectedResponse(
                "new_vminstance(): Failed to retrieve vApp {} after creation".format(
                    vmname_andid
                )
            )

        # Add PCI passthrough/SRIOV configrations
        pci_devices_info = []
        reserve_memory = False

        for net in net_list:
            if net["type"] == "PF" or net["type"] == "PCI-PASSTHROUGH":
                pci_devices_info.append(net)
            elif (
                net["type"] == "VF"
                or net["type"] == "SR-IOV"
                or net["type"] == "VFnotShared"
            ) and "net_id" in net:
                reserve_memory = True

        # Add PCI
        if len(pci_devices_info) > 0:
            self.logger.info(
                "Need to add PCI devices {} into VM {}".format(
                    pci_devices_info, vmname_andid
                )
            )
            PCI_devices_status, _, _ = self.add_pci_devices(
                vapp_uuid, pci_devices_info, vmname_andid
            )

            if PCI_devices_status:
                self.logger.info(
                    "Added PCI devives {} to VM {}".format(
                        pci_devices_info, vmname_andid
                    )
                )
                reserve_memory = True
            else:
                self.logger.info(
                    "Fail to add PCI devives {} to VM {}".format(
                        pci_devices_info, vmname_andid
                    )
                )

        # Add serial console - this allows cloud images to boot as if we are running under OpenStack
        self.add_serial_device(vapp_uuid)

        if vm_disk:
            # Assuming there is only one disk in ovf and fast provisioning in organization vDC is disabled
            result = self.modify_vm_disk(vapp_uuid, vm_disk)
            if result:
                self.logger.debug("Modified Disk size of VM {} ".format(vmname_andid))

        # Add new or existing disks to vApp
        if disk_list:
            added_existing_disk = False
            for disk in disk_list:
                if "device_type" in disk and disk["device_type"] == "cdrom":
                    image_id = disk["image_id"]
                    # Adding CD-ROM to VM
                    # will revisit code once specification ready to support this feature
                    self.insert_media_to_vm(vapp, image_id)
                elif "image_id" in disk and disk["image_id"] is not None:
                    self.logger.debug(
                        "Adding existing disk from image {} to vm {} ".format(
                            disk["image_id"], vapp_uuid
                        )
                    )
                    self.add_existing_disk(
                        catalogs=catalogs,
                        image_id=disk["image_id"],
                        size=disk["size"],
                        template_name=templateName,
                        vapp_uuid=vapp_uuid,
                    )
                    added_existing_disk = True
                else:
                    # Wait till added existing disk gets reflected into vCD database/API
                    if added_existing_disk:
                        time.sleep(5)
                        added_existing_disk = False
                    self.add_new_disk(vapp_uuid, disk["size"])

        if numas:
            # Assigning numa affinity setting
            for numa in numas:
                if "paired-threads-id" in numa:
                    paired_threads_id = numa["paired-threads-id"]
                    self.set_numa_affinity(vapp_uuid, paired_threads_id)

        # add NICs & connect to networks in netlist
        try:
            vdc_obj = VDC(self.client, href=vdc.get("href"))
            vapp_resource = vdc_obj.get_vapp(vmname_andid)
            vapp = VApp(self.client, resource=vapp_resource)
            vapp_id = vapp_resource.get("id").split(":")[-1]

            self.logger.info("Removing primary NIC: ")
            # First remove all NICs so that NIC properties can be adjusted as needed
            self.remove_primary_network_adapter_from_all_vms(vapp)

            self.logger.info("Request to connect VM to a network: {}".format(net_list))
            primary_nic_index = 0
            nicIndex = 0
            for net in net_list:
                # openmano uses network id in UUID format.
                # vCloud Director need a name so we do reverse operation from provided UUID we lookup a name
                # [{'use': 'bridge', 'net_id': '527d4bf7-566a-41e7-a9e7-ca3cdd9cef4f', 'type': 'virtual',
                #   'vpci': '0000:00:11.0', 'name': 'eth0'}]

                if "net_id" not in net:
                    continue

                # Using net_id as a vim_id i.e. vim interface id, as do not have saperate vim interface id
                # Same will be returned in refresh_vms_status() as vim_interface_id
                net["vim_id"] = net[
                    "net_id"
                ]  # Provide the same VIM identifier as the VIM network

                interface_net_id = net["net_id"]
                interface_net_name = self.get_network_name_by_id(
                    network_uuid=interface_net_id
                )
                interface_network_mode = net["use"]

                if interface_network_mode == "mgmt":
                    primary_nic_index = nicIndex

                """- POOL (A static IP address is allocated automatically from a pool of addresses.)
                                  - DHCP (The IP address is obtained from a DHCP service.)
                                  - MANUAL (The IP address is assigned manually in the IpAddress element.)
                                  - NONE (No IP addressing mode specified.)"""

                if primary_netname is not None:
                    self.logger.debug(
                        "new_vminstance(): Filtering by net name {}".format(
                            interface_net_name
                        )
                    )
                    nets = [
                        n
                        for n in self.get_network_list()
                        if n.get("name") == interface_net_name
                    ]

                    if len(nets) == 1:
                        self.logger.info(
                            "new_vminstance(): Found requested network: {}".format(
                                nets[0].get("name")
                            )
                        )

                        if interface_net_name != primary_netname:
                            # connect network to VM - with all DHCP by default
                            self.logger.info(
                                "new_vminstance(): Attaching net {} to vapp".format(
                                    interface_net_name
                                )
                            )
                            self.connect_vapp_to_org_vdc_network(
                                vapp_id, nets[0].get("name")
                            )

                        type_list = ("PF", "PCI-PASSTHROUGH", "VFnotShared")
                        nic_type = "VMXNET3"
                        if "type" in net and net["type"] not in type_list:
                            # fetching nic type from vnf
                            if "model" in net:
                                if net["model"] is not None:
                                    if (
                                        net["model"].lower() == "paravirt"
                                        or net["model"].lower() == "virtio"
                                    ):
                                        nic_type = "VMXNET3"
                                else:
                                    nic_type = net["model"]

                                self.logger.info(
                                    "new_vminstance(): adding network adapter "
                                    "to a network {}".format(nets[0].get("name"))
                                )
                                self.add_network_adapter_to_vms(
                                    vapp,
                                    nets[0].get("name"),
                                    primary_nic_index,
                                    nicIndex,
                                    net,
                                    nic_type=nic_type,
                                )
                            else:
                                self.logger.info(
                                    "new_vminstance(): adding network adapter "
                                    "to a network {}".format(nets[0].get("name"))
                                )

                                if net["type"] in ["SR-IOV", "VF"]:
                                    nic_type = net["type"]
                                self.add_network_adapter_to_vms(
                                    vapp,
                                    nets[0].get("name"),
                                    primary_nic_index,
                                    nicIndex,
                                    net,
                                    nic_type=nic_type,
                                )
                nicIndex += 1

            # cloud-init for ssh-key injection
            if cloud_config:
                # Create a catalog which will be carrying the config drive ISO
                # This catalog is deleted during vApp deletion. The catalog name carries
                # vApp UUID and thats how it gets identified during its deletion.
                config_drive_catalog_name = "cfg_drv-" + vapp_uuid
                self.logger.info(
                    'new_vminstance(): Creating catalog "{}" to carry config drive ISO'.format(
                        config_drive_catalog_name
                    )
                )
                config_drive_catalog_id = self.create_vimcatalog(
                    org, config_drive_catalog_name
                )

                if config_drive_catalog_id is None:
                    error_msg = (
                        "new_vminstance(): Failed to create new catalog '{}' to carry the config drive "
                        "ISO".format(config_drive_catalog_name)
                    )
                    raise Exception(error_msg)

                # Create config-drive ISO
                _, userdata = self._create_user_data(cloud_config)
                # self.logger.debug('new_vminstance(): The userdata for cloud-init: {}'.format(userdata))
                iso_path = self.create_config_drive_iso(userdata)
                self.logger.debug(
                    "new_vminstance(): The ISO is successfully created. Path: {}".format(
                        iso_path
                    )
                )

                self.logger.info(
                    "new_vminstance(): uploading iso to catalog {}".format(
                        config_drive_catalog_name
                    )
                )
                self.upload_iso_to_catalog(config_drive_catalog_id, iso_path)
                # Attach the config-drive ISO to the VM
                self.logger.info(
                    "new_vminstance(): Attaching the config-drive ISO to the VM"
                )
                self.insert_media_to_vm(vapp, config_drive_catalog_id)
                shutil.rmtree(os.path.dirname(iso_path), ignore_errors=True)

            # If VM has PCI devices or SRIOV reserve memory for VM
            if reserve_memory:
                self.reserve_memory_for_all_vms(vapp, memory_mb)

            self.logger.debug(
                "new_vminstance(): starting power on vApp {} ".format(vmname_andid)
            )

            poweron_task = self.power_on_vapp(vapp_id, vmname_andid)
            result = self.client.get_task_monitor().wait_for_success(task=poweron_task)
            if result.get("status") == "success":
                self.logger.info(
                    "new_vminstance(): Successfully power on "
                    "vApp {}".format(vmname_andid)
                )
            else:
                self.logger.error(
                    "new_vminstance(): failed to power on vApp "
                    "{}".format(vmname_andid)
                )

        except Exception as exp:
            try:
                self.delete_vminstance(vapp_uuid)
            except Exception as exp2:
                self.logger.error("new_vminstance rollback fail {}".format(exp2))
            # it might be a case if specific mandatory entry in dict is empty or some other pyVcloud exception
            self.logger.error(
                "new_vminstance(): Failed create new vm instance {} with exception {}".format(
                    name, exp
                )
            )
            raise vimconn.VimConnException(
                "new_vminstance(): Failed create new vm instance {} with exception {}".format(
                    name, exp
                )
            )
        # check if vApp deployed and if that the case return vApp UUID otherwise -1
        wait_time = 0
        vapp_uuid = None
        while wait_time <= MAX_WAIT_TIME:
            try:
                vapp_resource = vdc_obj.get_vapp(vmname_andid)
                vapp = VApp(self.client, resource=vapp_resource)
            except Exception as exp:
                raise vimconn.VimConnUnexpectedResponse(
                    "new_vminstance(): Failed to retrieve vApp {} after creation: Exception:{}".format(
                        vmname_andid, exp
                    )
                )

            # if vapp and vapp.me.deployed:
            if vapp and vapp_resource.get("deployed") == "true":
                vapp_uuid = vapp_resource.get("id").split(":")[-1]
                break
            else:
                self.logger.debug(
                    "new_vminstance(): Wait for vApp {} to deploy".format(name)
                )
                time.sleep(INTERVAL_TIME)

            wait_time += INTERVAL_TIME

        # SET Affinity Rule for VM
        # Pre-requisites: User has created Hosh Groups in vCenter with respective Hosts to be used
        # While creating VIM account user has to pass the Host Group names in availability_zone list
        # "availability_zone" is a  part of VIM "config" parameters
        # For example, in VIM config: "availability_zone":["HG_170","HG_174","HG_175"]
        # Host groups are referred as availability zones
        # With following procedure, deployed VM will be added into a VM group.
        # Then A VM to Host Affinity rule will be created using the VM group & Host group.
        if availability_zone_list:
            self.logger.debug(
                "Existing Host Groups in VIM {}".format(
                    self.config.get("availability_zone")
                )
            )
            # Admin access required for creating Affinity rules
            client = self.connect_as_admin()

            if not client:
                raise vimconn.VimConnConnectionException(
                    "Failed to connect vCD as admin"
                )
            else:
                self.client = client

            if self.client:
                headers = {
                    "Accept": "application/*+xml;version=27.0",
                    "x-vcloud-authorization": self.client._session.headers[
                        "x-vcloud-authorization"
                    ],
                }

            # Step1: Get provider vdc details from organization
            pvdc_href = self.get_pvdc_for_org(self.tenant_name, headers)
            if pvdc_href is not None:
                # Step2: Found required pvdc, now get resource pool information
                respool_href = self.get_resource_pool_details(pvdc_href, headers)
                if respool_href is None:
                    # Raise error if respool_href not found
                    msg = "new_vminstance():Error in finding resource pool details in pvdc {}".format(
                        pvdc_href
                    )
                    self.log_message(msg)

            # Step3: Verify requested availability zone(hostGroup) is present in vCD
            # get availability Zone
            vm_az = self.get_vm_availability_zone(
                availability_zone_index, availability_zone_list
            )

            # check if provided av zone(hostGroup) is present in vCD VIM
            status = self.check_availibility_zone(vm_az, respool_href, headers)
            if status is False:
                msg = (
                    "new_vminstance(): Error in finding availability zone(Host Group): {} in "
                    "resource pool {} status: {}"
                ).format(vm_az, respool_href, status)
                self.log_message(msg)
            else:
                self.logger.debug(
                    "new_vminstance(): Availability zone {} found in VIM".format(vm_az)
                )

            # Step4: Find VM group references to create vm group
            vmgrp_href = self.find_vmgroup_reference(respool_href, headers)
            if vmgrp_href is None:
                msg = "new_vminstance(): No reference to VmGroup found in resource pool"
                self.log_message(msg)

            # Step5: Create a VmGroup with name az_VmGroup
            vmgrp_name = (
                vm_az + "_" + name
            )  # Formed VM Group name = Host Group name + VM name
            status = self.create_vmgroup(vmgrp_name, vmgrp_href, headers)
            if status is not True:
                msg = "new_vminstance(): Error in creating VM group {}".format(
                    vmgrp_name
                )
                self.log_message(msg)

            # VM Group url to add vms to vm group
            vmgrpname_url = self.url + "/api/admin/extension/vmGroup/name/" + vmgrp_name

            # Step6: Add VM to VM Group
            # Find VM uuid from vapp_uuid
            vm_details = self.get_vapp_details_rest(vapp_uuid)
            vm_uuid = vm_details["vmuuid"]

            status = self.add_vm_to_vmgroup(vm_uuid, vmgrpname_url, vmgrp_name, headers)
            if status is not True:
                msg = "new_vminstance(): Error in adding VM to VM group {}".format(
                    vmgrp_name
                )
                self.log_message(msg)

            # Step7: Create VM to Host affinity rule
            addrule_href = self.get_add_rule_reference(respool_href, headers)
            if addrule_href is None:
                msg = "new_vminstance(): Error in finding href to add rule in resource pool: {}".format(
                    respool_href
                )
                self.log_message(msg)

            status = self.create_vm_to_host_affinity_rule(
                addrule_href, vmgrp_name, vm_az, "Affinity", headers
            )
            if status is False:
                msg = "new_vminstance(): Error in creating affinity rule for VM {} in Host group {}".format(
                    name, vm_az
                )
                self.log_message(msg)
            else:
                self.logger.debug(
                    "new_vminstance(): Affinity rule created successfully. Added {} in Host group {}".format(
                        name, vm_az
                    )
                )
            # Reset token to a normal user to perform other operations
            self.get_token()

        if vapp_uuid is not None:
            return vapp_uuid, None
        else:
            raise vimconn.VimConnUnexpectedResponse(
                "new_vminstance(): Failed create new vm instance {}".format(name)
            )

    def create_config_drive_iso(self, user_data):
        tmpdir = tempfile.mkdtemp()
        iso_path = os.path.join(tmpdir, "ConfigDrive.iso")
        latest_dir = os.path.join(tmpdir, "openstack", "latest")
        os.makedirs(latest_dir)
        with open(
            os.path.join(latest_dir, "meta_data.json"), "w"
        ) as meta_file_obj, open(
            os.path.join(latest_dir, "user_data"), "w"
        ) as userdata_file_obj:
            userdata_file_obj.write(user_data)
            meta_file_obj.write(
                json.dumps(
                    {
                        "availability_zone": "nova",
                        "launch_index": 0,
                        "name": "ConfigDrive",
                        "uuid": str(uuid.uuid4()),
                    }
                )
            )
        genisoimage_cmd = (
            "genisoimage -J -r -V config-2 -o {iso_path} {source_dir_path}".format(
                iso_path=iso_path, source_dir_path=tmpdir
            )
        )
        self.logger.info(
            'create_config_drive_iso(): Creating ISO by running command "{}"'.format(
                genisoimage_cmd
            )
        )

        try:
            FNULL = open(os.devnull, "w")
            subprocess.check_call(genisoimage_cmd, shell=True, stdout=FNULL)
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            error_msg = "create_config_drive_iso(): Exception while running genisoimage command: {}".format(
                e
            )
            self.logger.error(error_msg)
            raise Exception(error_msg)

        return iso_path

    def upload_iso_to_catalog(self, catalog_id, iso_file_path):
        if not os.path.isfile(iso_file_path):
            error_msg = "upload_iso_to_catalog(): Given iso file is not present. Given path: {}".format(
                iso_file_path
            )
            self.logger.error(error_msg)
            raise Exception(error_msg)

        iso_file_stat = os.stat(iso_file_path)
        xml_media_elem = """<?xml version="1.0" encoding="UTF-8"?>
                            <Media
                                xmlns="http://www.vmware.com/vcloud/v1.5"
                                name="{iso_name}"
                                size="{iso_size}"
                                imageType="iso">
                                <Description>ISO image for config-drive</Description>
                            </Media>""".format(
            iso_name=os.path.basename(iso_file_path), iso_size=iso_file_stat.st_size
        )
        headers = {
            "Accept": "application/*+xml;version=" + API_VERSION,
            "x-vcloud-authorization": self.client._session.headers[
                "x-vcloud-authorization"
            ],
        }
        headers["Content-Type"] = "application/vnd.vmware.vcloud.media+xml"
        catalog_href = self.url + "/api/catalog/" + catalog_id + "/action/upload"
        response = self.perform_request(
            req_type="POST", url=catalog_href, headers=headers, data=xml_media_elem
        )

        if response.status_code != 201:
            error_msg = "upload_iso_to_catalog(): Failed to POST an action/upload request to {}".format(
                catalog_href
            )
            self.logger.error(error_msg)
            raise Exception(error_msg)

        catalogItem = XmlElementTree.fromstring(response.text)
        entity = [
            child
            for child in catalogItem
            if child.get("type") == "application/vnd.vmware.vcloud.media+xml"
        ][0]
        entity_href = entity.get("href")

        response = self.perform_request(
            req_type="GET", url=entity_href, headers=headers
        )
        if response.status_code != 200:
            raise Exception(
                "upload_iso_to_catalog(): Failed to GET entity href {}".format(
                    entity_href
                )
            )

        match = re.search(
            r'<Files>\s+?<File.+?href="(.+?)"/>\s+?</File>\s+?</Files>',
            response.text,
            re.DOTALL,
        )
        if match:
            media_upload_href = match.group(1)
        else:
            raise Exception(
                "Could not parse the upload URL for the media file from the last response"
            )
        upload_iso_task = self.get_task_from_response(response.text)
        headers["Content-Type"] = "application/octet-stream"
        response = self.perform_request(
            req_type="PUT",
            url=media_upload_href,
            headers=headers,
            data=open(iso_file_path, "rb"),
        )

        if response.status_code != 200:
            raise Exception('PUT request to "{}" failed'.format(media_upload_href))

        result = self.client.get_task_monitor().wait_for_success(task=upload_iso_task)
        if result.get("status") != "success":
            raise Exception(
                "The upload iso task failed with status {}".format(result.get("status"))
            )

    def set_availability_zones(self):
        """
        Set vim availability zone
        """
        vim_availability_zones = None
        availability_zone = None

        if "availability_zone" in self.config:
            vim_availability_zones = self.config.get("availability_zone")

        if isinstance(vim_availability_zones, str):
            availability_zone = [vim_availability_zones]
        elif isinstance(vim_availability_zones, list):
            availability_zone = vim_availability_zones
        else:
            return availability_zone

        return availability_zone

    def get_vm_availability_zone(self, availability_zone_index, availability_zone_list):
        """
        Return the availability zone to be used by the created VM.
        returns: The VIM availability zone to be used or None
        """
        if availability_zone_index is None:
            if not self.config.get("availability_zone"):
                return None
            elif isinstance(self.config.get("availability_zone"), str):
                return self.config["availability_zone"]
            else:
                return self.config["availability_zone"][0]

        vim_availability_zones = self.availability_zone

        # check if VIM offer enough availability zones describe in the VNFD
        if vim_availability_zones and len(availability_zone_list) <= len(
            vim_availability_zones
        ):
            # check if all the names of NFV AV match VIM AV names
            match_by_index = False
            for av in availability_zone_list:
                if av not in vim_availability_zones:
                    match_by_index = True
                    break

            if match_by_index:
                self.logger.debug(
                    "Required Availability zone or Host Group not found in VIM config"
                )
                self.logger.debug(
                    "Input Availability zone list: {}".format(availability_zone_list)
                )
                self.logger.debug(
                    "VIM configured Availability zones: {}".format(
                        vim_availability_zones
                    )
                )
                self.logger.debug("VIM Availability zones will be used by index")
                return vim_availability_zones[availability_zone_index]
            else:
                return availability_zone_list[availability_zone_index]
        else:
            raise vimconn.VimConnConflictException(
                "No enough availability zones at VIM for this deployment"
            )

    def create_vm_to_host_affinity_rule(
        self, addrule_href, vmgrpname, hostgrpname, polarity, headers
    ):
        """Method to create VM to Host Affinity rule in vCD

        Args:
            addrule_href - href to make a POST request
            vmgrpname - name of the VM group created
            hostgrpnmae - name of the host group created earlier
            polarity - Affinity or Anti-affinity (default: Affinity)
            headers - headers to make REST call

        Returns:
            True- if rule is created
            False- Failed to create rule due to some error

        """
        task_status = False
        rule_name = polarity + "_" + vmgrpname
        payload = """<?xml version="1.0" encoding="UTF-8"?>
                     <vmext:VMWVmHostAffinityRule
                       xmlns:vmext="http://www.vmware.com/vcloud/extension/v1.5"
                       xmlns:vcloud="http://www.vmware.com/vcloud/v1.5"
                       type="application/vnd.vmware.admin.vmwVmHostAffinityRule+xml">
                       <vcloud:Name>{}</vcloud:Name>
                       <vcloud:IsEnabled>true</vcloud:IsEnabled>
                       <vcloud:IsMandatory>true</vcloud:IsMandatory>
                       <vcloud:Polarity>{}</vcloud:Polarity>
                       <vmext:HostGroupName>{}</vmext:HostGroupName>
                       <vmext:VmGroupName>{}</vmext:VmGroupName>
                     </vmext:VMWVmHostAffinityRule>""".format(
            rule_name, polarity, hostgrpname, vmgrpname
        )

        resp = self.perform_request(
            req_type="POST", url=addrule_href, headers=headers, data=payload
        )

        if resp.status_code != requests.codes.accepted:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    addrule_href, resp.status_code
                )
            )
            task_status = False

            return task_status
        else:
            affinity_task = self.get_task_from_response(resp.content)
            self.logger.debug("affinity_task: {}".format(affinity_task))

            if affinity_task is None or affinity_task is False:
                raise vimconn.VimConnUnexpectedResponse("failed to find affinity task")
            # wait for task to complete
            result = self.client.get_task_monitor().wait_for_success(task=affinity_task)

            if result.get("status") == "success":
                self.logger.debug(
                    "Successfully created affinity rule {}".format(rule_name)
                )
                return True
            else:
                raise vimconn.VimConnUnexpectedResponse(
                    "failed to create affinity rule {}".format(rule_name)
                )

    def get_add_rule_reference(self, respool_href, headers):
        """This method finds href to add vm to host affinity rule to vCD

        Args:
            respool_href- href to resource pool
            headers- header information to make REST call

        Returns:
            None - if no valid href to add rule found or
            addrule_href - href to add vm to host affinity rule of resource pool
        """
        addrule_href = None
        resp = self.perform_request(req_type="GET", url=respool_href, headers=headers)

        if resp.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    respool_href, resp.status_code
                )
            )
        else:
            resp_xml = XmlElementTree.fromstring(resp.content)
            for child in resp_xml:
                if "VMWProviderVdcResourcePool" in child.tag:
                    for schild in child:
                        if "Link" in schild.tag:
                            if (
                                schild.attrib.get("type")
                                == "application/vnd.vmware.admin.vmwVmHostAffinityRule+xml"
                                and schild.attrib.get("rel") == "add"
                            ):
                                addrule_href = schild.attrib.get("href")
                                break

        return addrule_href

    def add_vm_to_vmgroup(self, vm_uuid, vmGroupNameURL, vmGroup_name, headers):
        """Method to add deployed VM to newly created VM Group.
            This is required to create VM to Host affinity in vCD

        Args:
            vm_uuid- newly created vm uuid
            vmGroupNameURL- URL to VM Group name
            vmGroup_name- Name of VM group created
            headers- Headers for REST request

        Returns:
            True- if VM added to VM group successfully
            False- if any error encounter
        """
        addvm_resp = self.perform_request(
            req_type="GET", url=vmGroupNameURL, headers=headers
        )  # , data=payload)

        if addvm_resp.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call to get VM Group Name url {} failed. Return status code {}".format(
                    vmGroupNameURL, addvm_resp.status_code
                )
            )
            return False
        else:
            resp_xml = XmlElementTree.fromstring(addvm_resp.content)
            for child in resp_xml:
                if child.tag.split("}")[1] == "Link":
                    if child.attrib.get("rel") == "addVms":
                        addvmtogrpURL = child.attrib.get("href")

        # Get vm details
        url_list = [self.url, "/api/vApp/vm-", vm_uuid]
        vmdetailsURL = "".join(url_list)

        resp = self.perform_request(req_type="GET", url=vmdetailsURL, headers=headers)

        if resp.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    vmdetailsURL, resp.status_code
                )
            )
            return False

        # Parse VM details
        resp_xml = XmlElementTree.fromstring(resp.content)
        if resp_xml.tag.split("}")[1] == "Vm":
            vm_id = resp_xml.attrib.get("id")
            vm_name = resp_xml.attrib.get("name")
            vm_href = resp_xml.attrib.get("href")
            # print vm_id, vm_name, vm_href

        # Add VM into VMgroup
        payload = """<?xml version="1.0" encoding="UTF-8"?>\
                   <ns2:Vms xmlns:ns2="http://www.vmware.com/vcloud/v1.5" \
                    xmlns="http://www.vmware.com/vcloud/versions" \
                    xmlns:ns3="http://schemas.dmtf.org/ovf/envelope/1" \
                    xmlns:ns4="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" \
                    xmlns:ns5="http://schemas.dmtf.org/wbem/wscim/1/common" \
                    xmlns:ns6="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" \
                    xmlns:ns7="http://www.vmware.com/schema/ovf" \
                    xmlns:ns8="http://schemas.dmtf.org/ovf/environment/1" \
                    xmlns:ns9="http://www.vmware.com/vcloud/extension/v1.5">\
                    <ns2:VmReference href="{}" id="{}" name="{}" \
                    type="application/vnd.vmware.vcloud.vm+xml" />\
                   </ns2:Vms>""".format(
            vm_href, vm_id, vm_name
        )

        addvmtogrp_resp = self.perform_request(
            req_type="POST", url=addvmtogrpURL, headers=headers, data=payload
        )

        if addvmtogrp_resp.status_code != requests.codes.accepted:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    addvmtogrpURL, addvmtogrp_resp.status_code
                )
            )

            return False
        else:
            self.logger.debug(
                "Done adding VM {} to VMgroup {}".format(vm_name, vmGroup_name)
            )

            return True

    def create_vmgroup(self, vmgroup_name, vmgroup_href, headers):
        """Method to create a VM group in vCD

        Args:
           vmgroup_name : Name of VM group to be created
           vmgroup_href : href for vmgroup
           headers- Headers for REST request
        """
        # POST to add URL with required data
        vmgroup_status = False
        payload = """<VMWVmGroup xmlns="http://www.vmware.com/vcloud/extension/v1.5" \
                       xmlns:vcloud_v1.5="http://www.vmware.com/vcloud/v1.5" name="{}">\
                   <vmCount>1</vmCount>\
                   </VMWVmGroup>""".format(
            vmgroup_name
        )
        resp = self.perform_request(
            req_type="POST", url=vmgroup_href, headers=headers, data=payload
        )

        if resp.status_code != requests.codes.accepted:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    vmgroup_href, resp.status_code
                )
            )

            return vmgroup_status
        else:
            vmgroup_task = self.get_task_from_response(resp.content)
            if vmgroup_task is None or vmgroup_task is False:
                raise vimconn.VimConnUnexpectedResponse(
                    "create_vmgroup(): failed to create VM group {}".format(
                        vmgroup_name
                    )
                )

            # wait for task to complete
            result = self.client.get_task_monitor().wait_for_success(task=vmgroup_task)

            if result.get("status") == "success":
                self.logger.debug(
                    "create_vmgroup(): Successfully created VM group {}".format(
                        vmgroup_name
                    )
                )
                # time.sleep(10)
                vmgroup_status = True

                return vmgroup_status
            else:
                raise vimconn.VimConnUnexpectedResponse(
                    "create_vmgroup(): failed to create VM group {}".format(
                        vmgroup_name
                    )
                )

    def find_vmgroup_reference(self, url, headers):
        """Method to create a new VMGroup which is required to add created VM
        Args:
           url- resource pool href
           headers- header information

        Returns:
           returns href to VM group to create VM group
        """
        # Perform GET on resource pool to find 'add' link to create VMGroup
        # https://vcd-ip/api/admin/extension/providervdc/<providervdc id>/resourcePools
        vmgrp_href = None
        resp = self.perform_request(req_type="GET", url=url, headers=headers)

        if resp.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    url, resp.status_code
                )
            )
        else:
            # Get the href to add vmGroup to vCD
            resp_xml = XmlElementTree.fromstring(resp.content)
            for child in resp_xml:
                if "VMWProviderVdcResourcePool" in child.tag:
                    for schild in child:
                        if "Link" in schild.tag:
                            # Find href with type VMGroup and rel with add
                            if (
                                schild.attrib.get("type")
                                == "application/vnd.vmware.admin.vmwVmGroupType+xml"
                                and schild.attrib.get("rel") == "add"
                            ):
                                vmgrp_href = schild.attrib.get("href")

                                return vmgrp_href

    def check_availibility_zone(self, az, respool_href, headers):
        """Method to verify requested av zone is present or not in provided
        resource pool

        Args:
            az - name of hostgroup (availibility_zone)
            respool_href - Resource Pool href
            headers - Headers to make REST call
        Returns:
            az_found - True if availibility_zone is found else False
        """
        az_found = False
        headers["Accept"] = "application/*+xml;version=27.0"
        resp = self.perform_request(req_type="GET", url=respool_href, headers=headers)

        if resp.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    respool_href, resp.status_code
                )
            )
        else:
            # Get the href to hostGroups and find provided hostGroup is present in it
            resp_xml = XmlElementTree.fromstring(resp.content)

            for child in resp_xml:
                if "VMWProviderVdcResourcePool" in child.tag:
                    for schild in child:
                        if "Link" in schild.tag:
                            if (
                                schild.attrib.get("type")
                                == "application/vnd.vmware.admin.vmwHostGroupsType+xml"
                            ):
                                hostGroup_href = schild.attrib.get("href")
                                hg_resp = self.perform_request(
                                    req_type="GET", url=hostGroup_href, headers=headers
                                )

                                if hg_resp.status_code != requests.codes.ok:
                                    self.logger.debug(
                                        "REST API call {} failed. Return status code {}".format(
                                            hostGroup_href, hg_resp.status_code
                                        )
                                    )
                                else:
                                    hg_resp_xml = XmlElementTree.fromstring(
                                        hg_resp.content
                                    )
                                    for hostGroup in hg_resp_xml:
                                        if "HostGroup" in hostGroup.tag:
                                            if hostGroup.attrib.get("name") == az:
                                                az_found = True
                                                break

        return az_found

    def get_pvdc_for_org(self, org_vdc, headers):
        """This method gets provider vdc references from organisation

        Args:
           org_vdc - name of the organisation VDC to find pvdc
           headers - headers to make REST call

        Returns:
           None - if no pvdc href found else
           pvdc_href - href to pvdc
        """
        # Get provider VDC references from vCD
        pvdc_href = None
        # url = '<vcd url>/api/admin/extension/providerVdcReferences'
        url_list = [self.url, "/api/admin/extension/providerVdcReferences"]
        url = "".join(url_list)

        response = self.perform_request(req_type="GET", url=url, headers=headers)
        if response.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    url, response.status_code
                )
            )
        else:
            xmlroot_response = XmlElementTree.fromstring(response.text)
            for child in xmlroot_response:
                if "ProviderVdcReference" in child.tag:
                    pvdc_href = child.attrib.get("href")
                    # Get vdcReferences to find org
                    pvdc_resp = self.perform_request(
                        req_type="GET", url=pvdc_href, headers=headers
                    )

                    if pvdc_resp.status_code != requests.codes.ok:
                        raise vimconn.VimConnException(
                            "REST API call {} failed. "
                            "Return status code {}".format(url, pvdc_resp.status_code)
                        )

                    pvdc_resp_xml = XmlElementTree.fromstring(pvdc_resp.content)
                    for child in pvdc_resp_xml:
                        if "Link" in child.tag:
                            if (
                                child.attrib.get("type")
                                == "application/vnd.vmware.admin.vdcReferences+xml"
                            ):
                                vdc_href = child.attrib.get("href")

                                # Check if provided org is present in vdc
                                vdc_resp = self.perform_request(
                                    req_type="GET", url=vdc_href, headers=headers
                                )

                                if vdc_resp.status_code != requests.codes.ok:
                                    raise vimconn.VimConnException(
                                        "REST API call {} failed. "
                                        "Return status code {}".format(
                                            url, vdc_resp.status_code
                                        )
                                    )
                                vdc_resp_xml = XmlElementTree.fromstring(
                                    vdc_resp.content
                                )

                                for child in vdc_resp_xml:
                                    if "VdcReference" in child.tag:
                                        if child.attrib.get("name") == org_vdc:
                                            return pvdc_href

    def get_resource_pool_details(self, pvdc_href, headers):
        """Method to get resource pool information.
        Host groups are property of resource group.
        To get host groups, we need to GET details of resource pool.

        Args:
            pvdc_href: href to pvdc details
            headers: headers

        Returns:
            respool_href - Returns href link reference to resource pool
        """
        respool_href = None
        resp = self.perform_request(req_type="GET", url=pvdc_href, headers=headers)

        if resp.status_code != requests.codes.ok:
            self.logger.debug(
                "REST API call {} failed. Return status code {}".format(
                    pvdc_href, resp.status_code
                )
            )
        else:
            respool_resp_xml = XmlElementTree.fromstring(resp.content)
            for child in respool_resp_xml:
                if "Link" in child.tag:
                    if (
                        child.attrib.get("type")
                        == "application/vnd.vmware.admin.vmwProviderVdcResourcePoolSet+xml"
                    ):
                        respool_href = child.attrib.get("href")
                        break

        return respool_href

    def log_message(self, msg):
        """
        Method to log error messages related to Affinity rule creation
        in new_vminstance & raise Exception
            Args :
                msg - Error message to be logged

        """
        # get token to connect vCD as a normal user
        self.get_token()
        self.logger.debug(msg)

        raise vimconn.VimConnException(msg)

    def get_vminstance(self, vim_vm_uuid=None):
        """Returns the VM instance information from VIM"""
        self.logger.debug("Client requesting vm instance {} ".format(vim_vm_uuid))

        _, vdc = self.get_vdc_details()
        if vdc is None:
            raise vimconn.VimConnConnectionException(
                "Failed to get a reference of VDC for a tenant {}".format(
                    self.tenant_name
                )
            )

        vm_info_dict = self.get_vapp_details_rest(vapp_uuid=vim_vm_uuid)
        if not vm_info_dict:
            self.logger.debug(
                "get_vminstance(): Failed to get vApp name by UUID {}".format(
                    vim_vm_uuid
                )
            )
            raise vimconn.VimConnNotFoundException(
                "Failed to get vApp name by UUID {}".format(vim_vm_uuid)
            )

        status_key = vm_info_dict["status"]
        error = ""
        try:
            vm_dict = {
                "created": vm_info_dict["created"],
                "description": vm_info_dict["name"],
                "status": vcdStatusCode2manoFormat[int(status_key)],
                "hostId": vm_info_dict["vmuuid"],
                "error_msg": error,
                "vim_info": yaml.safe_dump(vm_info_dict),
                "interfaces": [],
            }

            if "interfaces" in vm_info_dict:
                vm_dict["interfaces"] = vm_info_dict["interfaces"]
            else:
                vm_dict["interfaces"] = []
        except KeyError:
            vm_dict = {
                "created": "",
                "description": "",
                "status": vcdStatusCode2manoFormat[int(-1)],
                "hostId": vm_info_dict["vmuuid"],
                "error_msg": "Inconsistency state",
                "vim_info": yaml.safe_dump(vm_info_dict),
                "interfaces": [],
            }

        return vm_dict

    def delete_vminstance(self, vm_id, created_items=None, volumes_to_hold=None):
        """Method poweroff and remove VM instance from vcloud director network.

        Args:
            vm_id: VM UUID

        Returns:
            Returns the instance identifier
        """
        self.logger.debug("Client requesting delete vm instance {} ".format(vm_id))

        _, vdc = self.get_vdc_details()
        vdc_obj = VDC(self.client, href=vdc.get("href"))
        if vdc_obj is None:
            self.logger.debug(
                "delete_vminstance(): Failed to get a reference of VDC for a tenant {}".format(
                    self.tenant_name
                )
            )
            raise vimconn.VimConnException(
                "delete_vminstance(): Failed to get a reference of VDC for a tenant {}".format(
                    self.tenant_name
                )
            )

        try:
            vapp_name = self.get_namebyvappid(vm_id)
            if vapp_name is None:
                self.logger.debug(
                    "delete_vminstance(): Failed to get vm by given {} vm uuid".format(
                        vm_id
                    )
                )

                return (
                    -1,
                    "delete_vminstance(): Failed to get vm by given {} vm uuid".format(
                        vm_id
                    ),
                )

            self.logger.info("Deleting vApp {} and UUID {}".format(vapp_name, vm_id))
            vapp_resource = vdc_obj.get_vapp(vapp_name)
            vapp = VApp(self.client, resource=vapp_resource)

            # Delete vApp and wait for status change if task executed and vApp is None.
            if vapp:
                if vapp_resource.get("deployed") == "true":
                    self.logger.info("Powering off vApp {}".format(vapp_name))
                    # Power off vApp
                    powered_off = False
                    wait_time = 0

                    while wait_time <= MAX_WAIT_TIME:
                        power_off_task = vapp.power_off()
                        result = self.client.get_task_monitor().wait_for_success(
                            task=power_off_task
                        )

                        if result.get("status") == "success":
                            powered_off = True
                            break
                        else:
                            self.logger.info(
                                "Wait for vApp {} to power off".format(vapp_name)
                            )
                            time.sleep(INTERVAL_TIME)

                        wait_time += INTERVAL_TIME

                    if not powered_off:
                        self.logger.debug(
                            "delete_vminstance(): Failed to power off VM instance {} ".format(
                                vm_id
                            )
                        )
                    else:
                        self.logger.info(
                            "delete_vminstance(): Powered off VM instance {} ".format(
                                vm_id
                            )
                        )

                    # Undeploy vApp
                    self.logger.info("Undeploy vApp {}".format(vapp_name))
                    wait_time = 0
                    undeployed = False
                    while wait_time <= MAX_WAIT_TIME:
                        vapp = VApp(self.client, resource=vapp_resource)
                        if not vapp:
                            self.logger.debug(
                                "delete_vminstance(): Failed to get vm by given {} vm uuid".format(
                                    vm_id
                                )
                            )

                            return (
                                -1,
                                "delete_vminstance(): Failed to get vm by given {} vm uuid".format(
                                    vm_id
                                ),
                            )

                        undeploy_task = vapp.undeploy()
                        result = self.client.get_task_monitor().wait_for_success(
                            task=undeploy_task
                        )

                        if result.get("status") == "success":
                            undeployed = True
                            break
                        else:
                            self.logger.debug(
                                "Wait for vApp {} to undeploy".format(vapp_name)
                            )
                            time.sleep(INTERVAL_TIME)

                        wait_time += INTERVAL_TIME

                    if not undeployed:
                        self.logger.debug(
                            "delete_vminstance(): Failed to undeploy vApp {} ".format(
                                vm_id
                            )
                        )

                # delete vapp
                self.logger.info("Start deletion of vApp {} ".format(vapp_name))
                if vapp is not None:
                    wait_time = 0
                    result = False

                    while wait_time <= MAX_WAIT_TIME:
                        vapp = VApp(self.client, resource=vapp_resource)
                        if not vapp:
                            self.logger.debug(
                                "delete_vminstance(): Failed to get vm by given {} vm uuid".format(
                                    vm_id
                                )
                            )

                            return (
                                -1,
                                "delete_vminstance(): Failed to get vm by given {} vm uuid".format(
                                    vm_id
                                ),
                            )

                        delete_task = vdc_obj.delete_vapp(vapp.name, force=True)
                        result = self.client.get_task_monitor().wait_for_success(
                            task=delete_task
                        )
                        if result.get("status") == "success":
                            break
                        else:
                            self.logger.debug(
                                "Wait for vApp {} to delete".format(vapp_name)
                            )
                            time.sleep(INTERVAL_TIME)

                        wait_time += INTERVAL_TIME

                    if result is None:
                        self.logger.debug(
                            "delete_vminstance(): Failed delete uuid {} ".format(vm_id)
                        )
                    else:
                        self.logger.info(
                            "Deleted vm instance {} successfully".format(vm_id)
                        )
                        config_drive_catalog_name, config_drive_catalog_id = (
                            "cfg_drv-" + vm_id,
                            None,
                        )
                        catalog_list = self.get_image_list()

                        try:
                            config_drive_catalog_id = [
                                catalog_["id"]
                                for catalog_ in catalog_list
                                if catalog_["name"] == config_drive_catalog_name
                            ][0]
                        except IndexError:
                            pass

                        if config_drive_catalog_id:
                            self.logger.debug(
                                "delete_vminstance(): Found a config drive catalog {} matching "
                                'vapp_name"{}". Deleting it.'.format(
                                    config_drive_catalog_id, vapp_name
                                )
                            )
                            self.delete_image(config_drive_catalog_id)

                        return vm_id
        except Exception:
            self.logger.debug(traceback.format_exc())

            raise vimconn.VimConnException(
                "delete_vminstance(): Failed delete vm instance {}".format(vm_id)
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
                             #  CREATING (on building process), ERROR
                             #  ACTIVE:NoMgmtIP (Active but any of its interface has an IP address
                             #
                 error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
                 vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
                 interfaces:
                  -  vim_info:         #Text with plain information obtained from vim (yaml.safe_dump)
                     mac_address:      #Text format XX:XX:XX:XX:XX:XX
                     vim_net_id:       #network id where this interface is connected
                     vim_interface_id: #interface/port VIM id
                     ip_address:       #null, or text with IPv4, IPv6 address
        """
        self.logger.debug("Client requesting refresh vm status for {} ".format(vm_list))

        _, vdc = self.get_vdc_details()
        if vdc is None:
            raise vimconn.VimConnException(
                "Failed to get a reference of VDC for a tenant {}".format(
                    self.tenant_name
                )
            )

        vms_dict = {}
        nsx_edge_list = []
        for vmuuid in vm_list:
            vapp_name = self.get_namebyvappid(vmuuid)
            if vapp_name is not None:
                try:
                    vm_pci_details = self.get_vm_pci_details(vmuuid)
                    vdc_obj = VDC(self.client, href=vdc.get("href"))
                    vapp_resource = vdc_obj.get_vapp(vapp_name)
                    the_vapp = VApp(self.client, resource=vapp_resource)

                    vm_details = {}
                    for vm in the_vapp.get_all_vms():
                        headers = {
                            "Accept": "application/*+xml;version=" + API_VERSION,
                            "x-vcloud-authorization": self.client._session.headers[
                                "x-vcloud-authorization"
                            ],
                        }
                        response = self.perform_request(
                            req_type="GET", url=vm.get("href"), headers=headers
                        )

                        if response.status_code != 200:
                            self.logger.error(
                                "refresh_vms_status : REST call {} failed reason : {}"
                                "status code : {}".format(
                                    vm.get("href"), response.text, response.status_code
                                )
                            )
                            raise vimconn.VimConnException(
                                "refresh_vms_status : Failed to get VM details"
                            )

                        xmlroot = XmlElementTree.fromstring(response.text)
                        result = response.text.replace("\n", " ")
                        hdd_match = re.search(
                            'vcloud:capacity="(\d+)"\svcloud:storageProfileOverrideVmDefault=',
                            result,
                        )

                        if hdd_match:
                            hdd_mb = hdd_match.group(1)
                            vm_details["hdd_mb"] = int(hdd_mb) if hdd_mb else None

                        cpus_match = re.search(
                            "<rasd:Description>Number of Virtual CPUs</.*?>(\d+)</rasd:VirtualQuantity>",
                            result,
                        )

                        if cpus_match:
                            cpus = cpus_match.group(1)
                            vm_details["cpus"] = int(cpus) if cpus else None

                        memory_mb = re.search(
                            "<rasd:Description>Memory Size</.*?>(\d+)</rasd:VirtualQuantity>",
                            result,
                        ).group(1)
                        vm_details["memory_mb"] = int(memory_mb) if memory_mb else None
                        vm_details["status"] = vcdStatusCode2manoFormat[
                            int(xmlroot.get("status"))
                        ]
                        vm_details["id"] = xmlroot.get("id")
                        vm_details["name"] = xmlroot.get("name")
                        vm_info = [vm_details]

                        if vm_pci_details:
                            vm_info[0].update(vm_pci_details)

                        vm_dict = {
                            "status": vcdStatusCode2manoFormat[
                                int(vapp_resource.get("status"))
                            ],
                            "error_msg": vcdStatusCode2manoFormat[
                                int(vapp_resource.get("status"))
                            ],
                            "vim_info": yaml.safe_dump(vm_info),
                            "interfaces": [],
                        }

                        # get networks
                        vm_ip = None
                        vm_mac = None
                        networks = re.findall(
                            "<NetworkConnection needsCustomization=.*?</NetworkConnection>",
                            result,
                        )

                        for network in networks:
                            mac_s = re.search("<MACAddress>(.*?)</MACAddress>", network)
                            vm_mac = mac_s.group(1) if mac_s else None
                            ip_s = re.search("<IpAddress>(.*?)</IpAddress>", network)
                            vm_ip = ip_s.group(1) if ip_s else None

                            if vm_ip is None:
                                if not nsx_edge_list:
                                    nsx_edge_list = self.get_edge_details()
                                    if nsx_edge_list is None:
                                        raise vimconn.VimConnException(
                                            "refresh_vms_status:"
                                            "Failed to get edge details from NSX Manager"
                                        )

                                if vm_mac is not None:
                                    vm_ip = self.get_ipaddr_from_NSXedge(
                                        nsx_edge_list, vm_mac
                                    )

                            net_s = re.search('network="(.*?)"', network)
                            network_name = net_s.group(1) if net_s else None
                            vm_net_id = self.get_network_id_by_name(network_name)
                            interface = {
                                "mac_address": vm_mac,
                                "vim_net_id": vm_net_id,
                                "vim_interface_id": vm_net_id,
                                "ip_address": vm_ip,
                            }
                            vm_dict["interfaces"].append(interface)

                    # add a vm to vm dict
                    vms_dict.setdefault(vmuuid, vm_dict)
                    self.logger.debug("refresh_vms_status : vm info {}".format(vm_dict))
                except Exception as exp:
                    self.logger.debug("Error in response {}".format(exp))
                    self.logger.debug(traceback.format_exc())

        return vms_dict

    def get_edge_details(self):
        """Get the NSX edge list from NSX Manager
        Returns list of NSX edges
        """
        edge_list = []
        rheaders = {"Content-Type": "application/xml"}
        nsx_api_url = "/api/4.0/edges"

        self.logger.debug(
            "Get edge details from NSX Manager {} {}".format(
                self.nsx_manager, nsx_api_url
            )
        )

        try:
            resp = requests.get(
                self.nsx_manager + nsx_api_url,
                auth=(self.nsx_user, self.nsx_password),
                verify=False,
                headers=rheaders,
            )
            if resp.status_code == requests.codes.ok:
                paged_Edge_List = XmlElementTree.fromstring(resp.text)
                for edge_pages in paged_Edge_List:
                    if edge_pages.tag == "edgePage":
                        for edge_summary in edge_pages:
                            if edge_summary.tag == "pagingInfo":
                                for element in edge_summary:
                                    if (
                                        element.tag == "totalCount"
                                        and element.text == "0"
                                    ):
                                        raise vimconn.VimConnException(
                                            "get_edge_details: No NSX edges details found: {}".format(
                                                self.nsx_manager
                                            )
                                        )

                            if edge_summary.tag == "edgeSummary":
                                for element in edge_summary:
                                    if element.tag == "id":
                                        edge_list.append(element.text)
                    else:
                        raise vimconn.VimConnException(
                            "get_edge_details: No NSX edge details found: {}".format(
                                self.nsx_manager
                            )
                        )

                if not edge_list:
                    raise vimconn.VimConnException(
                        "get_edge_details: "
                        "No NSX edge details found: {}".format(self.nsx_manager)
                    )
                else:
                    self.logger.debug(
                        "get_edge_details: Found NSX edges {}".format(edge_list)
                    )

                    return edge_list
            else:
                self.logger.debug(
                    "get_edge_details: "
                    "Failed to get NSX edge details from NSX Manager: {}".format(
                        resp.content
                    )
                )

                return None

        except Exception as exp:
            self.logger.debug(
                "get_edge_details: "
                "Failed to get NSX edge details from NSX Manager: {}".format(exp)
            )
            raise vimconn.VimConnException(
                "get_edge_details: "
                "Failed to get NSX edge details from NSX Manager: {}".format(exp)
            )

    def get_ipaddr_from_NSXedge(self, nsx_edges, mac_address):
        """Get IP address details from NSX edges, using the MAC address
        PARAMS: nsx_edges : List of NSX edges
                mac_address : Find IP address corresponding to this MAC address
        Returns: IP address corrresponding to the provided MAC address
        """
        ip_addr = None
        rheaders = {"Content-Type": "application/xml"}

        self.logger.debug("get_ipaddr_from_NSXedge: Finding IP addr from NSX edge")

        try:
            for edge in nsx_edges:
                nsx_api_url = "/api/4.0/edges/" + edge + "/dhcp/leaseInfo"

                resp = requests.get(
                    self.nsx_manager + nsx_api_url,
                    auth=(self.nsx_user, self.nsx_password),
                    verify=False,
                    headers=rheaders,
                )

                if resp.status_code == requests.codes.ok:
                    dhcp_leases = XmlElementTree.fromstring(resp.text)
                    for child in dhcp_leases:
                        if child.tag == "dhcpLeaseInfo":
                            dhcpLeaseInfo = child
                            for leaseInfo in dhcpLeaseInfo:
                                for elem in leaseInfo:
                                    if (elem.tag) == "macAddress":
                                        edge_mac_addr = elem.text

                                    if (elem.tag) == "ipAddress":
                                        ip_addr = elem.text

                                if edge_mac_addr is not None:
                                    if edge_mac_addr == mac_address:
                                        self.logger.debug(
                                            "Found ip addr {} for mac {} at NSX edge {}".format(
                                                ip_addr, mac_address, edge
                                            )
                                        )

                                        return ip_addr
                else:
                    self.logger.debug(
                        "get_ipaddr_from_NSXedge: "
                        "Error occurred while getting DHCP lease info from NSX Manager: {}".format(
                            resp.content
                        )
                    )

            self.logger.debug(
                "get_ipaddr_from_NSXedge: No IP addr found in any NSX edge"
            )

            return None

        except XmlElementTree.ParseError as Err:
            self.logger.debug(
                "ParseError in response from NSX Manager {}".format(Err.message),
                exc_info=True,
            )

    def action_vminstance(self, vm_id=None, action_dict=None, created_items={}):
        """Send and action over a VM instance from VIM
        Returns the vm_id if the action was successfully sent to the VIM"""

        self.logger.debug(
            "Received action for vm {} and action dict {}".format(vm_id, action_dict)
        )

        if vm_id is None or action_dict is None:
            raise vimconn.VimConnException("Invalid request. VM id or action is None.")

        _, vdc = self.get_vdc_details()
        if vdc is None:
            raise vimconn.VimConnException(
                "Failed to get a reference of VDC for a tenant {}".format(
                    self.tenant_name
                )
            )

        vapp_name = self.get_namebyvappid(vm_id)
        if vapp_name is None:
            self.logger.debug(
                "action_vminstance(): Failed to get vm by given {} vm uuid".format(
                    vm_id
                )
            )

            raise vimconn.VimConnException(
                "Failed to get vm by given {} vm uuid".format(vm_id)
            )
        else:
            self.logger.info(
                "Action_vminstance vApp {} and UUID {}".format(vapp_name, vm_id)
            )

        try:
            vdc_obj = VDC(self.client, href=vdc.get("href"))
            vapp_resource = vdc_obj.get_vapp(vapp_name)
            vapp = VApp(self.client, resource=vapp_resource)

            if "start" in action_dict:
                self.logger.info(
                    "action_vminstance: Power on vApp: {}".format(vapp_name)
                )
                poweron_task = self.power_on_vapp(vm_id, vapp_name)
                result = self.client.get_task_monitor().wait_for_success(
                    task=poweron_task
                )
                self.instance_actions_result("start", result, vapp_name)
            elif "rebuild" in action_dict:
                self.logger.info(
                    "action_vminstance: Rebuild vApp: {}".format(vapp_name)
                )
                rebuild_task = vapp.deploy(power_on=True)
                result = self.client.get_task_monitor().wait_for_success(
                    task=rebuild_task
                )
                self.instance_actions_result("rebuild", result, vapp_name)
            elif "pause" in action_dict:
                self.logger.info("action_vminstance: pause vApp: {}".format(vapp_name))
                pause_task = vapp.undeploy(action="suspend")
                result = self.client.get_task_monitor().wait_for_success(
                    task=pause_task
                )
                self.instance_actions_result("pause", result, vapp_name)
            elif "resume" in action_dict:
                self.logger.info("action_vminstance: resume vApp: {}".format(vapp_name))
                poweron_task = self.power_on_vapp(vm_id, vapp_name)
                result = self.client.get_task_monitor().wait_for_success(
                    task=poweron_task
                )
                self.instance_actions_result("resume", result, vapp_name)
            elif "shutoff" in action_dict or "shutdown" in action_dict:
                action_name, _ = list(action_dict.items())[0]
                self.logger.info(
                    "action_vminstance: {} vApp: {}".format(action_name, vapp_name)
                )
                shutdown_task = vapp.shutdown()
                result = self.client.get_task_monitor().wait_for_success(
                    task=shutdown_task
                )
                if action_name == "shutdown":
                    self.instance_actions_result("shutdown", result, vapp_name)
                else:
                    self.instance_actions_result("shutoff", result, vapp_name)
            elif "forceOff" in action_dict:
                result = vapp.undeploy(action="powerOff")
                self.instance_actions_result("forceOff", result, vapp_name)
            elif "reboot" in action_dict:
                self.logger.info("action_vminstance: reboot vApp: {}".format(vapp_name))
                reboot_task = vapp.reboot()
                self.client.get_task_monitor().wait_for_success(task=reboot_task)
            else:
                raise vimconn.VimConnException(
                    "action_vminstance: Invalid action {} or action is None.".format(
                        action_dict
                    )
                )

            return vm_id
        except Exception as exp:
            self.logger.debug("action_vminstance: Failed with Exception {}".format(exp))

            raise vimconn.VimConnException(
                "action_vminstance: Failed with Exception {}".format(exp)
            )

    def instance_actions_result(self, action, result, vapp_name):
        if result.get("status") == "success":
            self.logger.info(
                "action_vminstance: Sucessfully {} the vApp: {}".format(
                    action, vapp_name
                )
            )
        else:
            self.logger.error(
                "action_vminstance: Failed to {} vApp: {}".format(action, vapp_name)
            )

    def get_vminstance_console(self, vm_id, console_type="novnc"):
        """
        Get a console for the virtual machine
        Params:
            vm_id: uuid of the VM
            console_type, can be:
                "novnc" (by default), "xvpvnc" for VNC types,
                "rdp-html5" for RDP types, "spice-html5" for SPICE types
        Returns dict with the console parameters:
                protocol: ssh, ftp, http, https, ...
                server:   usually ip address
                port:     the http, ssh, ... port
                suffix:   extra text, e.g. the http path and query string
        """
        console_dict = {}

        if console_type is None or console_type == "novnc":
            url_rest_call = "{}/api/vApp/vm-{}/screen/action/acquireMksTicket".format(
                self.url, vm_id
            )
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="POST", url=url_rest_call, headers=headers
            )

            if response.status_code == 403:
                response = self.retry_rest("GET", url_rest_call)

            if response.status_code != 200:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {}".format(
                        url_rest_call, response.text, response.status_code
                    )
                )
                raise vimconn.VimConnException(
                    "get_vminstance_console : Failed to get " "VM Mks ticket details"
                )

            s = re.search("<Host>(.*?)</Host>", response.text)
            console_dict["server"] = s.group(1) if s else None
            s1 = re.search("<Port>(\d+)</Port>", response.text)
            console_dict["port"] = s1.group(1) if s1 else None
            url_rest_call = "{}/api/vApp/vm-{}/screen/action/acquireTicket".format(
                self.url, vm_id
            )
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="POST", url=url_rest_call, headers=headers
            )

            if response.status_code == 403:
                response = self.retry_rest("GET", url_rest_call)

            if response.status_code != 200:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {}".format(
                        url_rest_call, response.text, response.status_code
                    )
                )
                raise vimconn.VimConnException(
                    "get_vminstance_console : Failed to get " "VM console details"
                )

            s = re.search(">.*?/(vm-\d+.*)</", response.text)
            console_dict["suffix"] = s.group(1) if s else None
            console_dict["protocol"] = "https"

        return console_dict

    def get_hosts_info(self):
        """Get the information of deployed hosts
        Returns the hosts content"""
        raise vimconn.VimConnNotImplemented("Should have implemented this")

    def get_hosts(self, vim_tenant):
        """Get the hosts and deployed instances
        Returns the hosts content"""
        raise vimconn.VimConnNotImplemented("Should have implemented this")

    def get_network_name_by_id(self, network_uuid=None):
        """Method gets vcloud director network named based on supplied uuid.

        Args:
            network_uuid: network_id

        Returns:
            The return network name.
        """

        if not network_uuid:
            return None

        try:
            org_dict = self.get_org(self.org_uuid)
            if "networks" in org_dict:
                org_network_dict = org_dict["networks"]

                for net_uuid in org_network_dict:
                    if net_uuid == network_uuid:
                        return org_network_dict[net_uuid]
        except Exception:
            self.logger.debug("Exception in get_network_name_by_id")
            self.logger.debug(traceback.format_exc())

        return None

    def get_network_id_by_name(self, network_name=None):
        """Method gets vcloud director network uuid based on supplied name.

        Args:
            network_name: network_name
        Returns:
            The return network uuid.
            network_uuid: network_id
        """
        if not network_name:
            self.logger.debug("get_network_id_by_name() : Network name is empty")
            return None

        try:
            org_dict = self.get_org(self.org_uuid)
            if org_dict and "networks" in org_dict:
                org_network_dict = org_dict["networks"]

                for net_uuid, net_name in org_network_dict.items():
                    if net_name == network_name:
                        return net_uuid

        except KeyError as exp:
            self.logger.debug("get_network_id_by_name() : KeyError- {} ".format(exp))

        return None

    def get_physical_network_by_name(self, physical_network_name):
        """
        Methos returns uuid of physical network which passed
        Args:
            physical_network_name: physical network name
        Returns:
            UUID of physical_network_name
        """
        try:
            client_as_admin = self.connect_as_admin()

            if not client_as_admin:
                raise vimconn.VimConnConnectionException("Failed to connect vCD.")

            url_list = [self.url, "/api/admin/vdc/", self.tenant_id]
            vm_list_rest_call = "".join(url_list)

            if client_as_admin._session:
                headers = {
                    "Accept": "application/*+xml;version=" + API_VERSION,
                    "x-vcloud-authorization": client_as_admin._session.headers[
                        "x-vcloud-authorization"
                    ],
                }
                response = self.perform_request(
                    req_type="GET", url=vm_list_rest_call, headers=headers
                )
                provider_network = None
                available_network = None
                # add_vdc_rest_url = None

                if response.status_code != requests.codes.ok:
                    self.logger.debug(
                        "REST API call {} failed. Return status code {}".format(
                            vm_list_rest_call, response.status_code
                        )
                    )
                    return None
                else:
                    try:
                        vm_list_xmlroot = XmlElementTree.fromstring(response.text)
                        for child in vm_list_xmlroot:
                            if child.tag.split("}")[1] == "ProviderVdcReference":
                                provider_network = child.attrib.get("href")
                                # application/vnd.vmware.admin.providervdc+xml

                            if child.tag.split("}")[1] == "Link":
                                if (
                                    child.attrib.get("type")
                                    == "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
                                    and child.attrib.get("rel") == "add"
                                ):
                                    child.attrib.get("href")
                    except Exception:
                        self.logger.debug(
                            "Failed parse respond for rest api call {}".format(
                                vm_list_rest_call
                            )
                        )
                        self.logger.debug("Respond body {}".format(response.text))

                        return None

                # find  pvdc provided available network
                response = self.perform_request(
                    req_type="GET", url=provider_network, headers=headers
                )

                if response.status_code != requests.codes.ok:
                    self.logger.debug(
                        "REST API call {} failed. Return status code {}".format(
                            vm_list_rest_call, response.status_code
                        )
                    )

                    return None

                try:
                    vm_list_xmlroot = XmlElementTree.fromstring(response.text)
                    for child in vm_list_xmlroot.iter():
                        if child.tag.split("}")[1] == "AvailableNetworks":
                            for networks in child.iter():
                                if (
                                    networks.attrib.get("href") is not None
                                    and networks.attrib.get("name") is not None
                                ):
                                    if (
                                        networks.attrib.get("name")
                                        == physical_network_name
                                    ):
                                        network_url = networks.attrib.get("href")
                                        available_network = network_url[
                                            network_url.rindex("/") + 1 :
                                        ]
                                        break
                except Exception:
                    return None

            return available_network
        except Exception as e:
            self.logger.error("Error while getting physical network: {}".format(e))

    def list_org_action(self):
        """
        Method leverages vCloud director and query for available organization for particular user

        Args:
            vca - is active VCA connection.
            vdc_name - is a vdc name that will be used to query vms action

            Returns:
                The return XML respond
        """
        url_list = [self.url, "/api/org"]
        vm_list_rest_call = "".join(url_list)

        if self.client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }

            response = self.perform_request(
                req_type="GET", url=vm_list_rest_call, headers=headers
            )

            if response.status_code == 403:
                response = self.retry_rest("GET", vm_list_rest_call)

            if response.status_code == requests.codes.ok:
                return response.text

        return None

    def get_org_action(self, org_uuid=None):
        """
        Method leverages vCloud director and retrieve available object for organization.

        Args:
            org_uuid - vCD organization uuid
            self.client - is active connection.

            Returns:
                The return XML respond
        """

        if org_uuid is None:
            return None

        url_list = [self.url, "/api/org/", org_uuid]
        vm_list_rest_call = "".join(url_list)

        if self.client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }

            # response = requests.get(vm_list_rest_call, headers=headers, verify=False)
            response = self.perform_request(
                req_type="GET", url=vm_list_rest_call, headers=headers
            )

            if response.status_code == 403:
                response = self.retry_rest("GET", vm_list_rest_call)

            if response.status_code == requests.codes.ok:
                return response.text

        return None

    def get_org(self, org_uuid=None):
        """
        Method retrieves available organization in vCloud Director

        Args:
            org_uuid - is a organization uuid.

            Returns:
                The return dictionary with following key
                    "network" - for network list under the org
                    "catalogs" - for network list under the org
                    "vdcs" - for vdc list under org
        """

        org_dict = {}

        if org_uuid is None:
            return org_dict

        content = self.get_org_action(org_uuid=org_uuid)
        try:
            vdc_list = {}
            network_list = {}
            catalog_list = {}
            vm_list_xmlroot = XmlElementTree.fromstring(content)
            for child in vm_list_xmlroot:
                if child.attrib["type"] == "application/vnd.vmware.vcloud.vdc+xml":
                    vdc_list[child.attrib["href"].split("/")[-1:][0]] = child.attrib[
                        "name"
                    ]
                    org_dict["vdcs"] = vdc_list

                if (
                    child.attrib["type"]
                    == "application/vnd.vmware.vcloud.orgNetwork+xml"
                ):
                    network_list[child.attrib["href"].split("/")[-1:][0]] = (
                        child.attrib["name"]
                    )
                    org_dict["networks"] = network_list

                if child.attrib["type"] == "application/vnd.vmware.vcloud.catalog+xml":
                    catalog_list[child.attrib["href"].split("/")[-1:][0]] = (
                        child.attrib["name"]
                    )
                    org_dict["catalogs"] = catalog_list
        except Exception:
            pass

        return org_dict

    def get_org_list(self):
        """
        Method retrieves available organization in vCloud Director

        Args:
            vca - is active VCA connection.

            Returns:
                The return dictionary and key for each entry VDC UUID
        """
        org_dict = {}

        content = self.list_org_action()
        try:
            vm_list_xmlroot = XmlElementTree.fromstring(content)

            for vm_xml in vm_list_xmlroot:
                if vm_xml.tag.split("}")[1] == "Org":
                    org_uuid = vm_xml.attrib["href"].split("/")[-1:]
                    org_dict[org_uuid[0]] = vm_xml.attrib["name"]
        except Exception:
            pass

        return org_dict

    def vms_view_action(self, vdc_name=None):
        """Method leverages vCloud director vms query call

        Args:
            vca - is active VCA connection.
            vdc_name - is a vdc name that will be used to query vms action

            Returns:
                The return XML respond
        """
        vca = self.connect()
        if vdc_name is None:
            return None

        url_list = [vca.host, "/api/vms/query"]
        vm_list_rest_call = "".join(url_list)

        if not (not vca.vcloud_session or not vca.vcloud_session.organization):
            refs = [
                ref
                for ref in vca.vcloud_session.organization.Link
                if ref.name == vdc_name
                and ref.type_ == "application/vnd.vmware.vcloud.vdc+xml"
            ]

            if len(refs) == 1:
                response = self.perform_request(
                    req_type="GET",
                    url=vm_list_rest_call,
                    headers=vca.vcloud_session.get_vcloud_headers(),
                    verify=vca.verify,
                    logger=vca.logger,
                )

                if response.status_code == requests.codes.ok:
                    return response.text

        return None

    def get_vapp(self, vdc_name=None, vapp_name=None, isuuid=False):
        """
        Method retrieves VM deployed vCloud director. It returns VM attribute as dictionary
        contains a list of all VM's deployed for queried VDC.
        The key for a dictionary is VM UUID


        Args:
            vca - is active VCA connection.
            vdc_name - is a vdc name that will be used to query vms action

            Returns:
                The return dictionary and key for each entry vapp UUID
        """
        vm_dict = {}
        vca = self.connect()

        if not vca:
            raise vimconn.VimConnConnectionException("self.connect() is failed")

        if vdc_name is None:
            return vm_dict

        content = self.vms_view_action(vdc_name=vdc_name)
        try:
            vm_list_xmlroot = XmlElementTree.fromstring(content)
            for vm_xml in vm_list_xmlroot:
                if (
                    vm_xml.tag.split("}")[1] == "VMRecord"
                    and vm_xml.attrib["isVAppTemplate"] == "false"
                ):
                    # lookup done by UUID
                    if isuuid:
                        if vapp_name in vm_xml.attrib["container"]:
                            rawuuid = vm_xml.attrib["href"].split("/")[-1:]
                            if "vm-" in rawuuid[0]:
                                vm_dict[rawuuid[0][3:]] = vm_xml.attrib
                                break
                    # lookup done by Name
                    else:
                        if vapp_name in vm_xml.attrib["name"]:
                            rawuuid = vm_xml.attrib["href"].split("/")[-1:]
                            if "vm-" in rawuuid[0]:
                                vm_dict[rawuuid[0][3:]] = vm_xml.attrib
                                break
        except Exception:
            pass

        return vm_dict

    def get_network_action(self, network_uuid=None):
        """
        Method leverages vCloud director and query network based on network uuid

        Args:
            vca - is active VCA connection.
            network_uuid - is a network uuid

            Returns:
                The return XML respond
        """
        if network_uuid is None:
            return None

        url_list = [self.url, "/api/network/", network_uuid]
        vm_list_rest_call = "".join(url_list)

        if self.client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url=vm_list_rest_call, headers=headers
            )

            # Retry login if session expired & retry sending request
            if response.status_code == 403:
                response = self.retry_rest("GET", vm_list_rest_call)

            if response.status_code == requests.codes.ok:
                return response.text

        return None

    def get_vcd_network(self, network_uuid=None):
        """
        Method retrieves available network from vCloud Director

        Args:
            network_uuid - is VCD network UUID

        Each element serialized as key : value pair

        Following keys available for access.    network_configuration['Gateway'}
        <Configuration>
          <IpScopes>
            <IpScope>
                <IsInherited>true</IsInherited>
                <Gateway>172.16.252.100</Gateway>
                <Netmask>255.255.255.0</Netmask>
                <Dns1>172.16.254.201</Dns1>
                <Dns2>172.16.254.202</Dns2>
                <DnsSuffix>vmwarelab.edu</DnsSuffix>
                <IsEnabled>true</IsEnabled>
                <IpRanges>
                    <IpRange>
                        <StartAddress>172.16.252.1</StartAddress>
                        <EndAddress>172.16.252.99</EndAddress>
                    </IpRange>
                </IpRanges>
            </IpScope>
        </IpScopes>
        <FenceMode>bridged</FenceMode>

        Returns:
                The return dictionary and key for each entry vapp UUID
        """
        network_configuration = {}

        if network_uuid is None:
            return network_uuid

        try:
            content = self.get_network_action(network_uuid=network_uuid)
            if content is not None:
                vm_list_xmlroot = XmlElementTree.fromstring(content)
                network_configuration["status"] = vm_list_xmlroot.get("status")
                network_configuration["name"] = vm_list_xmlroot.get("name")
                network_configuration["uuid"] = vm_list_xmlroot.get("id").split(":")[3]

                for child in vm_list_xmlroot:
                    if child.tag.split("}")[1] == "IsShared":
                        network_configuration["isShared"] = child.text.strip()

                    if child.tag.split("}")[1] == "Configuration":
                        for configuration in child.iter():
                            tagKey = configuration.tag.split("}")[1].strip()
                            if tagKey != "":
                                network_configuration[tagKey] = (
                                    configuration.text.strip()
                                )
        except Exception as exp:
            self.logger.debug("get_vcd_network: Failed with Exception {}".format(exp))

            raise vimconn.VimConnException(
                "get_vcd_network: Failed with Exception {}".format(exp)
            )

        return network_configuration

    def delete_network_action(self, network_uuid=None):
        """
        Method delete given network from vCloud director

        Args:
            network_uuid - is a network uuid that client wish to delete

            Returns:
                The return None or XML respond or false
        """
        client = self.connect_as_admin()

        if not client:
            raise vimconn.VimConnConnectionException("Failed to connect vCD as admin")

        if network_uuid is None:
            return False

        url_list = [self.url, "/api/admin/network/", network_uuid]
        vm_list_rest_call = "".join(url_list)

        if client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="DELETE", url=vm_list_rest_call, headers=headers
            )

            if response.status_code == 202:
                return True

        return False

    def create_network(
        self,
        network_name=None,
        net_type="bridge",
        parent_network_uuid=None,
        ip_profile=None,
        isshared="true",
    ):
        """
        Method create network in vCloud director

        Args:
            network_name - is network name to be created.
            net_type - can be 'bridge','data','ptp','mgmt'.
            ip_profile is a dict containing the IP parameters of the network
            isshared - is a boolean
            parent_network_uuid - is parent provider vdc network that will be used for mapping.
            It optional attribute. by default if no parent network indicate the first available will be used.

            Returns:
                The return network uuid or return None
        """
        new_network_name = [network_name, "-", str(uuid.uuid4())]
        content = self.create_network_rest(
            network_name="".join(new_network_name),
            ip_profile=ip_profile,
            net_type=net_type,
            parent_network_uuid=parent_network_uuid,
            isshared=isshared,
        )

        if content is None:
            self.logger.debug("Failed create network {}.".format(network_name))

            return None

        try:
            vm_list_xmlroot = XmlElementTree.fromstring(content)
            vcd_uuid = vm_list_xmlroot.get("id").split(":")
            if len(vcd_uuid) == 4:
                self.logger.info(
                    "Created new network name: {} uuid: {}".format(
                        network_name, vcd_uuid[3]
                    )
                )

                return vcd_uuid[3]
        except Exception:
            self.logger.debug("Failed create network {}".format(network_name))

            return None

    def create_network_rest(
        self,
        network_name=None,
        net_type="bridge",
        parent_network_uuid=None,
        ip_profile=None,
        isshared="true",
    ):
        """
        Method create network in vCloud director

        Args:
            network_name - is network name to be created.
            net_type - can be 'bridge','data','ptp','mgmt'.
            ip_profile is a dict containing the IP parameters of the network
            isshared - is a boolean
            parent_network_uuid - is parent provider vdc network that will be used for mapping.
            It optional attribute. by default if no parent network indicate the first available will be used.

            Returns:
                The return network uuid or return None
        """
        client_as_admin = self.connect_as_admin()

        if not client_as_admin:
            raise vimconn.VimConnConnectionException("Failed to connect vCD.")

        if network_name is None:
            return None

        url_list = [self.url, "/api/admin/vdc/", self.tenant_id]
        vm_list_rest_call = "".join(url_list)

        if client_as_admin._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": client_as_admin._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url=vm_list_rest_call, headers=headers
            )
            provider_network = None
            available_networks = None
            add_vdc_rest_url = None

            if response.status_code != requests.codes.ok:
                self.logger.debug(
                    "REST API call {} failed. Return status code {}".format(
                        vm_list_rest_call, response.status_code
                    )
                )

                return None
            else:
                try:
                    vm_list_xmlroot = XmlElementTree.fromstring(response.text)
                    for child in vm_list_xmlroot:
                        if child.tag.split("}")[1] == "ProviderVdcReference":
                            provider_network = child.attrib.get("href")
                            # application/vnd.vmware.admin.providervdc+xml

                        if child.tag.split("}")[1] == "Link":
                            if (
                                child.attrib.get("type")
                                == "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
                                and child.attrib.get("rel") == "add"
                            ):
                                add_vdc_rest_url = child.attrib.get("href")
                except Exception:
                    self.logger.debug(
                        "Failed parse respond for rest api call {}".format(
                            vm_list_rest_call
                        )
                    )
                    self.logger.debug("Respond body {}".format(response.text))

                    return None

            # find  pvdc provided available network
            response = self.perform_request(
                req_type="GET", url=provider_network, headers=headers
            )

            if response.status_code != requests.codes.ok:
                self.logger.debug(
                    "REST API call {} failed. Return status code {}".format(
                        vm_list_rest_call, response.status_code
                    )
                )

                return None

            if parent_network_uuid is None:
                try:
                    vm_list_xmlroot = XmlElementTree.fromstring(response.text)
                    for child in vm_list_xmlroot.iter():
                        if child.tag.split("}")[1] == "AvailableNetworks":
                            for networks in child.iter():
                                # application/vnd.vmware.admin.network+xml
                                if networks.attrib.get("href") is not None:
                                    available_networks = networks.attrib.get("href")
                                    break
                except Exception:
                    return None

            try:
                # Configure IP profile of the network
                ip_profile = (
                    ip_profile if ip_profile is not None else DEFAULT_IP_PROFILE
                )

                if (
                    "subnet_address" not in ip_profile
                    or ip_profile["subnet_address"] is None
                ):
                    subnet_rand = random.randint(0, 255)
                    ip_base = "192.168.{}.".format(subnet_rand)
                    ip_profile["subnet_address"] = ip_base + "0/24"
                else:
                    ip_base = ip_profile["subnet_address"].rsplit(".", 1)[0] + "."

                if (
                    "gateway_address" not in ip_profile
                    or ip_profile["gateway_address"] is None
                ):
                    ip_profile["gateway_address"] = ip_base + "1"

                if "dhcp_count" not in ip_profile or ip_profile["dhcp_count"] is None:
                    ip_profile["dhcp_count"] = DEFAULT_IP_PROFILE["dhcp_count"]

                if (
                    "dhcp_enabled" not in ip_profile
                    or ip_profile["dhcp_enabled"] is None
                ):
                    ip_profile["dhcp_enabled"] = DEFAULT_IP_PROFILE["dhcp_enabled"]

                if (
                    "dhcp_start_address" not in ip_profile
                    or ip_profile["dhcp_start_address"] is None
                ):
                    ip_profile["dhcp_start_address"] = ip_base + "3"

                if "ip_version" not in ip_profile or ip_profile["ip_version"] is None:
                    ip_profile["ip_version"] = DEFAULT_IP_PROFILE["ip_version"]

                if "dns_address" not in ip_profile or ip_profile["dns_address"] is None:
                    ip_profile["dns_address"] = ip_base + "2"

                gateway_address = ip_profile["gateway_address"]
                dhcp_count = int(ip_profile["dhcp_count"])
                subnet_address = self.convert_cidr_to_netmask(
                    ip_profile["subnet_address"]
                )

                if ip_profile["dhcp_enabled"] is True:
                    dhcp_enabled = "true"
                else:
                    dhcp_enabled = "false"

                dhcp_start_address = ip_profile["dhcp_start_address"]

                # derive dhcp_end_address from dhcp_start_address & dhcp_count
                end_ip_int = int(netaddr.IPAddress(dhcp_start_address))
                end_ip_int += dhcp_count - 1
                dhcp_end_address = str(netaddr.IPAddress(end_ip_int))

                # ip_version = ip_profile['ip_version']
                dns_address = ip_profile["dns_address"]
            except KeyError as exp:
                self.logger.debug("Create Network REST: Key error {}".format(exp))

                raise vimconn.VimConnException(
                    "Create Network REST: Key error{}".format(exp)
                )

            # either use client provided UUID or search for a first available
            #  if both are not defined we return none
            if parent_network_uuid is not None:
                provider_network = None
                available_networks = None
                add_vdc_rest_url = None
                url_list = [self.url, "/api/admin/vdc/", self.tenant_id, "/networks"]
                add_vdc_rest_url = "".join(url_list)
                url_list = [self.url, "/api/admin/network/", parent_network_uuid]
                available_networks = "".join(url_list)

            # Creating all networks as Direct Org VDC type networks.
            # Unused in case of Underlay (data/ptp) network interface.
            fence_mode = "isolated"
            is_inherited = "false"
            dns_list = dns_address.split(";")
            dns1 = dns_list[0]
            dns2_text = ""

            if len(dns_list) >= 2:
                dns2_text = "\n                                                <Dns2>{}</Dns2>\n".format(
                    dns_list[1]
                )

            if net_type == "isolated":
                fence_mode = "isolated"
                data = """ <OrgVdcNetwork name="{0:s}" xmlns="http://www.vmware.com/vcloud/v1.5">
                                <Description>Openmano created</Description>
                                        <Configuration>
                                            <IpScopes>
                                                <IpScope>
                                                    <IsInherited>{1:s}</IsInherited>
                                                    <Gateway>{2:s}</Gateway>
                                                    <Netmask>{3:s}</Netmask>
                                                    <Dns1>{4:s}</Dns1>{5:s}
                                                    <IsEnabled>{6:s}</IsEnabled>
                                                    <IpRanges>
                                                        <IpRange>
                                                            <StartAddress>{7:s}</StartAddress>
                                                            <EndAddress>{8:s}</EndAddress>
                                                        </IpRange>
                                                    </IpRanges>
                                                </IpScope>
                                            </IpScopes>
                                            <FenceMode>{9:s}</FenceMode>
                                        </Configuration>
                                        <IsShared>{10:s}</IsShared>
                            </OrgVdcNetwork> """.format(
                    escape(network_name),
                    is_inherited,
                    gateway_address,
                    subnet_address,
                    dns1,
                    dns2_text,
                    dhcp_enabled,
                    dhcp_start_address,
                    dhcp_end_address,
                    fence_mode,
                    isshared,
                )
            else:
                fence_mode = "bridged"
                data = """ <OrgVdcNetwork name="{0:s}" xmlns="http://www.vmware.com/vcloud/v1.5">
                        <Description>Openmano created</Description>
                                <Configuration>
                                    <IpScopes>
                                        <IpScope>
                                            <IsInherited>{1:s}</IsInherited>
                                            <Gateway>{2:s}</Gateway>
                                            <Netmask>{3:s}</Netmask>
                                            <Dns1>{4:s}</Dns1>{5:s}
                                            <IsEnabled>{6:s}</IsEnabled>
                                            <IpRanges>
                                                <IpRange>
                                                    <StartAddress>{7:s}</StartAddress>
                                                    <EndAddress>{8:s}</EndAddress>
                                                </IpRange>
                                            </IpRanges>
                                        </IpScope>
                                    </IpScopes>
                                    <ParentNetwork href="{9:s}"/>
                                    <FenceMode>{10:s}</FenceMode>
                                </Configuration>
                                <IsShared>{11:s}</IsShared>
                    </OrgVdcNetwork> """.format(
                    escape(network_name),
                    is_inherited,
                    gateway_address,
                    subnet_address,
                    dns1,
                    dns2_text,
                    dhcp_enabled,
                    dhcp_start_address,
                    dhcp_end_address,
                    available_networks,
                    fence_mode,
                    isshared,
                )

            headers["Content-Type"] = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
            try:
                response = self.perform_request(
                    req_type="POST", url=add_vdc_rest_url, headers=headers, data=data
                )

                if response.status_code != 201:
                    self.logger.debug(
                        "Create Network POST REST API call failed. "
                        "Return status code {}, response.text: {}".format(
                            response.status_code, response.text
                        )
                    )
                else:
                    network_task = self.get_task_from_response(response.text)
                    self.logger.debug(
                        "Create Network REST : Waiting for Network creation complete"
                    )
                    time.sleep(5)
                    result = self.client.get_task_monitor().wait_for_success(
                        task=network_task
                    )

                    if result.get("status") == "success":
                        return response.text
                    else:
                        self.logger.debug(
                            "create_network_rest task failed. Network Create response : {}".format(
                                response.text
                            )
                        )
            except Exception as exp:
                self.logger.debug("create_network_rest : Exception : {} ".format(exp))

        return None

    def convert_cidr_to_netmask(self, cidr_ip=None):
        """
        Method sets convert CIDR netmask address to normal IP format
        Args:
            cidr_ip : CIDR IP address
            Returns:
                netmask : Converted netmask
        """
        if cidr_ip is not None:
            if "/" in cidr_ip:
                _, net_bits = cidr_ip.split("/")
                netmask = socket.inet_ntoa(
                    struct.pack(">I", (0xFFFFFFFF << (32 - int(net_bits))) & 0xFFFFFFFF)
                )
            else:
                netmask = cidr_ip

            return netmask

        return None

    def get_provider_rest(self, vca=None):
        """
        Method gets provider vdc view from vcloud director

        Args:
            network_name - is network name to be created.
            parent_network_uuid - is parent provider vdc network that will be used for mapping.
            It optional attribute. by default if no parent network indicate the first available will be used.

            Returns:
                The return xml content of respond or None
        """
        url_list = [self.url, "/api/admin"]

        if vca:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url="".join(url_list), headers=headers
            )

        if response.status_code == requests.codes.ok:
            return response.text

        return None

    def create_vdc(self, vdc_name=None):
        vdc_dict = {}
        xml_content = self.create_vdc_from_tmpl_rest(vdc_name=vdc_name)

        if xml_content is not None:
            try:
                task_resp_xmlroot = XmlElementTree.fromstring(xml_content)
                for child in task_resp_xmlroot:
                    if child.tag.split("}")[1] == "Owner":
                        vdc_id = child.attrib.get("href").split("/")[-1]
                        vdc_dict[vdc_id] = task_resp_xmlroot.get("href")

                        return vdc_dict
            except Exception:
                self.logger.debug("Respond body {}".format(xml_content))

        return None

    def create_vdc_from_tmpl_rest(self, vdc_name=None):
        """
        Method create vdc in vCloud director based on VDC template.
        it uses pre-defined template.

        Args:
            vdc_name -  name of a new vdc.

            Returns:
                The return xml content of respond or None
        """
        # pre-requesite atleast one vdc template should be available in vCD
        self.logger.info("Creating new vdc {}".format(vdc_name))
        vca = self.connect_as_admin()

        if not vca:
            raise vimconn.VimConnConnectionException("Failed to connect vCD")

        if vdc_name is None:
            return None

        url_list = [self.url, "/api/vdcTemplates"]
        vm_list_rest_call = "".join(url_list)
        headers = {
            "Accept": "application/*+xml;version=" + API_VERSION,
            "x-vcloud-authorization": vca._session.headers["x-vcloud-authorization"],
        }
        response = self.perform_request(
            req_type="GET", url=vm_list_rest_call, headers=headers
        )

        # container url to a template
        vdc_template_ref = None
        try:
            vm_list_xmlroot = XmlElementTree.fromstring(response.text)
            for child in vm_list_xmlroot:
                # application/vnd.vmware.admin.providervdc+xml
                # we need find a template from witch we instantiate VDC
                if child.tag.split("}")[1] == "VdcTemplate":
                    if (
                        child.attrib.get("type")
                        == "application/vnd.vmware.admin.vdcTemplate+xml"
                    ):
                        vdc_template_ref = child.attrib.get("href")
        except Exception:
            self.logger.debug(
                "Failed parse respond for rest api call {}".format(vm_list_rest_call)
            )
            self.logger.debug("Respond body {}".format(response.text))

            return None

        # if we didn't found required pre defined template we return None
        if vdc_template_ref is None:
            return None

        try:
            # instantiate vdc
            url_list = [self.url, "/api/org/", self.org_uuid, "/action/instantiate"]
            vm_list_rest_call = "".join(url_list)
            data = """<InstantiateVdcTemplateParams name="{0:s}" xmlns="http://www.vmware.com/vcloud/v1.5">
                                        <Source href="{1:s}"></Source>
                                        <Description>opnemano</Description>
                                        </InstantiateVdcTemplateParams>""".format(
                vdc_name, vdc_template_ref
            )
            headers["Content-Type"] = (
                "application/vnd.vmware.vcloud.instantiateVdcTemplateParams+xml"
            )
            response = self.perform_request(
                req_type="POST", url=vm_list_rest_call, headers=headers, data=data
            )
            vdc_task = self.get_task_from_response(response.text)
            self.client.get_task_monitor().wait_for_success(task=vdc_task)

            # if we all ok we respond with content otherwise by default None
            if response.status_code >= 200 and response.status_code < 300:
                return response.text

            return None
        except Exception:
            self.logger.debug(
                "Failed parse respond for rest api call {}".format(vm_list_rest_call)
            )
            self.logger.debug("Respond body {}".format(response.text))

        return None

    def get_vapp_details_rest(self, vapp_uuid=None, need_admin_access=False):
        """
        Method retrieve vapp detail from vCloud director

        Args:
            vapp_uuid - is vapp identifier.

            Returns:
                The return network uuid or return None
        """
        parsed_respond = {}
        vca = None

        if need_admin_access:
            vca = self.connect_as_admin()
        else:
            vca = self.client

        if not vca:
            raise vimconn.VimConnConnectionException("Failed to connect vCD")
        if vapp_uuid is None:
            return None

        url_list = [self.url, "/api/vApp/vapp-", vapp_uuid]
        get_vapp_restcall = "".join(url_list)

        if vca._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": vca._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url=get_vapp_restcall, headers=headers
            )

            if response.status_code == 403:
                if need_admin_access is False:
                    response = self.retry_rest("GET", get_vapp_restcall)

            if response.status_code != requests.codes.ok:
                self.logger.debug(
                    "REST API call {} failed. Return status code {}".format(
                        get_vapp_restcall, response.status_code
                    )
                )

                return parsed_respond

            try:
                xmlroot_respond = XmlElementTree.fromstring(response.text)
                parsed_respond["ovfDescriptorUploaded"] = xmlroot_respond.attrib[
                    "ovfDescriptorUploaded"
                ]
                namespaces = {
                    "vssd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData",
                    "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
                    "vmw": "http://www.vmware.com/schema/ovf",
                    "vm": "http://www.vmware.com/vcloud/v1.5",
                    "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
                    "vmext": "http://www.vmware.com/vcloud/extension/v1.5",
                    "xmlns": "http://www.vmware.com/vcloud/v1.5",
                }

                created_section = xmlroot_respond.find("vm:DateCreated", namespaces)
                if created_section is not None:
                    parsed_respond["created"] = created_section.text

                network_section = xmlroot_respond.find(
                    "vm:NetworkConfigSection/vm:NetworkConfig", namespaces
                )
                if (
                    network_section is not None
                    and "networkName" in network_section.attrib
                ):
                    parsed_respond["networkname"] = network_section.attrib[
                        "networkName"
                    ]

                ipscopes_section = xmlroot_respond.find(
                    "vm:NetworkConfigSection/vm:NetworkConfig/vm:Configuration/vm:IpScopes",
                    namespaces,
                )
                if ipscopes_section is not None:
                    for ipscope in ipscopes_section:
                        for scope in ipscope:
                            tag_key = scope.tag.split("}")[1]
                            if tag_key == "IpRanges":
                                ip_ranges = scope.getchildren()
                                for ipblock in ip_ranges:
                                    for block in ipblock:
                                        parsed_respond[block.tag.split("}")[1]] = (
                                            block.text
                                        )
                            else:
                                parsed_respond[tag_key] = scope.text

                # parse children section for other attrib
                children_section = xmlroot_respond.find("vm:Children/", namespaces)
                if children_section is not None:
                    parsed_respond["name"] = children_section.attrib["name"]
                    parsed_respond["nestedHypervisorEnabled"] = (
                        children_section.attrib["nestedHypervisorEnabled"]
                        if "nestedHypervisorEnabled" in children_section.attrib
                        else None
                    )
                    parsed_respond["deployed"] = children_section.attrib["deployed"]
                    parsed_respond["status"] = children_section.attrib["status"]
                    parsed_respond["vmuuid"] = children_section.attrib["id"].split(":")[
                        -1
                    ]
                    network_adapter = children_section.find(
                        "vm:NetworkConnectionSection", namespaces
                    )
                    nic_list = []
                    for adapters in network_adapter:
                        adapter_key = adapters.tag.split("}")[1]
                        if adapter_key == "PrimaryNetworkConnectionIndex":
                            parsed_respond["primarynetwork"] = adapters.text

                        if adapter_key == "NetworkConnection":
                            vnic = {}
                            if "network" in adapters.attrib:
                                vnic["network"] = adapters.attrib["network"]
                            for adapter in adapters:
                                setting_key = adapter.tag.split("}")[1]
                                vnic[setting_key] = adapter.text
                            nic_list.append(vnic)

                    for link in children_section:
                        if link.tag.split("}")[1] == "Link" and "rel" in link.attrib:
                            if link.attrib["rel"] == "screen:acquireTicket":
                                parsed_respond["acquireTicket"] = link.attrib

                            if link.attrib["rel"] == "screen:acquireMksTicket":
                                parsed_respond["acquireMksTicket"] = link.attrib

                    parsed_respond["interfaces"] = nic_list
                    vCloud_extension_section = children_section.find(
                        "xmlns:VCloudExtension", namespaces
                    )
                    if vCloud_extension_section is not None:
                        vm_vcenter_info = {}
                        vim_info = vCloud_extension_section.find(
                            "vmext:VmVimInfo", namespaces
                        )
                        vmext = vim_info.find("vmext:VmVimObjectRef", namespaces)

                        if vmext is not None:
                            vm_vcenter_info["vm_moref_id"] = vmext.find(
                                "vmext:MoRef", namespaces
                            ).text

                        parsed_respond["vm_vcenter_info"] = vm_vcenter_info

                    virtual_hardware_section = children_section.find(
                        "ovf:VirtualHardwareSection", namespaces
                    )
                    vm_virtual_hardware_info = {}
                    if virtual_hardware_section is not None:
                        for item in virtual_hardware_section.iterfind(
                            "ovf:Item", namespaces
                        ):
                            if (
                                item.find("rasd:Description", namespaces).text
                                == "Hard disk"
                            ):
                                disk_size = item.find(
                                    "rasd:HostResource", namespaces
                                ).attrib["{" + namespaces["vm"] + "}capacity"]
                                vm_virtual_hardware_info["disk_size"] = disk_size
                                break

                        for link in virtual_hardware_section:
                            if (
                                link.tag.split("}")[1] == "Link"
                                and "rel" in link.attrib
                            ):
                                if link.attrib["rel"] == "edit" and link.attrib[
                                    "href"
                                ].endswith("/disks"):
                                    vm_virtual_hardware_info["disk_edit_href"] = (
                                        link.attrib["href"]
                                    )
                                    break

                    parsed_respond["vm_virtual_hardware"] = vm_virtual_hardware_info
            except Exception as exp:
                self.logger.info(
                    "Error occurred calling rest api for getting vApp details {}".format(
                        exp
                    )
                )

        return parsed_respond

    def modify_vm_disk(self, vapp_uuid, flavor_disk):
        """
        Method retrieve vm disk details

        Args:
            vapp_uuid - is vapp identifier.
            flavor_disk - disk size as specified in VNFD (flavor)

            Returns:
                The return network uuid or return None
        """
        status = None
        try:
            # Flavor disk is in GB convert it into MB
            flavor_disk = int(flavor_disk) * 1024
            vm_details = self.get_vapp_details_rest(vapp_uuid)

            if vm_details:
                vm_name = vm_details["name"]
                self.logger.info("VM: {} flavor_disk :{}".format(vm_name, flavor_disk))

            if vm_details and "vm_virtual_hardware" in vm_details:
                vm_disk = int(vm_details["vm_virtual_hardware"]["disk_size"])
                disk_edit_href = vm_details["vm_virtual_hardware"]["disk_edit_href"]
                self.logger.info("VM: {} VM_disk :{}".format(vm_name, vm_disk))

                if flavor_disk > vm_disk:
                    status = self.modify_vm_disk_rest(disk_edit_href, flavor_disk)
                    self.logger.info(
                        "Modify disk of VM {} from {} to {} MB".format(
                            vm_name, vm_disk, flavor_disk
                        )
                    )
                else:
                    status = True
                    self.logger.info("No need to modify disk of VM {}".format(vm_name))

            return status
        except Exception as exp:
            self.logger.info("Error occurred while modifing disk size {}".format(exp))

    def modify_vm_disk_rest(self, disk_href, disk_size):
        """
        Method retrieve modify vm disk size

        Args:
            disk_href - vCD API URL to GET and PUT disk data
            disk_size - disk size as specified in VNFD (flavor)

            Returns:
                The return network uuid or return None
        """
        if disk_href is None or disk_size is None:
            return None

        if self.client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url=disk_href, headers=headers
            )

        if response.status_code == 403:
            response = self.retry_rest("GET", disk_href)

        if response.status_code != requests.codes.ok:
            self.logger.debug(
                "GET REST API call {} failed. Return status code {}".format(
                    disk_href, response.status_code
                )
            )

            return None

        try:
            lxmlroot_respond = lxmlElementTree.fromstring(response.content)
            namespaces = {
                prefix: uri for prefix, uri in lxmlroot_respond.nsmap.items() if prefix
            }
            namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"

            for item in lxmlroot_respond.iterfind("xmlns:Item", namespaces):
                if item.find("rasd:Description", namespaces).text == "Hard disk":
                    disk_item = item.find("rasd:HostResource", namespaces)
                    if disk_item is not None:
                        disk_item.attrib["{" + namespaces["xmlns"] + "}capacity"] = str(
                            disk_size
                        )
                        break

            data = lxmlElementTree.tostring(
                lxmlroot_respond, encoding="utf8", method="xml", xml_declaration=True
            )

            # Send PUT request to modify disk size
            headers["Content-Type"] = (
                "application/vnd.vmware.vcloud.rasdItemsList+xml; charset=ISO-8859-1"
            )

            response = self.perform_request(
                req_type="PUT", url=disk_href, headers=headers, data=data
            )
            if response.status_code == 403:
                add_headers = {"Content-Type": headers["Content-Type"]}
                response = self.retry_rest("PUT", disk_href, add_headers, data)

            if response.status_code != 202:
                self.logger.debug(
                    "PUT REST API call {} failed. Return status code {}".format(
                        disk_href, response.status_code
                    )
                )
            else:
                modify_disk_task = self.get_task_from_response(response.text)
                result = self.client.get_task_monitor().wait_for_success(
                    task=modify_disk_task
                )
                if result.get("status") == "success":
                    return True
                else:
                    return False

            return None
        except Exception as exp:
            self.logger.info(
                "Error occurred calling rest api for modifing disk size {}".format(exp)
            )

            return None

    def add_serial_device(self, vapp_uuid):
        """
        Method to attach a serial device to a VM

         Args:
            vapp_uuid - uuid of vApp/VM

        Returns:
        """
        self.logger.info("Add serial devices into vApp {}".format(vapp_uuid))
        _, content = self.get_vcenter_content()
        vm_moref_id = self.get_vm_moref_id(vapp_uuid)

        if vm_moref_id:
            try:
                host_obj, vm_obj = self.get_vm_obj(content, vm_moref_id)
                self.logger.info(
                    "VM {} is currently on host {}".format(vm_obj, host_obj)
                )
                if host_obj and vm_obj:
                    spec = vim.vm.ConfigSpec()
                    spec.deviceChange = []
                    serial_spec = vim.vm.device.VirtualDeviceSpec()
                    serial_spec.operation = "add"
                    serial_port = vim.vm.device.VirtualSerialPort()
                    serial_port.yieldOnPoll = True
                    backing = serial_port.URIBackingInfo()
                    backing.serviceURI = "tcp://:65500"
                    backing.direction = "server"
                    serial_port.backing = backing
                    serial_spec.device = serial_port
                    spec.deviceChange.append(serial_spec)
                    vm_obj.ReconfigVM_Task(spec=spec)
                    self.logger.info("Adding serial device to VM {}".format(vm_obj))
            except vmodl.MethodFault as error:
                self.logger.error("Error occurred while adding PCI devices {} ", error)

    def add_pci_devices(self, vapp_uuid, pci_devices, vmname_andid):
        """
        Method to attach pci devices to VM

         Args:
            vapp_uuid - uuid of vApp/VM
            pci_devices - pci devices infromation as specified in VNFD (flavor)

        Returns:
            The status of add pci device task , vm object and
            vcenter_conect object
        """
        vm_obj = None
        self.logger.info(
            "Add pci devices {} into vApp {}".format(pci_devices, vapp_uuid)
        )
        vcenter_conect, content = self.get_vcenter_content()
        vm_moref_id = self.get_vm_moref_id(vapp_uuid)

        if vm_moref_id:
            try:
                no_of_pci_devices = len(pci_devices)
                if no_of_pci_devices > 0:
                    # Get VM and its host
                    host_obj, vm_obj = self.get_vm_obj(content, vm_moref_id)
                    self.logger.info(
                        "VM {} is currently on host {}".format(vm_obj, host_obj)
                    )

                    if host_obj and vm_obj:
                        # get PCI devies from host on which vapp is currently installed
                        avilable_pci_devices = self.get_pci_devices(
                            host_obj, no_of_pci_devices
                        )

                        if avilable_pci_devices is None:
                            # find other hosts with active pci devices
                            (
                                new_host_obj,
                                avilable_pci_devices,
                            ) = self.get_host_and_PCIdevices(content, no_of_pci_devices)

                            if (
                                new_host_obj is not None
                                and avilable_pci_devices is not None
                                and len(avilable_pci_devices) > 0
                            ):
                                # Migrate vm to the host where PCI devices are availble
                                self.logger.info(
                                    "Relocate VM {} on new host {}".format(
                                        vm_obj, new_host_obj
                                    )
                                )

                                task = self.relocate_vm(new_host_obj, vm_obj)
                                if task is not None:
                                    result = self.wait_for_vcenter_task(
                                        task, vcenter_conect
                                    )
                                    self.logger.info(
                                        "Migrate VM status: {}".format(result)
                                    )
                                    host_obj = new_host_obj
                                else:
                                    self.logger.info(
                                        "Fail to migrate VM : {}".format(result)
                                    )
                                    raise vimconn.VimConnNotFoundException(
                                        "Fail to migrate VM : {} to host {}".format(
                                            vmname_andid, new_host_obj
                                        )
                                    )

                        if (
                            host_obj is not None
                            and avilable_pci_devices is not None
                            and len(avilable_pci_devices) > 0
                        ):
                            # Add PCI devices one by one
                            for pci_device in avilable_pci_devices:
                                task = self.add_pci_to_vm(host_obj, vm_obj, pci_device)
                                if task:
                                    status = self.wait_for_vcenter_task(
                                        task, vcenter_conect
                                    )

                                    if status:
                                        self.logger.info(
                                            "Added PCI device {} to VM {}".format(
                                                pci_device, str(vm_obj)
                                            )
                                        )
                                else:
                                    self.logger.error(
                                        "Fail to add PCI device {} to VM {}".format(
                                            pci_device, str(vm_obj)
                                        )
                                    )

                            return True, vm_obj, vcenter_conect
                        else:
                            self.logger.error(
                                "Currently there is no host with"
                                " {} number of avaialble PCI devices required for VM {}".format(
                                    no_of_pci_devices, vmname_andid
                                )
                            )

                            raise vimconn.VimConnNotFoundException(
                                "Currently there is no host with {} "
                                "number of avaialble PCI devices required for VM {}".format(
                                    no_of_pci_devices, vmname_andid
                                )
                            )
                else:
                    self.logger.debug(
                        "No infromation about PCI devices {} ", pci_devices
                    )
            except vmodl.MethodFault as error:
                self.logger.error("Error occurred while adding PCI devices {} ", error)

        return None, vm_obj, vcenter_conect

    def get_vm_obj(self, content, mob_id):
        """
        Method to get the vsphere VM object associated with a given morf ID
         Args:
            vapp_uuid - uuid of vApp/VM
            content - vCenter content object
            mob_id - mob_id of VM

        Returns:
                VM and host object
        """
        vm_obj = None
        host_obj = None

        try:
            container = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )
            for vm in container.view:
                mobID = vm._GetMoId()

                if mobID == mob_id:
                    vm_obj = vm
                    host_obj = vm_obj.runtime.host
                    break
        except Exception as exp:
            self.logger.error("Error occurred while finding VM object : {}".format(exp))

        return host_obj, vm_obj

    def get_pci_devices(self, host, need_devices):
        """
        Method to get the details of pci devices on given host
         Args:
            host - vSphere host object
            need_devices - number of pci devices needed on host

         Returns:
            array of pci devices
        """
        all_devices = []
        all_device_ids = []
        used_devices_ids = []

        try:
            if host:
                pciPassthruInfo = host.config.pciPassthruInfo
                pciDevies = host.hardware.pciDevice

            for pci_status in pciPassthruInfo:
                if pci_status.passthruActive:
                    for device in pciDevies:
                        if device.id == pci_status.id:
                            all_device_ids.append(device.id)
                            all_devices.append(device)

            # check if devices are in use
            avalible_devices = all_devices
            for vm in host.vm:
                if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                    vm_devices = vm.config.hardware.device
                    for device in vm_devices:
                        if type(device) is vim.vm.device.VirtualPCIPassthrough:
                            if device.backing.id in all_device_ids:
                                for use_device in avalible_devices:
                                    if use_device.id == device.backing.id:
                                        avalible_devices.remove(use_device)

                                used_devices_ids.append(device.backing.id)
                                self.logger.debug(
                                    "Device {} from devices {}"
                                    "is in use".format(device.backing.id, device)
                                )
            if len(avalible_devices) < need_devices:
                self.logger.debug(
                    "Host {} don't have {} number of active devices".format(
                        host, need_devices
                    )
                )
                self.logger.debug(
                    "found only {} devices {}".format(
                        len(avalible_devices), avalible_devices
                    )
                )

                return None
            else:
                required_devices = avalible_devices[:need_devices]
                self.logger.info(
                    "Found {} PCI devices on host {} but required only {}".format(
                        len(avalible_devices), host, need_devices
                    )
                )
                self.logger.info(
                    "Retruning {} devices as {}".format(need_devices, required_devices)
                )

                return required_devices
        except Exception as exp:
            self.logger.error(
                "Error {} occurred while finding pci devices on host: {}".format(
                    exp, host
                )
            )

        return None

    def get_host_and_PCIdevices(self, content, need_devices):
        """
        Method to get the details of pci devices infromation on all hosts

           Args:
               content - vSphere host object
               need_devices - number of pci devices needed on host

           Returns:
                array of pci devices and host object
        """
        host_obj = None
        pci_device_objs = None

        try:
            if content:
                container = content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.HostSystem], True
                )
                for host in container.view:
                    devices = self.get_pci_devices(host, need_devices)

                    if devices:
                        host_obj = host
                        pci_device_objs = devices
                        break
        except Exception as exp:
            self.logger.error(
                "Error {} occurred while finding pci devices on host: {}".format(
                    exp, host_obj
                )
            )

        return host_obj, pci_device_objs

    def relocate_vm(self, dest_host, vm):
        """
        Method to get the relocate VM to new host

           Args:
               dest_host - vSphere host object
               vm - vSphere VM object

           Returns:
               task object
        """
        task = None

        try:
            relocate_spec = vim.vm.RelocateSpec(host=dest_host)
            task = vm.Relocate(relocate_spec)
            self.logger.info(
                "Migrating {} to destination host {}".format(vm, dest_host)
            )
        except Exception as exp:
            self.logger.error(
                "Error occurred while relocate VM {} to new host {}: {}".format(
                    dest_host, vm, exp
                )
            )

        return task

    def wait_for_vcenter_task(self, task, actionName="job", hideResult=False):
        """
        Waits and provides updates on a vSphere task
        """
        while task.info.state == vim.TaskInfo.State.running:
            time.sleep(2)

        if task.info.state == vim.TaskInfo.State.success:
            if task.info.result is not None and not hideResult:
                self.logger.info(
                    "{} completed successfully, result: {}".format(
                        actionName, task.info.result
                    )
                )
            else:
                self.logger.info("Task {} completed successfully.".format(actionName))
        else:
            self.logger.error(
                "{} did not complete successfully: {} ".format(
                    actionName, task.info.error
                )
            )

        return task.info.result

    def add_pci_to_vm(self, host_object, vm_object, host_pci_dev):
        """
        Method to add pci device in given VM

           Args:
               host_object - vSphere host object
               vm_object - vSphere VM object
               host_pci_dev -  host_pci_dev must be one of the devices from the
                               host_object.hardware.pciDevice list
                               which is configured as a PCI passthrough device

           Returns:
               task object
        """
        task = None

        if vm_object and host_object and host_pci_dev:
            try:
                # Add PCI device to VM
                pci_passthroughs = vm_object.environmentBrowser.QueryConfigTarget(
                    host=None
                ).pciPassthrough
                systemid_by_pciid = {
                    item.pciDevice.id: item.systemId for item in pci_passthroughs
                }

                if host_pci_dev.id not in systemid_by_pciid:
                    self.logger.error(
                        "Device {} is not a passthrough device ".format(host_pci_dev)
                    )
                    return None

                deviceId = hex(host_pci_dev.deviceId % 2**16).lstrip("0x")
                backing = vim.VirtualPCIPassthroughDeviceBackingInfo(
                    deviceId=deviceId,
                    id=host_pci_dev.id,
                    systemId=systemid_by_pciid[host_pci_dev.id],
                    vendorId=host_pci_dev.vendorId,
                    deviceName=host_pci_dev.deviceName,
                )

                hba_object = vim.VirtualPCIPassthrough(key=-100, backing=backing)
                new_device_config = vim.VirtualDeviceConfigSpec(device=hba_object)
                new_device_config.operation = "add"
                vmConfigSpec = vim.vm.ConfigSpec()
                vmConfigSpec.deviceChange = [new_device_config]
                task = vm_object.ReconfigVM_Task(spec=vmConfigSpec)
                self.logger.info(
                    "Adding PCI device {} into VM {} from host {} ".format(
                        host_pci_dev, vm_object, host_object
                    )
                )
            except Exception as exp:
                self.logger.error(
                    "Error occurred while adding pci devive {} to VM {}: {}".format(
                        host_pci_dev, vm_object, exp
                    )
                )

        return task

    def get_vm_vcenter_info(self):
        """
        Method to get details of vCenter and vm

            Args:
                vapp_uuid - uuid of vApp or VM

            Returns:
                Moref Id of VM and deails of vCenter
        """
        vm_vcenter_info = {}

        if self.vcenter_ip is not None:
            vm_vcenter_info["vm_vcenter_ip"] = self.vcenter_ip
        else:
            raise vimconn.VimConnException(
                message="vCenter IP is not provided."
                " Please provide vCenter IP while attaching datacenter "
                "to tenant in --config"
            )

        if self.vcenter_port is not None:
            vm_vcenter_info["vm_vcenter_port"] = self.vcenter_port
        else:
            raise vimconn.VimConnException(
                message="vCenter port is not provided."
                " Please provide vCenter port while attaching datacenter "
                "to tenant in --config"
            )

        if self.vcenter_user is not None:
            vm_vcenter_info["vm_vcenter_user"] = self.vcenter_user
        else:
            raise vimconn.VimConnException(
                message="vCenter user is not provided."
                " Please provide vCenter user while attaching datacenter "
                "to tenant in --config"
            )

        if self.vcenter_password is not None:
            vm_vcenter_info["vm_vcenter_password"] = self.vcenter_password
        else:
            raise vimconn.VimConnException(
                message="vCenter user password is not provided."
                " Please provide vCenter user password while attaching datacenter "
                "to tenant in --config"
            )

        return vm_vcenter_info

    def get_vm_pci_details(self, vmuuid):
        """
        Method to get VM PCI device details from vCenter

        Args:
            vm_obj - vSphere VM object

        Returns:
            dict of PCI devives attached to VM

        """
        vm_pci_devices_info = {}

        try:
            _, content = self.get_vcenter_content()
            vm_moref_id = self.get_vm_moref_id(vmuuid)
            if vm_moref_id:
                # Get VM and its host
                if content:
                    host_obj, vm_obj = self.get_vm_obj(content, vm_moref_id)
                    if host_obj and vm_obj:
                        vm_pci_devices_info["host_name"] = host_obj.name
                        vm_pci_devices_info["host_ip"] = host_obj.config.network.vnic[
                            0
                        ].spec.ip.ipAddress

                        for device in vm_obj.config.hardware.device:
                            if device.isinstance(vim.vm.device.VirtualPCIPassthrough):
                                device_details = {
                                    "devide_id": device.backing.id,
                                    "pciSlotNumber": device.slotInfo.pciSlotNumber,
                                }
                                vm_pci_devices_info[device.deviceInfo.label] = (
                                    device_details
                                )
                else:
                    self.logger.error(
                        "Can not connect to vCenter while getting "
                        "PCI devices infromationn"
                    )

                return vm_pci_devices_info
        except Exception as exp:
            self.logger.error(
                "Error occurred while getting VM information" " for VM : {}".format(exp)
            )

            raise vimconn.VimConnException(message=exp)

    def reserve_memory_for_all_vms(self, vapp, memory_mb):
        """
        Method to reserve memory for all VMs
        Args :
            vapp - VApp
            memory_mb - Memory in MB
        Returns:
            None
        """
        self.logger.info("Reserve memory for all VMs")

        for vms in vapp.get_all_vms():
            vm_id = vms.get("id").split(":")[-1]
            url_rest_call = "{}/api/vApp/vm-{}/virtualHardwareSection/memory".format(
                self.url, vm_id
            )
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            headers["Content-Type"] = "application/vnd.vmware.vcloud.rasdItem+xml"
            response = self.perform_request(
                req_type="GET", url=url_rest_call, headers=headers
            )

            if response.status_code == 403:
                response = self.retry_rest("GET", url_rest_call)

            if response.status_code != 200:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {}".format(
                        url_rest_call, response.text, response.status_code
                    )
                )
                raise vimconn.VimConnException(
                    "reserve_memory_for_all_vms : Failed to get " "memory"
                )

            bytexml = bytes(bytearray(response.text, encoding="utf-8"))
            contentelem = lxmlElementTree.XML(bytexml)
            namespaces = {
                prefix: uri for prefix, uri in contentelem.nsmap.items() if prefix
            }
            namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"

            # Find the reservation element in the response
            memelem_list = contentelem.findall(".//rasd:Reservation", namespaces)
            for memelem in memelem_list:
                memelem.text = str(memory_mb)

            newdata = lxmlElementTree.tostring(contentelem, pretty_print=True)

            response = self.perform_request(
                req_type="PUT", url=url_rest_call, headers=headers, data=newdata
            )

            if response.status_code == 403:
                add_headers = {"Content-Type": headers["Content-Type"]}
                response = self.retry_rest("PUT", url_rest_call, add_headers, newdata)

            if response.status_code != 202:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {} ".format(
                        url_rest_call, response.text, response.status_code
                    )
                )
                raise vimconn.VimConnException(
                    "reserve_memory_for_all_vms : Failed to update "
                    "virtual hardware memory section"
                )
            else:
                mem_task = self.get_task_from_response(response.text)
                result = self.client.get_task_monitor().wait_for_success(task=mem_task)

                if result.get("status") == "success":
                    self.logger.info(
                        "reserve_memory_for_all_vms(): VM {} succeeded ".format(vm_id)
                    )
                else:
                    self.logger.error(
                        "reserve_memory_for_all_vms(): VM {} failed ".format(vm_id)
                    )

    def connect_vapp_to_org_vdc_network(self, vapp_id, net_name):
        """
        Configure VApp network config with org vdc network
        Args :
            vapp - VApp
        Returns:
            None
        """

        self.logger.info(
            "Connecting vapp {} to org vdc network {}".format(vapp_id, net_name)
        )

        url_rest_call = "{}/api/vApp/vapp-{}/networkConfigSection/".format(
            self.url, vapp_id
        )

        headers = {
            "Accept": "application/*+xml;version=" + API_VERSION,
            "x-vcloud-authorization": self.client._session.headers[
                "x-vcloud-authorization"
            ],
        }
        response = self.perform_request(
            req_type="GET", url=url_rest_call, headers=headers
        )

        if response.status_code == 403:
            response = self.retry_rest("GET", url_rest_call)

        if response.status_code != 200:
            self.logger.error(
                "REST call {} failed reason : {}"
                "status code : {}".format(
                    url_rest_call, response.text, response.status_code
                )
            )
            raise vimconn.VimConnException(
                "connect_vapp_to_org_vdc_network : Failed to get "
                "network config section"
            )

        data = response.text
        headers["Content-Type"] = (
            "application/vnd.vmware.vcloud.networkConfigSection+xml"
        )
        net_id = self.get_network_id_by_name(net_name)
        if not net_id:
            raise vimconn.VimConnException(
                "connect_vapp_to_org_vdc_network : Failed to find " "existing network"
            )

        bytexml = bytes(bytearray(data, encoding="utf-8"))
        newelem = lxmlElementTree.XML(bytexml)
        namespaces = {prefix: uri for prefix, uri in newelem.nsmap.items() if prefix}
        namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"
        nwcfglist = newelem.findall(".//xmlns:NetworkConfig", namespaces)

        # VCD 9.7 returns an incorrect parentnetwork element. Fix it before PUT operation
        parentnetworklist = newelem.findall(".//xmlns:ParentNetwork", namespaces)
        if parentnetworklist:
            for pn in parentnetworklist:
                if "href" not in pn.keys():
                    id_val = pn.get("id")
                    href_val = "{}/api/network/{}".format(self.url, id_val)
                    pn.set("href", href_val)

        newstr = """<NetworkConfig networkName="{}">
                  <Configuration>
                       <ParentNetwork href="{}/api/network/{}"/>
                       <FenceMode>bridged</FenceMode>
                  </Configuration>
              </NetworkConfig>
           """.format(
            net_name, self.url, net_id
        )
        newcfgelem = lxmlElementTree.fromstring(newstr)
        if nwcfglist:
            nwcfglist[0].addnext(newcfgelem)

        newdata = lxmlElementTree.tostring(newelem, pretty_print=True)

        response = self.perform_request(
            req_type="PUT", url=url_rest_call, headers=headers, data=newdata
        )

        if response.status_code == 403:
            add_headers = {"Content-Type": headers["Content-Type"]}
            response = self.retry_rest("PUT", url_rest_call, add_headers, newdata)

        if response.status_code != 202:
            self.logger.error(
                "REST call {} failed reason : {}"
                "status code : {} ".format(
                    url_rest_call, response.text, response.status_code
                )
            )
            raise vimconn.VimConnException(
                "connect_vapp_to_org_vdc_network : Failed to update "
                "network config section"
            )
        else:
            vapp_task = self.get_task_from_response(response.text)
            result = self.client.get_task_monitor().wait_for_success(task=vapp_task)
            if result.get("status") == "success":
                self.logger.info(
                    "connect_vapp_to_org_vdc_network(): Vapp {} connected to "
                    "network {}".format(vapp_id, net_name)
                )
            else:
                self.logger.error(
                    "connect_vapp_to_org_vdc_network(): Vapp {} failed to "
                    "connect to network {}".format(vapp_id, net_name)
                )

    def remove_primary_network_adapter_from_all_vms(self, vapp):
        """
        Method to remove network adapter type to vm
        Args :
            vapp - VApp
        Returns:
            None
        """
        self.logger.info("Removing network adapter from all VMs")

        for vms in vapp.get_all_vms():
            vm_id = vms.get("id").split(":")[-1]

            url_rest_call = "{}/api/vApp/vm-{}/networkConnectionSection/".format(
                self.url, vm_id
            )

            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url=url_rest_call, headers=headers
            )

            if response.status_code == 403:
                response = self.retry_rest("GET", url_rest_call)

            if response.status_code != 200:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {}".format(
                        url_rest_call, response.text, response.status_code
                    )
                )
                raise vimconn.VimConnException(
                    "remove_primary_network_adapter : Failed to get "
                    "network connection section"
                )

            data = response.text
            data = data.split('<Link rel="edit"')[0]

            headers["Content-Type"] = (
                "application/vnd.vmware.vcloud.networkConnectionSection+xml"
            )

            newdata = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                      <NetworkConnectionSection xmlns="http://www.vmware.com/vcloud/v1.5"
                              xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
                              xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
                              xmlns:common="http://schemas.dmtf.org/wbem/wscim/1/common"
                              xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
                              xmlns:vmw="http://www.vmware.com/schema/ovf"
                              xmlns:ovfenv="http://schemas.dmtf.org/ovf/environment/1"
                              xmlns:vmext="http://www.vmware.com/vcloud/extension/v1.5"
                              xmlns:ns9="http://www.vmware.com/vcloud/versions"
                              href="{url}" type="application/vnd.vmware.vcloud.networkConnectionSection+xml"
                                  ovf:required="false">
                              <ovf:Info>Specifies the available VM network connections</ovf:Info>
                             <PrimaryNetworkConnectionIndex>0</PrimaryNetworkConnectionIndex>
                             <Link rel="edit" href="{url}"
                                 type="application/vnd.vmware.vcloud.networkConnectionSection+xml"/>
                      </NetworkConnectionSection>""".format(
                url=url_rest_call
            )
            response = self.perform_request(
                req_type="PUT", url=url_rest_call, headers=headers, data=newdata
            )

            if response.status_code == 403:
                add_headers = {"Content-Type": headers["Content-Type"]}
                response = self.retry_rest("PUT", url_rest_call, add_headers, newdata)

            if response.status_code != 202:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {} ".format(
                        url_rest_call, response.text, response.status_code
                    )
                )
                raise vimconn.VimConnException(
                    "remove_primary_network_adapter : Failed to update "
                    "network connection section"
                )
            else:
                nic_task = self.get_task_from_response(response.text)
                result = self.client.get_task_monitor().wait_for_success(task=nic_task)
                if result.get("status") == "success":
                    self.logger.info(
                        "remove_primary_network_adapter(): VM {} conneced to "
                        "default NIC type".format(vm_id)
                    )
                else:
                    self.logger.error(
                        "remove_primary_network_adapter(): VM {} failed to "
                        "connect NIC type".format(vm_id)
                    )

    def add_network_adapter_to_vms(
        self, vapp, network_name, primary_nic_index, nicIndex, net, nic_type=None
    ):
        """
        Method to add network adapter type to vm
        Args :
            network_name - name of network
            primary_nic_index - int value for primary nic index
            nicIndex - int value for nic index
            nic_type - specify model name to which add to vm
        Returns:
            None
        """

        self.logger.info(
            "Add network adapter to VM: network_name {} nicIndex {} nic_type {}".format(
                network_name, nicIndex, nic_type
            )
        )
        try:
            ip_address = None
            floating_ip = False
            mac_address = None
            if "floating_ip" in net:
                floating_ip = net["floating_ip"]

            # Stub for ip_address feature
            if "ip_address" in net:
                ip_address = net["ip_address"]

            if "mac_address" in net:
                mac_address = net["mac_address"]

            if floating_ip:
                allocation_mode = "POOL"
            elif ip_address:
                allocation_mode = "MANUAL"
            else:
                allocation_mode = "DHCP"

            if not nic_type:
                for vms in vapp.get_all_vms():
                    vm_id = vms.get("id").split(":")[-1]

                    url_rest_call = (
                        "{}/api/vApp/vm-{}/networkConnectionSection/".format(
                            self.url, vm_id
                        )
                    )

                    headers = {
                        "Accept": "application/*+xml;version=" + API_VERSION,
                        "x-vcloud-authorization": self.client._session.headers[
                            "x-vcloud-authorization"
                        ],
                    }
                    response = self.perform_request(
                        req_type="GET", url=url_rest_call, headers=headers
                    )

                    if response.status_code == 403:
                        response = self.retry_rest("GET", url_rest_call)

                    if response.status_code != 200:
                        self.logger.error(
                            "REST call {} failed reason : {}"
                            "status code : {}".format(
                                url_rest_call, response.text, response.status_code
                            )
                        )
                        raise vimconn.VimConnException(
                            "add_network_adapter_to_vms : Failed to get "
                            "network connection section"
                        )

                    data = response.text
                    data = data.split('<Link rel="edit"')[0]
                    if "<PrimaryNetworkConnectionIndex>" not in data:
                        self.logger.debug("add_network_adapter PrimaryNIC not in data")
                        item = """<PrimaryNetworkConnectionIndex>{}</PrimaryNetworkConnectionIndex>
                                <NetworkConnection network="{}">
                                <NetworkConnectionIndex>{}</NetworkConnectionIndex>
                                <IsConnected>true</IsConnected>
                                <IpAddressAllocationMode>{}</IpAddressAllocationMode>
                                </NetworkConnection>""".format(
                            primary_nic_index, network_name, nicIndex, allocation_mode
                        )

                        # Stub for ip_address feature
                        if ip_address:
                            ip_tag = "<IpAddress>{}</IpAddress>".format(ip_address)
                            item = item.replace(
                                "</NetworkConnectionIndex>\n",
                                "</NetworkConnectionIndex>\n{}\n".format(ip_tag),
                            )

                        if mac_address:
                            mac_tag = "<MACAddress>{}</MACAddress>".format(mac_address)
                            item = item.replace(
                                "</IsConnected>\n",
                                "</IsConnected>\n{}\n".format(mac_tag),
                            )

                        data = data.replace(
                            "</ovf:Info>\n",
                            "</ovf:Info>\n{}\n</NetworkConnectionSection>".format(item),
                        )
                    else:
                        self.logger.debug("add_network_adapter PrimaryNIC in data")
                        new_item = """<NetworkConnection network="{}">
                                    <NetworkConnectionIndex>{}</NetworkConnectionIndex>
                                    <IsConnected>true</IsConnected>
                                    <IpAddressAllocationMode>{}</IpAddressAllocationMode>
                                    </NetworkConnection>""".format(
                            network_name, nicIndex, allocation_mode
                        )

                        # Stub for ip_address feature
                        if ip_address:
                            ip_tag = "<IpAddress>{}</IpAddress>".format(ip_address)
                            new_item = new_item.replace(
                                "</NetworkConnectionIndex>\n",
                                "</NetworkConnectionIndex>\n{}\n".format(ip_tag),
                            )

                        if mac_address:
                            mac_tag = "<MACAddress>{}</MACAddress>".format(mac_address)
                            new_item = new_item.replace(
                                "</IsConnected>\n",
                                "</IsConnected>\n{}\n".format(mac_tag),
                            )

                        data = data + new_item + "</NetworkConnectionSection>"

                    headers["Content-Type"] = (
                        "application/vnd.vmware.vcloud.networkConnectionSection+xml"
                    )

                    response = self.perform_request(
                        req_type="PUT", url=url_rest_call, headers=headers, data=data
                    )

                    if response.status_code == 403:
                        add_headers = {"Content-Type": headers["Content-Type"]}
                        response = self.retry_rest(
                            "PUT", url_rest_call, add_headers, data
                        )

                    if response.status_code != 202:
                        self.logger.error(
                            "REST call {} failed reason : {}"
                            "status code : {} ".format(
                                url_rest_call, response.text, response.status_code
                            )
                        )
                        raise vimconn.VimConnException(
                            "add_network_adapter_to_vms : Failed to update "
                            "network connection section"
                        )
                    else:
                        nic_task = self.get_task_from_response(response.text)
                        result = self.client.get_task_monitor().wait_for_success(
                            task=nic_task
                        )

                        if result.get("status") == "success":
                            self.logger.info(
                                "add_network_adapter_to_vms(): VM {} conneced to "
                                "default NIC type".format(vm_id)
                            )
                        else:
                            self.logger.error(
                                "add_network_adapter_to_vms(): VM {} failed to "
                                "connect NIC type".format(vm_id)
                            )
            else:
                for vms in vapp.get_all_vms():
                    vm_id = vms.get("id").split(":")[-1]

                    url_rest_call = (
                        "{}/api/vApp/vm-{}/networkConnectionSection/".format(
                            self.url, vm_id
                        )
                    )

                    headers = {
                        "Accept": "application/*+xml;version=" + API_VERSION,
                        "x-vcloud-authorization": self.client._session.headers[
                            "x-vcloud-authorization"
                        ],
                    }
                    response = self.perform_request(
                        req_type="GET", url=url_rest_call, headers=headers
                    )

                    if response.status_code == 403:
                        response = self.retry_rest("GET", url_rest_call)

                    if response.status_code != 200:
                        self.logger.error(
                            "REST call {} failed reason : {}"
                            "status code : {}".format(
                                url_rest_call, response.text, response.status_code
                            )
                        )
                        raise vimconn.VimConnException(
                            "add_network_adapter_to_vms : Failed to get "
                            "network connection section"
                        )
                    data = response.text
                    data = data.split('<Link rel="edit"')[0]
                    vcd_netadapter_type = nic_type

                    if nic_type in ["SR-IOV", "VF"]:
                        vcd_netadapter_type = "SRIOVETHERNETCARD"

                    if "<PrimaryNetworkConnectionIndex>" not in data:
                        self.logger.debug(
                            "add_network_adapter PrimaryNIC not in data nic_type {}".format(
                                nic_type
                            )
                        )
                        item = """<PrimaryNetworkConnectionIndex>{}</PrimaryNetworkConnectionIndex>
                                <NetworkConnection network="{}">
                                <NetworkConnectionIndex>{}</NetworkConnectionIndex>
                                <IsConnected>true</IsConnected>
                                <IpAddressAllocationMode>{}</IpAddressAllocationMode>
                                <NetworkAdapterType>{}</NetworkAdapterType>
                                </NetworkConnection>""".format(
                            primary_nic_index,
                            network_name,
                            nicIndex,
                            allocation_mode,
                            vcd_netadapter_type,
                        )

                        # Stub for ip_address feature
                        if ip_address:
                            ip_tag = "<IpAddress>{}</IpAddress>".format(ip_address)
                            item = item.replace(
                                "</NetworkConnectionIndex>\n",
                                "</NetworkConnectionIndex>\n{}\n".format(ip_tag),
                            )

                        if mac_address:
                            mac_tag = "<MACAddress>{}</MACAddress>".format(mac_address)
                            item = item.replace(
                                "</IsConnected>\n",
                                "</IsConnected>\n{}\n".format(mac_tag),
                            )

                        data = data.replace(
                            "</ovf:Info>\n",
                            "</ovf:Info>\n{}\n</NetworkConnectionSection>".format(item),
                        )
                    else:
                        self.logger.debug(
                            "add_network_adapter PrimaryNIC in data nic_type {}".format(
                                nic_type
                            )
                        )
                        new_item = """<NetworkConnection network="{}">
                                    <NetworkConnectionIndex>{}</NetworkConnectionIndex>
                                    <IsConnected>true</IsConnected>
                                    <IpAddressAllocationMode>{}</IpAddressAllocationMode>
                                    <NetworkAdapterType>{}</NetworkAdapterType>
                                    </NetworkConnection>""".format(
                            network_name, nicIndex, allocation_mode, vcd_netadapter_type
                        )

                        # Stub for ip_address feature
                        if ip_address:
                            ip_tag = "<IpAddress>{}</IpAddress>".format(ip_address)
                            new_item = new_item.replace(
                                "</NetworkConnectionIndex>\n",
                                "</NetworkConnectionIndex>\n{}\n".format(ip_tag),
                            )

                        if mac_address:
                            mac_tag = "<MACAddress>{}</MACAddress>".format(mac_address)
                            new_item = new_item.replace(
                                "</IsConnected>\n",
                                "</IsConnected>\n{}\n".format(mac_tag),
                            )

                        data = data + new_item + "</NetworkConnectionSection>"

                    headers["Content-Type"] = (
                        "application/vnd.vmware.vcloud.networkConnectionSection+xml"
                    )

                    response = self.perform_request(
                        req_type="PUT", url=url_rest_call, headers=headers, data=data
                    )

                    if response.status_code == 403:
                        add_headers = {"Content-Type": headers["Content-Type"]}
                        response = self.retry_rest(
                            "PUT", url_rest_call, add_headers, data
                        )

                    if response.status_code != 202:
                        self.logger.error(
                            "REST call {} failed reason : {}"
                            "status code : {}".format(
                                url_rest_call, response.text, response.status_code
                            )
                        )
                        raise vimconn.VimConnException(
                            "add_network_adapter_to_vms : Failed to update "
                            "network connection section"
                        )
                    else:
                        nic_task = self.get_task_from_response(response.text)
                        result = self.client.get_task_monitor().wait_for_success(
                            task=nic_task
                        )

                        if result.get("status") == "success":
                            self.logger.info(
                                "add_network_adapter_to_vms(): VM {} "
                                "conneced to NIC type {}".format(vm_id, nic_type)
                            )
                        else:
                            self.logger.error(
                                "add_network_adapter_to_vms(): VM {} "
                                "failed to connect NIC type {}".format(vm_id, nic_type)
                            )
        except Exception as exp:
            self.logger.error(
                "add_network_adapter_to_vms() : exception occurred "
                "while adding Network adapter"
            )

            raise vimconn.VimConnException(message=exp)

    def set_numa_affinity(self, vmuuid, paired_threads_id):
        """
        Method to assign numa affinity in vm configuration parammeters
        Args :
            vmuuid - vm uuid
            paired_threads_id - one or more virtual processor
                                numbers
        Returns:
            return if True
        """
        try:
            vcenter_conect, content = self.get_vcenter_content()
            vm_moref_id = self.get_vm_moref_id(vmuuid)
            _, vm_obj = self.get_vm_obj(content, vm_moref_id)

            if vm_obj:
                config_spec = vim.vm.ConfigSpec()
                config_spec.extraConfig = []
                opt = vim.option.OptionValue()
                opt.key = "numa.nodeAffinity"
                opt.value = str(paired_threads_id)
                config_spec.extraConfig.append(opt)
                task = vm_obj.ReconfigVM_Task(config_spec)

                if task:
                    self.wait_for_vcenter_task(task, vcenter_conect)
                    extra_config = vm_obj.config.extraConfig
                    flag = False

                    for opts in extra_config:
                        if "numa.nodeAffinity" in opts.key:
                            flag = True
                            self.logger.info(
                                "set_numa_affinity: Sucessfully assign numa affinity "
                                "value {} for vm {}".format(opt.value, vm_obj)
                            )

                        if flag:
                            return
            else:
                self.logger.error("set_numa_affinity: Failed to assign numa affinity")
        except Exception as exp:
            self.logger.error(
                "set_numa_affinity : exception occurred while setting numa affinity "
                "for VM {} : {}".format(vm_obj, vm_moref_id)
            )

            raise vimconn.VimConnException(
                "set_numa_affinity : Error {} failed to assign numa "
                "affinity".format(exp)
            )

    def add_new_disk(self, vapp_uuid, disk_size):
        """
        Method to create an empty vm disk

        Args:
            vapp_uuid - is vapp identifier.
            disk_size - size of disk to be created in GB

        Returns:
            None
        """
        status = False
        vm_details = None
        try:
            # Disk size in GB, convert it into MB
            if disk_size is not None:
                disk_size_mb = int(disk_size) * 1024
                vm_details = self.get_vapp_details_rest(vapp_uuid)

            if vm_details and "vm_virtual_hardware" in vm_details:
                self.logger.info(
                    "Adding disk to VM: {} disk size:{}GB".format(
                        vm_details["name"], disk_size
                    )
                )
                disk_href = vm_details["vm_virtual_hardware"]["disk_edit_href"]
                status = self.add_new_disk_rest(disk_href, disk_size_mb)
        except Exception as exp:
            msg = "Error occurred while creating new disk {}.".format(exp)
            self.rollback_newvm(vapp_uuid, msg)

        if status:
            self.logger.info(
                "Added new disk to VM: {} disk size:{}GB".format(
                    vm_details["name"], disk_size
                )
            )
        else:
            # If failed to add disk, delete VM
            msg = "add_new_disk: Failed to add new disk to {}".format(
                vm_details["name"]
            )
            self.rollback_newvm(vapp_uuid, msg)

    def add_new_disk_rest(self, disk_href, disk_size_mb):
        """
        Retrives vApp Disks section & add new empty disk

        Args:
            disk_href: Disk section href to addd disk
            disk_size_mb: Disk size in MB

            Returns: Status of add new disk task
        """
        status = False
        if self.client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }
            response = self.perform_request(
                req_type="GET", url=disk_href, headers=headers
            )

        if response.status_code == 403:
            response = self.retry_rest("GET", disk_href)

        if response.status_code != requests.codes.ok:
            self.logger.error(
                "add_new_disk_rest: GET REST API call {} failed. Return status code {}".format(
                    disk_href, response.status_code
                )
            )

            return status

        try:
            # Find but type & max of instance IDs assigned to disks
            lxmlroot_respond = lxmlElementTree.fromstring(response.content)
            namespaces = {
                prefix: uri for prefix, uri in lxmlroot_respond.nsmap.items() if prefix
            }
            namespaces["xmlns"] = "http://www.vmware.com/vcloud/v1.5"
            instance_id = 0

            for item in lxmlroot_respond.iterfind("xmlns:Item", namespaces):
                if item.find("rasd:Description", namespaces).text == "Hard disk":
                    inst_id = int(item.find("rasd:InstanceID", namespaces).text)

                    if inst_id > instance_id:
                        instance_id = inst_id
                        disk_item = item.find("rasd:HostResource", namespaces)
                        bus_subtype = disk_item.attrib[
                            "{" + namespaces["xmlns"] + "}busSubType"
                        ]
                        bus_type = disk_item.attrib[
                            "{" + namespaces["xmlns"] + "}busType"
                        ]

            instance_id = instance_id + 1
            new_item = """<Item>
                                <rasd:Description>Hard disk</rasd:Description>
                                <rasd:ElementName>New disk</rasd:ElementName>
                                <rasd:HostResource
                                    xmlns:vcloud="http://www.vmware.com/vcloud/v1.5"
                                    vcloud:capacity="{}"
                                    vcloud:busSubType="{}"
                                    vcloud:busType="{}"></rasd:HostResource>
                                <rasd:InstanceID>{}</rasd:InstanceID>
                                <rasd:ResourceType>17</rasd:ResourceType>
                            </Item>""".format(
                disk_size_mb, bus_subtype, bus_type, instance_id
            )

            new_data = response.text
            # Add new item at the bottom
            new_data = new_data.replace(
                "</Item>\n</RasdItemsList>",
                "</Item>\n{}\n</RasdItemsList>".format(new_item),
            )

            # Send PUT request to modify virtual hardware section with new disk
            headers["Content-Type"] = (
                "application/vnd.vmware.vcloud.rasdItemsList+xml; charset=ISO-8859-1"
            )

            response = self.perform_request(
                req_type="PUT", url=disk_href, data=new_data, headers=headers
            )

            if response.status_code == 403:
                add_headers = {"Content-Type": headers["Content-Type"]}
                response = self.retry_rest("PUT", disk_href, add_headers, new_data)

            if response.status_code != 202:
                self.logger.error(
                    "PUT REST API call {} failed. Return status code {}. response.text:{}".format(
                        disk_href, response.status_code, response.text
                    )
                )
            else:
                add_disk_task = self.get_task_from_response(response.text)
                result = self.client.get_task_monitor().wait_for_success(
                    task=add_disk_task
                )

                if result.get("status") == "success":
                    status = True
                else:
                    self.logger.error(
                        "Add new disk REST task failed to add {} MB disk".format(
                            disk_size_mb
                        )
                    )
        except Exception as exp:
            self.logger.error(
                "Error occurred calling rest api for creating new disk {}".format(exp)
            )

        return status

    def add_existing_disk(
        self,
        catalogs=None,
        image_id=None,
        size=None,
        template_name=None,
        vapp_uuid=None,
    ):
        """
        Method to add existing disk to vm
        Args :
            catalogs - List of VDC catalogs
            image_id - Catalog ID
            template_name - Name of template in catalog
            vapp_uuid - UUID of vApp
        Returns:
            None
        """
        disk_info = None
        vcenter_conect, content = self.get_vcenter_content()
        # find moref-id of vm in image
        catalog_vm_info = self.get_vapp_template_details(
            catalogs=catalogs,
            image_id=image_id,
        )

        if catalog_vm_info and "vm_vcenter_info" in catalog_vm_info:
            if "vm_moref_id" in catalog_vm_info["vm_vcenter_info"]:
                catalog_vm_moref_id = catalog_vm_info["vm_vcenter_info"].get(
                    "vm_moref_id", None
                )

                if catalog_vm_moref_id:
                    self.logger.info(
                        "Moref_id of VM in catalog : {}".format(catalog_vm_moref_id)
                    )
                    _, catalog_vm_obj = self.get_vm_obj(content, catalog_vm_moref_id)

                    if catalog_vm_obj:
                        # find existing disk
                        disk_info = self.find_disk(catalog_vm_obj)
                    else:
                        exp_msg = "No VM with image id {} found".format(image_id)
                        self.rollback_newvm(vapp_uuid, exp_msg, exp_type="NotFound")
        else:
            exp_msg = "No Image found with image ID {} ".format(image_id)
            self.rollback_newvm(vapp_uuid, exp_msg, exp_type="NotFound")

        if disk_info:
            self.logger.info("Existing disk_info : {}".format(disk_info))
            # get VM
            vm_moref_id = self.get_vm_moref_id(vapp_uuid)
            _, vm_obj = self.get_vm_obj(content, vm_moref_id)

            if vm_obj:
                status = self.add_disk(
                    vcenter_conect=vcenter_conect,
                    vm=vm_obj,
                    disk_info=disk_info,
                    size=size,
                    vapp_uuid=vapp_uuid,
                )

            if status:
                self.logger.info(
                    "Disk from image id {} added to {}".format(
                        image_id, vm_obj.config.name
                    )
                )
        else:
            msg = "No disk found with image id {} to add in VM {}".format(
                image_id, vm_obj.config.name
            )
            self.rollback_newvm(vapp_uuid, msg, exp_type="NotFound")

    def find_disk(self, vm_obj):
        """
        Method to find details of existing disk in VM
            Args:
                vm_obj - vCenter object of VM
            Returns:
                disk_info : dict of disk details
        """
        disk_info = {}
        if vm_obj:
            try:
                devices = vm_obj.config.hardware.device

                for device in devices:
                    if type(device) is vim.vm.device.VirtualDisk:
                        if isinstance(
                            device.backing,
                            vim.vm.device.VirtualDisk.FlatVer2BackingInfo,
                        ) and hasattr(device.backing, "fileName"):
                            disk_info["full_path"] = device.backing.fileName
                            disk_info["datastore"] = device.backing.datastore
                            disk_info["capacityKB"] = device.capacityInKB
                            break
            except Exception as exp:
                self.logger.error(
                    "find_disk() : exception occurred while "
                    "getting existing disk details :{}".format(exp)
                )

        return disk_info

    def add_disk(
        self, vcenter_conect=None, vm=None, size=None, vapp_uuid=None, disk_info={}
    ):
        """
        Method to add existing disk in VM
           Args :
               vcenter_conect - vCenter content object
               vm - vCenter vm object
               disk_info : dict of disk details
           Returns:
               status : status of add disk task
        """
        datastore = disk_info["datastore"] if "datastore" in disk_info else None
        fullpath = disk_info["full_path"] if "full_path" in disk_info else None
        capacityKB = disk_info["capacityKB"] if "capacityKB" in disk_info else None
        if size is not None:
            # Convert size from GB to KB
            sizeKB = int(size) * 1024 * 1024
            # compare size of existing disk and user given size.Assign whicherver is greater
            self.logger.info(
                "Add Existing disk : sizeKB {} , capacityKB {}".format(
                    sizeKB, capacityKB
                )
            )

            if sizeKB > capacityKB:
                capacityKB = sizeKB

        if datastore and fullpath and capacityKB:
            try:
                spec = vim.vm.ConfigSpec()
                # get all disks on a VM, set unit_number to the next available
                unit_number = 0
                for dev in vm.config.hardware.device:
                    if hasattr(dev.backing, "fileName"):
                        unit_number = int(dev.unitNumber) + 1
                        # unit_number 7 reserved for scsi controller

                        if unit_number == 7:
                            unit_number += 1

                    if isinstance(dev, vim.vm.device.VirtualDisk):
                        # vim.vm.device.VirtualSCSIController
                        controller_key = dev.controllerKey

                self.logger.info(
                    "Add Existing disk : unit number {} , controller key {}".format(
                        unit_number, controller_key
                    )
                )
                # add disk here
                dev_changes = []
                disk_spec = vim.vm.device.VirtualDeviceSpec()
                disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
                disk_spec.device = vim.vm.device.VirtualDisk()
                disk_spec.device.backing = (
                    vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
                )
                disk_spec.device.backing.thinProvisioned = True
                disk_spec.device.backing.diskMode = "persistent"
                disk_spec.device.backing.datastore = datastore
                disk_spec.device.backing.fileName = fullpath

                disk_spec.device.unitNumber = unit_number
                disk_spec.device.capacityInKB = capacityKB
                disk_spec.device.controllerKey = controller_key
                dev_changes.append(disk_spec)
                spec.deviceChange = dev_changes
                task = vm.ReconfigVM_Task(spec=spec)
                status = self.wait_for_vcenter_task(task, vcenter_conect)

                return status
            except Exception as exp:
                exp_msg = (
                    "add_disk() : exception {} occurred while adding disk "
                    "{} to vm {}".format(exp, fullpath, vm.config.name)
                )
                self.rollback_newvm(vapp_uuid, exp_msg)
        else:
            msg = "add_disk() : Can not add disk to VM with disk info {} ".format(
                disk_info
            )
            self.rollback_newvm(vapp_uuid, msg)

    def get_vcenter_content(self):
        """
        Get the vsphere content object
        """
        try:
            vm_vcenter_info = self.get_vm_vcenter_info()
        except Exception as exp:
            self.logger.error(
                "Error occurred while getting vCenter infromationn"
                " for VM : {}".format(exp)
            )

            raise vimconn.VimConnException(message=exp)

        context = None
        if hasattr(ssl, "_create_unverified_context"):
            context = ssl._create_unverified_context()

        vcenter_conect = SmartConnect(
            host=vm_vcenter_info["vm_vcenter_ip"],
            user=vm_vcenter_info["vm_vcenter_user"],
            pwd=vm_vcenter_info["vm_vcenter_password"],
            port=int(vm_vcenter_info["vm_vcenter_port"]),
            sslContext=context,
        )
        atexit.register(Disconnect, vcenter_conect)
        content = vcenter_conect.RetrieveContent()

        return vcenter_conect, content

    def get_vm_moref_id(self, vapp_uuid):
        """
        Get the moref_id of given VM
        """
        try:
            if vapp_uuid:
                vm_details = self.get_vapp_details_rest(
                    vapp_uuid, need_admin_access=True
                )

                if vm_details and "vm_vcenter_info" in vm_details:
                    vm_moref_id = vm_details["vm_vcenter_info"].get("vm_moref_id", None)

            return vm_moref_id
        except Exception as exp:
            self.logger.error(
                "Error occurred while getting VM moref ID " " for VM : {}".format(exp)
            )

            return None

    def get_vapp_template_details(
        self, catalogs=None, image_id=None, template_name=None
    ):
        """
        Method to get vApp template details
            Args :
                catalogs - list of VDC catalogs
                image_id - Catalog ID to find
                template_name : template name in catalog
            Returns:
                parsed_respond : dict of vApp tempalte details
        """
        parsed_response = {}

        vca = self.connect_as_admin()
        if not vca:
            raise vimconn.VimConnConnectionException("Failed to connect vCD")

        try:
            org, _ = self.get_vdc_details()
            catalog = self.get_catalog_obj(image_id, catalogs)
            if catalog:
                items = org.get_catalog_item(catalog.get("name"), catalog.get("name"))
                catalog_items = [items.attrib]

                if len(catalog_items) == 1:
                    headers = {
                        "Accept": "application/*+xml;version=" + API_VERSION,
                        "x-vcloud-authorization": vca._session.headers[
                            "x-vcloud-authorization"
                        ],
                    }
                    response = self.perform_request(
                        req_type="GET",
                        url=catalog_items[0].get("href"),
                        headers=headers,
                    )
                    catalogItem = XmlElementTree.fromstring(response.text)
                    entity = [
                        child
                        for child in catalogItem
                        if child.get("type")
                        == "application/vnd.vmware.vcloud.vAppTemplate+xml"
                    ][0]
                    vapp_tempalte_href = entity.get("href")
                    # get vapp details and parse moref id

                    namespaces = {
                        "vssd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData",
                        "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
                        "vmw": "http://www.vmware.com/schema/ovf",
                        "vm": "http://www.vmware.com/vcloud/v1.5",
                        "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
                        "vmext": "http://www.vmware.com/vcloud/extension/v1.5",
                        "xmlns": "http://www.vmware.com/vcloud/v1.5",
                    }

                    if vca._session:
                        response = self.perform_request(
                            req_type="GET", url=vapp_tempalte_href, headers=headers
                        )

                        if response.status_code != requests.codes.ok:
                            self.logger.debug(
                                "REST API call {} failed. Return status code {}".format(
                                    vapp_tempalte_href, response.status_code
                                )
                            )
                        else:
                            xmlroot_respond = XmlElementTree.fromstring(response.text)
                            children_section = xmlroot_respond.find(
                                "vm:Children/", namespaces
                            )

                            if children_section is not None:
                                vCloud_extension_section = children_section.find(
                                    "xmlns:VCloudExtension", namespaces
                                )

                            if vCloud_extension_section is not None:
                                vm_vcenter_info = {}
                                vim_info = vCloud_extension_section.find(
                                    "vmext:VmVimInfo", namespaces
                                )
                                vmext = vim_info.find(
                                    "vmext:VmVimObjectRef", namespaces
                                )

                                if vmext is not None:
                                    vm_vcenter_info["vm_moref_id"] = vmext.find(
                                        "vmext:MoRef", namespaces
                                    ).text

                                parsed_response["vm_vcenter_info"] = vm_vcenter_info
        except Exception as exp:
            self.logger.info(
                "Error occurred calling rest api for getting vApp details {}".format(
                    exp
                )
            )

        return parsed_response

    def rollback_newvm(self, vapp_uuid, msg, exp_type="Genric"):
        """
        Method to delete vApp
            Args :
                vapp_uuid - vApp UUID
                msg - Error message to be logged
                exp_type : Exception type
            Returns:
                None
        """
        if vapp_uuid:
            self.delete_vminstance(vapp_uuid)
        else:
            msg = "No vApp ID"

        self.logger.error(msg)

        if exp_type == "Genric":
            raise vimconn.VimConnException(msg)
        elif exp_type == "NotFound":
            raise vimconn.VimConnNotFoundException(message=msg)

    def get_sriov_devices(self, host, no_of_vfs):
        """
        Method to get the details of SRIOV devices on given host
         Args:
            host - vSphere host object
            no_of_vfs - number of VFs needed on host

         Returns:
            array of SRIOV devices
        """
        sriovInfo = []

        if host:
            for device in host.config.pciPassthruInfo:
                if isinstance(device, vim.host.SriovInfo) and device.sriovActive:
                    if device.numVirtualFunction >= no_of_vfs:
                        sriovInfo.append(device)
                        break

        return sriovInfo

    def reconfig_portgroup(self, content, dvPort_group_name, config_info={}):
        """
        Method to reconfigure disributed virtual portgroup

           Args:
               dvPort_group_name - name of disributed virtual portgroup
               content - vCenter content object
               config_info - disributed virtual portgroup configuration

           Returns:
               task object
        """
        try:
            dvPort_group = self.get_dvport_group(dvPort_group_name)

            if dvPort_group:
                dv_pg_spec = vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
                dv_pg_spec.configVersion = dvPort_group.config.configVersion
                dv_pg_spec.defaultPortConfig = (
                    vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy()
                )

                if "vlanID" in config_info:
                    dv_pg_spec.defaultPortConfig.vlan = (
                        vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec()
                    )
                    dv_pg_spec.defaultPortConfig.vlan.vlanId = config_info.get("vlanID")

                task = dvPort_group.ReconfigureDVPortgroup_Task(spec=dv_pg_spec)

                return task
            else:
                return None
        except Exception as exp:
            self.logger.error(
                "Error occurred while reconfiguraing disributed virtaul port group {}"
                " : {}".format(dvPort_group_name, exp)
            )

            return None

    def get_dvport_group(self, dvPort_group_name):
        """
        Method to get disributed virtual portgroup

            Args:
                network_name - name of network/portgroup

            Returns:
                portgroup object
        """
        _, content = self.get_vcenter_content()
        dvPort_group = None

        try:
            container = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.dvs.DistributedVirtualPortgroup], True
            )

            for item in container.view:
                if item.key == dvPort_group_name:
                    dvPort_group = item
                    break

            return dvPort_group
        except vmodl.MethodFault as exp:
            self.logger.error(
                "Caught vmodl fault {} for disributed virtual port group {}".format(
                    exp, dvPort_group_name
                )
            )

            return None

    def get_vlanID_from_dvs_portgr(self, dvPort_group_name):
        """
        Method to get disributed virtual portgroup vlanID

           Args:
               network_name - name of network/portgroup

           Returns:
               vlan ID
        """
        vlanId = None

        try:
            dvPort_group = self.get_dvport_group(dvPort_group_name)

            if dvPort_group:
                vlanId = dvPort_group.config.defaultPortConfig.vlan.vlanId
        except vmodl.MethodFault as exp:
            self.logger.error(
                "Caught vmodl fault {} for disributed virtaul port group {}".format(
                    exp, dvPort_group_name
                )
            )

        return vlanId

    def insert_media_to_vm(self, vapp, image_id):
        """
        Method to insert media CD-ROM (ISO image) from catalog to vm.
        vapp - vapp object to get vm id
        Image_id - image id for cdrom to be inerted to vm
        """
        # create connection object
        vca = self.connect()
        try:
            # fetching catalog details
            rest_url = "{}/api/catalog/{}".format(self.url, image_id)

            if vca._session:
                headers = {
                    "Accept": "application/*+xml;version=" + API_VERSION,
                    "x-vcloud-authorization": vca._session.headers[
                        "x-vcloud-authorization"
                    ],
                }
                response = self.perform_request(
                    req_type="GET", url=rest_url, headers=headers
                )

            if response.status_code != 200:
                self.logger.error(
                    "REST call {} failed reason : {}"
                    "status code : {}".format(
                        rest_url, response.text, response.status_code
                    )
                )

                raise vimconn.VimConnException(
                    "insert_media_to_vm(): Failed to get " "catalog details"
                )

            # searching iso name and id
            iso_name, media_id = self.get_media_details(vca, response.text)

            if iso_name and media_id:
                data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                     <ns6:MediaInsertOrEjectParams
                     xmlns="http://www.vmware.com/vcloud/versions" xmlns:ns2="http://schemas.dmtf.org/ovf/envelope/1"
                     xmlns:ns3="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
                     xmlns:ns4="http://schemas.dmtf.org/wbem/wscim/1/common"
                     xmlns:ns5="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
                     xmlns:ns6="http://www.vmware.com/vcloud/v1.5"
                     xmlns:ns7="http://www.vmware.com/schema/ovf"
                     xmlns:ns8="http://schemas.dmtf.org/ovf/environment/1"
                     xmlns:ns9="http://www.vmware.com/vcloud/extension/v1.5">
                     <ns6:Media
                        type="application/vnd.vmware.vcloud.media+xml"
                        name="{}"
                        id="urn:vcloud:media:{}"
                        href="https://{}/api/media/{}"/>
                     </ns6:MediaInsertOrEjectParams>""".format(
                    iso_name, media_id, self.url, media_id
                )

                for vms in vapp.get_all_vms():
                    vm_id = vms.get("id").split(":")[-1]

                    headers["Content-Type"] = (
                        "application/vnd.vmware.vcloud.mediaInsertOrEjectParams+xml"
                    )
                    rest_url = "{}/api/vApp/vm-{}/media/action/insertMedia".format(
                        self.url, vm_id
                    )

                    response = self.perform_request(
                        req_type="POST", url=rest_url, data=data, headers=headers
                    )

                    if response.status_code != 202:
                        error_msg = (
                            "insert_media_to_vm() : Failed to insert CD-ROM to vm. Reason {}. "
                            "Status code {}".format(response.text, response.status_code)
                        )
                        self.logger.error(error_msg)

                        raise vimconn.VimConnException(error_msg)
                    else:
                        task = self.get_task_from_response(response.text)
                        result = self.client.get_task_monitor().wait_for_success(
                            task=task
                        )

                        if result.get("status") == "success":
                            self.logger.info(
                                "insert_media_to_vm(): Sucessfully inserted media ISO"
                                " image to vm {}".format(vm_id)
                            )
        except Exception as exp:
            self.logger.error(
                "insert_media_to_vm() : exception occurred "
                "while inserting media CD-ROM"
            )

            raise vimconn.VimConnException(message=exp)

    def get_media_details(self, vca, content):
        """
        Method to get catalog item details
        vca - connection object
        content - Catalog details
        Return - Media name, media id
        """
        cataloghref_list = []
        try:
            if content:
                vm_list_xmlroot = XmlElementTree.fromstring(content)

                for child in vm_list_xmlroot.iter():
                    if "CatalogItem" in child.tag:
                        cataloghref_list.append(child.attrib.get("href"))

                if cataloghref_list is not None:
                    for href in cataloghref_list:
                        if href:
                            headers = {
                                "Accept": "application/*+xml;version=" + API_VERSION,
                                "x-vcloud-authorization": vca._session.headers[
                                    "x-vcloud-authorization"
                                ],
                            }
                            response = self.perform_request(
                                req_type="GET", url=href, headers=headers
                            )

                            if response.status_code != 200:
                                self.logger.error(
                                    "REST call {} failed reason : {}"
                                    "status code : {}".format(
                                        href, response.text, response.status_code
                                    )
                                )

                                raise vimconn.VimConnException(
                                    "get_media_details : Failed to get "
                                    "catalogitem details"
                                )

                            list_xmlroot = XmlElementTree.fromstring(response.text)

                            for child in list_xmlroot.iter():
                                if "Entity" in child.tag:
                                    if "media" in child.attrib.get("href"):
                                        name = child.attrib.get("name")
                                        media_id = (
                                            child.attrib.get("href").split("/").pop()
                                        )

                                        return name, media_id
                            else:
                                self.logger.debug("Media name and id not found")

                                return False, False
        except Exception as exp:
            self.logger.error(
                "get_media_details : exception occurred " "getting media details"
            )

            raise vimconn.VimConnException(message=exp)

    def retry_rest(self, method, url, add_headers=None, data=None):
        """Method to get Token & retry respective REST request
        Args:
            api - REST API - Can be one of 'GET' or 'PUT' or 'POST'
            url - request url to be used
            add_headers - Additional headers (optional)
            data - Request payload data to be passed in request
        Returns:
            response - Response of request
        """
        response = None

        # Get token
        self.get_token()

        if self.client._session:
            headers = {
                "Accept": "application/*+xml;version=" + API_VERSION,
                "x-vcloud-authorization": self.client._session.headers[
                    "x-vcloud-authorization"
                ],
            }

        if add_headers:
            headers.update(add_headers)

        if method == "GET":
            response = self.perform_request(req_type="GET", url=url, headers=headers)
        elif method == "PUT":
            response = self.perform_request(
                req_type="PUT", url=url, headers=headers, data=data
            )
        elif method == "POST":
            response = self.perform_request(
                req_type="POST", url=url, headers=headers, data=data
            )
        elif method == "DELETE":
            response = self.perform_request(req_type="DELETE", url=url, headers=headers)

        return response

    def get_token(self):
        """Generate a new token if expired

        Returns:
            The return client object that letter can be used to connect to vCloud director as admin for VDC
        """
        self.client = self.connect()

    def get_vdc_details(self):
        """Get VDC details using pyVcloud Lib

        Returns org and vdc object
        """
        vdc = None

        try:
            org = Org(self.client, resource=self.client.get_org())
            vdc = org.get_vdc(self.tenant_name)
        except Exception as e:
            # pyvcloud not giving a specific exception, Refresh nevertheless
            self.logger.debug("Received exception {}, refreshing token ".format(str(e)))

        # Retry once, if failed by refreshing token
        if vdc is None:
            self.get_token()
            org = Org(self.client, resource=self.client.get_org())
            vdc = org.get_vdc(self.tenant_name)

        return org, vdc

    def perform_request(self, req_type, url, headers=None, data=None):
        """Perform the POST/PUT/GET/DELETE request."""
        # Log REST request details
        self.log_request(req_type, url=url, headers=headers, data=data)
        # perform request and return its result

        if req_type == "GET":
            response = requests.get(url=url, headers=headers, verify=False)
        elif req_type == "PUT":
            response = requests.put(url=url, headers=headers, data=data, verify=False)
        elif req_type == "POST":
            response = requests.post(url=url, headers=headers, data=data, verify=False)
        elif req_type == "DELETE":
            response = requests.delete(url=url, headers=headers, verify=False)

        # Log the REST response
        self.log_response(response)

        return response

    def log_request(self, req_type, url=None, headers=None, data=None):
        """Logs REST request details"""

        if req_type is not None:
            self.logger.debug("Request type: {}".format(req_type))

        if url is not None:
            self.logger.debug("Request url: {}".format(url))

        if headers is not None:
            for header in headers:
                self.logger.debug(
                    "Request header: {}: {}".format(header, headers[header])
                )

        if data is not None:
            self.logger.debug("Request data: {}".format(data))

    def log_response(self, response):
        """Logs REST response details"""

        self.logger.debug("Response status code: {} ".format(response.status_code))

    def get_task_from_response(self, content):
        """
        content - API response.text(response.text)
        return task object
        """
        xmlroot = XmlElementTree.fromstring(content)

        if xmlroot.tag.split("}")[1] == "Task":
            return xmlroot
        else:
            for ele in xmlroot:
                if ele.tag.split("}")[1] == "Tasks":
                    task = ele[0]
                    break

            return task

    def power_on_vapp(self, vapp_id, vapp_name):
        """
        vapp_id - vApp uuid
        vapp_name - vAapp name
        return - Task object
        """
        headers = {
            "Accept": "application/*+xml;version=" + API_VERSION,
            "x-vcloud-authorization": self.client._session.headers[
                "x-vcloud-authorization"
            ],
        }

        poweron_href = "{}/api/vApp/vapp-{}/power/action/powerOn".format(
            self.url, vapp_id
        )
        response = self.perform_request(
            req_type="POST", url=poweron_href, headers=headers
        )

        if response.status_code != 202:
            self.logger.error(
                "REST call {} failed reason : {}"
                "status code : {} ".format(
                    poweron_href, response.text, response.status_code
                )
            )

            raise vimconn.VimConnException(
                "power_on_vapp() : Failed to power on " "vApp {}".format(vapp_name)
            )
        else:
            poweron_task = self.get_task_from_response(response.text)

            return poweron_task

    def migrate_instance(self, vm_id, compute_host=None):
        """
        Migrate a vdu
        param:
            vm_id: ID of an instance
            compute_host: Host to migrate the vdu to
        """
        # TODO: Add support for migration
        raise vimconn.VimConnNotImplemented("Should have implemented this")

    def resize_instance(self, vm_id, flavor_id=None):
        """
        resize a vdu
        param:
            vm_id: ID of an instance
            flavor_id: flavor_id to resize the vdu to
        """
        # TODO: Add support for resize
        raise vimconn.VimConnNotImplemented("Should have implemented this")
