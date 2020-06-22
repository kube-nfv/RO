# Copyright 2020 ETSI
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import json

from osm_ro.wim.sdnconn import SdnConnectorError
from osm_rosdn_juniper_contrail.rest_lib import ContrailHttp
from osm_rosdn_juniper_contrail.rest_lib import NotFound
from osm_rosdn_juniper_contrail.rest_lib import DuplicateFound
from osm_rosdn_juniper_contrail.rest_lib import HttpException

class UnderlayApi:
    """ Class with CRUD operations for the underlay API """

    def __init__(self, url, config=None, user=None, password=None, logger=None):

        self.logger = logger or logging.getLogger("openmano.sdnconn.junipercontrail.sdnapi")
        self.controller_url = url

        if not url:
            raise SdnConnectorError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url

        self.auth_url = None
        self.project = None
        self.domain = None
        self.asn = None
        self.fabric = None
        if config:
            self.auth_url = config.get("auth_url")
            self.project = config.get("project")
            self.domain = config.get("domain")
            self.asn = config.get("asn")
            self.fabric = config.get("fabric")

        # Init http headers for all requests
        self.http_header = {'Content-Type': 'application/json'}

        if user:
            self.user = user
        if password:
            self.password = password

        self.logger.debug("Config parameters for the underlay controller: auth_url: {}, project: {},"
                          " domain: {}, user: {}, password: {}".format(self.auth_url, self.project,
                            self.domain, self.user, self.password))

        auth_dict = {}
        auth_dict['auth'] = {}
        auth_dict['auth']['scope'] = {}
        auth_dict['auth']['scope']['project'] = {}
        auth_dict['auth']['scope']['project']['domain'] = {}
        auth_dict['auth']['scope']['project']['domain']["id"] = self.domain
        auth_dict['auth']['scope']['project']['name'] = self.project
        auth_dict['auth']['identity'] = {}
        auth_dict['auth']['identity']['methods'] = ['password']
        auth_dict['auth']['identity']['password'] = {}
        auth_dict['auth']['identity']['password']['user'] = {}
        auth_dict['auth']['identity']['password']['user']['name'] = self.user
        auth_dict['auth']['identity']['password']['user']['password'] = self.password
        auth_dict['auth']['identity']['password']['user']['domain'] = {}
        auth_dict['auth']['identity']['password']['user']['domain']['id'] = self.domain
        self.auth_dict = auth_dict

        # Init http lib
        auth_info = {"auth_url": self.auth_url, "auth_dict": auth_dict}
        self.http = ContrailHttp(auth_info, self.logger)

    def check_auth(self):
        response = self.http.get_cmd(url=self.auth_url, headers=self.http_header)
        return response

    # Helper methods for CRUD operations
    def get_all_by_type(self, controller_url, type):
        endpoint = controller_url + type
        response = self.http.get_cmd(url=endpoint, headers=self.http_header)
        return response.get(type)

    def get_by_uuid(self, type, uuid):
        try:
            endpoint = self.controller_url + type + "/{}".format(uuid)
            response = self.http.get_cmd(url=endpoint, headers=self.http_header)
            return response.get(type)
        except NotFound:
            return None

    def delete_by_uuid(self, controller_url, type, uuid):
        endpoint = controller_url + type + "/{}".format(uuid)
        self.http.delete_cmd(url=endpoint, headers=self.http_header)

    def get_uuid_from_fqname(self, type, fq_name):
        """
        Obtain uuid from fqname
        Returns: If resource not found returns None
        In case of error raises an Exception
        """
        payload = {
            "type": type,
            "fq_name": fq_name
        }
        try:
            endpoint = self.controller_url + "fqname-to-id"
            resp = self.http.post_cmd(url=endpoint,
                                      headers=self.http_header,
                                      post_fields_dict=payload)
            return json.loads(resp).get("uuid")
        except NotFound:
            return None

    def get_by_fq_name(self, type, fq_name):
        # Obtain uuid by fqdn and then get data by uuid
        uuid = self.get_uuid_from_fqname(type, fq_name)
        if uuid:
            return self.get_by_uuid(type, uuid)
        else:
            return None

    def delete_ref(self, type, uuid, ref_type, ref_uuid, ref_fq_name):
        payload = {
            "type": type,
            "uuid": uuid,
            "ref-type": ref_type,
            "ref-fq-name": ref_fq_name,
            "operation": "DELETE"
        }
        endpoint = self.controller_url + "ref-update"
        resp = self.http.post_cmd(url=endpoint,
                                headers=self.http_header,
                                post_fields_dict=payload)
        return resp

    # Aux methods to avoid code duplication of name conventions
    def get_vpg_name(self, switch_id, switch_port):
        return "{}_{}".format(switch_id, switch_port).replace(":","_")

    def get_vmi_name(self, switch_id, switch_port, vlan):
        return "{}_{}-{}".format(switch_id, switch_port, vlan).replace(":","_")

    # Virtual network operations

    def create_virtual_network(self, name, vni):
        self.logger.debug("create vname, name: {}, vni: {}".format(name, vni))
        routetarget = '{}:{}'.format(self.asn, vni)
        vnet_dict = {
            "virtual-network": {
                "virtual_network_properties": {
                    "vxlan_network_identifier": vni,
                },
                "parent_type": "project",
                "fq_name": [
                    self.domain,
                    self.project,
                    name
                ],
                "route_target_list": {
                    "route_target": [
                        "target:" + routetarget
                    ]
                }
            }
        }
        endpoint = self.controller_url + 'virtual-networks'
        resp = self.http.post_cmd(url=endpoint,
                                  headers=self.http_header,
                                  post_fields_dict=vnet_dict)
        if not resp:
            raise SdnConnectorError('Error creating virtual network: empty response')
        vnet_info = json.loads(resp)
        self.logger.debug("created vnet, vnet_info: {}".format(vnet_info))
        return vnet_info.get("virtual-network").get('uuid'), vnet_info.get("virtual-network")

    def get_virtual_networks(self):
        return self.get_all_by_type('virtual-networks')

    def get_virtual_network(self, network_id):
        return self.get_by_uuid('virtual-network', network_id)

    def delete_virtual_network(self, network_id):
        self.logger.debug("delete vnet uuid: {}".format(network_id))
        self.delete_by_uuid(self.controller_url, 'virtual-network', network_id)
        self.logger.debug("deleted vnet uuid: {}".format(network_id))

    # Vpg operations

    def create_vpg(self, switch_id, switch_port):
        self.logger.debug("create vpg, switch_id: {}, switch_port: {}".format(switch_id, switch_port))
        vpg_name = self.get_vpg_name(switch_id, switch_port)
        vpg_dict = {
            "virtual-port-group": {
                "parent_type": "fabric",
                "fq_name": [
                    "default-global-system-config",
                    self.fabric,
                    vpg_name
                ]
            }
        }
        endpoint = self.controller_url + 'virtual-port-groups'
        resp = self.http.post_cmd(url=endpoint,
                                  headers=self.http_header,
                                  post_fields_dict=vpg_dict)
        if not resp:
            raise SdnConnectorError('Error creating virtual port group: empty response')
        vpg_info = json.loads(resp)
        self.logger.debug("created vpg, vpg_info: {}".format(vpg_info))
        return vpg_info.get("virtual-port-group").get('uuid'), vpg_info.get("virtual-port-group")

    def get_vpgs(self):
        return self.get_all_by_type(self.controller_url, 'virtual-port-groups')

    def get_vpg(self, vpg_id):
        return self.get_by_uuid(self.controller_url, "virtual-port-group", vpg_id)

    def get_vpg_by_name(self, vpg_name):
        fq_name = [
                    "default-global-system-config",
                    self.fabric,
                    vpg_name
                ]
        return self.get_by_fq_name("virtual-port-group", fq_name)

    def delete_vpg(self, vpg_id):
        self.logger.debug("delete vpg, uuid: {}".format(vpg_id))
        self.delete_by_uuid(self.controller_url, 'virtual-port-group', vpg_id)
        self.logger.debug("deleted vpg, uuid: {}".format(vpg_id))

    def create_vmi(self, switch_id, switch_port, network, vlan):
        self.logger.debug("create vmi, switch_id: {}, switch_port: {}, network: {}, vlan: {}".format(
            switch_id, switch_port, network, vlan))
        vmi_name = self.get_vmi_name(switch_id, switch_port, vlan)
        vpg_name = self.get_vpg_name(switch_id, switch_port)
        profile_dict = {
            "local_link_information": [
                {
                    "port_id": switch_port.replace(":","_"),
                    "switch_id": switch_port.replace(":","_"),
                    "switch_info": switch_id,
                    "fabric": self.fabric
                }
            ]

        }
        vmi_dict = {
            "virtual-machine-interface": {
                "parent_type": "project",
                "fq_name": [
                    self.domain,
                    self.project,
                    vmi_name
                ],
                "virtual_network_refs": [
                    {
                        "to": [
                            self.domain,
                            self.project,
                            network
                        ]
                    }
                ],
                "virtual_machine_interface_properties": {
                    "sub_interface_vlan_tag": vlan
                },
                "virtual_machine_interface_bindings": {
                    "key_value_pair": [
                        {
                            "key": "vnic_type",
                            "value": "baremetal"
                        },
                        {
                            "key": "vif_type",
                            "value": "vrouter"
                        },
                        {
                            "key": "vpg",
                            "value": vpg_name
                        },
                        {
                            "key": "profile",
                            "value": json.dumps(profile_dict)
                        }
                    ]
                }
            }
        }
        endpoint = self.controller_url + 'virtual-machine-interfaces'
        self.logger.debug("vmi_dict: {}".format(vmi_dict))
        resp = self.http.post_cmd(url=endpoint,
                                  headers=self.http_header,
                                  post_fields_dict=vmi_dict)
        if not resp:
            raise SdnConnectorError('Error creating vmi: empty response')
        vmi_info = json.loads(resp)
        self.logger.debug("created vmi, info: {}".format(vmi_info))
        return vmi_info.get("virtual-machine-interface").get('uuid'), vmi_info.get("virtual-machine-interface")

    def get_vmi(self, vmi_uuid):
        return self.get_by_uuid(self.controller_url, 'virtual-machine-interface', vmi_uuid)

    def delete_vmi(self, uuid):
        self.logger.debug("delete vmi uuid: {}".format(uuid))
        self.delete_by_uuid(self.controller_url, 'virtual-machine-interface', uuid)
        self.logger.debug("deleted vmi: {}".format(uuid))

    def unref_vmi_vpg(self, vpg_id, vmi_id, vmi_fq_name):
        self.delete_ref("virtual-port-group", vpg_id, "virtual-machine-interface", vmi_id, vmi_fq_name)

