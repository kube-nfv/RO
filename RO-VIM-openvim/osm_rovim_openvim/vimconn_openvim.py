# -*- coding: utf-8 -*-

##
# Copyright 2015 Telefonica Investigacion y Desarrollo, S.A.U.
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
# contact with: nfvlabs@tid.es
##

"""
vimconnector implements all the methods to interact with openvim using the openvim API.
"""
__author__ = "Alfonso Tierno, Gerardo Garcia"
__date__ = "$26-aug-2014 11:09:29$"

import json
import logging
import math
from urllib.parse import quote

from jsonschema import exceptions as js_e, validate as js_v
from osm_ro.openmano_schemas import (
    description_schema,
    id_schema,
    integer0_schema,
    name_schema,
    nameshort_schema,
    vlan1000_schema,
)
from osm_ro_plugin import vimconn
import requests
import yaml

"""contain the openvim virtual machine status to openmano status"""
vmStatus2manoFormat = {
    "ACTIVE": "ACTIVE",
    "PAUSED": "PAUSED",
    "SUSPENDED": "SUSPENDED",
    "INACTIVE": "INACTIVE",
    "CREATING": "BUILD",
    "ERROR": "ERROR",
    "DELETED": "DELETED",
}
netStatus2manoFormat = {
    "ACTIVE": "ACTIVE",
    "INACTIVE": "INACTIVE",
    "BUILD": "BUILD",
    "ERROR": "ERROR",
    "DELETED": "DELETED",
    "DOWN": "DOWN",
}


host_schema = {
    "type": "object",
    "properties": {
        "id": id_schema,
        "name": name_schema,
    },
    "required": ["id"],
}
image_schema = {
    "type": "object",
    "properties": {
        "id": id_schema,
        "name": name_schema,
    },
    "required": ["id", "name"],
}
server_schema = {
    "type": "object",
    "properties": {
        "id": id_schema,
        "name": name_schema,
    },
    "required": ["id", "name"],
}
new_host_response_schema = {
    "title": "host response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {"host": host_schema},
    "required": ["host"],
    "additionalProperties": False,
}

get_images_response_schema = {
    "title": "openvim images response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "images": {
            "type": "array",
            "items": image_schema,
        }
    },
    "required": ["images"],
    "additionalProperties": False,
}

get_hosts_response_schema = {
    "title": "openvim hosts response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "hosts": {
            "type": "array",
            "items": host_schema,
        }
    },
    "required": ["hosts"],
    "additionalProperties": False,
}

get_host_detail_response_schema = (
    new_host_response_schema  # TODO: Content is not parsed yet
)

get_server_response_schema = {
    "title": "openvim server response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "servers": {
            "type": "array",
            "items": server_schema,
        }
    },
    "required": ["servers"],
    "additionalProperties": False,
}

new_tenant_response_schema = {
    "title": "tenant response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "tenant": {
            "type": "object",
            "properties": {
                "id": id_schema,
                "name": nameshort_schema,
                "description": description_schema,
                "enabled": {"type": "boolean"},
            },
            "required": ["id"],
        }
    },
    "required": ["tenant"],
    "additionalProperties": False,
}

new_network_response_schema = {
    "title": "network response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "network": {
            "type": "object",
            "properties": {
                "id": id_schema,
                "name": name_schema,
                "type": {
                    "type": "string",
                    "enum": ["bridge_man", "bridge_data", "data", "ptp"],
                },
                "shared": {"type": "boolean"},
                "tenant_id": id_schema,
                "admin_state_up": {"type": "boolean"},
                "vlan": vlan1000_schema,
            },
            "required": ["id"],
        }
    },
    "required": ["network"],
    "additionalProperties": False,
}


# get_network_response_schema = {
#     "title":"get network response information schema",
#     "$schema": "http://json-schema.org/draft-04/schema#",
#     "type":"object",
#     "properties":{
#         "network":{
#             "type":"object",
#             "properties":{
#                 "id":id_schema,
#                 "name":name_schema,
#                 "type":{"type":"string", "enum":["bridge_man","bridge_data","data", "ptp"]},
#                 "shared":{"type":"boolean"},
#                 "tenant_id":id_schema,
#                 "admin_state_up":{"type":"boolean"},
#                 "vlan":vlan1000_schema
#             },
#             "required": ["id"]
#         }
#     },
#     "required": ["network"],
#     "additionalProperties": False
# }


new_port_response_schema = {
    "title": "port response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "port": {
            "type": "object",
            "properties": {
                "id": id_schema,
            },
            "required": ["id"],
        }
    },
    "required": ["port"],
    "additionalProperties": False,
}

get_flavor_response_schema = {
    "title": "openvim flavors response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "flavor": {
            "type": "object",
            "properties": {
                "id": id_schema,
                "name": name_schema,
                "extended": {"type": "object"},
            },
            "required": ["id", "name"],
        }
    },
    "required": ["flavor"],
    "additionalProperties": False,
}

new_flavor_response_schema = {
    "title": "flavor response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "flavor": {
            "type": "object",
            "properties": {
                "id": id_schema,
            },
            "required": ["id"],
        }
    },
    "required": ["flavor"],
    "additionalProperties": False,
}

get_image_response_schema = {
    "title": "openvim images response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "image": {
            "type": "object",
            "properties": {
                "id": id_schema,
                "name": name_schema,
            },
            "required": ["id", "name"],
        }
    },
    "required": ["flavor"],
    "additionalProperties": False,
}
new_image_response_schema = {
    "title": "image response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "image": {
            "type": "object",
            "properties": {
                "id": id_schema,
            },
            "required": ["id"],
        }
    },
    "required": ["image"],
    "additionalProperties": False,
}

new_vminstance_response_schema = {
    "title": "server response information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "server": {
            "type": "object",
            "properties": {
                "id": id_schema,
            },
            "required": ["id"],
        }
    },
    "required": ["server"],
    "additionalProperties": False,
}

get_processor_rankings_response_schema = {
    "title": "processor rankings information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "rankings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"model": description_schema, "value": integer0_schema},
                "additionalProperties": False,
                "required": ["model", "value"],
            },
        },
        "additionalProperties": False,
        "required": ["rankings"],
    },
}


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
        log_level="DEBUG",
        config={},
        persistent_info={},
    ):
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
        self.tenant = None
        self.headers_req = {"content-type": "application/json"}
        self.logger = logging.getLogger("ro.vim.openvim")
        self.persistent_info = persistent_info
        if tenant_id:
            self.tenant = tenant_id

    def __setitem__(self, index, value):
        """Set individuals parameters
        Throw TypeError, KeyError
        """
        if index == "tenant_id":
            self.tenant = value
        elif index == "tenant_name":
            self.tenant = None
        vimconn.VimConnector.__setitem__(self, index, value)

    def _get_my_tenant(self):
        """Obtain uuid of my tenant from name"""
        if self.tenant:
            return self.tenant

        url = self.url + "/tenants?name=" + quote(self.tenant_name)
        self.logger.info("Getting VIM tenant_id GET %s", url)
        vim_response = requests.get(url, headers=self.headers_req)
        self._check_http_request_response(vim_response)
        try:
            tenant_list = vim_response.json()["tenants"]
            if len(tenant_list) == 0:
                raise vimconn.VimConnNotFoundException(
                    "No tenant found for name '{}'".format(self.tenant_name)
                )
            elif len(tenant_list) > 1:
                raise vimconn.VimConnConflictException(
                    "More that one tenant found for name '{}'".format(self.tenant_name)
                )
            self.tenant = tenant_list[0]["id"]
            return self.tenant
        except Exception as e:
            raise vimconn.VimConnUnexpectedResponse(
                "Get VIM tenant {} '{}'".format(type(e).__name__, str(e))
            )

    def _format_jsonerror(self, http_response):
        # DEPRECATED, to delete in the future
        try:
            data = http_response.json()
            return data["error"]["description"]
        except Exception:
            return http_response.text

    def _format_in(self, http_response, schema):
        # DEPRECATED, to delete in the future
        try:
            client_data = http_response.json()
            js_v(client_data, schema)
            # print "Input data: ", str(client_data)
            return True, client_data
        except js_e.ValidationError as exc:
            print(
                "validate_in error, jsonschema exception ", exc.message, "at", exc.path
            )
            return False, (
                "validate_in error, jsonschema exception ",
                exc.message,
                "at",
                exc.path,
            )

    def _remove_extra_items(self, data, schema):
        deleted = []
        if type(data) is tuple or type(data) is list:
            for d in data:
                a = self._remove_extra_items(d, schema["items"])
                if a is not None:
                    deleted.append(a)
        elif type(data) is dict:
            to_delete = []
            for k in data.keys():
                if "properties" not in schema or k not in schema["properties"].keys():
                    to_delete.append(k)
                    deleted.append(k)
                else:
                    a = self._remove_extra_items(data[k], schema["properties"][k])
                    if a is not None:
                        deleted.append({k: a})
            for k in to_delete:
                del data[k]
        if len(deleted) == 0:
            return None
        elif len(deleted) == 1:
            return deleted[0]
        else:
            return deleted

    def _format_request_exception(self, request_exception):
        """Transform a request exception into a vimconn exception"""
        if isinstance(request_exception, js_e.ValidationError):
            raise vimconn.VimConnUnexpectedResponse(
                "jsonschema exception '{}' at '{}'".format(
                    request_exception.message, request_exception.path
                )
            )
        elif isinstance(request_exception, requests.exceptions.HTTPError):
            raise vimconn.VimConnUnexpectedResponse(
                type(request_exception).__name__ + ": " + str(request_exception)
            )
        else:
            raise vimconn.VimConnConnectionException(
                type(request_exception).__name__ + ": " + str(request_exception)
            )

    def _check_http_request_response(self, request_response):
        """Raise a vimconn exception if the response is not Ok"""
        if request_response.status_code >= 200 and request_response.status_code < 300:
            return
        if request_response.status_code == vimconn.HTTP_Unauthorized:
            raise vimconn.VimConnAuthException(request_response.text)
        elif request_response.status_code == vimconn.HTTP_Not_Found:
            raise vimconn.VimConnNotFoundException(request_response.text)
        elif request_response.status_code == vimconn.HTTP_Conflict:
            raise vimconn.VimConnConflictException(request_response.text)
        else:
            raise vimconn.VimConnUnexpectedResponse(
                "VIM HTTP_response {}, {}".format(
                    request_response.status_code, str(request_response.text)
                )
            )

    def new_tenant(self, tenant_name, tenant_description):
        """Adds a new tenant to VIM with this name and description, returns the tenant identifier"""
        # print "VIMConnector: Adding a new tenant to VIM"
        payload_dict = {
            "tenant": {
                "name": tenant_name,
                "description": tenant_description,
                "enabled": True,
            }
        }
        payload_req = json.dumps(payload_dict)
        try:
            url = self.url_admin + "/tenants"
            self.logger.info("Adding a new tenant %s", url)
            vim_response = requests.post(
                url, headers=self.headers_req, data=payload_req
            )
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, new_tenant_response_schema)
            # r = self._remove_extra_items(response, new_tenant_response_schema)
            # if r is not None:
            #    self.logger.warn("Warning: remove extra items %s", str(r))
            tenant_id = response["tenant"]["id"]
            return tenant_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def delete_tenant(self, tenant_id):
        """Delete a tenant from VIM. Returns the old tenant identifier"""
        try:
            url = self.url_admin + "/tenants/" + tenant_id
            self.logger.info("Delete a tenant DELETE %s", url)
            vim_response = requests.delete(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            return tenant_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_tenant_list(self, filter_dict={}):
        """Obtain tenants of VIM
        filter_dict can contain the following keys:
            name: filter by tenant name
            id: filter by tenant uuid/id
            <other VIM specific>
        Returns the tenant list of dictionaries: [{'name':'<name>, 'id':'<id>, ...}, ...]
        """
        filterquery = []
        filterquery_text = ""
        for k, v in filter_dict.items():
            filterquery.append(str(k) + "=" + str(v))
        if len(filterquery) > 0:
            filterquery_text = "?" + "&".join(filterquery)
        try:
            url = self.url + "/tenants" + filterquery_text
            self.logger.info("get_tenant_list GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            return vim_response.json()["tenants"]
        except requests.exceptions.RequestException as e:
            self._format_request_exception(e)

    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):  # , **vim_specific):
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
        try:
            vlan = None
            if provider_network_profile:
                vlan = provider_network_profile.get("segmentation-id")
            created_items = {}
            self._get_my_tenant()
            if net_type == "bridge":
                net_type = "bridge_data"
            payload_req = {
                "name": net_name,
                "type": net_type,
                "tenant_id": self.tenant,
                "shared": shared,
            }
            if vlan:
                payload_req["provider:vlan"] = vlan
            # payload_req.update(vim_specific)
            url = self.url + "/networks"
            self.logger.info(
                "Adding a new network POST: %s  DATA: %s", url, str(payload_req)
            )
            vim_response = requests.post(
                url, headers=self.headers_req, data=json.dumps({"network": payload_req})
            )
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, new_network_response_schema)
            # r = self._remove_extra_items(response, new_network_response_schema)
            # if r is not None:
            #    self.logger.warn("Warning: remove extra items %s", str(r))
            network_id = response["network"]["id"]
            return network_id, created_items
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_network_list(self, filter_dict={}):
        """Obtain tenant networks of VIM
        Filter_dict can be:
            name: network name
            id: network uuid
            public: boolean
            tenant_id: tenant
            admin_state_up: boolean
            status: 'ACTIVE'
        Returns the network list of dictionaries
        """
        try:
            if "tenant_id" not in filter_dict:
                filter_dict["tenant_id"] = self._get_my_tenant()
            elif not filter_dict["tenant_id"]:
                del filter_dict["tenant_id"]
            filterquery = []
            filterquery_text = ""
            for k, v in filter_dict.items():
                filterquery.append(str(k) + "=" + str(v))
            if len(filterquery) > 0:
                filterquery_text = "?" + "&".join(filterquery)
            url = self.url + "/networks" + filterquery_text
            self.logger.info("Getting network list GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            return response["networks"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_network(self, net_id):
        """Obtain network details of network id"""
        try:
            url = self.url + "/networks/" + net_id
            self.logger.info("Getting network GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            return response["network"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def delete_network(self, net_id, created_items=None):
        """
        Removes a tenant network from VIM and its associated elements
        :param net_id: VIM identifier of the network, provided by method new_network
        :param created_items: dictionary with extra items to be deleted. provided by method new_network
        Returns the network identifier or raises an exception upon error or when network is not found
        """
        try:
            self._get_my_tenant()
            url = self.url + "/networks/" + net_id
            self.logger.info("Deleting VIM network DELETE %s", url)
            vim_response = requests.delete(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            # self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            return net_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_flavor(self, flavor_id):
        """Obtain flavor details from the  VIM"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/flavors/" + flavor_id
            self.logger.info("Getting flavor GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, get_flavor_response_schema)
            r = self._remove_extra_items(response, get_flavor_response_schema)
            if r is not None:
                self.logger.warn("Warning: remove extra items %s", str(r))
            return response["flavor"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def new_flavor(self, flavor_data):
        """Adds a tenant flavor to VIM"""
        """Returns the flavor identifier"""
        try:
            new_flavor_dict = flavor_data.copy()
            for device in new_flavor_dict.get("extended", {}).get("devices", ()):
                if "image name" in device:
                    del device["image name"]
                if "name" in device:
                    del device["name"]
            numas = new_flavor_dict.get("extended", {}).get("numas")
            if numas:
                numa = numas[0]
                # translate memory, cpus to EPA
                if (
                    "cores" not in numa
                    and "threads" not in numa
                    and "paired-threads" not in numa
                ):
                    numa["paired-threads"] = new_flavor_dict["vcpus"]
                if "memory" not in numa:
                    numa["memory"] = int(math.ceil(new_flavor_dict["ram"] / 1024.0))
                for iface in numa.get("interfaces", ()):
                    if not iface.get("bandwidth"):
                        iface["bandwidth"] = "1 Mbps"

            new_flavor_dict["name"] = flavor_data["name"][:64]
            self._get_my_tenant()
            payload_req = json.dumps({"flavor": new_flavor_dict})
            url = self.url + "/" + self.tenant + "/flavors"
            self.logger.info("Adding a new VIM flavor POST %s", url)
            vim_response = requests.post(
                url, headers=self.headers_req, data=payload_req
            )
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, new_flavor_response_schema)
            r = self._remove_extra_items(response, new_flavor_response_schema)
            if r is not None:
                self.logger.warn("Warning: remove extra items %s", str(r))
            flavor_id = response["flavor"]["id"]
            return flavor_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def delete_flavor(self, flavor_id):
        """Deletes a tenant flavor from VIM"""
        """Returns the old flavor_id"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/flavors/" + flavor_id
            self.logger.info("Deleting VIM flavor DELETE %s", url)
            vim_response = requests.delete(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            # self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            return flavor_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_image(self, image_id):
        """Obtain image details from the  VIM"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/images/" + image_id
            self.logger.info("Getting image GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, get_image_response_schema)
            r = self._remove_extra_items(response, get_image_response_schema)
            if r is not None:
                self.logger.warn("Warning: remove extra items %s", str(r))
            return response["image"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def new_image(self, image_dict):
        """Adds a tenant image to VIM, returns image_id"""
        try:
            self._get_my_tenant()
            new_image_dict = {"name": image_dict["name"][:64]}
            if image_dict.get("description"):
                new_image_dict["description"] = image_dict["description"]
            if image_dict.get("metadata"):
                new_image_dict["metadata"] = yaml.load(
                    image_dict["metadata"], Loader=yaml.SafeLoader
                )
            if image_dict.get("location"):
                new_image_dict["path"] = image_dict["location"]
            payload_req = json.dumps({"image": new_image_dict})
            url = self.url + "/" + self.tenant + "/images"
            self.logger.info("Adding a new VIM image POST %s", url)
            vim_response = requests.post(
                url, headers=self.headers_req, data=payload_req
            )
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, new_image_response_schema)
            r = self._remove_extra_items(response, new_image_response_schema)
            if r is not None:
                self.logger.warn("Warning: remove extra items %s", str(r))
            image_id = response["image"]["id"]
            return image_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def delete_image(self, image_id):
        """Deletes a tenant image from VIM"""
        """Returns the deleted image_id"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/images/" + image_id
            self.logger.info("Deleting VIM image DELETE %s", url)
            vim_response = requests.delete(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            # self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            return image_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_image_id_from_path(self, path):
        """Get the image id from image path in the VIM database. Returns the image_id"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/images?path=" + quote(path)
            self.logger.info("Getting images GET %s", url)
            vim_response = requests.get(url)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, get_images_response_schema)
            # r = self._remove_extra_items(response, get_images_response_schema)
            # if r is not None:
            #    self.logger.warn("Warning: remove extra items %s", str(r))
            if len(response["images"]) == 0:
                raise vimconn.VimConnNotFoundException(
                    "Image not found at VIM with path '{}'".format(path)
                )
            elif len(response["images"]) > 1:
                raise vimconn.VimConnConflictException(
                    "More than one image found at VIM with path '{}'".format(path)
                )
            return response["images"][0]["id"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

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
            self._get_my_tenant()
            filterquery = []
            filterquery_text = ""
            for k, v in filter_dict.items():
                filterquery.append(str(k) + "=" + str(v))
            if len(filterquery) > 0:
                filterquery_text = "?" + "&".join(filterquery)
            url = self.url + "/" + self.tenant + "/images" + filterquery_text
            self.logger.info("Getting image list GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            return response["images"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

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
        """Adds a VM instance to VIM
        Params:
            start: indicates if VM must start or boot in pause mode. Ignored
            image_id,flavor_id: image and flavor uuid
            net_list: list of interfaces, each one is a dictionary with:
                name:
                net_id: network uuid to connect
                vpci: virtual vcpi to assign
                model: interface model, virtio, e1000, ...
                mac_address:
                use: 'data', 'bridge',  'mgmt'
                type: 'virtual', 'PCI-PASSTHROUGH'('PF'), 'SR-IOV'('VF'), 'VFnotShared'
                vim_id: filled/added by this function
                #TODO ip, security groups
        Returns a tuple with the instance identifier and created_items or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_vminstance and action_vminstance. Can be used to store created ports, volumes, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        self.logger.debug(
            "new_vminstance input: image='%s' flavor='%s' nics='%s'",
            image_id,
            flavor_id,
            str(net_list),
        )
        try:
            self._get_my_tenant()
            #            net_list = []
            #            for k,v in net_dict.items():
            #                print k,v
            #                net_list.append('{"name":"' + k + '", "uuid":"' + v + '"}')
            #            net_list_string = ', '.join(net_list)
            virtio_net_list = []
            for net in net_list:
                if not net.get("net_id"):
                    continue
                net_dict = {"uuid": net["net_id"]}
                if net.get("type"):
                    if net["type"] == "SR-IOV":
                        net_dict["type"] = "VF"
                    elif net["type"] == "PCI-PASSTHROUGH":
                        net_dict["type"] = "PF"
                    else:
                        net_dict["type"] = net["type"]
                if net.get("name"):
                    net_dict["name"] = net["name"]
                if net.get("vpci"):
                    net_dict["vpci"] = net["vpci"]
                if net.get("model"):
                    if net["model"] == "VIRTIO" or net["model"] == "paravirt":
                        net_dict["model"] = "virtio"
                    else:
                        net_dict["model"] = net["model"]
                if net.get("mac_address"):
                    net_dict["mac_address"] = net["mac_address"]
                if net.get("ip_address"):
                    net_dict["ip_address"] = net["ip_address"]
                virtio_net_list.append(net_dict)
            payload_dict = {
                "name": name[:64],
                "description": description,
                "imageRef": image_id,
                "flavorRef": flavor_id,
                "networks": virtio_net_list,
            }
            if start is not None:
                payload_dict["start"] = start
            payload_req = json.dumps({"server": payload_dict})
            url = self.url + "/" + self.tenant + "/servers"
            self.logger.info("Adding a new vm POST %s DATA %s", url, payload_req)
            vim_response = requests.post(
                url, headers=self.headers_req, data=payload_req
            )
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, new_vminstance_response_schema)
            # r = self._remove_extra_items(response, new_vminstance_response_schema)
            # if r is not None:
            #    self.logger.warn("Warning: remove extra items %s", str(r))
            vminstance_id = response["server"]["id"]

            # connect data plane interfaces to network
            for net in net_list:
                if net["type"] == "virtual":
                    if not net.get("net_id"):
                        continue
                    for iface in response["server"]["networks"]:
                        if "name" in net:
                            if net["name"] == iface["name"]:
                                net["vim_id"] = iface["iface_id"]
                                break
                        elif "net_id" in net:
                            if net["net_id"] == iface["net_id"]:
                                net["vim_id"] = iface["iface_id"]
                                break
                else:  # dataplane
                    for numa in response["server"].get("extended", {}).get("numas", ()):
                        for iface in numa.get("interfaces", ()):
                            if net["name"] == iface["name"]:
                                net["vim_id"] = iface["iface_id"]
                                # Code bellow is not needed, current openvim connect dataplane interfaces
                                # if net.get("net_id"):
                                # connect dataplane interface
                                #    result, port_id = self.connect_port_network(iface['iface_id'], net["net_id"])
                                #    if result < 0:
                                #        error_text = "Error attaching port %s to network %s: %s." % (iface['iface_id']
                                #        , net["net_id"], port_id)
                                #        print "new_vminstance: " + error_text
                                #        self.delete_vminstance(vminstance_id)
                                #        return result, error_text
                                break

            return vminstance_id, None
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def get_vminstance(self, vm_id):
        """Returns the VM instance information from VIM"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/servers/" + vm_id
            self.logger.info("Getting vm GET %s", url)
            vim_response = requests.get(url, headers=self.headers_req)
            vim_response = requests.get(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            response = vim_response.json()
            js_v(response, new_vminstance_response_schema)
            # r = self._remove_extra_items(response, new_vminstance_response_schema)
            # if r is not None:
            #    self.logger.warn("Warning: remove extra items %s", str(r))
            return response["server"]
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def delete_vminstance(self, vm_id, created_items=None, volumes_to_hold=None):
        """Removes a VM instance from VIM, returns the deleted vm_id"""
        try:
            self._get_my_tenant()
            url = self.url + "/" + self.tenant + "/servers/" + vm_id
            self.logger.info("Deleting VIM vm DELETE %s", url)
            vim_response = requests.delete(url, headers=self.headers_req)
            self._check_http_request_response(vim_response)
            # self.logger.debug(vim_response.text)
            # print json.dumps(vim_response.json(), indent=4)
            return vm_id
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

    def refresh_vms_status(self, vm_list):
        """Refreshes the status of the virtual machines"""
        try:
            self._get_my_tenant()
        except requests.exceptions.RequestException as e:
            self._format_request_exception(e)
        vm_dict = {}
        for vm_id in vm_list:
            vm = {}
            # print "VIMConnector refresh_tenant_vms and nets: Getting tenant VM instance information from VIM"
            try:
                url = self.url + "/" + self.tenant + "/servers/" + vm_id
                self.logger.info("Getting vm GET %s", url)
                vim_response = requests.get(url, headers=self.headers_req)
                self._check_http_request_response(vim_response)
                response = vim_response.json()
                js_v(response, new_vminstance_response_schema)
                if response["server"]["status"] in vmStatus2manoFormat:
                    vm["status"] = vmStatus2manoFormat[response["server"]["status"]]
                else:
                    vm["status"] = "OTHER"
                    vm["error_msg"] = (
                        "VIM status reported " + response["server"]["status"]
                    )
                if response["server"].get("last_error"):
                    vm["error_msg"] = response["server"]["last_error"]
                vm["vim_info"] = yaml.safe_dump(response["server"])
                # get interfaces info
                try:
                    management_ip = False
                    url2 = self.url + "/ports?device_id=" + quote(vm_id)
                    self.logger.info("Getting PORTS GET %s", url2)
                    vim_response2 = requests.get(url2, headers=self.headers_req)
                    self._check_http_request_response(vim_response2)
                    client_data = vim_response2.json()
                    if isinstance(client_data.get("ports"), list):
                        vm["interfaces"] = []
                    for port in client_data.get("ports"):
                        interface = {}
                        interface["vim_info"] = yaml.safe_dump(port)
                        interface["mac_address"] = port.get("mac_address")
                        interface["vim_net_id"] = port.get("network_id")
                        interface["vim_interface_id"] = port["id"]
                        interface["ip_address"] = port.get("ip_address")
                        if interface["ip_address"]:
                            management_ip = True
                        if interface["ip_address"] == "0.0.0.0":
                            interface["ip_address"] = None
                        vm["interfaces"].append(interface)

                except Exception as e:
                    self.logger.error(
                        "refresh_vms_and_nets. Port get %s: %s",
                        type(e).__name__,
                        str(e),
                    )

                if vm["status"] == "ACTIVE" and not management_ip:
                    vm["status"] = "ACTIVE:NoMgmtIP"

            except vimconn.VimConnNotFoundException as e:
                self.logger.error("Exception getting vm status: %s", str(e))
                vm["status"] = "DELETED"
                vm["error_msg"] = str(e)
            except (
                requests.exceptions.RequestException,
                js_e.ValidationError,
                vimconn.VimConnException,
            ) as e:
                self.logger.error("Exception getting vm status: %s", str(e))
                vm["status"] = "VIM_ERROR"
                vm["error_msg"] = str(e)
            vm_dict[vm_id] = vm
        return vm_dict

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
        try:
            self._get_my_tenant()
        except requests.exceptions.RequestException as e:
            self._format_request_exception(e)

        net_dict = {}
        for net_id in net_list:
            net = {}
            # print "VIMConnector refresh_tenant_vms_and_nets:
            # Getting tenant network from VIM (tenant: " + str(self.tenant) + "): "
            try:
                net_vim = self.get_network(net_id)
                if net_vim["status"] in netStatus2manoFormat:
                    net["status"] = netStatus2manoFormat[net_vim["status"]]
                else:
                    net["status"] = "OTHER"
                    net["error_msg"] = "VIM status reported " + net_vim["status"]

                if net["status"] == "ACTIVE" and not net_vim["admin_state_up"]:
                    net["status"] = "DOWN"
                if net_vim.get("last_error"):
                    net["error_msg"] = net_vim["last_error"]
                net["vim_info"] = yaml.safe_dump(net_vim)
            except vimconn.VimConnNotFoundException as e:
                self.logger.error("Exception getting net status: %s", str(e))
                net["status"] = "DELETED"
                net["error_msg"] = str(e)
            except (
                requests.exceptions.RequestException,
                js_e.ValidationError,
                vimconn.VimConnException,
            ) as e:
                self.logger.error("Exception getting net status: %s", str(e))
                net["status"] = "VIM_ERROR"
                net["error_msg"] = str(e)
            net_dict[net_id] = net
        return net_dict

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        """Send and action over a VM instance from VIM"""
        """Returns the status"""
        try:
            self._get_my_tenant()
            if "console" in action_dict:
                raise vimconn.VimConnException(
                    "getting console is not available at openvim",
                    http_code=vimconn.HTTP_Service_Unavailable,
                )
            url = self.url + "/" + self.tenant + "/servers/" + vm_id + "/action"
            self.logger.info("Action over VM instance POST %s", url)
            vim_response = requests.post(
                url, headers=self.headers_req, data=json.dumps(action_dict)
            )
            self._check_http_request_response(vim_response)
            return None
        except (requests.exceptions.RequestException, js_e.ValidationError) as e:
            self._format_request_exception(e)

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
            flavor_id: flavor_id to resize the vdu to
        """
        # TODO: Add support for resize
        raise vimconn.VimConnNotImplemented("Not implemented")
