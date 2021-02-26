#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# Copyright 2015 Telefonica Investigacion y Desarrollo, S.A.U.
# This file is part of openvim
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
Implement the plugging for floodligth openflow controller
It creates the class OF_conn to create dataplane connections
with static rules based on packet destination MAC address
"""

__author__ = "Pablo Montes, Alfonso Tierno"
__date__ = "$28-oct-2014 12:07:15$"

import json
import requests
import logging
from osm_ro_plugin.openflow_conn import OpenflowConn, OpenflowConnUnexpectedResponse, OpenflowConnConnectionException


class OfConnFloodLight(OpenflowConn):
    """
    Openflow Connector for Floodlight.
    No MAC learning is used
    version 0.9 or 1.X is autodetected
    version 1.X is in progress, not finished!!!
    """

    def __init__(self, params):
        """
        Constructor
            :param params: dictionary with the following keys:
                of_dpid:     DPID to use for this controller ?? Does a controller have a dpid?
                url:         must be [http://HOST:PORT/]
                of_user:     user credentials, can be missing or None
                of_password: password credentials
                of_debug:    debug level for logging. Default to ERROR
                other keys are ignored
            Raise an exception if same parameter is missing or wrong
        """
        # check params
        url = params.get("of_url")
        if not url:
            raise ValueError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url

        OpenflowConn.__init__(self, params)

        self.name = "Floodlight"
        self.dpid = str(params["of_dpid"])

        self.pp2ofi = {}  # From Physical Port to OpenFlow Index
        self.ofi2pp = {}  # From OpenFlow Index to Physical Port
        self.headers = {'content-type': 'application/json', 'Accept': 'application/json'}
        self.version = None
        self.logger = logging.getLogger('ro.sdn.floodlightof')
        self.logger.setLevel(params.get("of_debug", "ERROR"))
        self._set_version(params.get("of_version"))

    def _set_version(self, version):
        """
        set up a version of the controller.
         Depending on the version it fills the self.ver_names with the naming used in this version
        :param version: Openflow controller version
        :return: Raise an ValueError exception if same parameter is missing or wrong
        """
        # static version names
        if version is None:
            self.version = None
        elif version == "0.9":
            self.version = version
            self.name = "Floodlightv0.9"
            self.ver_names = {
                "dpid": "dpid",
                "URLmodifier": "staticflowentrypusher",
                "destmac": "dst-mac",
                "vlanid": "vlan-id",
                "inport": "ingress-port",
                "setvlan": "set-vlan-id",
                "stripvlan": "strip-vlan",
            }
        elif version[0] == "1":  # version 1.X
            self.version = version
            self.name = "Floodlightv1.X"
            self.ver_names = {
                "dpid": "switchDPID",
                "URLmodifier": "staticflowpusher",
                "destmac": "eth_dst",
                "vlanid": "eth_vlan_vid",
                "inport": "in_port",
                "setvlan": "set_vlan_vid",
                "stripvlan": "strip_vlan",
            }
        else:
            raise ValueError("Invalid version for floodlight controller")

    def get_of_switches(self):
        """
        Obtain a a list of switches or DPID detected by this controller
        :return: list where each element a tuple pair (DPID, IP address)
                      Raise an OpenflowconnConnectionException or OpenflowconnConnectionException exception if same
                      parameter is missing or wrong
        """
        try:
            of_response = requests.get(self.url + "wm/core/controller/switches/json", headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("get_of_switches " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("get_of_switches " + error_text)
            info = of_response.json()
            if not isinstance(info, (list, tuple)):
                self.logger.error("get_of_switches. Unexpected response not a list %s", str(type(info)))
                raise OpenflowConnUnexpectedResponse("Unexpected response, not a list. Wrong version?")
            if len(info) == 0:
                return info
            # autodiscover version
            if self.version is None:
                if 'dpid' in info[0] and 'inetAddress' in info[0]:
                    self._set_version("0.9")
                # elif 'switchDPID' in info[0] and 'inetAddress' in info[0]:
                #     self._set_version("1.X")
                else:
                    self.logger.error("get_of_switches. Unexpected response, not found 'dpid' or 'switchDPID' "
                                      "field: %s", str(info[0]))
                    raise OpenflowConnUnexpectedResponse("Unexpected response, not found 'dpid' or "
                                                         "'switchDPID' field. Wrong version?")

            switch_list = []
            for switch in info:
                switch_list.append((switch[self.ver_names["dpid"]], switch['inetAddress']))
            return switch_list
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_switches " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except Exception as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_switches " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def get_of_rules(self, translate_of_ports=True):
        """
        Obtain the rules inserted at openflow controller
        :param translate_of_ports: if True it translates ports from openflow index to physical switch name
        :return: list where each item is a  dictionary with the following content:
            priority: rule priority
            name:         rule name (present also as the master dict key)
            ingress_port: match input port of the rule
            dst_mac:      match destination mac address of the rule, can be missing or None if not apply
            vlan_id:      match vlan tag of the rule, can be missing or None if not apply
            actions:      list of actions, composed by a pair tuples:
                (vlan, None/int): for stripping/setting a vlan tag
                (out, port):      send to this port
            switch:       DPID, all
        Raise an openflowconnUnexpectedResponse exception if fails with text_error
        """

        try:
            # get translation, autodiscover version
            if len(self.ofi2pp) == 0:
                self.obtain_port_correspondence()

            of_response = requests.get(self.url + "wm/{}/list/{}/json".format(self.ver_names["URLmodifier"], self.dpid),
                                       headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("get_of_rules " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("get_of_rules " + error_text)
            info = of_response.json()
            if type(info) != dict:
                self.logger.error("get_of_rules. Unexpected response not a dict %s", str(type(info)))
                raise OpenflowConnUnexpectedResponse("Unexpected response, not a dict. Wrong version?")
            rule_list = []
            for switch, switch_info in info.items():
                if switch_info is None:
                    continue
                if str(switch) != self.dpid:
                    continue
                for name, details in switch_info.items():
                    rule = {
                        "name": name,
                        "switch": str(switch)
                    }
                    # rule["active"] = "true"
                    rule["priority"] = int(details["priority"])
                    if self.version[0] == "0":
                        if translate_of_ports:
                            rule["ingress_port"] = self.ofi2pp[details["match"]["inputPort"]]
                        else:
                            rule["ingress_port"] = str(details["match"]["inputPort"])
                        dst_mac = details["match"]["dataLayerDestination"]
                        if dst_mac != "00:00:00:00:00:00":
                            rule["dst_mac"] = dst_mac
                        vlan = details["match"]["dataLayerVirtualLan"]
                        if vlan != -1:
                            rule["vlan_id"] = vlan
                        actionlist = []
                        for action in details["actions"]:
                            if action["type"] == "OUTPUT":
                                if translate_of_ports:
                                    port = self.ofi2pp[action["port"]]
                                else:
                                    port = action["port"]
                                actionlist.append(("out", port))
                            elif action["type"] == "STRIP_VLAN":
                                actionlist.append(("vlan", None))
                            elif action["type"] == "SET_VLAN_ID":
                                actionlist.append(("vlan", action["virtualLanIdentifier"]))
                            else:
                                actionlist.append((action["type"], str(action)))
                                self.logger.warning("get_of_rules() Unknown action in rule %s: %s", rule["name"],
                                                    str(action))
                            rule["actions"] = actionlist
                    elif self.version[0] == "1":
                        if translate_of_ports:
                            rule["ingress_port"] = self.ofi2pp[details["match"]["in_port"]]
                        else:
                            rule["ingress_port"] = details["match"]["in_port"]
                        if "eth_dst" in details["match"]:
                            dst_mac = details["match"]["eth_dst"]
                            if dst_mac != "00:00:00:00:00:00":
                                rule["dst_mac"] = dst_mac
                        if "eth_vlan_vid" in details["match"]:
                            vlan = int(details["match"]["eth_vlan_vid"], 16) & 0xFFF
                            rule["vlan_id"] = str(vlan)
                        actionlist = []
                        for action in details["instructions"]["instruction_apply_actions"]:
                            if action == "output":
                                if translate_of_ports:
                                    port = self.ofi2pp[details["instructions"]["instruction_apply_actions"]["output"]]
                                else:
                                    port = details["instructions"]["instruction_apply_actions"]["output"]
                                actionlist.append(("out", port))
                            elif action == "strip_vlan":
                                actionlist.append(("vlan", None))
                            elif action == "set_vlan_vid":
                                actionlist.append(
                                    ("vlan", details["instructions"]["instruction_apply_actions"]["set_vlan_vid"]))
                            else:
                                self.logger.error("get_of_rules Unknown action in rule %s: %s", rule["name"],
                                                  str(action))
                                # actionlist.append((action, str(details["instructions"]["instruction_apply_actions"])))
                    rule_list.append(rule)
            return rule_list
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_rules " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except Exception as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_rules " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def obtain_port_correspondence(self):
        """
        Obtain the correspondence between physical and openflow port names
        :return: dictionary: with physical name as key, openflow name as value
                 Raise an openflowconnUnexpectedResponse exception if fails with text_error
        """
        try:
            of_response = requests.get(self.url + "wm/core/controller/switches/json", headers=self.headers)
            # print vim_response.status_code
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("obtain_port_correspondence " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("obtain_port_correspondence " + error_text)
            info = of_response.json()

            if not isinstance(info, (list, tuple)):
                raise OpenflowConnUnexpectedResponse("unexpected openflow response, not a list. Wrong version?")

            index = -1
            if len(info) > 0:
                # autodiscover version
                if self.version is None:
                    if 'dpid' in info[0] and 'ports' in info[0]:
                        self._set_version("0.9")
                    elif 'switchDPID' in info[0]:
                        self._set_version("1.X")
                    else:
                        raise OpenflowConnUnexpectedResponse("unexpected openflow response, Wrong version?")

            for i, info_item in enumerate(info):
                if info_item[self.ver_names["dpid"]] == self.dpid:
                    index = i
                    break
            if index == -1:
                text = "DPID '{}' not present in controller {}".format(self.dpid, self.url)
                # print self.name, ": get_of_controller_info ERROR", text
                raise OpenflowConnUnexpectedResponse(text)
            else:
                if self.version[0] == "0":
                    ports = info[index]["ports"]
                else:  # version 1.X
                    of_response = requests.get(self.url + "wm/core/switch/{}/port-desc/json".format(self.dpid),
                                               headers=self.headers)
                    # print vim_response.status_code
                    error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
                    if of_response.status_code != 200:
                        self.logger.warning("obtain_port_correspondence " + error_text)
                        raise OpenflowConnUnexpectedResponse(error_text)
                    self.logger.debug("obtain_port_correspondence " + error_text)
                    info = of_response.json()
                    if type(info) != dict:
                        raise OpenflowConnUnexpectedResponse("unexpected openflow port-desc response, "
                                                             "not a dict. Wrong version?")
                    if "portDesc" not in info:
                        raise OpenflowConnUnexpectedResponse("unexpected openflow port-desc response, "
                                                             "'portDesc' not found. Wrong version?")
                    if type(info["portDesc"]) != list and type(info["portDesc"]) != tuple:
                        raise OpenflowConnUnexpectedResponse("unexpected openflow port-desc response at "
                                                             "'portDesc', not a list. Wrong version?")
                    ports = info["portDesc"]
                for port in ports:
                    self.pp2ofi[str(port["name"])] = str(port["portNumber"])
                    self.ofi2pp[port["portNumber"]] = str(port["name"])
                    # print self.name, ": get_of_controller_info ports:", self.pp2ofi
            return self.pp2ofi
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("obtain_port_correspondence " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except Exception as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("obtain_port_correspondence " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def del_flow(self, flow_name):
        """
        Delete an existing rule
        :param flow_name: this is the rule name
        :return: None if ok
                 Raise an openflowconnUnexpectedResponse exception if fails with text_error
        """
        try:
            if self.version is None:
                self.get_of_switches()

            of_response = requests.delete(self.url + "wm/{}/json".format(self.ver_names["URLmodifier"]),
                                          headers=self.headers,
                                          data='{{"switch":"{}","name":"{}"}}'.format(self.dpid, flow_name))
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("del_flow " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("del_flow OK " + error_text)
            return None

        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("del_flow " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except Exception as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("del_flow " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def new_flow(self, data):
        """
        Insert a new static rule
        :param data: dictionary with the following content:
                        priority:     rule priority
                        name:         rule name
                        ingress_port: match input port of the rule
                        dst_mac:      match destination mac address of the rule, missing or None if not apply
                        vlan_id:      match vlan tag of the rule, missing or None if not apply
                        actions:      list of actions, composed by a pair tuples with these posibilities:
                            ('vlan', None/int): for stripping/setting a vlan tag
                            ('out', port):      send to this port
        :return: None if ok
                 Raise an openflowconnUnexpectedResponse exception if fails with text_error
        """
        # get translation, autodiscover version
        if len(self.pp2ofi) == 0:
            self.obtain_port_correspondence()

        try:
            # We have to build the data for the floodlight call from the generic data
            sdata = {'active': "true", "name": data["name"]}
            if data.get("priority"):
                sdata["priority"] = str(data["priority"])
            if data.get("vlan_id"):
                sdata[self.ver_names["vlanid"]] = data["vlan_id"]
            if data.get("dst_mac"):
                sdata[self.ver_names["destmac"]] = data["dst_mac"]
            sdata['switch'] = self.dpid
            if not data['ingress_port'] in self.pp2ofi:
                error_text = 'Error. Port {} is not present in the switch'.format(data['ingress_port'])
                self.logger.warning("new_flow " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)

            sdata[self.ver_names["inport"]] = self.pp2ofi[data['ingress_port']]
            sdata['actions'] = ""

            for action in data['actions']:
                if len(sdata['actions']) > 0:
                    sdata['actions'] += ','
                if action[0] == "vlan":
                    if action[1] is None:
                        sdata['actions'] += self.ver_names["stripvlan"]
                    else:
                        sdata['actions'] += self.ver_names["setvlan"] + "=" + str(action[1])
                elif action[0] == 'out':
                    sdata['actions'] += "output=" + self.pp2ofi[action[1]]

            of_response = requests.post(self.url + "wm/{}/json".format(self.ver_names["URLmodifier"]),
                                        headers=self.headers, data=json.dumps(sdata))
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("new_flow " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("new_flow OK" + error_text)
            return None

        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("new_flow " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except Exception as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("new_flow " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def clear_all_flows(self):
        """
        Delete all existing rules
        :return: None if ok
                 Raise an openflowconnUnexpectedResponse exception if fails with text_error
        """

        try:
            # autodiscover version
            if self.version is None:
                sw_list = self.get_of_switches()
                if len(sw_list) == 0:  # empty
                    return None

            url = self.url + "wm/{}/clear/{}/json".format(self.ver_names["URLmodifier"], self.dpid)
            of_response = requests.get(url)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code < 200 or of_response.status_code >= 300:
                self.logger.warning("clear_all_flows " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("clear_all_flows OK " + error_text)
            return None
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("clear_all_flows " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except Exception as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("clear_all_flows " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)
