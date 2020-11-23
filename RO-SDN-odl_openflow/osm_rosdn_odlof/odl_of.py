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
Implement the plugging for OpenDayLight openflow controller
It creates the class OF_conn to create dataplane connections
with static rules based on packet destination MAC address
"""

import json
import requests
import base64
import logging
from osm_ro_plugin.openflow_conn import OpenflowConn, OpenflowConnConnectionException, OpenflowConnUnexpectedResponse
# OpenflowConnException, OpenflowConnAuthException, OpenflowConnNotFoundException,
# OpenflowConnConflictException, OpenflowConnNotSupportedException, OpenflowConnNotImplemented

__author__ = "Pablo Montes, Alfonso Tierno"
__date__ = "$28-oct-2014 12:07:15$"


class OfConnOdl(OpenflowConn):
    """OpenDayLight connector. No MAC learning is used"""

    def __init__(self, params):
        """ Constructor.
            Params: dictionary with the following keys:
                of_dpid:     DPID to use for this controller
                of_url:      must be [http://HOST:PORT/]
                of_user:     user credentials, can be missing or None
                of_password: password credentials
                of_debug:    debug level for logging. Default to ERROR
                other keys are ignored
            Raise an exception if same parameter is missing or wrong
        """

        OpenflowConn.__init__(self, params)

        # check params
        url = params.get("of_url")
        if not url:
            raise ValueError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url

        # internal variables
        self.name = "OpenDayLight"
        self.headers = {'content-type': 'application/json', 'Accept': 'application/json'}
        self.auth = None
        self.pp2ofi = {}  # From Physical Port to OpenFlow Index
        self.ofi2pp = {}  # From OpenFlow Index to Physical Port

        self.dpid = str(params["of_dpid"])
        self.id = 'openflow:'+str(int(self.dpid.replace(':', ''), 16))
        if params and params.get("of_user"):
            of_password = params.get("of_password", "")
            self.auth = base64.b64encode(bytes(params["of_user"] + ":" + of_password, "utf-8"))
            self.auth = self.auth.decode()
            self.headers['authorization'] = 'Basic ' + self.auth

        self.logger = logging.getLogger('openmano.sdnconn.onosof')
        # self.logger.setLevel(getattr(logging, params.get("of_debug", "ERROR")))
        self.logger.debug("odlof plugin initialized")

    def get_of_switches(self):
        """
        Obtain a a list of switches or DPID detected by this controller
        :return: list length, and a list where each element a tuple pair (DPID, IP address)
                 Raise an OpenflowConnConnectionException exception if fails with text_error
        """
        try:
            of_response = requests.get(self.url + "restconf/operational/opendaylight-inventory:nodes",
                                       headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("get_of_switches " + error_text)
                raise OpenflowConnUnexpectedResponse("Error get_of_switches " + error_text)

            self.logger.debug("get_of_switches " + error_text)
            info = of_response.json()

            if not isinstance(info, dict):
                self.logger.error("get_of_switches. Unexpected response, not a dict: %s", str(info))
                raise OpenflowConnUnexpectedResponse("Unexpected response, not a dict. Wrong version?")

            nodes = info.get('nodes')
            if type(nodes) is not dict:
                self.logger.error("get_of_switches. Unexpected response at 'nodes', not found or not a dict: %s",
                                  str(type(info)))
                raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes', not found or not a dict."
                                                     " Wrong version?")

            node_list = nodes.get('node')
            if type(node_list) is not list:
                self.logger.error("get_of_switches. Unexpected response, at 'nodes':'node', "
                                  "not found or not a list: %s", str(type(node_list)))
                raise OpenflowConnUnexpectedResponse("Unexpected response, at 'nodes':'node', not found "
                                                     "or not a list. Wrong version?")

            switch_list = []
            for node in node_list:
                node_id = node.get('id')
                if node_id is None:
                    self.logger.error("get_of_switches. Unexpected response at 'nodes':'node'[]:'id', not found: %s",
                                      str(node))
                    raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes':'node'[]:'id', not found. "
                                                         "Wrong version?")

                if node_id == 'controller-config':
                    continue

                node_ip_address = node.get('flow-node-inventory:ip-address')
                if node_ip_address is None:
                    self.logger.error("get_of_switches. Unexpected response at 'nodes':'node'[]:'flow-node-inventory:"
                                      "ip-address', not found: %s", str(node))
                    raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes':'node'[]:"
                                                         "'flow-node-inventory:ip-address', not found. Wrong version?")

                node_id_hex = hex(int(node_id.split(':')[1])).split('x')[1].zfill(16)
                switch_list.append((':'.join(a+b for a, b in zip(node_id_hex[::2], node_id_hex[1::2])),
                                    node_ip_address))
            return switch_list

        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_switches " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except ValueError as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_switches " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def obtain_port_correspondence(self):
        """
        Obtain the correspondence between physical and openflow port names
        :return: dictionary: with physical name as key, openflow name as value,
                 Raise a OpenflowConnConnectionException expection in case of failure
        """
        try:
            of_response = requests.get(self.url + "restconf/operational/opendaylight-inventory:nodes",
                                       headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("obtain_port_correspondence " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("obtain_port_correspondence " + error_text)
            info = of_response.json()

            if not isinstance(info, dict):
                self.logger.error("obtain_port_correspondence. Unexpected response not a dict: %s", str(info))
                raise OpenflowConnUnexpectedResponse("Unexpected openflow response, not a dict. Wrong version?")

            nodes = info.get('nodes')
            if not isinstance(nodes, dict):
                self.logger.error("obtain_port_correspondence. Unexpected response at 'nodes', "
                                  "not found or not a dict: %s", str(type(nodes)))
                raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes',not found or not a dict. "
                                                     "Wrong version?")

            node_list = nodes.get('node')
            if not isinstance(node_list, list):
                self.logger.error("obtain_port_correspondence. Unexpected response, at 'nodes':'node', "
                                  "not found or not a list: %s", str(type(node_list)))
                raise OpenflowConnUnexpectedResponse("Unexpected response, at 'nodes':'node', not found or not a list."
                                                     " Wrong version?")

            for node in node_list:
                node_id = node.get('id')
                if node_id is None:
                    self.logger.error("obtain_port_correspondence. Unexpected response at 'nodes':'node'[]:'id', "
                                      "not found: %s", str(node))
                    raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes':'node'[]:'id', not found. "
                                                         "Wrong version?")

                if node_id == 'controller-config':
                    continue

                # Figure out if this is the appropriate switch. The 'id' is 'openflow:' plus the decimal value
                # of the dpid
                #  In case this is not the desired switch, continue
                if self.id != node_id:
                    continue

                node_connector_list = node.get('node-connector')
                if not isinstance(node_connector_list, list):
                    self.logger.error("obtain_port_correspondence. Unexpected response at "
                                      "'nodes':'node'[]:'node-connector', not found or not a list: %s", str(node))
                    raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes':'node'[]:'node-connector', "
                                                         "not found  or not a list. Wrong version?")

                for node_connector in node_connector_list:
                    self.pp2ofi[str(node_connector['flow-node-inventory:name'])] = str(node_connector['id'])
                    self.ofi2pp[node_connector['id']] = str(node_connector['flow-node-inventory:name'])

                node_ip_address = node.get('flow-node-inventory:ip-address')
                if node_ip_address is None:
                    self.logger.error("obtain_port_correspondence. Unexpected response at 'nodes':'node'[]:"
                                      "'flow-node-inventory:ip-address', not found: %s", str(node))
                    raise OpenflowConnUnexpectedResponse("Unexpected response at 'nodes':'node'[]:"
                                                         "'flow-node-inventory:ip-address', not found. Wrong version?")

                # If we found the appropriate dpid no need to continue in the for loop
                break

            # print self.name, ": obtain_port_correspondence ports:", self.pp2ofi
            return self.pp2ofi
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("obtain_port_correspondence " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except ValueError as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("obtain_port_correspondence " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def get_of_rules(self, translate_of_ports=True):
        """
        Obtain the rules inserted at openflow controller
        :param translate_of_ports:
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
            Raise a OpenflowConnConnectionException exception in case of failure

        """

        try:
            # get rules
            if len(self.ofi2pp) == 0:
                self.obtain_port_correspondence()

            of_response = requests.get(self.url + "restconf/config/opendaylight-inventory:nodes/node/" + self.id +
                                       "/table/0", headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)

            # The configured page does not exist if there are no rules installed. In that case we return an empty dict
            if of_response.status_code == 404:
                return []

            elif of_response.status_code != 200:
                self.logger.warning("get_of_rules " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)

            self.logger.debug("get_of_rules " + error_text)

            info = of_response.json()

            if not isinstance(info, dict):
                self.logger.error("get_of_rules. Unexpected response not a dict: %s", str(info))
                raise OpenflowConnUnexpectedResponse("Unexpected openflow response, not a dict. Wrong version?")

            table = info.get('flow-node-inventory:table')
            if not isinstance(table, list):
                self.logger.error("get_of_rules. Unexpected response at 'flow-node-inventory:table', "
                                  "not a list: %s", str(type(table)))
                raise OpenflowConnUnexpectedResponse("Unexpected response at 'flow-node-inventory:table', not a list. "
                                                     "Wrong version?")

            flow_list = table[0].get('flow')
            if flow_list is None:
                return []

            if not isinstance(flow_list, list):
                self.logger.error("get_of_rules. Unexpected response at 'flow-node-inventory:table'[0]:'flow', not a "
                                  "list: %s", str(type(flow_list)))
                raise OpenflowConnUnexpectedResponse("Unexpected response at 'flow-node-inventory:table'[0]:'flow', "
                                                     "not a list. Wrong version?")

            # TODO translate ports according to translate_of_ports parameter

            rules = []  # Response list
            for flow in flow_list:
                if not ('id' in flow and 'match' in flow and 'instructions' in flow and
                        'instruction' in flow['instructions'] and
                        'apply-actions' in flow['instructions']['instruction'][0] and
                        'action' in flow['instructions']['instruction'][0]['apply-actions']):
                    raise OpenflowConnUnexpectedResponse("unexpected openflow response, one or more elements are "
                                                         "missing. Wrong version?")

                flow['instructions']['instruction'][0]['apply-actions']['action']

                rule = dict()
                rule['switch'] = self.dpid
                rule['priority'] = flow.get('priority')
                # rule['name'] = flow['id']
                # rule['cookie'] = flow['cookie']
                if 'in-port' in flow['match']:
                    in_port = flow['match']['in-port']
                    if in_port not in self.ofi2pp:
                        raise OpenflowConnUnexpectedResponse("Error: Ingress port {} is not in switch port list".
                                                             format(in_port))

                    if translate_of_ports:
                        in_port = self.ofi2pp[in_port]

                    rule['ingress_port'] = in_port

                    if 'vlan-match' in flow['match'] and 'vlan-id' in flow['match']['vlan-match'] and \
                            'vlan-id' in flow['match']['vlan-match']['vlan-id'] and \
                            'vlan-id-present' in flow['match']['vlan-match']['vlan-id'] and \
                            flow['match']['vlan-match']['vlan-id']['vlan-id-present'] is True:
                        rule['vlan_id'] = flow['match']['vlan-match']['vlan-id']['vlan-id']

                    if 'ethernet-match' in flow['match'] and 'ethernet-destination' in flow['match']['ethernet-match'] \
                            and 'address' in flow['match']['ethernet-match']['ethernet-destination']:
                        rule['dst_mac'] = flow['match']['ethernet-match']['ethernet-destination']['address']

                instructions = flow['instructions']['instruction'][0]['apply-actions']['action']

                max_index = 0
                for instruction in instructions:
                    if instruction['order'] > max_index:
                        max_index = instruction['order']

                actions = [None]*(max_index+1)
                for instruction in instructions:
                    if 'output-action' in instruction:
                        if 'output-node-connector' not in instruction['output-action']:
                            raise OpenflowConnUnexpectedResponse("unexpected openflow response, one or more elementa "
                                                                 "are missing. Wrong version?")

                        out_port = instruction['output-action']['output-node-connector']
                        if out_port not in self.ofi2pp:
                            raise OpenflowConnUnexpectedResponse("Error: Output port {} is not in switch port list".
                                                                 format(out_port))

                        if translate_of_ports:
                            out_port = self.ofi2pp[out_port]

                        actions[instruction['order']] = ('out', out_port)

                    elif 'strip-vlan-action' in instruction:
                        actions[instruction['order']] = ('vlan', None)

                    elif 'set-field' in instruction:
                        if not ('vlan-match' in instruction['set-field'] and
                                'vlan-id' in instruction['set-field']['vlan-match'] and
                                'vlan-id' in instruction['set-field']['vlan-match']['vlan-id']):
                            raise OpenflowConnUnexpectedResponse("unexpected openflow response, one or more elements "
                                                                 "are missing. Wrong version?")

                        actions[instruction['order']] = ('vlan',
                                                         instruction['set-field']['vlan-match']['vlan-id']['vlan-id'])

                actions = [x for x in actions if x is not None]

                rule['actions'] = list(actions)
                rules.append(rule)

            return rules
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_rules " + error_text)
            raise OpenflowConnConnectionException(error_text)
        except ValueError as e:
            # ValueError in the case that JSON can not be decoded
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("get_of_rules " + error_text)
            raise OpenflowConnUnexpectedResponse(error_text)

    def del_flow(self, flow_name):
        """
        Delete an existing rule
        :param flow_name: flow_name, this is the rule name
        :return: Raise a OpenflowConnConnectionException expection in case of failure
        """

        try:
            of_response = requests.delete(self.url + "restconf/config/opendaylight-inventory:nodes/node/" + self.id +
                                          "/table/0/flow/" + flow_name, headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("del_flow " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("del_flow OK " + error_text)
            return None
        except requests.exceptions.RequestException as e:
            # raise an exception in case of contection error
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("del_flow " + error_text)
            raise OpenflowConnConnectionException(error_text)

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
        :return: Raise a OpenflowConnConnectionException exception in case of failure
        """

        try:
            self.logger.debug("new_flow data: {}".format(data))
            if len(self.pp2ofi) == 0:
                self.obtain_port_correspondence()

            # We have to build the data for the opendaylight call from the generic data
            flow = {
                'id': data['name'],
                'flow-name': data['name'],
                'idle-timeout': 0,
                'hard-timeout': 0,
                'table_id': 0,
                'priority': data.get('priority'),
                'match': {}
            }
            sdata = {'flow-node-inventory:flow': [flow]}
            if not data['ingress_port'] in self.pp2ofi:
                error_text = 'Error. Port ' + data['ingress_port'] + ' is not present in the switch'
                self.logger.warning("new_flow " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            flow['match']['in-port'] = self.pp2ofi[data['ingress_port']]
            if data.get('dst_mac'):
                flow['match']['ethernet-match'] = {
                    'ethernet-destination': {'address': data['dst_mac']}
                }
            if data.get('vlan_id'):
                flow['match']['vlan-match'] = {
                    'vlan-id': {
                        'vlan-id-present': True,
                        'vlan-id': int(data['vlan_id'])
                    }
                }
            actions = []
            flow['instructions'] = {
                'instruction': [{
                    'order': 1,
                    'apply-actions': {'action': actions}
                }]
            }

            order = 0
            for action in data['actions']:
                new_action = {'order': order}
                if action[0] == "vlan":
                    if action[1] is None:
                        # strip vlan
                        new_action['strip-vlan-action'] = {}
                    else:
                        new_action['set-field'] = {
                            'vlan-match': {
                                'vlan-id': {
                                    'vlan-id-present': True,
                                    'vlan-id': int(action[1])
                                }
                            }
                        }
                elif action[0] == 'out':
                    new_action['output-action'] = {}
                    if not action[1] in self.pp2ofi:
                        error_msg = 'Port ' + action[1] + ' is not present in the switch'
                        raise OpenflowConnUnexpectedResponse(error_msg)

                    new_action['output-action']['output-node-connector'] = self.pp2ofi[action[1]]
                else:
                    error_msg = "Unknown item '{}' in action list".format(action[0])
                    self.logger.error("new_flow " + error_msg)
                    raise OpenflowConnUnexpectedResponse(error_msg)

                actions.append(new_action)
                order += 1

            # print json.dumps(sdata)
            of_response = requests.put(self.url + "restconf/config/opendaylight-inventory:nodes/node/" + self.id +
                                       "/table/0/flow/" + data['name'], headers=self.headers, data=json.dumps(sdata))
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200:
                self.logger.warning("new_flow " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("new_flow OK " + error_text)
            return None

        except requests.exceptions.RequestException as e:
            # raise an exception in case of contection error
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("new_flow " + error_text)
            raise OpenflowConnConnectionException(error_text)

    def clear_all_flows(self):
        """
        Delete all existing rules
        :return: Raise a OpenflowConnConnectionException expection in case of failure
        """
        try:
            of_response = requests.delete(self.url + "restconf/config/opendaylight-inventory:nodes/node/" + self.id +
                                          "/table/0", headers=self.headers)
            error_text = "Openflow response {}: {}".format(of_response.status_code, of_response.text)
            if of_response.status_code != 200 and of_response.status_code != 404:   # HTTP_Not_Found
                self.logger.warning("clear_all_flows " + error_text)
                raise OpenflowConnUnexpectedResponse(error_text)
            self.logger.debug("clear_all_flows OK " + error_text)
            return None
        except requests.exceptions.RequestException as e:
            error_text = type(e).__name__ + ": " + str(e)
            self.logger.error("clear_all_flows " + error_text)
            raise OpenflowConnConnectionException(error_text)
