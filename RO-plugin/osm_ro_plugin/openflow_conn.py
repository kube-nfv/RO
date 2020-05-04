##
# Copyright 2019 Telefonica Investigacion y Desarrollo, S.A.U.
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
##
import logging
from http import HTTPStatus
from osm_ro_plugin.sdnconn import SdnConnectorBase, SdnConnectorError
from uuid import uuid4

"""
Implement an Abstract class 'OpenflowConn' and an engine 'SdnConnectorOpenFlow' used for base class for SDN plugings
that implements a pro-active opeflow rules.
"""

__author__ = "Alfonso Tierno"
__date__ = "2019-11-11"


class OpenflowConnException(Exception):
    """Common and base class Exception for all vimconnector exceptions"""
    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST.value):
        Exception.__init__(self, message)
        self.http_code = http_code


class OpenflowConnConnectionException(OpenflowConnException):
    """Connectivity error with the VIM"""
    def __init__(self, message, http_code=HTTPStatus.SERVICE_UNAVAILABLE.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConnUnexpectedResponse(OpenflowConnException):
    """Get an wrong response from VIM"""
    def __init__(self, message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConnAuthException(OpenflowConnException):
    """Invalid credentials or authorization to perform this action over the VIM"""
    def __init__(self, message, http_code=HTTPStatus.UNAUTHORIZED.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConnNotFoundException(OpenflowConnException):
    """The item is not found at VIM"""
    def __init__(self, message, http_code=HTTPStatus.NOT_FOUND.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConnConflictException(OpenflowConnException):
    """There is a conflict, e.g. more item found than one"""
    def __init__(self, message, http_code=HTTPStatus.CONFLICT.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConnNotSupportedException(OpenflowConnException):
    """The request is not supported by connector"""
    def __init__(self, message, http_code=HTTPStatus.SERVICE_UNAVAILABLE.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConnNotImplemented(OpenflowConnException):
    """The method is not implemented by the connected"""
    def __init__(self, message, http_code=HTTPStatus.NOT_IMPLEMENTED.value):
        OpenflowConnException.__init__(self, message, http_code)


class OpenflowConn:
    """
    Openflow controller connector abstract implementeation.
    """
    def __init__(self, params):
        self.name = "openflow_conector"
        self.pp2ofi = {}  # From Physical Port to OpenFlow Index
        self.ofi2pp = {}  # From OpenFlow Index to Physical Port
        self.logger = logging.getLogger('openmano.sdn.openflow_conn')

    def get_of_switches(self):
        """"
        Obtain a a list of switches or DPID detected by this controller
        :return: list length, and a list where each element a tuple pair (DPID, IP address), text_error: if fails
        """
        raise OpenflowConnNotImplemented("Should have implemented this")

    def obtain_port_correspondence(self):
        """
        Obtain the correspondence between physical and openflow port names
        :return: dictionary: with physical name as key, openflow name as value, error_text: if fails
        """
        raise OpenflowConnNotImplemented("Should have implemented this")

    def get_of_rules(self, translate_of_ports=True):
        """
        Obtain the rules inserted at openflow controller
        :param translate_of_ports: if True it translates ports from openflow index to physical switch name
        :return: list where each item is a  dictionary with the following content:
                    priority: rule priority
                    priority: rule priority
                    name:         rule name (present also as the master dict key)
                    ingress_port: match input port of the rule
                    dst_mac:      match destination mac address of the rule, can be missing or None if not apply
                    vlan_id:      match vlan tag of the rule, can be missing or None if not apply
                    actions:      list of actions, composed by a pair tuples:
                        (vlan, None/int): for stripping/setting a vlan tag
                        (out, port):      send to this port
                    switch:       DPID, all
                 text_error if fails
        """
        raise OpenflowConnNotImplemented("Should have implemented this")

    def del_flow(self, flow_name):
        """
        Delete all existing rules
        :param flow_name: flow_name, this is the rule name
        :return: None if ok, text_error if fails
        """
        raise OpenflowConnNotImplemented("Should have implemented this")

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
        :return: None if ok, text_error if fails
        """
        raise OpenflowConnNotImplemented("Should have implemented this")

    def clear_all_flows(self):
        """"
        Delete all existing rules
        :return: None if ok, text_error if fails
        """
        raise OpenflowConnNotImplemented("Should have implemented this")


class SdnConnectorOpenFlow(SdnConnectorBase):
    """
    This class is the base engine of SDN plugins base on openflow rules
    """
    flow_fields = ('priority', 'vlan', 'ingress_port', 'actions', 'dst_mac', 'src_mac', 'net_id')

    def __init__(self, wim, wim_account, config=None, logger=None, of_connector=None):
        self.logger = logger or logging.getLogger('openmano.sdn.openflow_conn')
        self.of_connector = of_connector
        self.of_controller_nets_with_same_vlan = config.get("of_controller_nets_with_same_vlan", False)

    def check_credentials(self):
        try:
            self.openflow_conn.obtain_port_correspondence()
        except OpenflowConnException as e:
            raise SdnConnectorError(e, http_code=e.http_code)

    def get_connectivity_service_status(self, service_uuid, conn_info=None):
        conn_info = conn_info or {}
        return {
            "sdn_status": conn_info.get("status", "ERROR"),
            "error_msg": conn_info.get("error_msg", "Variable conn_info not provided"),
        }
        # TODO check rules connectirng to of_connector

    def create_connectivity_service(self, service_type, connection_points, **kwargs):
        net_id = str(uuid4())
        ports = []
        for cp in connection_points:
            port = {
                "uuid": cp["service_endpoint_id"],
                "vlan": cp.get("service_endpoint_encapsulation_info", {}).get("vlan"),
                "mac": cp.get("service_endpoint_encapsulation_info", {}).get("mac"),
                "switch_port": cp.get("service_endpoint_encapsulation_info", {}).get("switch_port"),
            }
            ports.append(port)
        try:
            created_items = self._set_openflow_rules(service_type, net_id, ports, created_items=None)
            return net_id, created_items
        except (SdnConnectorError, OpenflowConnException) as e:
            raise SdnConnectorError(e, http_code=e.http_code)

    def delete_connectivity_service(self, service_uuid, conn_info=None):
        try:
            service_type = "ELAN"
            ports = []
            self._set_openflow_rules(service_type, service_uuid, ports, created_items=conn_info)
            return None
        except (SdnConnectorError, OpenflowConnException) as e:
            raise SdnConnectorError(e, http_code=e.http_code)

    def edit_connectivity_service(self, service_uuid, conn_info=None, connection_points=None, **kwargs):
        ports = []
        for cp in connection_points:
            port = {
                "uuid": cp["service_endpoint_id"],
                "vlan": cp.get("service_endpoint_encapsulation_info", {}).get("vlan"),
                "mac": cp.get("service_endpoint_encapsulation_info", {}).get("mac"),
                "switch_port": cp.get("service_endpoint_encapsulation_info", {}).get("switch_port"),
            }
            ports.append(port)
        service_type = "ELAN"  # TODO. Store at conn_info for later use
        try:
            created_items = self._set_openflow_rules(service_type, service_uuid, ports, created_items=conn_info)
            return created_items
        except (SdnConnectorError, OpenflowConnException) as e:
            raise SdnConnectorError(e, http_code=e.http_code)

    def clear_all_connectivity_services(self):
        """Delete all WAN Links corresponding to a WIM"""
        pass

    def get_all_active_connectivity_services(self):
        """Provide information about all active connections provisioned by a
        WIM
        """
        pass

    def _set_openflow_rules(self, net_type, net_id, ports, created_items=None):
        ifaces_nb = len(ports)
        if not created_items:
            created_items = {"status": None, "error_msg": None, "installed_rules_ids": []}
        rules_to_delete = created_items.get("installed_rules_ids") or []
        new_installed_rules_ids = []
        error_list = []

        try:
            step = "Checking ports and network type compatibility"
            if ifaces_nb < 2:
                pass
            elif net_type == 'ELINE':
                if ifaces_nb > 2:
                    raise SdnConnectorError("'ELINE' type network cannot connect {} interfaces, only 2".format(
                        ifaces_nb))
            elif net_type == 'ELAN':
                if ifaces_nb > 2 and self.of_controller_nets_with_same_vlan:
                    # check all ports are VLAN (tagged) or none
                    vlan_tags = []
                    for port in ports:
                        if port["vlan"] not in vlan_tags:
                            vlan_tags.append(port["vlan"])
                    if len(vlan_tags) > 1:
                        raise SdnConnectorError("This pluging cannot connect ports with diferent VLAN tags when flag "
                                                "'of_controller_nets_with_same_vlan' is active")
            else:
                raise SdnConnectorError('Only ELINE or ELAN network types are supported for openflow')

            # Get the existing flows at openflow controller
            step = "Getting installed openflow rules"
            existing_flows = self.of_connector.get_of_rules()
            existing_flows_ids = [flow["name"] for flow in existing_flows]

            # calculate new flows to be inserted
            step = "Compute needed openflow rules"
            new_flows = self._compute_net_flows(net_id, ports)

            name_index = 0
            for flow in new_flows:
                # 1 check if an equal flow is already present
                index = self._check_flow_already_present(flow, existing_flows)
                if index >= 0:
                    flow_id = existing_flows[index]["name"]
                    self.logger.debug("Skipping already present flow %s", str(flow))
                else:
                    # 2 look for a non used name
                    flow_name = flow["net_id"] + "." + str(name_index)
                    while flow_name in existing_flows_ids:
                        name_index += 1
                        flow_name = flow["net_id"] + "." + str(name_index)
                    flow['name'] = flow_name
                    # 3 insert at openflow
                    try:
                        self.of_connector.new_flow(flow)
                        flow_id = flow["name"]
                        existing_flows_ids.append(flow_id)
                    except OpenflowConnException as e:
                        flow_id = None
                        error_list.append("Cannot create rule for ingress_port={}, dst_mac={}: {}"
                                          .format(flow["ingress_port"], flow["dst_mac"], e))

                # 4 insert at database
                if flow_id:
                    new_installed_rules_ids.append(flow_id)
                    if flow_id in rules_to_delete:
                        rules_to_delete.remove(flow_id)

            # delete not needed old flows from openflow
            for flow_id in rules_to_delete:
                # Delete flow
                try:
                    self.of_connector.del_flow(flow_id)
                except OpenflowConnNotFoundException:
                    pass
                except OpenflowConnException as e:
                    error_text = "Cannot remove rule '{}': {}".format(flow_id, e)
                    error_list.append(error_text)
                    self.logger.error(error_text)
            created_items["installed_rules_ids"] = new_installed_rules_ids
            if error_list:
                created_items["error_msg"] = ";".join(error_list)[:1000]
                created_items["error_msg"] = "ERROR"
            else:
                created_items["error_msg"] = None
                created_items["status"] = "ACTIVE"
            return created_items
        except (SdnConnectorError, OpenflowConnException) as e:
            raise SdnConnectorError("Error while {}: {}".format(step, e)) from e
        except Exception as e:
            error_text = "Error while {}: {}".format(step, e)
            self.logger.critical(error_text, exc_info=True)
            raise SdnConnectorError(error_text)

    def _compute_net_flows(self, net_id, ports):
        new_flows = []
        new_broadcast_flows = {}
        nb_ports = len(ports)

        # Check switch_port information is right
        for port in ports:
            nb_ports += 1
            if str(port['switch_port']) not in self.of_connector.pp2ofi:
                raise SdnConnectorError("switch port name '{}' is not valid for the openflow controller".
                                        format(port['switch_port']))
        priority = 1000  # 1100

        for src_port in ports:
            # if src_port.get("groups")
            vlan_in = src_port['vlan']

            # BROADCAST:
            broadcast_key = src_port['uuid'] + "." + str(vlan_in)
            if broadcast_key in new_broadcast_flows:
                flow_broadcast = new_broadcast_flows[broadcast_key]
            else:
                flow_broadcast = {'priority': priority,
                                  'net_id': net_id,
                                  'dst_mac': 'ff:ff:ff:ff:ff:ff',
                                  "ingress_port": str(src_port['switch_port']),
                                  'vlan_id': vlan_in,
                                  'actions': []
                                  }
                new_broadcast_flows[broadcast_key] = flow_broadcast
                if vlan_in is not None:
                    flow_broadcast['vlan_id'] = str(vlan_in)

            for dst_port in ports:
                vlan_out = dst_port['vlan']
                if src_port['switch_port'] == dst_port['switch_port'] and vlan_in == vlan_out:
                    continue
                flow = {
                    "priority": priority,
                    'net_id': net_id,
                    "ingress_port": str(src_port['switch_port']),
                    'vlan_id': vlan_in,
                    'actions': []
                }
                # allow that one port have no mac
                if dst_port['mac'] is None or nb_ports == 2:  # point to point or nets with 2 elements
                    flow['priority'] = priority - 5  # less priority
                else:
                    flow['dst_mac'] = str(dst_port['mac'])

                if vlan_out is None:
                    if vlan_in:
                        flow['actions'].append(('vlan', None))
                else:
                    flow['actions'].append(('vlan', vlan_out))
                flow['actions'].append(('out', str(dst_port['switch_port'])))

                if self._check_flow_already_present(flow, new_flows) >= 0:
                    self.logger.debug("Skipping repeated flow '%s'", str(flow))
                    continue

                new_flows.append(flow)

                # BROADCAST:
                if nb_ports <= 2:  # point to multipoint or nets with more than 2 elements
                    continue
                out = (vlan_out, str(dst_port['switch_port']))
                if out not in flow_broadcast['actions']:
                    flow_broadcast['actions'].append(out)

        # BROADCAST
        for flow_broadcast in new_broadcast_flows.values():
            if len(flow_broadcast['actions']) == 0:
                continue  # nothing to do, skip
            flow_broadcast['actions'].sort()
            if 'vlan_id' in flow_broadcast:
                previous_vlan = 0  # indicates that a packet contains a vlan, and the vlan
            else:
                previous_vlan = None
            final_actions = []
            action_number = 0
            for action in flow_broadcast['actions']:
                if action[0] != previous_vlan:
                    final_actions.append(('vlan', action[0]))
                    previous_vlan = action[0]
                    if self.of_controller_nets_with_same_vlan and action_number:
                        raise SdnConnectorError("Cannot interconnect different vlan tags in a network when flag "
                                                "'of_controller_nets_with_same_vlan' is True.")
                    action_number += 1
                final_actions.append(('out', action[1]))
            flow_broadcast['actions'] = final_actions

            if self._check_flow_already_present(flow_broadcast, new_flows) >= 0:
                self.logger.debug("Skipping repeated flow '%s'", str(flow_broadcast))
                continue

            new_flows.append(flow_broadcast)

        # UNIFY openflow rules with the same input port and vlan and the same output actions
        # These flows differ at the dst_mac; and they are unified by not filtering by dst_mac
        # this can happen if there is only two ports. It is converted to a point to point connection
        flow_dict = {}  # use as key vlan_id+ingress_port and as value the list of flows matching these values
        for flow in new_flows:
            key = str(flow.get("vlan_id")) + ":" + flow["ingress_port"]
            if key in flow_dict:
                flow_dict[key].append(flow)
            else:
                flow_dict[key] = [flow]
        new_flows2 = []
        for flow_list in flow_dict.values():
            convert2ptp = False
            if len(flow_list) >= 2:
                convert2ptp = True
                for f in flow_list:
                    if f['actions'] != flow_list[0]['actions']:
                        convert2ptp = False
                        break
            if convert2ptp:  # add only one unified rule without dst_mac
                self.logger.debug("Convert flow rules to NON mac dst_address " + str(flow_list))
                flow_list[0].pop('dst_mac')
                flow_list[0]["priority"] -= 5
                new_flows2.append(flow_list[0])
            else:  # add all the rules
                new_flows2 += flow_list
        return new_flows2

    def _check_flow_already_present(self, new_flow, flow_list):
        '''check if the same flow is already present in the flow list
        The flow is repeated if all the fields, apart from name, are equal
        Return the index of matching flow, -1 if not match'''
        for index, flow in enumerate(flow_list):
            for f in self.flow_fields:
                if flow.get(f) != new_flow.get(f):
                    break
            else:
                return index
        return -1
