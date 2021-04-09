# -*- coding: utf-8 -*-

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
##

"""
This is the thread for the http server North API. 
Two thread will be launched, with normal and administrative permissions.
"""
import yaml
from uuid import uuid4
from http import HTTPStatus

__author__ = "Alfonso Tierno"
__date__ = "2019-10-22"
__version__ = "0.1"
version_date = "Oct 2019"


class SdnException(Exception):
    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST.value):
        self.http_code = http_code
        Exception.__init__(self, message)


class Sdn:

    def __init__(self, db, plugins):
        self.db = db
        self.plugins = plugins

    def start_service(self):
        pass  # TODO py3 needed to load wims and plugins

    def stop_service(self):
        pass  # nothing needed

    def show_network(self, uuid):
        pass

    def delete_network(self, uuid):
        pass

    def new_network(self, network):
        pass

    def get_openflow_rules(self, network_id=None):
        """
        Get openflow id from DB
        :param network_id: Network id, if none all networks will be retrieved
        :return: Return a list with Openflow rules per net
        """
        # ignore input data
        if not network_id:

            where_ = {}
        else:
            where_ = {"net_id": network_id}
        result, content = self.db.get_table(
            SELECT=("name", "net_id", "ofc_id", "priority", "vlan_id", "ingress_port", "src_mac", "dst_mac", "actions"),
            WHERE=where_, FROM='of_flows')

        if result < 0:
            raise SdnException(str(content), -result)
        return content

    def edit_openflow_rules(self, network_id=None):
        """
        To make actions over the net. The action is to reinstall the openflow rules
        network_id can be 'all'
        :param network_id: Network id, if none all networks will be retrieved
        :return : Number of nets updated
        """

        # ignore input data
        if not network_id:
            where_ = {}
        else:
            where_ = {"uuid": network_id}
        result, content = self.db.get_table(SELECT=("uuid", "type"), WHERE=where_, FROM='nets')

        if result < 0:
            raise SdnException(str(content), -result)

        for net in content:
            if net["type"] != "ptp" and net["type"] != "data":
                result -= 1
                continue

            try:
                self.net_update_ofc_thread(net['uuid'])
            except SdnException as e:
                raise SdnException("Error updating network'{}' {}".format(net['uuid'], e),
                                   HTTPStatus.INTERNAL_SERVER_ERROR.value)
            except Exception as e:
                raise SdnException("Error updating network '{}' {}".format(net['uuid'], e),
                                   HTTPStatus.INTERNAL_SERVER_ERROR.value)

        return result

    def delete_openflow_rules(self, ofc_id=None):
        """
        To make actions over the net. The action is to delete ALL openflow rules
        :return: return operation result
        """

        if not ofc_id:
            if 'Default' in self.config['ofcs_thread']:
                r, c = self.config['ofcs_thread']['Default'].insert_task("clear-all")
            else:
                raise SdnException("Default Openflow controller not not running", HTTPStatus.NOT_FOUND.value)

        elif ofc_id in self.config['ofcs_thread']:
            r, c = self.config['ofcs_thread'][ofc_id].insert_task("clear-all")

            # ignore input data
            if r < 0:
                raise SdnException(str(c), -r)
        else:
            raise SdnException("Openflow controller not found with ofc_id={}".format(ofc_id),
                               HTTPStatus.NOT_FOUND.value)
        return r

    def get_openflow_ports(self, ofc_id=None):
        """
        Obtain switch ports names of openflow controller
        :return: Return flow ports in DB
        """
        if not ofc_id:
            if 'Default' in self.config['ofcs_thread']:
                conn = self.config['ofcs_thread']['Default'].OF_connector
            else:
                raise SdnException("Default Openflow controller not not running", HTTPStatus.NOT_FOUND.value)

        elif ofc_id in self.config['ofcs_thread']:
            conn = self.config['ofcs_thread'][ofc_id].OF_connector
        else:
            raise SdnException("Openflow controller not found with ofc_id={}".format(ofc_id),
                               HTTPStatus.NOT_FOUND.value)
        return conn.pp2ofi

    def new_of_controller(self, ofc_data):
        """
        Create a new openflow controller into DB
        :param ofc_data: Dict openflow controller data
        :return: openflow controller uuid
        """
        db_wim = {
            "uuid": str(uuid4()),
            "name": ofc_data["name"],
            "description": ofc_data.get("description"),
            "type": ofc_data["type"],
            "wim_url": ofc_data.get("url"),
        }
        if not db_wim["wim_url"]:
            if not ofc_data.get("ip") or not ofc_data.get("port"):
                raise SdnException("Provide either 'url' or both 'ip' and 'port'")
            db_wim["wim_url"] = "{}:{}".format(ofc_data["ip"], ofc_data["port"])

        db_wim_account = {
            "uuid": str(uuid4()),
            "name": ofc_data["name"],
            "wim_id": db_wim["uuid"],
            "sdn": "true",
            "user": ofc_data.get("user"),
            "password": ofc_data.get("password"),
        }
        db_wim_account_config = ofc_data.get("config", {})
        if ofc_data.get("dpid"):
            db_wim_account_config["dpid"] = ofc_data["dpid"]
        if ofc_data.get("version"):
            db_wim_account_config["version"] = ofc_data["version"]

        db_wim_account["config"] = yaml.safe_dump(db_wim_account_config, default_flow_style=True, width=256)

        db_tables = [
            {"wims": db_wim},
            {"wim_accounts": db_wim_account},
        ]
        uuid_list = [db_wim["uuid"], db_wim_account["uuid"]]
        self.db.new_rows(db_tables, uuid_list)
        return db_wim_account["uuid"]

    def edit_of_controller(self, of_id, ofc_data):
        """
        Edit an openflow controller entry from DB
        :return:
        """
        if not ofc_data:
            raise SdnException("No data received during uptade OF contorller",
                               http_code=HTTPStatus.INTERNAL_SERVER_ERROR.value)

        # get database wim_accounts
        wim_account = self._get_of_controller(of_id)

        db_wim_update = {x: ofc_data[x] for x in ("name", "description", "type", "wim_url") if x in ofc_data}
        db_wim_account_update = {x: ofc_data[x] for x in ("name", "user", "password") if x in ofc_data}
        db_wim_account_config = ofc_data.get("config", {})

        if ofc_data.get("ip") or ofc_data.get("port"):
            if not ofc_data.get("ip") or not ofc_data.get("port"):
                raise SdnException("Provide or both 'ip' and 'port'")
            db_wim_update["wim_url"] = "{}:{}".format(ofc_data["ip"], ofc_data["port"])

        if ofc_data.get("dpid"):
            db_wim_account_config["dpid"] = ofc_data["dpid"]
        if ofc_data.get("version"):
            db_wim_account_config["version"] = ofc_data["version"]

        if db_wim_account_config:
            db_wim_account_update["config"] = yaml.load(wim_account["config"], Loader=yaml.Loader) or {}
            db_wim_account_update["config"].update(db_wim_account_config)
            db_wim_account_update["config"] = yaml.safe_dump(db_wim_account_update["config"], default_flow_style=True,
                                                             width=256)

        if db_wim_account_update:
            self.db.update_rows('wim_accounts', db_wim_account_update, WHERE={'uuid': of_id})
        if db_wim_update:
            self.db.update_rows('wims', db_wim_update, WHERE={'uuid': wim_account["wim_id"]})

    def _get_of_controller(self, of_id):
        wim_accounts = self.db.get_rows(FROM='wim_accounts', WHERE={"uuid": of_id, "sdn": "true"})

        if not wim_accounts:
            raise SdnException("Cannot find sdn controller with id='{}'".format(of_id),
                               http_code=HTTPStatus.NOT_FOUND.value)
        elif len(wim_accounts) > 1:
            raise SdnException("Found more than one sdn controller with id='{}'".format(of_id),
                               http_code=HTTPStatus.CONFLICT.value)
        return wim_accounts[0]

    def delete_of_controller(self, of_id):
        """
        Delete an openflow controller from DB.
        :param of_id: openflow controller dpid
        :return:
        """
        wim_account = self._get_of_controller(of_id)
        self.db.delete_row(FROM='wim_accounts', WHERE={"uuid": of_id})
        self.db.delete_row(FROM='wims', WHERE={"uuid": wim_account["wim_id"]})
        return of_id

    @staticmethod
    def _format_of_controller(wim_account, wim=None):
        of_data = {x: wim_account[x] for x in ("uuid", "name", "user")}
        if isinstance(wim_account["config"], str):
            config = yaml.load(wim_account["config"], Loader=yaml.Loader)
        of_data["dpid"] = config.get("switch_id") or config.get("dpid")
        of_data["version"] = config.get("version")
        if wim:
            of_data["url"] = wim["wim_url"]
            of_data["type"] = wim["type"]
        return of_data

    def show_of_controller(self, of_id):
        """
        Show an openflow controller by dpid from DB.
        :param db_filter: List with where query parameters
        :return:
        """
        wim_account = self._get_of_controller(of_id)
        wims = self.db.get_rows(FROM='wims', WHERE={"uuid": wim_account["wim_id"]})
        return self._format_of_controller(wim_account, wims[0])

    def get_of_controllers(self, filter=None):
        """
        Show an openflow controllers from DB.
        :return:
        """
        filter = filter or {}
        filter["sdn"] = "true"
        wim_accounts = self.db.get_rows(FROM='wim_accounts', WHERE=filter)
        return [self._format_of_controller(w) for w in wim_accounts]

    def set_of_port_mapping(self, maps, sdn_id, switch_dpid, vim_id):
        """
        Create new port mapping entry
        :param of_maps: List with port mapping information
        # maps =[{"ofc_id": <ofc_id>,"region": datacenter region,"compute_node": compute uuid,"pci": pci adress,
                "switch_dpid": swith dpid,"switch_port": port name,"switch_mac": mac}]
        :param sdn_id: ofc id
        :param switch_dpid: switch  dpid
        :param vim_id: datacenter
        :return:
        """
        # get wim from wim_account
        wim_account = self._get_of_controller(sdn_id)
        wim_id = wim_account["wim_id"]
        db_wim_port_mappings = []
        for map in maps:
            _switch_dpid = map.get("switch_id") or map.get("switch_dpid") or switch_dpid
            new_map = {
                'wim_id': wim_id,
                'switch_dpid': _switch_dpid,
                "switch_port": map.get("switch_port"),
                'datacenter_id': vim_id,
                "device_id": map.get("compute_node"),
                "service_endpoint_id": _switch_dpid + "-" + str(uuid4())
            }
            if map.get("pci"):
                new_map["device_interface_id"] = map["pci"].lower()
            config = {}
            if map.get("switch_mac"):
                config["switch_mac"] = map["switch_mac"]
            if config:
                new_map["service_mapping_info"] = yaml.safe_dump(config, default_flow_style=True, width=256)
            db_wim_port_mappings.append(new_map)

        db_tables = [
            {"wim_port_mappings": db_wim_port_mappings},
        ]
        self.db.new_rows(db_tables, [])
        return db_wim_port_mappings

    def clear_of_port_mapping(self, db_filter=None):
        """
        Clear port mapping filtering using db_filter dict
        :param db_filter: Parameter to filter during remove process
        :return:
        """
        return self.db.delete_row(FROM='wim_port_mappings', WHERE=db_filter)

    def get_of_port_mappings(self, db_filter=None):
        """
        Retrive port mapping from DB
        :param db_filter:
        :return:
        """
        maps = self.db.get_rows(WHERE=db_filter, FROM='wim_port_mappings')
        for map in maps:
            if map.get("service_mapping_info"):
                map["service_mapping_info"] = yaml.load(map["service_mapping_info"], Loader=yaml.Loader)
            else:
                map["service_mapping_info"] = {}
        return maps

    def get_ports(self, instance_wim_net_id):
        # get wim_id
        instance_wim_net = self.db.get_rows(FROM='instance_wim_nets', WHERE={"uuid": instance_wim_net_id})
        wim_id = instance_wim_net[0]["wim_id"]
        switch_ports = []
        ports = self.db.get_rows(FROM='instance_interfaces', WHERE={"instance_wim_net_id": instance_wim_net_id})
        maps = self.get_of_port_mappings(db_filter={"wim_id": wim_id})
        for port in ports:
            map_ = next((x for x in maps if x.get("device_id") == port["compute_node"] and
                         x.get("device_interface_id") == port["pci"]), None)
            if map_:
                switch_port = {'switch_dpid': map_.get('switch_dpid') or map_.get('switch_id'),
                               'switch_port': map_.get('switch_port')}
                if switch_port not in switch_ports:
                    switch_ports.append(switch_port)
        return switch_ports

