# -*- coding: utf-8 -*-

# Copyright 2018 Whitestack, LLC
# *************************************************************

# This file is part of OSM RO module
# All Rights Reserved to Whitestack, LLC

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# For those usages not covered by the Apache License, Version 2.0 please
# contact: bdiaz@whitestack.com or glavado@whitestack.com
##
import logging
import uuid
import copy

import requests
from requests.auth import HTTPBasicAuth

from osm_ro.wim.sdnconn import SdnConnectorBase, SdnConnectorError


class OnosVpls(SdnConnectorBase):
    """
    https://wiki.onosproject.org/display/ONOS/VPLS+User+Guide
    """
    _WIM_LOGGER = "sdn.assist.onos.vpls"

    def __init__(self, wim, wim_account, config=None, logger=None):
        self.logger = logger or logging.getLogger(self._WIM_LOGGER)
        super().__init__(wim, wim_account, config, logger)
        self.user = wim_account.get("user")
        self.password = wim_account.get("password")
        url = wim.get("wim_url")
        if not url:
            raise SdnConnectorError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url + "onos/v1/network/configuration"
        self.logger.info("ONOS VPLS Connector Initialized.")

    def check_credentials(self):
        status_code = 503
        onos_config_req = None
        try:
            onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
            onos_config_req.raise_for_status()
        except Exception as e:
            if onos_config_req:
                status_code = onos_config_req.status_code
            self.logger.exception('Error checking credentials')
            raise SdnConnectorError('Error checking credentials', http_code=status_code)

    def get_connectivity_service_status(self, service_uuid, conn_info=None):
        try:
            result = None
            onos_config = self._get_onos_netconfig()
            vpls_config = onos_config.get('apps', {}).get('org.onosproject.vpls')
            if vpls_config:
                for vpls in vpls_config.get('vpls', {}).get('vplsList'):
                    if vpls.get('name') == service_uuid:
                        return {'sdn_status': 'ACTIVE', 'sdn_info': vpls}

            return {'sdn_status': 'ERROR', 'sdn_info': 'not found'}

        except Exception as e:
            self.logger.error('Exception getting connectivity service info: %s', e)
            return {'sdn_status': 'ERROR', 'error_msg': str(e)}

    def _get_onos_netconfig(self):
        try:
            onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
            status_code = onos_config_req.status_code
            if status_code == requests.codes.ok:
                return onos_config_req.json()
            else:
                self.logger.info("Error obtaining network config, status code: {}".format(status_code))
                raise SdnConnectorError("Error obtaining network config status code: {}".format(status_code),
                                        http_code=status_code)
        except requests.exceptions.ConnectionError as e:
            self.logger.info('Exception connecting to onos: %s', e)
            raise SdnConnectorError("Error connecting to onos: {}".format(e))
        except Exception as e:
            self.logger.error('Exception getting onos network config: %s', e)
            raise SdnConnectorError("Exception getting onos network config: {}".format(e))

    def _post_onos_netconfig(self, onos_config):
        try:
            onos_config_resp = requests.post(self.url, json=onos_config, auth=HTTPBasicAuth(self.user, self.password))
            status_code = onos_config_resp.status_code
            if status_code != requests.codes.ok:
                self.logger.info("Error updating network config, status code: {}".format(status_code))
                raise SdnConnectorError("Error obtaining network config status code: {}".format(status_code),
                                        http_code=status_code)
        except requests.exceptions.ConnectionError as e:
            self.logger.info('Exception connecting to onos: %s', e)
            raise SdnConnectorError("Error connecting to onos: {}".format(e))
        except Exception as e:
            self.logger.info('Exception posting onos network config: %s', e)
            raise SdnConnectorError("Exception posting onos network config: {}".format(e))

    def create_connectivity_service(self, service_type, connection_points):
        self.logger.debug("create_connectivity_service, service_type: {}, connection_points: {}".
                          format(service_type, connection_points))
        if service_type.lower() != 'elan':
            raise SdnConnectorError('Only ELAN network type is supported by ONOS VPLS.')

        # FIXME ¿must check number of connection_points?
        service_uuid = str(uuid.uuid4())

        # Obtain current configuration
        onos_config_orig = self._get_onos_netconfig()
        #self.logger.debug("onos config: %s",  onos_config_orig)
        onos_config = copy.deepcopy(onos_config_orig)

        try:
            # Create missing interfaces
            created_ifs = self._create_missing_interfaces(connection_points, onos_config)
            self._post_onos_netconfig(onos_config)
            created_items = created_ifs

            # Add vpls service to config
            interfaces = [port.get("service_endpoint_id") for port in connection_points]
            if 'org.onosproject.vpls' in onos_config['apps']:
                if 'vpls' not in onos_config['apps']['org.onosproject.vpls']:
                    onos_config['apps']['org.onosproject.vpls']['vpls'] = {
                        'vplsList': []
                    }
                for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
                    if vpls['name'] == service_uuid:
                        raise SdnConnectorError('Network {} already exists.'.format(service_uuid))
                onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList'].append({
                    'name': service_uuid,
                    'interfaces': interfaces
                })
                self._pop_last_update_time(onos_config)
            else:
                onos_config['apps'] = {
                    'org.onosproject.vpls': {
                        'vpls': {
                            "vplsList": [
                                {
                                    'name': service_uuid,
                                    'interfaces': interfaces
                                }
                            ]
                        }
                    }
                }
            self._set_encapsulation(service_uuid, connection_points, onos_config)
            #self.logger.debug("original config: %s", onos_config_orig)
            #self.logger.debug("original config: %s", onos_config)
            self._post_onos_netconfig(onos_config)

            self.logger.debug("created connectivity_service, service_uuid: {}, created_items: {}".
                              format(service_uuid, created_items))
            return service_uuid, created_items
        except Exception as e:
            self.logger.error('Exception add connection_service: %s', e)
            # try to rollback push original config
            try:
                self._post_onos_netconfig(onos_config_orig)
            except Exception as e:
                self.logger.error('Exception rolling back to original config: %s', e)
            # raise exception
            if isinstance(e, SdnConnectorError):
                raise
            else:
                raise SdnConnectorError("Exception create_connectivity_service: {}".format(e))

    def _set_encapsulation(self, service_uuid, connection_points, onos_config):

        # check if encapsulation is vlan, check just one connection point
        encapsulation = None
        for connection_point in connection_points:
            if connection_point.get("service_endpoint_encapsulation_type") == "dot1q":
                encapsulation = "VLAN"
                break
        # if encapsulation is defined, assign
        if encapsulation:
            #self.logger.debug("assign encapsulation")
            for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
                if vpls['name'] == service_uuid:
                    vpls['encapsulation'] = encapsulation

    def edit_connectivity_service(self, service_uuid,
                                  conn_info, connection_points,
                                  **kwargs):
        raise SdnConnectorError('Not supported', http_code=501)

    def delete_connectivity_service(self, service_uuid, conn_info=None):
        self.logger.debug("delete_connectivity_service uuid: {}".format(service_uuid))

        conn_info = conn_info or []
        # Obtain current config
        onos_config = self._get_onos_netconfig()

        try:
            # created_interfaces
            created_ifs = [item[1] for item in conn_info]

            # Removes ports used by network from onos config
            for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
                if vpls['name'] == service_uuid:
                    # iterate interfaces to check if must delete them
                    for interface in vpls['interfaces']:
                        for port in onos_config['ports'].values():
                            for port_interface in port['interfaces']:
                                if port_interface['name'] == interface:
                                    # Delete only created ifzs
                                    if port_interface['name'] in created_ifs:
                                        self.logger.debug("Delete ifz: {}".format(port_interface['name']))
                                        port['interfaces'].remove(port_interface)
                    onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList'].remove(vpls)
                    break
            else:
                raise SdnConnectorError("service uuid: {} does not exist".format(service_uuid))

            self._post_onos_netconfig(onos_config)
            self.logger.debug("deleted connectivity service uuid: {}".format(service_uuid))
        except Exception as e:
            if isinstance(e, SdnConnectorError):
                raise
            else:
                self.logger.error('Exception delete connection_service: %s', e, exc_info=True)
                raise SdnConnectorError("Exception create_connectivity_service: {}".format(str(e)))

    def _delete_network_port(self, net_id, port):
        onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
        onos_config_req.raise_for_status()
        onos_config = onos_config_req.json()
        for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
            if vpls['name'] == net_id:
                for interface in vpls['interfaces']:
                    if interface == port['service_endpoint_id']:
                        vpls['interfaces'].remove(interface)
                        break
        for onos_port in onos_config['ports'].values():
            for port_interface in onos_port['interfaces']:
                if port_interface['name'] == port['service_endpoint_id']:
                    onos_port['interfaces'].remove(port_interface)
                    break
        self._pop_last_update_time(onos_config)
        response = requests.post(self.url, json=onos_config, auth=HTTPBasicAuth(self.user, self.password))
        response.raise_for_status()

    def _pop_last_update_time(self, onos_config):
        onos_config['apps']['org.onosproject.vpls']['vpls'].pop('lastUpdateTime', None)

    def _create_missing_interfaces(self,connection_points, onos_config):
        created_ifs = []
        for port in connection_points:
            created_ifz = self._append_port_to_onos_config(port, onos_config)
            if created_ifz:
                created_ifs.append(created_ifz)
        return created_ifs

    def _append_port_to_onos_config(self, port, onos_config):
        created_item = None
        port_name = 'of:{}/{}'.format(port['service_endpoint_encapsulation_info']['switch_dpid'],
                                        port['service_endpoint_encapsulation_info']['switch_port'])
        interface_config = {'name': port['service_endpoint_id']}
        if 'vlan' in port['service_endpoint_encapsulation_info'] \
                and port['service_endpoint_encapsulation_info']['vlan']:
            interface_config['vlan'] = port['service_endpoint_encapsulation_info']['vlan']
        if port_name in onos_config['ports'] and 'interfaces' in onos_config['ports'][port_name]:
            for interface in onos_config['ports'][port_name]['interfaces']:
                if interface['name'] == port['service_endpoint_id']:
                    #self.logger.debug("interface with same name and port exits")
                    # interface already exists TODO ¿check vlan? ¿delete and recreate?
                    # by the moment use and do not touch
                    #onos_config['ports'][port_name]['interfaces'].remove(interface)
                    break
            else:
                #self.logger.debug("port with same name exits but not interface")
                onos_config['ports'][port_name]['interfaces'].append(interface_config)
                created_item = (port_name, port['service_endpoint_id'])
        else:
            #self.logger.debug("create port and interface")
            onos_config['ports'][port_name] = {
                'interfaces': [interface_config]
            }
            created_item = (port_name, port['service_endpoint_id'])
        return created_item


if __name__ == '__main__':
    logger = logging.getLogger('openmano.sdn.onos_vpls')
    logging.basicConfig()
    logger.setLevel(getattr(logging, "DEBUG"))
    # wim_url = "http://10.95.172.251:8181"
    wim_url = "http://192.168.56.106:8181"
    user = "karaf"
    password = "karaf"
    wim = {'wim_url': wim_url}
    wim_account = {'user': user, 'password': password}
    onos_vpls = OnosVpls(wim=wim, wim_account=wim_account, logger=logger)
    conn_service = onos_vpls.get_connectivity_service_status("4e1f4c8a-a874-425d-a9b5-955cb77178f8")
    print(conn_service)
    service_type = 'ELAN'
    conn_point_0 = {
        "service_endpoint_id": "switch1_ifz2",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000011",
            "switch_port": "1",
            "vlan": "600"
        }
    }
    conn_point_1 = {
        "service_endpoint_id": "switch3_ifz2",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000031",
            "switch_port": "3",
            "vlan": "600"
        }
    }
    connection_points = [conn_point_0, conn_point_1]
    #service_uuid, created_items = onos_vpls.create_connectivity_service(service_type, connection_points)
    #print(service_uuid)
    #print(created_items)

    #conn_info = None
    conn_info = [('of:0000000000000011/1', 'switch1_ifz2'), ('of:0000000000000031/3', 'switch3_ifz2')]
    onos_vpls.delete_connectivity_service("3a6a752e-8153-4b89-8b43-a7cebe0f0628", conn_info)
