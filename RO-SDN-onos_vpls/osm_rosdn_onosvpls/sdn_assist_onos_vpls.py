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

import requests
from requests.auth import HTTPBasicAuth

from osm_ro.wim.sdnconn import SdnConnectorBase, SdnConnectorError

log = logging.getLogger(__name__)


class OnosVpls(SdnConnectorBase):
    """
    https://wiki.onosproject.org/display/ONOS/VPLS+User+Guide
    """

    def __init__(self, wim, wim_account, config=None, logger=None):

        super().__init__(wim, wim_account, config, log)
        self.user = wim_account.get("user")
        self.password = wim_account.get("password")
        url = wim_account.get("wim_url")
        if not url:
            raise ValueError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url + "onos/v1/network/configuration"
        log.info("ONOS VPLS Connector Initialized.")

    def check_credentials(self):
        status_code = 503
        onos_config_req = None
        try:
            onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
            onos_config_req.raise_for_status()
        except Exception as e:
            if onos_config_req:
                status_code = onos_config_req.status_code
            log.exception('Error checking credentials')
            raise SdnConnectorError('Error checking credentials', http_code=status_code)

    def get_connectivity_service_status(self, service_uuid, conn_info=None):
        onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
        onos_config_req.raise_for_status()
        onos_config = onos_config_req.json()
        for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
            if vpls['name'] == service_uuid:
                return vpls
        raise SdnConnectorError('VPLS %s not found' % service_uuid, http_code=404)

    def create_connectivity_service(self, service_type, connection_points):
        if service_type.lower() != 'elan':
            raise SdnConnectorError('Only ELAN network type is supported by ONOS VPLS.')
        onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
        onos_config_req.raise_for_status()
        onos_config = onos_config_req.json()
        service_uuid = uuid.uuid4()

        if 'org.onosproject.vpls' in onos_config['apps']:
            if 'vpls' not in onos_config['apps']['org.onosproject.vpls']:
                onos_config['apps']['org.onosproject.vpls']['vpls'] = {
                    'vplsList': []
                }
            for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
                if vpls['name'] == service_uuid:
                    raise SdnConnectorError('Network %s already exists.' % service_uuid)
            onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList'].append({
                'name': service_uuid,
                'interfaces': []
            })
            self._pop_last_update_time(onos_config)
        else:
            onos_config['apps'] = {
                'org.onosproject.vpls': {
                    'vpls': {
                        "vplsList": [
                            {
                                'name': service_uuid,
                                'interfaces': []
                            }
                        ]
                    }
                }
            }
        response = requests.post(self.url, json=onos_config, auth=HTTPBasicAuth(self.user, self.password))
        log.info(onos_config)
        response.raise_for_status()
        for connection_point in connection_points:
            self._add_network_port(service_uuid, connection_point)
        return service_uuid, onos_config

    def edit_connectivity_service(self, service_uuid,
                                  conn_info, connection_points,
                                  **kwargs):
        raise SdnConnectorError('Not supported', http_code=501)

    def delete_connectivity_service(self, service_uuid, conn_info=None):
        onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
        onos_config_req.raise_for_status()
        onos_config = onos_config_req.json()
        # Removes ports used by network from onos config
        for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
            if vpls['name'] == service_uuid:
                for interface in vpls['interfaces']:
                    for port in onos_config['ports'].values():
                        for port_interface in port['interfaces']:
                            if port_interface['name'] == interface:
                                port['interfaces'].remove(port_interface)
                onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList'].remove(vpls)
                break
        self._pop_last_update_time(onos_config)
        response = requests.post(self.url, json=onos_config, auth=HTTPBasicAuth(self.user, self.password))
        response.raise_for_status()

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

    def _add_network_port(self, net_id, port):
        onos_config_req = requests.get(self.url, auth=HTTPBasicAuth(self.user, self.password))
        onos_config_req.raise_for_status()
        onos_config = onos_config_req.json()
        self._append_port_to_onos_config(port, onos_config)
        # Interfaces need to be registered before adding them to VPLS
        response = requests.post(self.url, json=onos_config, auth=HTTPBasicAuth(self.user, self.password))
        response.raise_for_status()
        for vpls in onos_config['apps']['org.onosproject.vpls']['vpls']['vplsList']:
            if vpls['name'] == net_id:
                vpls['interfaces'].append(port['service_endpoint_id'])
                break
        self._pop_last_update_time(onos_config)
        response = requests.post(self.url, json=onos_config, auth=HTTPBasicAuth(self.user, self.password))
        response.raise_for_status()

    def _pop_last_update_time(self, onos_config):
        if 'lastUpdateTime' in onos_config['apps']['org.onosproject.vpls']['vpls']:
            onos_config['apps']['org.onosproject.vpls']['vpls'].pop('lastUpdateTime')

    def _append_port_to_onos_config(self, port, onos_config):
        port_name = 'of:%s/%s' % (port['service_endpoint_encapsulation_info']['switch_dpid'],
                                  port['service_endpoint_encapsulation_info']['switch_port'])
        interface_config = {'name': port['service_endpoint_id']}
        if 'vlan' in port['service_endpoint_encapsulation_info'] and port['service_endpoint_encapsulation_info'][
            'vlan']:
            interface_config['vlan'] = port['service_endpoint_encapsulation_info']['vlan']
        if port_name in onos_config['ports'] and 'interfaces' in onos_config['ports'][port_name]:
            for interface in onos_config['ports'][port_name]['interfaces']:
                if interface['name'] == port['service_endpoint_id']:
                    onos_config['ports'][port_name]['interfaces'].remove(interface)
            onos_config['ports'][port_name]['interfaces'].append(interface_config)
        else:
            onos_config['ports'][port_name] = {
                'interfaces': [interface_config]
            }


if __name__ == '__main__':
    pass
    # host = '198.204.228.85'
    # port = 8181
    # onos_vpls = OnosVpls(host, port, 'onos', 'rocks')
    # ports = [
    #     {
    #         'uuid': '0a43961d',
    #         'switch_dpid': '0000000000000001',
    #         'switch_port': '1',
    #         'vlan': 100
    #     },
    #     {
    #         'uuid': 'ade3eefc',
    #         'switch_dpid': '0000000000000003',
    #         'switch_port': '1',
    #         'vlan': 100
    #     }
    # ]
    # onos_vpls.create_network('94979b37-3875-4f77-b620-01ff78f9c4fa', 'data')
    # onos_vpls.add_network_port('94979b37-3875-4f77-b620-01ff78f9c4fa', ports[0])
    # onos_vpls.add_network_port('94979b37-3875-4f77-b620-01ff78f9c4fa', ports[1])
    # onos_vpls.delete_network_port('94979b37-3875-4f77-b620-01ff78f9c4fa', ports[1])
    # onos_vpls.delete_network('94979b37-3875-4f77-b620-01ff78f9c4fa')
