# -*- coding: utf-8 -*-

# Copyright 2020 ETSI OSM
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
#

import logging
import uuid
import copy
import json
import yaml

#import requests
#from requests.auth import HTTPBasicAuth
from osm_ro.wim.sdnconn import SdnConnectorBase, SdnConnectorError
from osm_rosdn_juniper_contrail.rest_lib import Http

from io import BytesIO
import pycurl


class JuniperContrail(SdnConnectorBase):
    """
    Juniper Contrail SDN plugin. The plugin interacts with Juniper Contrail Controller,
    whose API details can be found in these links:

    - https://github.com/tonyliu0592/contrail/wiki/API-Configuration-REST
    - https://www.juniper.net/documentation/en_US/contrail19/information-products/pathway-pages/api-guide-1910/tutorial_with_rest.html
    - https://github.com/tonyliu0592/contrail-toolbox/blob/master/sriov/sriov
    """
    _WIM_LOGGER = "openmano.sdnconn.junipercontrail"

    def __init__(self, wim, wim_account, config=None, logger=None):
        """

        :param wim: (dict). Contains among others 'wim_url'
        :param wim_account: (dict). Contains among others 'uuid' (internal id), 'name',
            'sdn' (True if is intended for SDN-assist or False if intended for WIM), 'user', 'password'.
        :param config: (dict or None): Particular information of plugin. These keys if present have a common meaning:
            'mapping_not_needed': (bool) False by default or if missing, indicates that mapping is not needed.
            'service_endpoint_mapping': (list) provides the internal endpoint mapping. The meaning is:
                KEY                     meaning for WIM                 meaning for SDN assist
                --------                --------                    --------
                device_id                       pop_switch_dpid                 compute_id
                device_interface_id             pop_switch_port                 compute_pci_address
                service_endpoint_id         wan_service_endpoint_id     SDN_service_endpoint_id
                service_mapping_info    wan_service_mapping_info    SDN_service_mapping_info
                    contains extra information if needed. Text in Yaml format
                switch_dpid                     wan_switch_dpid                 SDN_switch_dpid
                switch_port                     wan_switch_port                 SDN_switch_port
                datacenter_id           vim_account                 vim_account
                id: (internal, do not use)
                wim_id: (internal, do not use)
        :param logger (logging.Logger): optional logger object. If none is passed 'openmano.sdn.sdnconn' is used.
        """
        self.logger = logger or logging.getLogger(self._WIM_LOGGER)
        self.logger.debug('wim: {}, wim_account: {}, config: {}'.format(wim, wim_account, config))
        super().__init__(wim, wim_account, config, logger)

        self.user = wim_account.get("user")
        self.password = wim_account.get("password")

        url = wim.get("wim_url")
        auth_url = None
        overlay_url = None
        self.project = None
        self.domain = None
        self.asn = None
        self.fabric = None
        self.vni_range = None
        if config:
            auth_url = config.get("auth_url")
            overlay_url = config.get("overlay_url")
            self.project = config.get("project")
            self.domain = config.get("domain")
            self.asn = config.get("asn")
            self.fabric = config.get("fabric")
            self.vni_range = config.get("vni_range")

        if not url:
            raise SdnConnectorError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url

        if not self.project:
            raise SdnConnectorError("'project' must be provided")
        if not self.asn:
            # TODO: Get ASN from controller config; otherwise raise ERROR for the moment
            raise SdnConnectorError("'asn' was not provided and was not possible to obtain it")
        if not self.fabric:
            # TODO: Get FABRIC from controller config; otherwise raise ERROR for the moment
            raise SdnConnectorError("'fabric' was not provided and was not possible to obtain it")
        if not self.domain:
            self.domain = 'default'
            self.logger.info("No domain was provided. Using 'default'")
        if not self.vni_range:
            self.vni_range = ['1000001-2000000']
            self.logger.info("No vni_range was provided. Using ['1000001-2000000']")
        self.used_vni = set()

        if overlay_url:
            if not overlay_url.startswith("http"):
                overlay_url = "http://" + overlay_url
            if not overlay_url.endswith("/"):
                overlay_url = overlay_url + "/"
        self.overlay_url = overlay_url

        if auth_url:
            if not auth_url.startswith("http"):
                auth_url = "http://" + auth_url
            if not auth_url.endswith("/"):
                auth_url = auth_url + "/"
        self.auth_url = auth_url

        # Init http lib
        self.http = Http(self.logger)

        # Init http headers for all requests
        self.headers = {'Content-Type': 'application/json'}
        self.http_header = ['{}: {}'.format(key, val)
                           for (key, val) in list(self.headers.items())]

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
        self.token = None

        self.logger.info("Juniper Contrail Connector Initialized.")


    def _generate_vni(self):
        """
         Method to get unused VxLAN Network Identifier (VNI)
            Args:
                None
            Returns:
                VNI
        """
        #find unused VLAN ID
        for vlanID_range in self.vni_range:
            try:
                start_vni , end_vni = map(int, vlanID_range.replace(" ", "").split("-"))
                for vni in range(start_vni, end_vni + 1):
                    if vni not in self.used_vni:
                        return vni
            except Exception as exp:
                raise SdnConnectorError("Exception {} occurred while searching a free VNI.".format(exp))
        else:
            raise SdnConnectorError("Unable to create the virtual network."\
                " All VNI in VNI range {} are in use.".format(self.vni_range))


    def _get_token(self):
        self.logger.debug('Current Token:'.format(str(self.token)))
        auth_url = self.auth_url + 'auth/tokens'
        if self.token is None:
            if not self.auth_url:
                self.token = ""
            http_code, resp = self.http.post_cmd(url=auth_url, headers=self.http_header,
                                                 postfields_dict=self.auth_dict,
                                                 return_header = 'x-subject-token')
            self.token = resp
            self.logger.debug('Token: '.format(self.token))

            if self.token:
                self.headers['X-Auth-Token'] = self.token
            else:
                self.headers.pop('X-Auth-Token', None)
            http_header = ['{}: {}'.format(key, val)
                           for (key, val) in list(self.headers.items())]

    
    # Aux functions for testing
    def get_url(self):
        return self.url


    def get_overlay_url(self):
        return self.overlay_url

    # Virtual network operations

    def _create_virtual_network(self, controller_url, name, vni):
        routetarget = '{}:{}'.format(self.asn,vni)
        vnet_dict = {
                        "virtual-network": {
                            "virtual_network_properties": {
                                "vxlan_network_identifier": vni,
                            },
                            "parent_type": "project",
                            "fq_name": [
                                "default-domain",
                                "admin",
                                name
                            ],
                            "route_target_list": {
                                "route_target": [
                                    "target:" + routetarget
                                ]
                            }
                        }
                    }
        self._get_token()
        endpoint = controller_url + 'virtual-networks'
        http_code, resp = self.http.post_cmd(url = endpoint,
                                             headers = self.http_header,
                                             postfields_dict = vnet_dict)
        if http_code not in (200, 201, 202, 204) or not resp:
           raise SdnConnectorError('Unexpected http status code, or empty response')
        vnet_info = json.loads(resp)
        self.logger.debug("vnet_info: {}".format(vnet_info))
        return vnet_info.get("virtual-network").get('uuid'), vnet_info.get("virtual-network")


    def _get_virtual_networks(self, controller_url):
        self._get_token()
        endpoint = controller_url + 'virtual-networks'
        print(endpoint)
        http_code, resp = self.http.get_cmd(url=endpoint, headers=self.http_header)
        if http_code not in (200, 201, 202, 204) or not resp:
            raise SdnConnectorError('Unexpected http status code, or empty response')
        vnets_info = json.loads(resp)
        self.logger.debug("vnets_info: {}".format(vnets_info))
        return vnets_info.get('virtual-networks')


    def _get_virtual_network(self, controller_url, network_id):
        self._get_token()
        endpoint = controller_url + 'virtual-network/{}'.format(network_id)
        http_code, resp = self.http.get_cmd(url=endpoint, headers=self.http_header)
        if http_code not in (200, 201, 202, 204) or not resp:
            if http_code == 404:
                return None
            raise SdnConnectorError('Unexpected http status code, or empty response')
        vnet_info = json.loads(resp)
        self.logger.debug("vnet_info: {}".format(vnet_info))
        return vnet_info.get("virtual-network")


    def _delete_virtual_network(self, controller_url, network_id):
        self._get_token()
        endpoint = controller_url + 'virtual-network/{}'.format(network_id)
        http_code, _ = self.http.delete_cmd(url=endpoint, headers=self.http_header)
        if http_code not in (200, 201, 202, 204):
            raise SdnConnectorError('Unexpected http status code')
        return


    # Virtual port group operations

    def _create_vpg(self, controller_url, switch_id, switch_port, network, vlan):
        vpg_dict = {
                       "virtual-port-group": {
                       }
                   }
        self._get_token()
        endpoint = controller_url + 'virtual-port-groups'
        http_code, resp = self.http.post_cmd(url = endpoint,
                                               headers = self.http_header,
                                               postfields_dict = vpg_dict)
        if http_code not in (200, 201, 202, 204) or not resp:
           raise SdnConnectorError('Unexpected http status code, or empty response')
        vpg_info = json.loads(resp)
        self.logger.debug("vpg_info: {}".format(vpg_info))
        return vpg_info.get("virtual-port-group").get('uuid'), vpg_info.get("virtual-port-group")


    def _get_vpgs(self, controller_url):
        self._get_token()
        endpoint = controller_url + 'virtual-port-groups'
        http_code, resp = self.http.get_cmd(url=endpoint, headers=self.http_header)
        if http_code not in (200, 201, 202, 204) or not resp:
            raise SdnConnectorError('Unexpected http status code, or empty response')
        vpgs_info = json.loads(resp)
        self.logger.debug("vpgs_info: {}".format(vpgs_info))
        return vpgs_info.get('virtual-port-groups')


    def _get_vpg(self, controller_url, vpg_id):
        self._get_token()
        endpoint = controller_url + 'virtual-port-group/{}'.format(vpg_id)
        http_code, resp = self.http.get_cmd(url=endpoint, headers=self.http_header)
        if http_code not in (200, 201, 202, 204) or not resp:
            if http_code == 404:
                return None
            raise SdnConnectorError('Unexpected http status code, or empty response')
        vpg_info = json.loads(resp)
        self.logger.debug("vpg_info: {}".format(vpg_info))
        return vpg_info.get("virtual-port-group")


    def _delete_vpg(self, controller_url, vpg_id):
        self._get_token()
        endpoint = controller_url + 'virtual-port-group/{}'.format(vpg_id)
        http_code, resp = self.http.delete_cmd(url=endpoint, headers=self.http_header)
        if http_code not in (200, 201, 202, 204):
            raise SdnConnectorError('Unexpected http status code')
        return


    def check_credentials(self):
        """Check if the connector itself can access the SDN/WIM with the provided url (wim.wim_url),
            user (wim_account.user), and password (wim_account.password)

        Raises:
            SdnConnectorError: Issues regarding authorization, access to
                external URLs, etc are detected.
        """
        self.logger.debug("")
        self._get_token()
        try:
            http_code, resp = self.http.get_cmd(url=self.auth_url, headers=self.http_header)
            if http_code not in (200, 201, 202, 204) or not resp:
                raise SdnConnectorError('Unexpected http status code, or empty response')
        except Exception as e:
            self.logger.error('Error checking credentials')
            raise SdnConnectorError('Error checking credentials', http_code=http_code)


    def get_connectivity_service_status(self, service_uuid, conn_info=None):
        """Monitor the status of the connectivity service established

        Arguments:
            service_uuid (str): UUID of the connectivity service
            conn_info (dict or None): Information returned by the connector
                during the service creation/edition and subsequently stored in
                the database.

        Returns:
            dict: JSON/YAML-serializable dict that contains a mandatory key
                ``sdn_status`` associated with one of the following values::

                    {'sdn_status': 'ACTIVE'}
                        # The service is up and running.

                    {'sdn_status': 'INACTIVE'}
                        # The service was created, but the connector
                        # cannot determine yet if connectivity exists
                        # (ideally, the caller needs to wait and check again).

                    {'sdn_status': 'DOWN'}
                        # Connection was previously established,
                        # but an error/failure was detected.

                    {'sdn_status': 'ERROR'}
                        # An error occurred when trying to create the service/
                        # establish the connectivity.

                    {'sdn_status': 'BUILD'}
                        # Still trying to create the service, the caller
                        # needs to wait and check again.

                Additionally ``error_msg``(**str**) and ``sdn_info``(**dict**)
                keys can be used to provide additional status explanation or
                new information available for the connectivity service.
        """
        self.logger.debug("")
        self._get_token()
        try:
            http_code, resp = self.http.get_cmd(endpoint='virtual-network/{}'.format(service_uuid))
            if http_code not in (200, 201, 202, 204) or not resp:
                raise SdnConnectorError('Unexpected http status code, or empty response')
            if resp:
                vnet_info = json.loads(resp)
                return {'sdn_status': 'ACTIVE', 'sdn_info': vnet_info['virtual-network']}
            else:
                return {'sdn_status': 'ERROR', 'sdn_info': 'not found'}
        except Exception as e:
            self.logger.error('Exception getting connectivity service info: %s', e)
            return {'sdn_status': 'ERROR', 'error_msg': str(e)}


    def create_connectivity_service(self, service_type, connection_points, **kwargs):
        """
        Establish SDN/WAN connectivity between the endpoints
        :param service_type: (str): ``ELINE`` (L2), ``ELAN`` (L2), ``ETREE`` (L2), ``L3``.
        :param connection_points:  (list): each point corresponds to
            an entry point to be connected. For WIM: from the DC to the transport network.
            For SDN: Compute/PCI to the transport network. One
            connection point serves to identify the specific access and
            some other service parameters, such as encapsulation type.
            Each item of the list is a dict with:
                "service_endpoint_id": (str)(uuid)  Same meaning that for 'service_endpoint_mapping' (see __init__)
                    In case the config attribute mapping_not_needed is True, this value is not relevant. In this case
                    it will contain the string "device_id:device_interface_id"
                "service_endpoint_encapsulation_type": None, "dot1q", ...
                "service_endpoint_encapsulation_info": (dict) with:
                    "vlan": ..., (int, present if encapsulation is dot1q)
                    "vni": ... (int, present if encapsulation is vxlan),
                    "peers": [(ipv4_1), (ipv4_2)] (present if encapsulation is vxlan)
                    "mac": ...
                    "device_id": ..., same meaning that for 'service_endpoint_mapping' (see __init__)
                    "device_interface_id": same meaning that for 'service_endpoint_mapping' (see __init__)
                    "switch_dpid": ..., present if mapping has been found for this device_id,device_interface_id
                    "switch_port": ... present if mapping has been found for this device_id,device_interface_id
                    "service_mapping_info": present if mapping has been found for this device_id,device_interface_id
        :param kwargs: For future versions:
            bandwidth (int): value in kilobytes
            latency (int): value in milliseconds
            Other QoS might be passed as keyword arguments.
        :return: tuple: ``(service_id, conn_info)`` containing:
            - *service_uuid* (str): UUID of the established connectivity service
            - *conn_info* (dict or None): Information to be stored at the database (or ``None``).
                This information will be provided to the :meth:`~.edit_connectivity_service` and :obj:`~.delete`.
                **MUST** be JSON/YAML-serializable (plain data structures).
        :raises: SdnConnectorException: In case of error. Nothing should be created in this case.
            Provide the parameter http_code
        """
        self.logger.debug("create_connectivity_service, service_type: {}, connection_points: {}".
                          format(service_type, connection_points))
        if service_type.lower() != 'elan':
            raise SdnConnectorError('Only ELAN network type is supported by Juniper Contrail.')

        # Step 1. Check in the overlay controller the virtual network created by the VIM
        #   Best option: get network id of the VIM as param (if the VIM already created the network),
        #    and do a request to the controller of the virtual networks whose VIM network id is the provided
        #   Next best option: obtain the network by doing a request to the controller
        #    of the virtual networks using the VLAN ID of any service endpoint.
        #   1.1 Read VLAN ID from a service endpoint
        #   1.2 Look for virtual networks with "Provider Network" including a VLAN ID.
        #   1.3 If more than one, ERROR
        # Step 2. Modify the existing virtual network in the overlay controller
        #   2.1 Add VNI (VxLAN Network Identifier - one free from the provided range)
        #   2.2 Add RouteTarget (RT) ('ASN:VNI', ASN = Autonomous System Number, provided as param or read from controller config)
        # Step 3. Create a virtual network in the underlay controller
        #   3.1 Create virtual network (name, VNI, RT)
        #      If the network already existed in the overlay controller, we should use the same name
        #         name = 'osm-plugin-' + overlay_name
        #      Else:
        #         name = 'osm-plugin-' + VNI
        try:
            name = 'test-test-1'
            vni = 999999
            network_id, network_info = self._create_virtual_network(self.url, name, vni)
        except SdnConnectorError:
            raise SdnConnectorError('Failed to create connectivity service {}'.format(name))
        except Exception as e:
            self.logger.error('Exception creating connection_service: %s', e, exc_info=True)
            raise SdnConnectorError("Exception creating connectivity service: {}".format(str(e)))
        return service_id


    def edit_connectivity_service(self, service_uuid, conn_info = None, connection_points = None, **kwargs):
        """ Change an existing connectivity service.

        This method's arguments and return value follow the same convention as
        :meth:`~.create_connectivity_service`.

        :param service_uuid: UUID of the connectivity service.
        :param conn_info: (dict or None): Information previously returned by last call to create_connectivity_service
            or edit_connectivity_service
        :param connection_points: (list): If provided, the old list of connection points will be replaced.
        :param kwargs: Same meaning that create_connectivity_service
        :return: dict or None: Information to be updated and stored at the database.
                When ``None`` is returned, no information should be changed.
                When an empty dict is returned, the database record will be deleted.
                **MUST** be JSON/YAML-serializable (plain data structures).
        Raises:
            SdnConnectorException: In case of error.
        """
        #TODO: to be done. This comes from ONOS VPLS plugin
        self.logger.debug("edit connectivity service, service_uuid: {}, conn_info: {}, "
                          "connection points: {} ".format(service_uuid, conn_info, connection_points))

        conn_info = conn_info or []
        # Obtain current configuration
        config_orig = self._get_onos_netconfig()
        config = copy.deepcopy(config_orig)

        # get current service data and check if it does not exists
        #TODO: update
        for vpls in config.get('apps', {}).get('org.onosproject.vpls', {}).get('vpls', {}).get('vplsList', {}):
            if vpls['name'] == service_uuid:
                self.logger.debug("service exists")
                curr_interfaces = vpls.get("interfaces", [])
                curr_encapsulation = vpls.get("encapsulation")
                break
        else:
            raise SdnConnectorError("service uuid: {} does not exist".format(service_uuid))

        self.logger.debug("current interfaces: {}".format(curr_interfaces))
        self.logger.debug("current encapsulation: {}".format(curr_encapsulation))

        # new interfaces names
        new_interfaces = [port['service_endpoint_id'] for port in new_connection_points]

        # obtain interfaces to delete, list will contain port
        ifs_delete = list(set(curr_interfaces) - set(new_interfaces))
        ifs_add = list(set(new_interfaces) - set(curr_interfaces))
        self.logger.debug("interfaces to delete: {}".format(ifs_delete))
        self.logger.debug("interfaces to add: {}".format(ifs_add))

        # check if some data of the interfaces that already existed has changed
        # in that case delete it and add it again
        ifs_remain = list(set(new_interfaces) & set(curr_interfaces))
        for port in connection_points:
            if port['service_endpoint_id'] in ifs_remain:
                # check if there are some changes
                curr_port_name, curr_vlan = self._get_current_port_data(config, port['service_endpoint_id'])
                new_port_name = 'of:{}/{}'.format(port['service_endpoint_encapsulation_info']['switch_dpid'],
                                        port['service_endpoint_encapsulation_info']['switch_port'])
                new_vlan = port['service_endpoint_encapsulation_info']['vlan']
                if (curr_port_name != new_port_name or curr_vlan != new_vlan):
                    self.logger.debug("TODO: must update data interface: {}".format(port['service_endpoint_id']))
                    ifs_delete.append(port['service_endpoint_id'])
                    ifs_add.append(port['service_endpoint_id'])

        new_encapsulation = self._get_encapsulation(connection_points)

        try:
            # Delete interfaces, only will delete interfaces that are in provided conn_info
            # because these are the ones that have been created for this service
            if ifs_delete:
                for port in config['ports'].values():
                    for port_interface in port['interfaces']:
                        interface_name = port_interface['name']
                        self.logger.debug("interface name: {}".format(port_interface['name']))
                        if interface_name in ifs_delete and interface_name in conn_info:
                            self.logger.debug("delete interface name: {}".format(interface_name))
                            port['interfaces'].remove(port_interface)
                            conn_info.remove(interface_name)

            # Add new interfaces
            for port in connection_points:
                if port['service_endpoint_id'] in ifs_add:
                    created_ifz = self._append_port_to_config(port, config)
                    if created_ifz:
                        conn_info.append(created_ifz[1])
            self._pop_last_update_time(config)
            self._post_netconfig(config)

            self.logger.debug("contrail config after updating interfaces: {}".format(config))
            self.logger.debug("conn_info after updating interfaces: {}".format(conn_info))

            # Update interfaces list in vpls service
            for vpls in config.get('apps', {}).get('org.onosproject.vpls', {}).get('vpls', {}).get('vplsList', {}):
                if vpls['name'] == service_uuid:
                    vpls['interfaces'] = new_interfaces
                    vpls['encapsulation'] = new_encapsulation

            self._pop_last_update_time(config)
            self._post_netconfig(config)
            return conn_info
        except Exception as e:
            self.logger.error('Exception add connection_service: %s', e)
            # try to rollback push original config
            try:
                self._post_netconfig(config_orig)
            except Exception as e2:
                self.logger.error('Exception rolling back to original config: %s', e2)
            # raise exception
            if isinstance(e, SdnConnectorError):
                raise
            else:
                raise SdnConnectorError("Exception create_connectivity_service: {}".format(e))


    def delete_connectivity_service(self, service_uuid, conn_info=None):
        """
        Disconnect multi-site endpoints previously connected

        :param service_uuid: The one returned by create_connectivity_service
        :param conn_info: The one returned by last call to 'create_connectivity_service' or 'edit_connectivity_service'
            if they do not return None
        :return: None
        :raises: SdnConnectorException: In case of error. The parameter http_code must be filled
        """
        self.logger.debug("delete_connectivity_service uuid: {}".format(service_uuid))
        try:
            #TO DO: check if virtual port groups have to be deleted
            self._delete_virtual_network(self.url, service_uuid)
        except SdnConnectorError:
            raise SdnConnectorError('Failed to delete service uuid {}'.format(service_uuid))
        except Exception as e:
            self.logger.error('Exception deleting connection_service: %s', e, exc_info=True)
            raise SdnConnectorError("Exception deleting connectivity service: {}".format(str(e)))


if __name__ == '__main__':
    # Init logger
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    log_formatter = logging.Formatter(log_format, datefmt='%Y-%m-%dT%H:%M:%S')
    handler = logging.StreamHandler()
    handler.setFormatter(log_formatter)
    logger = logging.getLogger('openmano.sdnconn.junipercontrail')
    #logger.setLevel(level=logging.ERROR)
    logger.setLevel(level=logging.INFO)
    #logger.setLevel(level=logging.DEBUG)
    logger.addHandler(handler)

    # Read config
    with open('test.yaml') as f:
        config = yaml.safe_load(f.read())
    wim = {'wim_url': config.pop('wim_url')}
    wim_account = {'user': config.pop('user'), 'password': config.pop('password')}
    logger.info('wim: {}, wim_account: {}, config: {}'.format(wim, wim_account, config))

    # Init controller
    juniper_contrail = JuniperContrail(wim=wim, wim_account=wim_account, config=config, logger=logger)

    # Tests
    # Generate VNI
    for i in range(5):
        vni = juniper_contrail._generate_vni()
        juniper_contrail.used_vni.add(vni)
    print(juniper_contrail.used_vni)
    juniper_contrail.used_vni.remove(1000003)
    print(juniper_contrail.used_vni)
    for i in range(2):
        vni = juniper_contrail._generate_vni()
        juniper_contrail.used_vni.add(vni)
    print(juniper_contrail.used_vni)
    # 0. Check credentials
    print('0. Check credentials')
    juniper_contrail.check_credentials()

    underlay_url = juniper_contrail.get_url()
    overlay_url = juniper_contrail.get_overlay_url()
    # 1. Read virtual networks from overlay controller
    print('1. Read virtual networks from overlay controller')
    try:
        vnets = juniper_contrail._get_virtual_networks(overlay_url)
        logger.debug(yaml.safe_dump(vnets, indent=4, default_flow_style=False))
        print('OK')
    except Exception as e:
        logger.error('Exception reading virtual networks from overlay controller: %s', e)
        print('FAILED')

    # 2. Read virtual networks from underlay controller
    print('2. Read virtual networks from underlay controller')
    vnets = juniper_contrail._get_virtual_networks(underlay_url)
    logger.debug(yaml.safe_dump(vnets, indent=4, default_flow_style=False))
    print('OK')
    # 3. Delete virtual networks gerardoX from underlay controller
    print('3. Delete virtual networks gerardoX from underlay controller')
    for vn in vnets:
        name = vn['fq_name'][2]
        logger.debug('Virtual network: {}'.format(name))
    for vn in vnets:
        name = vn['fq_name'][2]
        if 'gerardo' in name:
            logger.info('Virtual Network *gerardo*: {}, {}'.format(name,vn['uuid']))
            if name != "gerardo":
                print('Deleting Virtual Network: {}, {}'.format(name,vn['uuid']))
                logger.info('Deleting Virtual Network: {}, {}'.format(name,vn['uuid']))
                juniper_contrail._delete_virtual_network(underlay_url, vn['uuid'])
                print('OK')
    # 4. Get virtual network (gerardo) from underlay controller
    print('4. Get virtual network (gerardo) from underlay controller')
    vnet1_info = juniper_contrail._get_virtual_network(underlay_url, 'c5d332f7-420a-4e2b-a7b1-b56a59f20c97')
    print(yaml.safe_dump(vnet1_info, indent=4, default_flow_style=False))
    print('OK')
    # 5. Create virtual network in underlay controller
    print('5. Create virtual network in underlay controller')
    myname = 'gerardo4'
    myvni = 20004
    vnet2_id, _ = juniper_contrail._create_virtual_network(underlay_url, myname, myvni)
    vnet2_info = juniper_contrail._get_virtual_network(underlay_url, vnet2_id)
    print(yaml.safe_dump(vnet2_info, indent=4, default_flow_style=False))
    print('OK')
    # 6. Delete virtual network in underlay controller
    print('6. Delete virtual network in underlay controller')
    juniper_contrail._delete_virtual_network(underlay_url, vnet2_id)
    print('OK')
    # 7. Read previously deleted virtual network in underlay controller
    print('7. Read previously deleted virtual network in underlay controller')
    try:
        vnet2_info = juniper_contrail._get_virtual_network(underlay_url, vnet2_id)
        if vnet2_info:
            print('FAILED. Network {} exists'.format(vnet2_id))
        else:
            print('OK. Network {} does not exist because it has been deleted'.format(vnet2_id))
    except Exception as e:
        logger.info('Exception reading virtual networks from overlay controller: %s', e)
    exit(0)


    #TODO: to be deleted (it comes from ONOS VPLS plugin)
    service_type = 'ELAN'
    conn_point_0 = {
        "service_endpoint_id": "switch1:ifz1",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000011",
            "switch_port": "1",
            "vlan": "600"
        }
    }
    conn_point_1 = {
        "service_endpoint_id": "switch3:ifz1",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000031",
            "switch_port": "3",
            "vlan": "600"
        }
    }
    connection_points = [conn_point_0, conn_point_1]
    # service_uuid, created_items = juniper_contrail.create_connectivity_service(service_type, connection_points)
    #print(service_uuid)
    #print(created_items)
    #sleep(10)
    #juniper_contrail.delete_connectivity_service("5496dfea-27dc-457d-970d-b82bac266e5c"))


    conn_info = None
    conn_info = ['switch1:ifz1', 'switch3_ifz3']
    juniper_contrail.delete_connectivity_service("f7afc4de-556d-4b5a-8a12-12b5ef97d269", conn_info)

    conn_point_0 = {
        "service_endpoint_id": "switch1:ifz1",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000011",
            "switch_port": "1",
            "vlan": "500"
        }
    }
    conn_point_2 = {
        "service_endpoint_id": "switch1:ifz3",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000011",
            "switch_port": "3",
            "vlan": "500"
        }
    }
    conn_point_3 = {
        "service_endpoint_id": "switch3_ifz3",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "0000000000000033",
            "switch_port": "3",
            "vlan": "500"
        }
    }
    new_connection_points = [conn_point_0, conn_point_3]
    #conn_info = juniper_contrail.edit_connectivity_service("f7afc4de-556d-4b5a-8a12-12b5ef97d269", conn_info, new_connection_points)
    #print(conn_info)
