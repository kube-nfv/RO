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
import json
import yaml

from osm_ro.wim.sdnconn import SdnConnectorBase, SdnConnectorError
from osm_rosdn_juniper_contrail.rest_lib import ContrailHttp
from osm_rosdn_juniper_contrail.rest_lib import NotFound
from osm_rosdn_juniper_contrail.rest_lib import DuplicateFound
from osm_rosdn_juniper_contrail.rest_lib import HttpException

from osm_rosdn_juniper_contrail.sdn_api import UnderlayApi


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

        url = wim.get("wim_url") # underlay url
        auth_url = None
        self.project = None
        self.domain = None
        self.asn = None
        self.fabric = None
        overlay_url = None
        self.vni_range = None
        if config:
            auth_url = config.get("auth_url")
            self.project = config.get("project")
            self.domain = config.get("domain")
            self.asn = config.get("asn")
            self.fabric = config.get("fabric")
            self.overlay_url = config.get("overlay_url")
            self.vni_range = config.get("vni_range")

        if not url:
            raise SdnConnectorError("'url' must be provided")
        if not url.startswith("http"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        self.url = url

        if not self.vni_range:
            self.vni_range = ['1000001-2000000']
            self.logger.info("No vni_range was provided. Using ['1000001-2000000']")
        self.used_vni = set()

        if auth_url:
            if not auth_url.startswith("http"):
                auth_url = "http://" + auth_url
            if not auth_url.endswith("/"):
                auth_url = auth_url + "/"
        self.auth_url = auth_url

        if overlay_url:
            if not overlay_url.startswith("http"):
                overlay_url = "http://" + overlay_url
            if not overlay_url.endswith("/"):
                overlay_url = overlay_url + "/"
        self.overlay_url = overlay_url

        if not self.project:
            raise SdnConnectorError("'project' must be provided")
        if not self.asn:
            # TODO: Get ASN from controller config; otherwise raise ERROR for the moment
            raise SdnConnectorError("'asn' was not provided and it was not possible to obtain it")
        if not self.fabric:
            # TODO: Get FABRIC from controller config; otherwise raise ERROR for the moment
            raise SdnConnectorError("'fabric' was not provided and was not possible to obtain it")
        if not self.domain:
            self.domain = 'default-domain'
            self.logger.info("No domain was provided. Using 'default-domain'")

        underlay_api_config = {
            "auth_url": self.auth_url,
            "project": self.project,
            "domain": self.domain,
            "asn": self.asn,
            "fabric": self.fabric
        }
        self.underlay_api = UnderlayApi(url, underlay_api_config, user=self.user, password=self.password, logger=logger)

        self._max_duplicate_retry = 2
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

    
    # Aux functions for testing
    def get_url(self):
        return self.url

    def get_overlay_url(self):
        return self.overlay_url

    def _create_port(self, switch_id, switch_port, network, vlan):
        """
        1 - Look for virtual port groups for provided switch_id, switch_port using name
        2 - It the virtual port group does not exist, create it
        3 - Create virtual machine interface for the indicated network and vlan
        """
        self.logger.debug("create_port: switch_id: {}, switch_port: {}, network: {}, vlan: {}".format(
            switch_id, switch_port, network, vlan))

        # 1 - Check if the vpg exists
        vpg_name = self.underlay_api.get_vpg_name(switch_id, switch_port)
        vpg = self.underlay_api.get_vpg_by_name(vpg_name)
        if not vpg:
            # 2 - If it does not exist create it
            vpg_id, _ = self.underlay_api.create_vpg(switch_id, switch_port)
        else:
            # Assign vpg_id from vpg
            vpg_id = vpg.get("uuid")

        # 3 - Create vmi
        vmi_id, _ = self.underlay_api.create_vmi(switch_id, switch_port, network, vlan)
        self.logger.debug("port created")

        return vpg_id, vmi_id

    def _delete_port(self, vpg_id, vmi_id):
        self.logger.debug("delete port, vpg_id: {}, vmi_id: {}".format(vpg_id, vmi_id))

        # 1 - Obtain vpg by id (if not vpg_id must have been error creating ig, nothing to be done)
        if vpg_id:
            vpg = self.underlay_api.get_by_uuid("virtual-port-group", vpg_id)
            if not vpg:
                self.logger.warning("vpg: {} to be deleted not found".format(vpg_id))
            else:
                # 2 - Get vmi interfaces from vpg
                vmi_list = vpg.get("virtual_machine_interface_refs")
                if not vmi_list:
                    # must have been an error during port creation when vmi is created
                    # may happen if there has been an error during creation
                    self.logger.warning("vpg: {} has not vmi, will delete nothing".format(vpg))
                else:
                    num_vmis = len(vmi_list)
                    for vmi in vmi_list:
                        uuid = vmi.get("uuid")
                        if uuid == vmi_id:
                            self.underlay_api.delete_vmi(vmi.get("uuid"))
                            num_vmis = num_vmis - 1

                # 3 - If there are no more vmi delete the vpg
                if not vmi_list or num_vmis == 0:
                    self.underlay_api.delete_vpg(vpg.get("uuid"))

    def check_credentials(self):
        """Check if the connector itself can access the SDN/WIM with the provided url (wim.wim_url),
            user (wim_account.user), and password (wim_account.password)

        Raises:
            SdnConnectorError: Issues regarding authorization, access to
                external URLs, etc are detected.
        """
        self.logger.debug("")
        try:
            resp = self.underlay_api.check_auth()
            if not resp:
                raise SdnConnectorError('Empty response')
        except Exception as e:
            self.logger.error('Error checking credentials')
            raise SdnConnectorError('Error checking credentials: {}'.format(str(e)))

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
        try:
            resp = self.http.get_cmd(endpoint='virtual-network/{}'.format(service_uuid))
            if not resp:
                raise SdnConnectorError('Empty response')
            if resp:
                vnet_info = json.loads(resp)

                # Check if conn_info reports error
                if conn_info.get("sdn_status") == "ERROR":
                    return {'sdn_status': 'ACTIVE', 'sdn_info': "conn_info indicates pending error"}
                else:
                    return {'sdn_status': 'ACTIVE', 'sdn_info': vnet_info['virtual-network']}
            else:
                return {'sdn_status': 'ERROR', 'sdn_info': 'not found'}
        except SdnConnectorError:
            raise
        except HttpException as e:
            self.logger.error("Error getting connectivity service: {}".format(e))
            raise SdnConnectorError("Exception deleting connectivity service: {}".format(str(e)))
        except Exception as e:
            self.logger.error('Exception getting connectivity service info: %s', e, exc_info=True)
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
        self.logger.info("create_connectivity_service, service_type: {}, connection_points: {}".
                         format(service_type, connection_points))
        if service_type.lower() != 'elan':
            raise SdnConnectorError('Only ELAN network type is supported by Juniper Contrail.')

        try:
            # Initialize data
            conn_info = None
            conn_info_cp = {}

            # 1 - Obtain VLAN-ID
            vlan = self._get_vlan(connection_points)
            self.logger.debug("Provided vlan: {}".format(vlan))

            # 2 - Obtain free VNI
            vni = self._generate_vni()
            self.logger.debug("VNI: {}".format(vni))

            # 3 - Create virtual network (name, VNI, RT), by the moment the name will use VNI
            retry = 0
            while retry < self._max_duplicate_retry:
                try:
                    vnet_name = 'osm-plugin-' + str(vni)
                    vnet_id, _ = self.underlay_api.create_virtual_network(vnet_name, vni)
                    self.used_vni.add(vni)
                    break
                except DuplicateFound as e:
                    self.logger.debug("Duplicate error for vnet_name: {}".format(vnet_name))
                    self.used_vni.add(vni)
                    retry += 1
                    if retry >= self._max_duplicate_retry:
                        raise e
                    else:
                        # Try to obtain a new vni
                        vni = self._generate_vni()
                        continue
            conn_info = {
                "vnet": {
                    "uuid": vnet_id,
                    "name": vnet_name
                },
                "connection_points": conn_info_cp # dict with port_name as key
            }

            # 4 - Create a port for each endpoint
            for cp in connection_points:
                switch_id = cp.get("service_endpoint_encapsulation_info").get("switch_dpid")
                switch_port = cp.get("service_endpoint_encapsulation_info").get("switch_port")
                vpg_id, vmi_id = self._create_port(switch_id, switch_port, vnet_name, vlan)
                cp_added = cp.copy()
                cp_added["vpg_id"] = vpg_id
                cp_added["vmi_id"] = vmi_id
                conn_info_cp[self.underlay_api.get_vpg_name(switch_id, switch_port)] = cp_added

            return vnet_id, conn_info
            self.logger.info("created connectivity service, uuid: {}, name: {}".format(vnet_id, vnet_name))
        except Exception as e:
            # Log error
            if isinstance(e, SdnConnectorError) or isinstance(e, HttpException):
                self.logger.error("Error creating connectivity service: {}".format(e))
            else:
                self.logger.error("Error creating connectivity service: {}".format(e), exc_info=True)


            # If nothing is created raise error else return what has been created and mask as error
            if not conn_info:
                raise SdnConnectorError("Exception create connectivity service: {}".format(str(e)))
            else:
                conn_info["sdn_status"] = "ERROR"
                # iterate over not added connection_points and add but marking them as error
                for cp in connection_points[len(conn_info_cp):]:
                    cp_error = cp.copy()
                    cp_error["sdn_status"] = "ERROR"
                    switch_id = cp.get("service_endpoint_encapsulation_info").get("switch_dpid")
                    switch_port = cp.get("service_endpoint_encapsulation_info").get("switch_port")
                    conn_info_cp[self.underlay_api.get_vpg_name(switch_id, switch_port)] = cp_error
                return vnet_id, conn_info

    def delete_connectivity_service(self, service_uuid, conn_info=None):
        """
        Disconnect multi-site endpoints previously connected

        :param service_uuid: The one returned by create_connectivity_service
        :param conn_info: The one returned by last call to 'create_connectivity_service' or 'edit_connectivity_service'
            if they do not return None
        :return: None
        :raises: SdnConnectorException: In case of error. The parameter http_code must be filled
        """
        self.logger.info("delete_connectivity_service vnet_name: {}, connection_points: {}".
                          format(service_uuid, conn_info))

        try:
            vnet_uuid = service_uuid
            vnet_name = conn_info["vnet"]["name"]   # always should exist as the network is the first thing created
            connection_points = conn_info["connection_points"].values()
            vlan = self._get_vlan(connection_points)

            # 1: For each connection point delete vlan from vpg and it is is the
            # last one, delete vpg
            for cp in connection_points:
                self._delete_port(cp.get("vpg_id"), cp.get("vmi_id"))

            # 2: Delete vnet
            self.underlay_api.delete_virtual_network(vnet_uuid)
        except SdnConnectorError:
            raise
        except HttpException as e:
            self.logger.error("Error deleting connectivity service: {}".format(e))
            raise SdnConnectorError("Exception deleting connectivity service: {}".format(str(e)))
        except Exception as e:
            self.logger.error("Error deleting connectivity service: {}".format(e), exc_info=True)
            raise SdnConnectorError("Exception deleting connectivity service: {}".format(str(e)))

    # Helper methods
    @staticmethod
    def _get_vlan(connection_points):
        vlan = None
        for cp in connection_points:
            cp_vlan = cp.get("service_endpoint_encapsulation_info").get("vlan")
            if not vlan:
                vlan = cp_vlan
            else:
                if vlan != cp_vlan:
                    raise SdnConnectorError("More that one cp provided")
        return vlan

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
        # 0 - Check if there are connection_points marked as error and delete them
        # 1 - Compare conn_info (old connection points) and connection_points (new ones to be applied):
        #     Obtain list of connection points to be added and to be deleted
        #     Obtain vlan and check it has not changed
        # 2 - Obtain network: Check vnet exists and obtain name
        # 3 - Delete unnecesary ports
        # 4 - Add new ports
        self.logger.info("edit connectivity service, service_uuid: {}, conn_info: {}, "
                          "connection points: {} ".format(service_uuid, conn_info, connection_points))

        # conn_info should always exist and have connection_points and vnet elements
        old_cp = conn_info.get("connection_points", {})
        old_vlan = self._get_vlan(old_cp)

        # Check if an element of old_cp is marked as error, in case it is delete it
        # Not return a new conn_info in this case because it is only partial information
        # Current conn_info already marks ports as error
        try:
            delete_conn_info = []
            for cp in old_cp:
                if cp.get("sdn_status") == "ERROR":
                    switch_id = cp.get("service_endpoint_encapsulation_info").get("switch_dpid")
                    switch_port = cp.get("service_endpoint_encapsulation_info").get("switch_port")
                    self._delete_port(switch_id, switch_port, old_vlan)
                    delete_conn_info.append(self.underlay_api.get_vpg_name(switch_id, switch_port))

            for i in delete_conn_info:
                del old_cp[i]

            # Delete vnet status if exists (possibly marked as error)
            if conn_info.get("vnet",{}).get("sdn_status"):
                del conn_info["vnet"]["sdn_status"]
        except HttpException as e:
            self.logger.error("Error trying to delete old ports marked as error: {}".format(e))
            raise SdnConnectorError(e)
        except SdnConnectorError as e:
            self.logger.error("Error trying to delete old ports marked as error: {}".format(e))
            raise
        except Exception as e:
            self.logger.error("Error trying to delete old ports marked as error: {}".format(e), exc_info=True)
            raise SdnConnectorError("Error trying to delete old ports marked as error: {}".format(e))

        if connection_points:

            # Check and obtain what should be added and deleted, if there is an error here raise an exception
            try:

                vlan = self._get_vlan(connection_points)

                old_port_list = ["{}_{}".format(cp["service_endpoint_encapsulation_info"]["switch_dpid"],
                                          cp["service_endpoint_encapsulation_info"]["switch_port"])
                           for cp in old_cp.values()]
                port_list = ["{}_{}".format(cp["service_endpoint_encapsulation_info"]["switch_dpid"],
                                          cp["service_endpoint_encapsulation_info"]["switch_port"])
                           for cp in connection_points]
                to_delete_ports = list(set(old_port_list) - set(port_list))
                to_add_ports = list(set(port_list) - set(old_port_list))

                # Obtain network
                vnet = self.underlay_api.get_virtual_network(self.get_url(), service_uuid)
                vnet_name = vnet["name"]

            except SdnConnectorError:
                raise
            except Exception as e:
                self.logger.error("Error edit connectivity service: {}".format(e), exc_info=True)
                raise SdnConnectorError("Exception edit connectivity service: {}".format(str(e)))


            # Delete unneeded ports and add new ones: if there is an error return conn_info
            try:
                # Connection points returned in con_info should reflect what has (and should as ERROR) be done
                # Start with old cp dictionary and modify it as we work
                conn_info_cp = old_cp

                # Delete unneeded ports
                for port_name in conn_info_cp.keys():
                    if port_name in to_delete_ports:
                        cp = conn_info_cp[port_name]
                        switch_id = cp.get("service_endpoint_encapsulation_info").get("switch_dpid")
                        switch_port = cp.get("service_endpoint_encapsulation_info").get("switch_port")
                        self.logger.debug("delete port switch_id, switch_port: {}".format(switch_id, switch_port))
                        self._delete_port(switch_id, switch_port, vlan)
                        del conn_info_cp[port_name]

                # Add needed ports
                for cp in connection_points:
                    if port_name in to_add_ports:
                        switch_id = cp.get("service_endpoint_encapsulation_info").get("switch_dpid")
                        switch_port = cp.get("service_endpoint_encapsulation_info").get("switch_port")
                        self.logger.debug("add port switch_id, switch_port: {}".format(switch_id, switch_port))
                        self._create_port(switch_id, switch_port, vnet_name, vlan)
                        conn_info_cp[port_name]

                conn_info["connection_points"] = conn_info_cp
                return conn_info

            except Exception as e:
                # Log error
                if isinstance(e, SdnConnectorError) or isinstance(e, HttpException):
                    self.logger.error("Error edit connectivity service: {}".format(e), exc_info=True)
                else:
                    self.logger.error("Error edit connectivity service: {}".format(e))

                # There has been an error mount conn_info_cp marking as error cp that should
                # have been deleted but have not or should have been added
                for port_name, cp in conn_info_cp.items():
                    if port_name in to_delete_ports:
                        cp["sdn_status"] = "ERROR"

                for cp in connection_points:
                    switch_id = cp.get("service_endpoint_encapsulation_info").get("switch_dpid")
                    switch_port = cp.get("service_endpoint_encapsulation_info").get("switch_port")
                    port_name = self.underlay_api.get_vpg_name(switch_id, switch_port)
                    if port_name in to_add_ports:
                        cp_error = cp.copy()
                        cp_error["sdn_status"] = "ERROR"
                        conn_info_cp[port_name] = cp_error

                conn_info["sdn_status"] = "ERROR"
                conn_info["connection_points"] = conn_info_cp
                return conn_info


        else:
            # Connection points have not changed, so do nothing
            self.logger.info("no new connection_points provided, nothing to be done")
            return


if __name__ == '__main__':
    # Init logger
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    log_formatter = logging.Formatter(log_format, datefmt='%Y-%m-%dT%H:%M:%S')
    handler = logging.StreamHandler()
    handler.setFormatter(log_formatter)
    logger = logging.getLogger('openmano.sdnconn.junipercontrail')
    #logger.setLevel(level=logging.ERROR)
    #logger.setLevel(level=logging.INFO)
    logger.setLevel(level=logging.DEBUG)
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

    # Test CRUD:
    net_name = "gerardo"
    net_vni = "2000"
    net_vlan = "501"
    switch_1 = "LEAF-2"
    port_1 = "xe-0/0/18"
    switch_2 = "LEAF-1"
    port_2 = "xe-0/0/18"

    # 1 - Create a new virtual network
    vnet2_id, vnet2_created = juniper_contrail._create_virtual_network(underlay_url, net_name, net_vni)
    print("Created virtual network:")
    print(vnet2_id)
    print(yaml.safe_dump(vnet2_created, indent=4, default_flow_style=False))
    print("Get virtual network:")
    vnet2_info = juniper_contrail._get_virtual_network(underlay_url, vnet2_id)
    print(json.dumps(vnet2_info, indent=4))
    print('OK')

    # 2 - Create a new virtual port group
    vpg_id, vpg_info = juniper_contrail._create_vpg(underlay_url, switch_1, port_1, net_name, net_vlan)
    print("Created virtual port group:")
    print(vpg_id)
    print(json.dumps(vpg_info, indent=4))

    print("Get virtual network:")
    vnet2_info = juniper_contrail._get_virtual_network(underlay_url, vnet2_id)
    print(yaml.safe_dump(vnet2_info, indent=4, default_flow_style=False))
    print('OK')

    # 3 - Create a new virtual machine interface
    vmi_id, vmi_info = juniper_contrail._create_vmi(underlay_url, switch_1, port_1, net_name, net_vlan)
    print("Created virtual machine interface:")
    print(vmi_id)
    print(yaml.safe_dump(vmi_info, indent=4, default_flow_style=False))

    # 4 - Create a second virtual port group
    # 5 - Create a second virtual machine interface

    ### Test rapido de modificación de requests:
    # Ver que metodos siguen funcionando y cuales no e irlos corrigiendo

    """
    vnets = juniper_contrail._get_virtual_networks(underlay_url)
    logger.debug("Virtual networks:")
    logger.debug(json.dumps(vnets, indent=2))

    vpgs = juniper_contrail._get_vpgs(underlay_url)
    logger.debug("Virtual port groups:")
    logger.debug(json.dumps(vpgs, indent=2))
    """
    # Get by uuid

    """
    # 3 - Get vmi
    vmi_uuid = "dbfd2099-b895-459e-98af-882d77d968c1"
    vmi = juniper_contrail._get_vmi(underlay_url, vmi_uuid)
    logger.debug("Virtual machine interface:")
    logger.debug(json.dumps(vmi, indent=2))

    # Delete vmi    
    logger.debug("Delete vmi")
    juniper_contrail._delete_vmi(underlay_url, vmi_uuid)
    """

    """
    # 2 - Get vpg
    vpg_uuid = "85156474-d1a5-44c0-9d8b-8f690f39d27e"
    vpg = juniper_contrail._get_vpg(underlay_url, vpg_uuid)
    logger.debug("Virtual port group:")
    logger.debug(json.dumps(vpg, indent=2))
    # Delete vpg
    vpg = juniper_contrail._delete_vpg(underlay_url, vpg_uuid)
    """

    # 1 - Obtain virtual network
    """
    vnet_uuid = "68457d61-6558-4d38-a03d-369a9de803ea"
    vnet = juniper_contrail._get_virtual_network(underlay_url, vnet_uuid)
    logger.debug("Virtual network:")
    logger.debug(json.dumps(vnet, indent=2))
    # Delete virtual network
    juniper_contrail._delete_virtual_network(underlay_url, vnet_uuid)
    """
