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
import random

from osm_ro_plugin.sdnconn import SdnConnectorBase, SdnConnectorError
from osm_rosdn_juniper_contrail.rest_lib import DuplicateFound
from osm_rosdn_juniper_contrail.rest_lib import HttpException
from osm_rosdn_juniper_contrail.sdn_api import UnderlayApi
import yaml


class JuniperContrail(SdnConnectorBase):
    """
    Juniper Contrail SDN plugin. The plugin interacts with Juniper Contrail Controller,
    whose API details can be found in these links:

    - https://github.com/tonyliu0592/contrail/wiki/API-Configuration-REST
    - https://www.juniper.net/documentation/en_US/contrail19/information-products/pathway-pages/api-guide-1910/
      tutorial_with_rest.html
    - https://github.com/tonyliu0592/contrail-toolbox/blob/master/sriov/sriov
    """

    _WIM_LOGGER = "ro.sdn.junipercontrail"

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
        :param logger (logging.Logger): optional logger object. If none is passed 'ro.sdn.sdnconn' is used.
        """
        self.logger = logger or logging.getLogger(self._WIM_LOGGER)
        self.logger.debug(
            "wim: {}, wim_account: {}, config: {}".format(wim, wim_account, config)
        )
        super().__init__(wim, wim_account, config, logger)

        self.user = wim_account.get("user")
        self.password = wim_account.get("password")

        url = wim.get("wim_url")  # underlay url
        auth_url = None
        self.project = None
        self.domain = None
        self.asn = None
        self.fabric = None
        overlay_url = None
        self.vni_range = None
        self.verify = True

        if config:
            auth_url = config.get("auth_url")
            self.project = config.get("project")
            self.domain = config.get("domain")
            self.asn = config.get("asn")
            self.fabric = config.get("fabric")
            self.overlay_url = config.get("overlay_url")
            self.vni_range = config.get("vni_range")

            if config.get("insecure") and config.get("ca_cert"):
                raise SdnConnectorError(
                    "options insecure and ca_cert are mutually exclusive"
                )

            if config.get("ca_cert"):
                self.verify = config.get("ca_cert")

            elif config.get("insecure"):
                self.verify = False

            else:
                raise SdnConnectorError(
                    "certificate should provided or ssl verification should be "
                    "disabled by setting insecure as True in sdn/wim config."
                )

        if not url:
            raise SdnConnectorError("'url' must be provided")

        if not url.startswith("http"):
            url = "http://" + url

        if not url.endswith("/"):
            url = url + "/"

        self.url = url

        if not self.vni_range:
            self.vni_range = ["1000001-2000000"]
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
            raise SdnConnectorError(
                "'asn' was not provided and it was not possible to obtain it"
            )

        if not self.fabric:
            # TODO: Get FABRIC from controller config; otherwise raise ERROR for the moment
            raise SdnConnectorError(
                "'fabric' was not provided and was not possible to obtain it"
            )

        if not self.domain:
            self.domain = "default-domain"
            self.logger.info("No domain was provided. Using 'default-domain'")

        underlay_api_config = {
            "auth_url": self.auth_url,
            "project": self.project,
            "domain": self.domain,
            "asn": self.asn,
            "fabric": self.fabric,
            "verify": self.verify,
        }
        self.underlay_api = UnderlayApi(
            url,
            underlay_api_config,
            user=self.user,
            password=self.password,
            logger=logger,
        )

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
        # find unused VLAN ID
        for vlanID_range in self.vni_range:
            try:
                start_vni, end_vni = map(int, vlanID_range.replace(" ", "").split("-"))

                for i in range(start_vni, end_vni + 1):
                    vni = random.randrange(start_vni, end_vni, 1)

                    if vni not in self.used_vni:
                        return vni
            except Exception as exp:
                raise SdnConnectorError(
                    "Exception {} occurred while searching a free VNI.".format(exp)
                )
        else:
            raise SdnConnectorError(
                "Unable to create the virtual network."
                " All VNI in VNI range {} are in use.".format(self.vni_range)
            )

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
        self.logger.debug(
            "create_port: switch_id: {}, switch_port: {}, network: {}, vlan: {}".format(
                switch_id, switch_port, network, vlan
            )
        )

        # 1 - Check if the vpg exists
        vpg_name = self.underlay_api.get_vpg_name(switch_id, switch_port)
        vpg = self.underlay_api.get_vpg_by_name(vpg_name)

        if not vpg:
            # 2 - If it does not exist create it
            vpg_id, _ = self.underlay_api.create_vpg(switch_id, switch_port)
        else:
            # Assign vpg_id from vpg
            vpg_id = vpg.get("uuid")

        # 3 - Check if the vmi alreaady exists
        vmi_id, _ = self.underlay_api.create_vmi(switch_id, switch_port, network, vlan)
        self.logger.debug("port created")

        return vpg_id, vmi_id

    def _delete_port(self, switch_id, switch_port, vlan):
        self.logger.debug(
            "delete port, switch_id: {}, switch_port: {}, vlan: {}".format(
                switch_id, switch_port, vlan
            )
        )

        vpg_name = self.underlay_api.get_vpg_name(switch_id, switch_port)
        vmi_name = self.underlay_api.get_vmi_name(switch_id, switch_port, vlan)

        # 1 - Obtain vpg by id (if not vpg_id must have been error creating ig, nothing to be done)
        vpg_fqdn = ["default-global-system-config", self.fabric, vpg_name]
        vpg = self.underlay_api.get_by_fq_name("virtual-port-group", vpg_fqdn)

        if not vpg:
            self.logger.warning("vpg: {} to be deleted not found".format(vpg_name))
        else:
            # 2 - Get vmi interfaces from vpg
            vmi_list = vpg.get("virtual_machine_interface_refs")

            if not vmi_list:
                # must have been an error during port creation when vmi is created
                # may happen if there has been an error during creation
                self.logger.warning(
                    "vpg: {} has not vmi, will delete nothing".format(vpg)
                )
            else:
                num_vmis = len(vmi_list)

                for vmi in vmi_list:
                    fqdn = vmi.get("to")
                    # check by name

                    if fqdn[2] == vmi_name:
                        self.underlay_api.unref_vmi_vpg(
                            vpg.get("uuid"), vmi.get("uuid"), fqdn
                        )
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
                raise SdnConnectorError("Empty response")
        except Exception as e:
            self.logger.error("Error checking credentials")

            raise SdnConnectorError("Error checking credentials: {}".format(str(e)))

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
            resp = self.underlay_api.get_virtual_network(service_uuid)
            if not resp:
                raise SdnConnectorError("Empty response")

            if resp:
                vnet_info = resp

                # Check if conn_info reports error
                if conn_info.get("sdn_status") == "ERROR":
                    return {"sdn_status": "ERROR", "sdn_info": conn_info}
                else:
                    return {"sdn_status": "ACTIVE", "sdn_info": vnet_info}
            else:
                return {"sdn_status": "ERROR", "sdn_info": "not found"}
        except SdnConnectorError:
            raise
        except HttpException as e:
            self.logger.error("Error getting connectivity service: {}".format(e))

            raise SdnConnectorError(
                "Exception deleting connectivity service: {}".format(str(e))
            )
        except Exception as e:
            self.logger.error(
                "Exception getting connectivity service info: %s", e, exc_info=True
            )

            return {"sdn_status": "ERROR", "error_msg": str(e)}

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
        #   2.2 Add RouteTarget (RT) ('ASN:VNI', ASN = Autonomous System Number, provided as param or read from
        #   controller config)
        # Step 3. Create a virtual network in the underlay controller
        #   3.1 Create virtual network (name, VNI, RT)
        #      If the network already existed in the overlay controller, we should use the same name
        #         name = 'osm-plugin-' + overlay_name
        #      Else:
        #         name = 'osm-plugin-' + VNI
        self.logger.info(
            "create_connectivity_service, service_type: {}, connection_points: {}".format(
                service_type, connection_points
            )
        )

        if service_type.lower() != "elan":
            raise SdnConnectorError(
                "Only ELAN network type is supported by Juniper Contrail."
            )

        try:
            # Initialize data
            conn_info = None

            # 1 - Filter connection_points (transform cp to a dictionary with no duplicates)
            # This data will be returned even if no cp can be created if something is created
            work_cps = {}
            for cp in connection_points:
                switch_id = cp.get("service_endpoint_encapsulation_info").get(
                    "switch_dpid"
                )
                switch_port = cp.get("service_endpoint_encapsulation_info").get(
                    "switch_port"
                )
                service_endpoint_id = cp.get("service_endpoint_id")
                cp_name = self.underlay_api.get_vpg_name(switch_id, switch_port)
                add_cp = work_cps.get(cp_name)

                if not add_cp:
                    # check cp has vlan
                    vlan = cp.get("service_endpoint_encapsulation_info").get("vlan")

                    if vlan:
                        # add cp to dict
                        service_endpoint_ids = []
                        service_endpoint_ids.append(service_endpoint_id)
                        add_cp = {
                            "service_endpoint_ids": service_endpoint_ids,
                            "switch_dpid": switch_id,
                            "switch_port": switch_port,
                            "vlan": vlan,
                        }
                        work_cps[cp_name] = add_cp
                    else:
                        self.logger.warning(
                            "cp service_endpoint_id : {} has no vlan, ignore".format(
                                service_endpoint_id
                            )
                        )
                else:
                    # add service_endpoint_id to list
                    service_endpoint_ids = add_cp["service_endpoint_ids"]
                    service_endpoint_ids.append(service_endpoint_id)

            # 2 - Obtain free VNI
            vni = self._generate_vni()
            self.logger.debug("VNI: {}".format(vni))

            # 3 - Create virtual network (name, VNI, RT), by the moment the name will use VNI
            retry = 0
            while retry < self._max_duplicate_retry:
                try:
                    vnet_name = "osm-plugin-" + str(vni)
                    vnet_id, _ = self.underlay_api.create_virtual_network(
                        vnet_name, vni
                    )
                    self.used_vni.add(vni)
                    break
                except DuplicateFound as e:
                    self.logger.debug(
                        "Duplicate error for vnet_name: {}".format(vnet_name)
                    )
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
                    "name": vnet_name,
                },
                "connection_points": work_cps,  # dict with port_name as key
            }

            # 4 - Create a port for each endpoint
            for cp in work_cps.values():
                switch_id = cp.get("switch_dpid")
                switch_port = cp.get("switch_port")
                vlan = cp.get("vlan")
                vpg_id, vmi_id = self._create_port(
                    switch_id, switch_port, vnet_name, vlan
                )
                cp["vpg_id"] = vpg_id
                cp["vmi_id"] = vmi_id

            self.logger.info(
                "created connectivity service, uuid: {}, name: {}".format(
                    vnet_id, vnet_name
                )
            )

            return vnet_id, conn_info
        except Exception as e:
            # Log error
            if isinstance(e, SdnConnectorError) or isinstance(e, HttpException):
                self.logger.error("Error creating connectivity service: {}".format(e))
            else:
                self.logger.error(
                    "Error creating connectivity service: {}".format(e), exc_info=True
                )

            # If nothing is created raise error else return what has been created and mask as error
            if not conn_info:
                raise SdnConnectorError(
                    "Exception create connectivity service: {}".format(str(e))
                )
            else:
                conn_info["sdn_status"] = "ERROR"
                conn_info["sdn_info"] = repr(e)
                # iterate over not added connection_points and add but marking them as error
                for cp in work_cps.values():
                    if not cp.get("vmi_id") or not cp.get("vpg_id"):
                        cp["sdn_status"] = "ERROR"

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
        self.logger.info(
            "delete_connectivity_service vnet_name: {}, connection_points: {}".format(
                service_uuid, conn_info
            )
        )

        try:
            vnet_uuid = service_uuid
            # vnet_name = conn_info["vnet"]["name"]
            # always should exist as the network is the first thing created
            work_cps = conn_info["connection_points"]

            # 1: For each connection point delete vlan from vpg and it is is the
            # last one, delete vpg
            for cp in work_cps.values():
                self._delete_port(
                    cp.get("switch_dpid"), cp.get("switch_port"), cp.get("vlan")
                )

            # 2: Delete vnet
            self.underlay_api.delete_virtual_network(vnet_uuid)
            self.logger.info(
                "deleted connectivity_service vnet_uuid: {}, connection_points: {}".format(
                    service_uuid, conn_info
                )
            )
        except SdnConnectorError:
            raise
        except HttpException as e:
            self.logger.error("Error deleting connectivity service: {}".format(e))

            raise SdnConnectorError(
                "Exception deleting connectivity service: {}".format(str(e))
            )
        except Exception as e:
            self.logger.error(
                "Error deleting connectivity service: {}".format(e),
                exc_info=True,
            )

            raise SdnConnectorError(
                "Exception deleting connectivity service: {}".format(str(e))
            )

    def edit_connectivity_service(
        self, service_uuid, conn_info=None, connection_points=None, **kwargs
    ):
        """Change an existing connectivity service.

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
        self.logger.info(
            "edit connectivity service, service_uuid: {}, conn_info: {}, "
            "connection points: {} ".format(service_uuid, conn_info, connection_points)
        )

        # conn_info should always exist and have connection_points and vnet elements
        old_cp = conn_info.get("connection_points", {})

        # Check if an element of old_cp is marked as error, in case it is delete it
        # Not return a new conn_info in this case because it is only partial information
        # Current conn_info already marks ports as error
        try:
            deleted_ports = []
            for cp in old_cp.values():
                if cp.get("sdn_status") == "ERROR":
                    switch_id = cp.get("switch_dpid")
                    switch_port = cp.get("switch_port")
                    old_vlan = cp.get("vlan")
                    self._delete_port(switch_id, switch_port, old_vlan)
                    deleted_ports.append(
                        self.underlay_api.get_vpg_name(switch_id, switch_port)
                    )

            for port in deleted_ports:
                del old_cp[port]

            # Delete sdn_status and sdn_info if exists (possibly marked as error)
            if conn_info.get("vnet", {}).get("sdn_status"):
                del conn_info["vnet"]["sdn_status"]
        except HttpException as e:
            self.logger.error(
                "Error trying to delete old ports marked as error: {}".format(e)
            )

            raise SdnConnectorError(e)
        except SdnConnectorError as e:
            self.logger.error(
                "Error trying to delete old ports marked as error: {}".format(e)
            )

            raise
        except Exception as e:
            self.logger.error(
                "Error trying to delete old ports marked as error: {}".format(e),
                exc_info=True,
            )

            raise SdnConnectorError(
                "Error trying to delete old ports marked as error: {}".format(e)
            )

        if connection_points:
            # Check and obtain what should be added and deleted, if there is an error here raise an exception
            try:
                work_cps = {}
                for cp in connection_points:
                    switch_id = cp.get("service_endpoint_encapsulation_info").get(
                        "switch_dpid"
                    )
                    switch_port = cp.get("service_endpoint_encapsulation_info").get(
                        "switch_port"
                    )
                    service_endpoint_id = cp.get("service_endpoint_id")
                    cp_name = self.underlay_api.get_vpg_name(switch_id, switch_port)
                    add_cp = work_cps.get(cp_name)

                    if not add_cp:
                        # add cp to dict
                        # check cp has vlan
                        vlan = cp.get("service_endpoint_encapsulation_info").get("vlan")

                        if vlan:
                            service_endpoint_ids = []
                            service_endpoint_ids.append(service_endpoint_id)
                            add_cp = {
                                "service_endpoint_ids": service_endpoint_ids,
                                "switch_dpid": switch_id,
                                "switch_port": switch_port,
                                "vlan": vlan,
                            }
                            work_cps[cp_name] = add_cp
                        else:
                            self.logger.warning(
                                "cp service_endpoint_id : {} has no vlan, ignore".format(
                                    service_endpoint_id
                                )
                            )
                    else:
                        # add service_endpoint_id to list
                        service_endpoint_ids = add_cp["service_endpoint_ids"]
                        service_endpoint_ids.append(service_endpoint_id)

                old_port_list = list(old_cp.keys())
                port_list = list(work_cps.keys())
                to_delete_ports = list(set(old_port_list) - set(port_list))
                to_add_ports = list(set(port_list) - set(old_port_list))
                self.logger.debug("ports to delete: {}".format(to_delete_ports))
                self.logger.debug("ports to add: {}".format(to_add_ports))

                # Obtain network (check it is correctly created)
                vnet = self.underlay_api.get_virtual_network(service_uuid)
                if vnet:
                    vnet_name = vnet["name"]
                else:
                    raise SdnConnectorError(
                        "vnet uuid: {} not found".format(service_uuid)
                    )
            except SdnConnectorError:
                raise
            except Exception as e:
                self.logger.error(
                    "Error edit connectivity service: {}".format(e), exc_info=True
                )

                raise SdnConnectorError(
                    "Exception edit connectivity service: {}".format(str(e))
                )

            # Delete unneeded ports and add new ones: if there is an error return conn_info
            try:
                # Connection points returned in con_info should reflect what has (and should as ERROR) be done
                # Start with old cp dictionary and modify it as we work
                conn_info_cp = old_cp

                # Delete unneeded ports
                deleted_ports = []
                for port_name in conn_info_cp.keys():
                    if port_name in to_delete_ports:
                        cp = conn_info_cp[port_name]
                        switch_id = cp.get("switch_dpid")
                        switch_port = cp.get("switch_port")
                        self.logger.debug(
                            "delete port switch_id={}, switch_port={}".format(
                                switch_id, switch_port
                            )
                        )
                        self._delete_port(switch_id, switch_port, vlan)
                        deleted_ports.append(port_name)

                # Delete ports
                for port_name in deleted_ports:
                    del conn_info_cp[port_name]

                # Add needed ports
                for port_name, cp in work_cps.items():
                    if port_name in to_add_ports:
                        switch_id = cp.get("switch_dpid")
                        switch_port = cp.get("switch_port")
                        vlan = cp.get("vlan")
                        self.logger.debug(
                            "add port switch_id={}, switch_port={}".format(
                                switch_id, switch_port
                            )
                        )
                        vpg_id, vmi_id = self._create_port(
                            switch_id, switch_port, vnet_name, vlan
                        )
                        cp_added = cp.copy()
                        cp_added["vpg_id"] = vpg_id
                        cp_added["vmi_id"] = vmi_id
                        conn_info_cp[port_name] = cp_added

                    # replace endpoints in case they have changed
                    conn_info_cp[port_name]["service_endpoint_ids"] = cp[
                        "service_endpoint_ids"
                    ]

                conn_info["connection_points"] = conn_info_cp
                return conn_info

            except Exception as e:
                # Log error
                if isinstance(e, SdnConnectorError) or isinstance(e, HttpException):
                    self.logger.error(
                        "Error edit connectivity service: {}".format(e), exc_info=True
                    )
                else:
                    self.logger.error("Error edit connectivity service: {}".format(e))

                # There has been an error mount conn_info_cp marking as error cp that should
                # have been deleted but have not or should have been added
                for port_name, cp in conn_info_cp.items():
                    if port_name in to_delete_ports:
                        cp["sdn_status"] = "ERROR"

                for port_name, cp in work_cps.items():
                    curr_cp = conn_info_cp.get(port_name)

                    if not curr_cp:
                        cp_error = work_cps.get(port_name).copy()
                        cp_error["sdn_status"] = "ERROR"
                        conn_info_cp[port_name] = cp_error

                    conn_info_cp[port_name]["service_endpoint_ids"] = cp[
                        "service_endpoint_ids"
                    ]

                conn_info["sdn_status"] = "ERROR"
                conn_info["sdn_info"] = repr(e)
                conn_info["connection_points"] = conn_info_cp

                return conn_info
        else:
            # Connection points have not changed, so do nothing
            self.logger.info("no new connection_points provided, nothing to be done")

            return


if __name__ == "__main__":
    # Init logger
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    log_formatter = logging.Formatter(log_format, datefmt="%Y-%m-%dT%H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(log_formatter)
    logger = logging.getLogger("ro.sdn.junipercontrail")
    # logger.setLevel(level=logging.ERROR)
    # logger.setLevel(level=logging.INFO)
    logger.setLevel(level=logging.DEBUG)
    logger.addHandler(handler)

    # Read config
    with open("test.yaml") as f:
        config = yaml.safe_load(f.read())

    wim = {"wim_url": config.pop("wim_url")}
    wim_account = {"user": config.pop("user"), "password": config.pop("password")}
    logger.info("wim: {}, wim_account: {}, config: {}".format(wim, wim_account, config))

    # Init controller
    juniper_contrail = JuniperContrail(
        wim=wim, wim_account=wim_account, config=config, logger=logger
    )

    # Tests
    # Generate VNI
    for i in range(5):
        vni = juniper_contrail._generate_vni()
        juniper_contrail.used_vni.add(vni)

    print(juniper_contrail.used_vni)
    # juniper_contrail.used_vni.remove(1000003)
    print(juniper_contrail.used_vni)

    for i in range(2):
        vni = juniper_contrail._generate_vni()
        juniper_contrail.used_vni.add(vni)

    print(juniper_contrail.used_vni)

    # 0. Check credentials
    print("0. Check credentials")
    # juniper_contrail.check_credentials()

    # 1 - Create and delete connectivity service
    conn_point_0 = {
        "service_endpoint_id": "0000:83:11.4",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "LEAF-1",
            "switch_port": "xe-0/0/17",
            "vlan": "501",
        },
    }
    conn_point_1 = {
        "service_endpoint_id": "0000:81:10.3",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "LEAF-2",
            "switch_port": "xe-0/0/16",
            "vlan": "501",
        },
    }
    conn_point_2 = {
        "service_endpoint_id": "0000:08:11.7",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "LEAF-2",
            "switch_port": "xe-0/0/16",
            "vlan": "502",
        },
    }
    conn_point_3 = {
        "service_endpoint_id": "0000:83:10.4",
        "service_endpoint_encapsulation_type": "dot1q",
        "service_endpoint_encapsulation_info": {
            "switch_dpid": "LEAF-1",
            "switch_port": "xe-0/0/17",
            "vlan": "502",
        },
    }

    # 1 - Define connection points
    logger.debug("create first connection service")
    print("Create connectivity service")
    connection_points = [conn_point_0, conn_point_1]
    service_id, conn_info = juniper_contrail.create_connectivity_service(
        "ELAN", connection_points
    )
    logger.info("Created connectivity service 1")
    logger.info(service_id)
    logger.info(yaml.safe_dump(conn_info, indent=4, default_flow_style=False))

    logger.debug("create second connection service")
    print("Create connectivity service")
    connection_points = [conn_point_2, conn_point_3]
    service_id2, conn_info2 = juniper_contrail.create_connectivity_service(
        "ELAN", connection_points
    )
    logger.info("Created connectivity service 2")
    logger.info(service_id2)
    logger.info(yaml.safe_dump(conn_info2, indent=4, default_flow_style=False))

    logger.debug("Delete connectivity service 1")
    juniper_contrail.delete_connectivity_service(service_id, conn_info)
    logger.debug("Delete Ok")

    logger.debug("Delete connectivity service 2")
    juniper_contrail.delete_connectivity_service(service_id2, conn_info2)
    logger.debug("Delete Ok")
