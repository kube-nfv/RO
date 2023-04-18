# -*- coding: utf-8 -*-

#######################################################################################
# This file is part of OSM RO module
#
# Copyright ETSI Contributors and Others.
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
#######################################################################################
# This work has been performed in the context of the TeraFlow Project -
# funded by the European Commission under Grant number 101015857 through the
# Horizon 2020 program.
# Contributors:
# - Lluis Gifre <lluis.gifre@cttc.es>
# - Ricard Vilalta <ricard.vilalta@cttc.es>
#######################################################################################

"""The SDN/WIM connector is responsible for establishing wide area network
connectivity.

This SDN/WIM connector implements the standard ONF Transport API (TAPI).

It receives the endpoints and the necessary details to request the Layer 2
service through the use of the ONF Transport API.
"""

import logging
import uuid

from osm_ro_plugin.sdnconn import SdnConnectorBase

from .conn_info import (
    conn_info_compose_bidirectional,
    conn_info_compose_unidirectional,
)
from .exceptions import (
    WimTapiConnectionPointsBadFormat,
    WimTapiMissingConnPointField,
    WimTapiUnsupportedServiceType,
)
from .services_composer import ServicesComposer
from .tapi_client import TransportApiClient


class WimconnectorTAPI(SdnConnectorBase):
    """ONF TAPI WIM connector"""

    def __init__(self, wim, wim_account, config=None, logger=None):
        """ONF TAPI WIM connector

        Arguments:
            wim (dict): WIM record, as stored in the database
            wim_account (dict): WIM account record, as stored in the database
            config (optional dict): optional configuration from the configuration database
            logger (optional Logger): logger to use with this WIM connector
        The arguments of the constructor are converted to object attributes.
        An extra property, ``service_endpoint_mapping`` is created from ``config``.
        """
        logger = logger or logging.getLogger("ro.sdn.tapi")

        super().__init__(wim, wim_account, config, logger)

        self.logger.debug("self.config={:s}".format(str(self.config)))

        if len(self.service_endpoint_mapping) == 0 and self.config.get(
            "wim_port_mapping"
        ):
            self.service_endpoint_mapping = self.config.get("wim_port_mapping", [])

        self.mappings = {
            m["service_endpoint_id"]: m for m in self.service_endpoint_mapping
        }

        self.logger.debug("self.mappings={:s}".format(str(self.mappings)))

        self.tapi_client = TransportApiClient(self.logger, wim, wim_account, config)

        self.logger.info("TAPI WIM Connector Initialized.")

    def check_credentials(self):
        """Check if the connector itself can access the SDN/WIM with the provided url (wim.wim_url),
            user (wim_account.user), and password (wim_account.password)

        Raises:
            SdnConnectorError: Issues regarding authorization, access to
                external URLs, etc are detected.
        """
        _ = self.tapi_client.get_root_context()
        self.logger.info("Credentials checked")

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
        sdn_status = set()
        bidirectional = conn_info["bidirectional"]

        tapi_client = self.tapi_client
        if bidirectional:
            service_uuid = conn_info["uuid"]
            service_status = tapi_client.get_service_status("<>", service_uuid)
            sdn_status.add(service_status["sdn_status"])
        else:
            service_az_uuid = conn_info["az"]["uuid"]
            service_za_uuid = conn_info["za"]["uuid"]
            service_az_status = tapi_client.get_service_status(">>", service_az_uuid)
            service_za_status = tapi_client.get_service_status("<<", service_za_uuid)
            sdn_status.add(service_az_status["sdn_status"])
            sdn_status.add(service_za_status["sdn_status"])

        if len(sdn_status) == 1 and "ACTIVE" in sdn_status:
            service_status = {"sdn_status": "ACTIVE"}
        else:
            service_status = {"sdn_status": "ERROR"}

        return service_status

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
                    "swith_port": ... present if mapping has been found for this device_id,device_interface_id
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
        supported_service_types = {"ELINE"}
        if service_type not in supported_service_types:
            raise WimTapiUnsupportedServiceType(service_type, supported_service_types)

        self.logger.debug("connection_points={:s}".format(str(connection_points)))

        if not isinstance(connection_points, (list, tuple)):
            raise WimTapiConnectionPointsBadFormat(connection_points)

        if len(connection_points) != 2:
            raise WimTapiConnectionPointsBadFormat(connection_points)

        sips = self.tapi_client.get_service_interface_points()
        services_composer = ServicesComposer(sips)

        for connection_point in connection_points:
            service_endpoint_id = connection_point.get("service_endpoint_id")
            if service_endpoint_id is None:
                raise WimTapiMissingConnPointField(
                    connection_point, "service_endpoint_id"
                )

            mapping = self.mappings.get(service_endpoint_id, {})
            services_composer.add_service_endpoint(service_endpoint_id, mapping)

        services_composer.dump(self.logger)

        service_uuid, conn_info = self._create_services_and_conn_info(services_composer)
        return service_uuid, conn_info

    def _create_services_and_conn_info(self, services_composer: ServicesComposer):
        services = services_composer.services
        requested_capacity = services_composer.requested_capacity
        vlan_constraint = services_composer.vlan_constraint

        service_uuid = str(uuid.uuid4())

        if services_composer.is_bidirectional():
            service_endpoints = services[0]
            self.tapi_client.create_service(
                "<>",
                service_uuid,
                service_endpoints,
                bidirectional=True,
                requested_capacity=requested_capacity,
                vlan_constraint=vlan_constraint,
            )
            conn_info = conn_info_compose_bidirectional(
                service_uuid,
                service_endpoints,
                requested_capacity=requested_capacity,
                vlan_constraint=vlan_constraint,
            )

        else:
            service_uuid = service_uuid[0 : len(service_uuid) - 4] + "00**"
            service_az_uuid = service_uuid.replace("**", "af")
            service_az_endpoints = services[0]
            service_za_uuid = service_uuid.replace("**", "fa")
            service_za_endpoints = services[1]

            self.tapi_client.create_service(
                ">>",
                service_az_uuid,
                service_az_endpoints,
                bidirectional=False,
                requested_capacity=requested_capacity,
                vlan_constraint=vlan_constraint,
            )
            self.tapi_client.create_service(
                "<<",
                service_za_uuid,
                service_za_endpoints,
                bidirectional=False,
                requested_capacity=requested_capacity,
                vlan_constraint=vlan_constraint,
            )
            conn_info = conn_info_compose_unidirectional(
                service_az_uuid,
                service_az_endpoints,
                service_za_uuid,
                service_za_endpoints,
                requested_capacity=requested_capacity,
                vlan_constraint=vlan_constraint,
            )

        return service_uuid, conn_info

    def delete_connectivity_service(self, service_uuid, conn_info=None):
        """
        Disconnect multi-site endpoints previously connected

        :param service_uuid: The one returned by create_connectivity_service
        :param conn_info: The one returned by last call to 'create_connectivity_service' or 'edit_connectivity_service'
            if they do not return None
        :return: None
        :raises: SdnConnectorException: In case of error. The parameter http_code must be filled
        """
        bidirectional = conn_info["bidirectional"]
        if bidirectional:
            service_uuid = conn_info["uuid"]
            self.tapi_client.delete_service("<>", service_uuid)
        else:
            service_az_uuid = conn_info["az"]["uuid"]
            service_za_uuid = conn_info["za"]["uuid"]
            self.tapi_client.delete_service(">>", service_az_uuid)
            self.tapi_client.delete_service("<<", service_za_uuid)

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
        raise NotImplementedError

    def clear_all_connectivity_services(self):
        """Delete all WAN Links in a WIM.

        This method is intended for debugging only, and should delete all the
        connections controlled by the WIM/SDN, not only the  connections that
        a specific RO is aware of.

        Raises:
            SdnConnectorException: In case of error.
        """
        raise NotImplementedError

    def get_all_active_connectivity_services(self):
        """Provide information about all active connections provisioned by a
        WIM.

        Raises:
            SdnConnectorException: In case of error.
        """
        raise NotImplementedError
