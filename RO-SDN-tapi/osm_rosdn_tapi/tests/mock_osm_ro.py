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

"""This file contains a Mock OSM RO component that can be used for rapid unit testing.

This code is based on code taken with permission from ETSI TeraFlowSDN project at:
  https://labs.etsi.org/rep/tfs/controller
"""


from typing import Dict, List

from osm_ro_plugin.sdnconn import SdnConnectorBase

from .exceptions import MockOsmRoServiceNotFound


class MockOsmRo:
    def __init__(
        self,
        klass: SdnConnectorBase,
        url: str,
        wim_account: Dict,
        wim_port_mapping: Dict,
    ) -> None:
        wim = {"wim_url": url}
        config = {
            "mapping_not_needed": False,
            "service_endpoint_mapping": wim_port_mapping,
        }

        # Instantiate WIM connector
        self.wim_connector = klass(wim, wim_account, config=config)

        # Internal DB emulating OSM RO storage provided to WIM Connectors
        self.conn_info = {}

    def create_connectivity_service(
        self, service_type: str, connection_points: List[Dict]
    ) -> str:
        self.wim_connector.check_credentials()
        service_uuid, conn_info = self.wim_connector.create_connectivity_service(
            service_type, connection_points
        )
        self.conn_info[service_uuid] = conn_info
        return service_uuid

    def get_connectivity_service_status(self, service_uuid: str) -> Dict:
        conn_info = self.conn_info.get(service_uuid)
        if conn_info is None:
            raise MockOsmRoServiceNotFound(service_uuid)
        self.wim_connector.check_credentials()
        return self.wim_connector.get_connectivity_service_status(
            service_uuid, conn_info=conn_info
        )

    def edit_connectivity_service(
        self, service_uuid: str, connection_points: List[Dict]
    ) -> None:
        conn_info = self.conn_info.get(service_uuid)
        if conn_info is None:
            raise MockOsmRoServiceNotFound(service_uuid)
        self.wim_connector.check_credentials()
        self.wim_connector.edit_connectivity_service(
            service_uuid, conn_info=conn_info, connection_points=connection_points
        )

    def delete_connectivity_service(self, service_uuid: str) -> None:
        conn_info = self.conn_info.get(service_uuid)
        if conn_info is None:
            raise MockOsmRoServiceNotFound(service_uuid)
        self.wim_connector.check_credentials()
        self.wim_connector.delete_connectivity_service(
            service_uuid, conn_info=conn_info
        )
