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

"""This file contains the unit tests for the Transport API (TAPI) WIM connector."""

import http.server
import threading
import unittest

from osm_rosdn_tapi.exceptions import (
    WimTapiConnectionPointsBadFormat,
    WimTapiMissingConnPointField,
    WimTapiUnsupportedServiceType,
)
from osm_rosdn_tapi.tests.constants import (
    WIM_ACCOUNT,
    WIM_HOST_PORT,
    WIM_PORT_MAPPING,
    WIM_URL,
)
from osm_rosdn_tapi.tests.mock_osm_ro import MockOsmRo
from osm_rosdn_tapi.tests.mock_tapi_handler import MockTapiRequestHandler
from osm_rosdn_tapi.wimconn_tapi import WimconnectorTAPI


SERVICE_TYPE = "ELINE"
SERVICE_CONNECTION_POINTS_BIDIRECTIONAL = [
    # SIPs taken from mock_tapi_handler.py
    {"service_endpoint_id": "R1-eth0"},
    {"service_endpoint_id": "R2-eth0"},
]
SERVICE_CONNECTION_POINTS_UNIDIRECTIONAL = [
    # SIPs taken from mock_tapi_handler.py
    {"service_endpoint_id": "R3-opt1"},
    {"service_endpoint_id": "R4-opt1"},
]


class UnitTests(unittest.TestCase):
    """Unit tests for Transport API WIM connector"""

    def setUp(self) -> None:
        self.wim_server = http.server.ThreadingHTTPServer(
            WIM_HOST_PORT, MockTapiRequestHandler
        )

    def test_wrong_cases(self):
        with self.wim_server:
            wim_server_thread = threading.Thread(target=self.wim_server.serve_forever)
            wim_server_thread.daemon = True
            wim_server_thread.start()

            mock_osm_ro_tapi = MockOsmRo(
                WimconnectorTAPI, WIM_URL, WIM_ACCOUNT, WIM_PORT_MAPPING
            )

            # Unsupported service type
            with self.assertRaises(WimTapiUnsupportedServiceType) as test_context:
                mock_osm_ro_tapi.create_connectivity_service(
                    "ELAN", SERVICE_CONNECTION_POINTS_BIDIRECTIONAL
                )
            self.assertEqual(
                str(test_context.exception.args[0]),
                "Unsupported ServiceType(ELAN). Supported ServiceTypes({'ELINE'})",
            )

            # Wrong number of connection_points
            with self.assertRaises(WimTapiConnectionPointsBadFormat) as test_context:
                mock_osm_ro_tapi.create_connectivity_service(SERVICE_TYPE, [])
            self.assertEqual(
                str(test_context.exception.args[0]),
                "ConnectionPoints([]) must be a list or tuple of length 2",
            )

            # Wrong type of connection_points
            with self.assertRaises(WimTapiConnectionPointsBadFormat) as test_context:
                mock_osm_ro_tapi.create_connectivity_service(
                    SERVICE_TYPE, {"a": "b", "c": "d"}
                )
            self.assertEqual(
                str(test_context.exception.args[0]),
                "ConnectionPoints({'a': 'b', 'c': 'd'}) must be a list or tuple of length 2",
            )

            with self.assertRaises(WimTapiMissingConnPointField) as test_context:
                mock_osm_ro_tapi.create_connectivity_service(
                    SERVICE_TYPE,
                    [
                        {"wrong_service_endpoint_id": "value"},
                        {"service_endpoint_id": "value"},
                    ],
                )
            self.assertEqual(
                str(test_context.exception.args[0]),
                "WIM TAPI Connector: ConnectionPoint({'wrong_service_endpoint_id': 'value'}) has no field 'service_endpoint_id'",
            )

            self.wim_server.shutdown()
            wim_server_thread.join()

    def test_correct_bidirectional(self):
        with self.wim_server:
            wim_server_thread = threading.Thread(target=self.wim_server.serve_forever)
            wim_server_thread.daemon = True
            wim_server_thread.start()

            mock_osm_ro_tapi = MockOsmRo(
                WimconnectorTAPI, WIM_URL, WIM_ACCOUNT, WIM_PORT_MAPPING
            )

            # Create bidirectional TAPI service
            service_uuid = mock_osm_ro_tapi.create_connectivity_service(
                SERVICE_TYPE, SERVICE_CONNECTION_POINTS_BIDIRECTIONAL
            )
            self.assertIsInstance(service_uuid, str)

            # Check status of bidirectional TAPI service
            status = mock_osm_ro_tapi.get_connectivity_service_status(service_uuid)
            self.assertIsInstance(status, dict)
            self.assertIn("sdn_status", status)
            self.assertEqual(status["sdn_status"], "ACTIVE")

            # Delete bidirectional TAPI service
            mock_osm_ro_tapi.delete_connectivity_service(service_uuid)

            self.wim_server.shutdown()
            wim_server_thread.join()

    def test_correct_unidirectional(self):
        with self.wim_server:
            wim_server_thread = threading.Thread(target=self.wim_server.serve_forever)
            wim_server_thread.daemon = True
            wim_server_thread.start()

            mock_osm_ro_tapi = MockOsmRo(
                WimconnectorTAPI, WIM_URL, WIM_ACCOUNT, WIM_PORT_MAPPING
            )

            # Create unidirectional TAPI service
            service_uuid = mock_osm_ro_tapi.create_connectivity_service(
                SERVICE_TYPE, SERVICE_CONNECTION_POINTS_UNIDIRECTIONAL
            )
            self.assertIsInstance(service_uuid, str)

            # Check status of unidirectional TAPI service
            status = mock_osm_ro_tapi.get_connectivity_service_status(service_uuid)
            self.assertIsInstance(status, dict)
            self.assertIn("sdn_status", status)
            self.assertEqual(status["sdn_status"], "ACTIVE")

            # Delete unidirectional TAPI service
            mock_osm_ro_tapi.delete_connectivity_service(service_uuid)

            self.wim_server.shutdown()
            wim_server_thread.join()
