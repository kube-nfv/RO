#######################################################################################
# Copyright ETSI Contributors and Others.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################

import unittest
from unittest.mock import patch

from osm_ro_plugin.sdnconn import SdnConnectorError
from osm_rosdn_juniper_contrail.sdn_assist_juniper_contrail import JuniperContrail


class TestJuniperContrail(unittest.TestCase):
    @patch("logging.getLogger")
    def setUp(self, mock_logger):
        self.wim = {"wim_url": "http://dummy.url"}
        self.wim_account = {
            "user": "sdn_user",
            "password": "dummy_pass",
        }
        self.logger = None
        self.mock_logger = mock_logger

    @patch("osm_rosdn_juniper_contrail.sdn_api.UnderlayApi")
    def test_juniper_contrail_sdn_with_ssl_cert(self, mock_underlay_api):
        config = {
            "ca_cert": "/path/to/certfile",
            "project": "test_project",
            "domain": "test_default",
            "asn": "test_asn",
            "fabric": "test_fabric",
        }

        underlay_api_config = {
            "auth_url": self.wim,
            "verify": config["ca_cert"],
            "user": self.wim_account["user"],
            "password": self.wim_account["password"],
        }
        expected_underlay_api_call = [
            self.wim,
            underlay_api_config,
            self.wim_account["user"],
            self.wim_account["password"],
            self.mock_logger,
        ]

        JuniperContrail(self.wim, self.wim_account, config, self.logger)
        mock_underlay_api.called_once_with(expected_underlay_api_call)

    @patch("osm_rosdn_juniper_contrail.sdn_api.UnderlayApi")
    def test_juniper_contrail_sdn_insecure_connection(self, mock_underlay_api):
        config = {
            "insecure": True,
            "project": "test_project",
            "domain": "test_default",
            "asn": "test_asn",
            "fabric": "test_fabric",
        }
        underlay_api_config = {
            "auth_url": self.wim,
            "verify": False,
            "user": self.wim_account["user"],
            "password": self.wim_account["password"],
        }
        expected_underlay_api_call = [
            self.wim,
            underlay_api_config,
            self.wim_account["user"],
            self.wim_account["password"],
            self.mock_logger,
        ]

        JuniperContrail(self.wim, self.wim_account, config, self.logger)
        mock_underlay_api.called_once_with(expected_underlay_api_call)

    @patch("osm_rosdn_juniper_contrail.sdn_api.UnderlayApi")
    def test_juniper_contrail_sdn_config_does_not_include_ssl_config_options(
        self, mock_underlay_api
    ):
        config = {
            "project": "test_project",
            "domain": "test_default",
            "asn": "test_asn",
            "fabric": "test_fabric",
        }
        with self.assertRaises(SdnConnectorError):
            JuniperContrail(self.wim, self.wim_account, config, self.logger)

    @patch("osm_rosdn_juniper_contrail.sdn_api.UnderlayApi")
    def test_juniper_contrail_sdn_config_includes_both_ca_cert_and_insecure(
        self, mock_underlay_api
    ):
        config = {
            "project": "test_project",
            "domain": "test_default",
            "asn": "test_asn",
            "fabric": "test_fabric",
            "insecure": True,
            "ca_cert": "/path/to/certfile",
        }

        with self.assertRaises(SdnConnectorError):
            JuniperContrail(self.wim, self.wim_account, config, self.logger)
