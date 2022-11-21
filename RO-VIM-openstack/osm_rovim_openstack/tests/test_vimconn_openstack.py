# -*- coding: utf-8 -*-

##
# Copyright 2017 Intel Corporation.
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
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact with: nfvlabs@tid.es
##

"""
This module contains unit tests for the OpenStack VIM connector
Run this directly with python2 or python3.
"""
import copy
from copy import deepcopy
import logging
import unittest

import mock
from mock import MagicMock, patch
from neutronclient.v2_0.client import Client
from novaclient import exceptions as nvExceptions
from osm_ro_plugin import vimconn
from osm_ro_plugin.vimconn import (
    VimConnConnectionException,
    VimConnException,
    VimConnNotFoundException,
)
from osm_rovim_openstack.vimconn_openstack import vimconnector

__author__ = "Igor D.C."
__date__ = "$23-aug-2017 23:59:59$"

# Variables Used in TestNewVmInstance Class
name = "basicvm"
description = "my firewall"
start = True
image_id = "408b73-e9cc-5a6a-t270-82cc4811bd4a"
flavor_id = "208b73-e9cc-5a6a-t270-82cc4811bd4a"
affinity_group_list = []
net_list = []
cloud_config = {}
disk_list = []
disk_list2 = [
    {"size": 10, "image_id": image_id},
    {"size": 20},
]
availability_zone_index = 0
availability_zone_list = ["nova"]
floating_network_vim_id = "108b73-e9cc-5a6a-t270-82cc4811bd4a"
net_id = "83372685-f67f-49fd-8722-eabb7692fc22"
net2_id = "46472685-f67f-49fd-8722-eabb7692fc22"
mac_address = "00:00:5e:00:53:af"
port_id = "03372685-f67f-49fd-8722-eabb7692fc22"
time_return_value = 156570000
port2_id = "17472685-f67f-49fd-8722-eabb7692fc22"
root_vol_id = "tc408b73-r9cc-5a6a-a270-82cc4811bd4a"
ip_addr1 = "20.3.4.5"
volume_id = "ac408b73-b9cc-4a6a-a270-82cc4811bd4a"
volume_id2 = "o4e0e83-b9uu-4akk-a234-89cc4811bd4a"
volume_id3 = "44e0e83-t9uu-4akk-a234-p9cc4811bd4a"
virtual_mac_id = "64e0e83-t9uu-4akk-a234-p9cc4811bd4a"
created_items_all_true = {
    f"floating_ip:{floating_network_vim_id}": True,
    f"volume:{volume_id}": True,
    f"port:{port_id}": True,
}


class TestSfcOperations(unittest.TestCase):
    @mock.patch("logging.getLogger", autospec=True)
    def setUp(self, mock_logger):
        # Instantiate dummy VIM connector so we can test it
        # It throws exception because of dummy parameters,
        # We are disabling the logging of exception not to print them to console.
        mock_logger = logging.getLogger()
        mock_logger.disabled = True
        self.vimconn = vimconnector(
            "123",
            "openstackvim",
            "456",
            "789",
            "http://dummy.url",
            None,
            "user",
            "pass",
        )

    def _test_new_sfi(
        self,
        create_sfc_port_pair,
        sfc_encap,
        ingress_ports=["5311c75d-d718-4369-bbda-cdcc6da60fcc"],
        egress_ports=["230cdf1b-de37-4891-bc07-f9010cf1f967"],
    ):
        # input to VIM connector
        name = "osm_sfi"
        # + ingress_ports
        # + egress_ports
        # TODO(igordc): must be changed to NSH in Queens (MPLS is a workaround)
        correlation = "nsh"
        if sfc_encap is not None:
            if not sfc_encap:
                correlation = None

        # what OpenStack is assumed to respond (patch OpenStack"s return value)
        dict_from_neutron = {
            "port_pair": {
                "id": "3d7ddc13-923c-4332-971e-708ed82902ce",
                "name": name,
                "description": "",
                "tenant_id": "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c",
                "project_id": "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c",
                "ingress": ingress_ports[0] if len(ingress_ports) else None,
                "egress": egress_ports[0] if len(egress_ports) else None,
                "service_function_parameters": {"correlation": correlation},
            }
        }
        create_sfc_port_pair.return_value = dict_from_neutron

        # what the VIM connector is expected to
        # send to OpenStack based on the input
        dict_to_neutron = {
            "port_pair": {
                "name": name,
                "ingress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                "egress": "230cdf1b-de37-4891-bc07-f9010cf1f967",
                "service_function_parameters": {"correlation": correlation},
            }
        }

        # call the VIM connector
        if sfc_encap is None:
            result = self.vimconn.new_sfi(name, ingress_ports, egress_ports)
        else:
            result = self.vimconn.new_sfi(name, ingress_ports, egress_ports, sfc_encap)

        # assert that the VIM connector made the expected call to OpenStack
        create_sfc_port_pair.assert_called_with(dict_to_neutron)
        # assert that the VIM connector had the expected result / return value
        self.assertEqual(result, dict_from_neutron["port_pair"]["id"])

    def _test_new_sf(self, create_sfc_port_pair_group):
        # input to VIM connector
        name = "osm_sf"
        instances = [
            "bbd01220-cf72-41f2-9e70-0669c2e5c4cd",
            "12ba215e-3987-4892-bd3a-d0fd91eecf98",
            "e25a7c79-14c8-469a-9ae1-f601c9371ffd",
        ]

        # what OpenStack is assumed to respond (patch OpenStack"s return value)
        dict_from_neutron = {
            "port_pair_group": {
                "id": "3d7ddc13-923c-4332-971e-708ed82902ce",
                "name": name,
                "description": "",
                "tenant_id": "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c",
                "project_id": "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c",
                "port_pairs": instances,
                "group_id": 1,
                "port_pair_group_parameters": {
                    "lb_fields": [],
                    "ppg_n_tuple_mapping": {
                        "ingress_n_tuple": {},
                        "egress_n_tuple": {},
                    },
                },
            }
        }
        create_sfc_port_pair_group.return_value = dict_from_neutron

        # what the VIM connector is expected to
        # send to OpenStack based on the input
        dict_to_neutron = {
            "port_pair_group": {
                "name": name,
                "port_pairs": [
                    "bbd01220-cf72-41f2-9e70-0669c2e5c4cd",
                    "12ba215e-3987-4892-bd3a-d0fd91eecf98",
                    "e25a7c79-14c8-469a-9ae1-f601c9371ffd",
                ],
            }
        }

        # call the VIM connector
        result = self.vimconn.new_sf(name, instances)

        # assert that the VIM connector made the expected call to OpenStack
        create_sfc_port_pair_group.assert_called_with(dict_to_neutron)
        # assert that the VIM connector had the expected result / return value
        self.assertEqual(result, dict_from_neutron["port_pair_group"]["id"])

    def _test_new_sfp(self, create_sfc_port_chain, sfc_encap, spi):
        # input to VIM connector
        name = "osm_sfp"
        classifications = [
            "2bd2a2e5-c5fd-4eac-a297-d5e255c35c19",
            "00f23389-bdfa-43c2-8b16-5815f2582fa8",
        ]
        sfs = [
            "2314daec-c262-414a-86e3-69bb6fa5bc16",
            "d8bfdb5d-195e-4f34-81aa-6135705317df",
        ]

        # TODO(igordc): must be changed to NSH in Queens (MPLS is a workaround)
        correlation = "nsh"
        chain_id = 33
        if spi:
            chain_id = spi

        # what OpenStack is assumed to respond (patch OpenStack"s return value)
        dict_from_neutron = {
            "port_chain": {
                "id": "5bc05721-079b-4b6e-a235-47cac331cbb6",
                "name": name,
                "description": "",
                "tenant_id": "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c",
                "project_id": "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c",
                "chain_id": chain_id,
                "flow_classifiers": classifications,
                "port_pair_groups": sfs,
                "chain_parameters": {"correlation": correlation},
            }
        }
        create_sfc_port_chain.return_value = dict_from_neutron

        # what the VIM connector is expected to
        # send to OpenStack based on the input
        dict_to_neutron = {
            "port_chain": {
                "name": name,
                "flow_classifiers": [
                    "2bd2a2e5-c5fd-4eac-a297-d5e255c35c19",
                    "00f23389-bdfa-43c2-8b16-5815f2582fa8",
                ],
                "port_pair_groups": [
                    "2314daec-c262-414a-86e3-69bb6fa5bc16",
                    "d8bfdb5d-195e-4f34-81aa-6135705317df",
                ],
                "chain_parameters": {"correlation": correlation},
            }
        }
        if spi:
            dict_to_neutron["port_chain"]["chain_id"] = spi

        # call the VIM connector
        if sfc_encap is None:
            dict_to_neutron["port_chain"]["chain_parameters"] = {"correlation": "mpls"}
            if spi is None:
                result = self.vimconn.new_sfp(
                    name, classifications, sfs, sfc_encap=False
                )
            else:
                result = self.vimconn.new_sfp(
                    name, classifications, sfs, sfc_encap=False, spi=spi
                )
        else:
            if spi is None:
                result = self.vimconn.new_sfp(name, classifications, sfs, sfc_encap)
            else:
                result = self.vimconn.new_sfp(
                    name, classifications, sfs, sfc_encap, spi
                )

        # assert that the VIM connector made the expected call to OpenStack
        create_sfc_port_chain.assert_called_with(dict_to_neutron)
        # assert that the VIM connector had the expected result / return value
        self.assertEqual(result, dict_from_neutron["port_chain"]["id"])

    def _test_new_classification(self, create_sfc_flow_classifier, ctype):
        # input to VIM connector
        name = "osm_classification"
        definition = {
            "ethertype": "IPv4",
            "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
            "protocol": "tcp",
            "source_ip_prefix": "192.168.2.0/24",
            "source_port_range_max": 99,
            "source_port_range_min": 50,
        }

        # what OpenStack is assumed to respond (patch OpenStack"s return value)
        dict_from_neutron = {"flow_classifier": copy.copy(definition)}
        dict_from_neutron["flow_classifier"][
            "id"
        ] = "7735ec2c-fddf-4130-9712-32ed2ab6a372"
        dict_from_neutron["flow_classifier"]["name"] = name
        dict_from_neutron["flow_classifier"]["description"] = ""
        dict_from_neutron["flow_classifier"][
            "tenant_id"
        ] = "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c"
        dict_from_neutron["flow_classifier"][
            "project_id"
        ] = "130b1e97-b0f1-40a8-8804-b6ad9b8c3e0c"
        create_sfc_flow_classifier.return_value = dict_from_neutron

        # what the VIM connector is expected to
        # send to OpenStack based on the input
        dict_to_neutron = {"flow_classifier": copy.copy(definition)}
        dict_to_neutron["flow_classifier"]["name"] = "osm_classification"

        # call the VIM connector
        result = self.vimconn.new_classification(name, ctype, definition)

        # assert that the VIM connector made the expected call to OpenStack
        create_sfc_flow_classifier.assert_called_with(dict_to_neutron)
        # assert that the VIM connector had the expected result / return value
        self.assertEqual(result, dict_from_neutron["flow_classifier"]["id"])

    @mock.patch.object(Client, "create_sfc_flow_classifier")
    def test_new_classification(self, create_sfc_flow_classifier):
        self._test_new_classification(
            create_sfc_flow_classifier, "legacy_flow_classifier"
        )

    @mock.patch.object(Client, "create_sfc_flow_classifier")
    def test_new_classification_unsupported_type(self, create_sfc_flow_classifier):
        self.assertRaises(
            vimconn.VimConnNotSupportedException,
            self._test_new_classification,
            create_sfc_flow_classifier,
            "h265",
        )

    @mock.patch.object(Client, "create_sfc_port_pair")
    def test_new_sfi_with_sfc_encap(self, create_sfc_port_pair):
        self._test_new_sfi(create_sfc_port_pair, True)

    @mock.patch.object(Client, "create_sfc_port_pair")
    def test_new_sfi_without_sfc_encap(self, create_sfc_port_pair):
        self._test_new_sfi(create_sfc_port_pair, False)

    @mock.patch.object(Client, "create_sfc_port_pair")
    def test_new_sfi_default_sfc_encap(self, create_sfc_port_pair):
        self._test_new_sfi(create_sfc_port_pair, None)

    @mock.patch.object(Client, "create_sfc_port_pair")
    def test_new_sfi_bad_ingress_ports(self, create_sfc_port_pair):
        ingress_ports = [
            "5311c75d-d718-4369-bbda-cdcc6da60fcc",
            "a0273f64-82c9-11e7-b08f-6328e53f0fa7",
        ]
        self.assertRaises(
            vimconn.VimConnNotSupportedException,
            self._test_new_sfi,
            create_sfc_port_pair,
            True,
            ingress_ports=ingress_ports,
        )
        ingress_ports = []
        self.assertRaises(
            vimconn.VimConnNotSupportedException,
            self._test_new_sfi,
            create_sfc_port_pair,
            True,
            ingress_ports=ingress_ports,
        )

    @mock.patch.object(Client, "create_sfc_port_pair")
    def test_new_sfi_bad_egress_ports(self, create_sfc_port_pair):
        egress_ports = [
            "230cdf1b-de37-4891-bc07-f9010cf1f967",
            "b41228fe-82c9-11e7-9b44-17504174320b",
        ]
        self.assertRaises(
            vimconn.VimConnNotSupportedException,
            self._test_new_sfi,
            create_sfc_port_pair,
            True,
            egress_ports=egress_ports,
        )
        egress_ports = []
        self.assertRaises(
            vimconn.VimConnNotSupportedException,
            self._test_new_sfi,
            create_sfc_port_pair,
            True,
            egress_ports=egress_ports,
        )

    @mock.patch.object(vimconnector, "get_sfi")
    @mock.patch.object(Client, "create_sfc_port_pair_group")
    def test_new_sf(self, create_sfc_port_pair_group, get_sfi):
        get_sfi.return_value = {"sfc_encap": True}
        self._test_new_sf(create_sfc_port_pair_group)

    @mock.patch.object(vimconnector, "get_sfi")
    @mock.patch.object(Client, "create_sfc_port_pair_group")
    def test_new_sf_inconsistent_sfc_encap(self, create_sfc_port_pair_group, get_sfi):
        get_sfi.return_value = {"sfc_encap": "nsh"}
        self.assertRaises(
            vimconn.VimConnNotSupportedException,
            self._test_new_sf,
            create_sfc_port_pair_group,
        )

    @mock.patch.object(Client, "create_sfc_port_chain")
    def test_new_sfp_with_sfc_encap(self, create_sfc_port_chain):
        self._test_new_sfp(create_sfc_port_chain, True, None)

    @mock.patch.object(Client, "create_sfc_port_chain")
    def test_new_sfp_without_sfc_encap(self, create_sfc_port_chain):
        self._test_new_sfp(create_sfc_port_chain, None, None)
        self._test_new_sfp(create_sfc_port_chain, None, 25)

    @mock.patch.object(Client, "create_sfc_port_chain")
    def test_new_sfp_default_sfc_encap(self, create_sfc_port_chain):
        self._test_new_sfp(create_sfc_port_chain, None, None)

    @mock.patch.object(Client, "create_sfc_port_chain")
    def test_new_sfp_with_sfc_encap_spi(self, create_sfc_port_chain):
        self._test_new_sfp(create_sfc_port_chain, True, 25)

    @mock.patch.object(Client, "create_sfc_port_chain")
    def test_new_sfp_default_sfc_encap_spi(self, create_sfc_port_chain):
        self._test_new_sfp(create_sfc_port_chain, None, 25)

    @mock.patch.object(Client, "list_sfc_flow_classifiers")
    def test_get_classification_list(self, list_sfc_flow_classifiers):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_flow_classifiers.return_value = {
            "flow_classifiers": [
                {
                    "source_port_range_min": 2000,
                    "destination_ip_prefix": "192.168.3.0/24",
                    "protocol": "udp",
                    "description": "",
                    "ethertype": "IPv4",
                    "l7_parameters": {},
                    "source_port_range_max": 2000,
                    "destination_port_range_min": 3000,
                    "source_ip_prefix": "192.168.2.0/24",
                    "logical_destination_port": None,
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "destination_port_range_max": None,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
                    "id": "22198366-d4e8-4d6b-b4d2-637d5d6cbb7d",
                    "name": "fc1",
                }
            ]
        }

        # call the VIM connector
        filter_dict = {"protocol": "tcp", "ethertype": "IPv4"}
        result = self.vimconn.get_classification_list(filter_dict.copy())

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_flow_classifiers.assert_called_with(**filter_dict)
        # assert that the VIM connector successfully
        # translated and returned the OpenStack result
        self.assertEqual(
            result,
            [
                {
                    "id": "22198366-d4e8-4d6b-b4d2-637d5d6cbb7d",
                    "name": "fc1",
                    "description": "",
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "ctype": "legacy_flow_classifier",
                    "definition": {
                        "source_port_range_min": 2000,
                        "destination_ip_prefix": "192.168.3.0/24",
                        "protocol": "udp",
                        "ethertype": "IPv4",
                        "l7_parameters": {},
                        "source_port_range_max": 2000,
                        "destination_port_range_min": 3000,
                        "source_ip_prefix": "192.168.2.0/24",
                        "logical_destination_port": None,
                        "destination_port_range_max": None,
                        "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
                    },
                }
            ],
        )

    def _test_get_sfi_list(self, list_port_pair, correlation, sfc_encap):
        # what OpenStack is assumed to return to the VIM connector
        list_port_pair.return_value = {
            "port_pairs": [
                {
                    "ingress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "egress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "service_function_parameters": {"correlation": correlation},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "c121ebdd-7f2d-4213-b933-3325298a6966",
                    "name": "osm_sfi",
                }
            ]
        }

        # call the VIM connector
        filter_dict = {"name": "osm_sfi", "description": ""}
        result = self.vimconn.get_sfi_list(filter_dict.copy())

        # assert that VIM connector called OpenStack with the expected filter
        list_port_pair.assert_called_with(**filter_dict)
        # assert that the VIM connector successfully
        # translated and returned the OpenStack result
        self.assertEqual(
            result,
            [
                {
                    "ingress_ports": ["5311c75d-d718-4369-bbda-cdcc6da60fcc"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "egress_ports": ["5311c75d-d718-4369-bbda-cdcc6da60fcc"],
                    "sfc_encap": sfc_encap,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "c121ebdd-7f2d-4213-b933-3325298a6966",
                    "name": "osm_sfi",
                }
            ],
        )

    @mock.patch.object(Client, "list_sfc_port_pairs")
    def test_get_sfi_list_with_sfc_encap(self, list_sfc_port_pairs):
        self._test_get_sfi_list(list_sfc_port_pairs, "nsh", True)

    @mock.patch.object(Client, "list_sfc_port_pairs")
    def test_get_sfi_list_without_sfc_encap(self, list_sfc_port_pairs):
        self._test_get_sfi_list(list_sfc_port_pairs, None, False)

    @mock.patch.object(Client, "list_sfc_port_pair_groups")
    def test_get_sf_list(self, list_sfc_port_pair_groups):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pair_groups.return_value = {
            "port_pair_groups": [
                {
                    "port_pairs": [
                        "08fbdbb0-82d6-11e7-ad95-9bb52fbec2f2",
                        "0d63799c-82d6-11e7-8deb-a746bb3ae9f5",
                    ],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "port_pair_group_parameters": {},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "f4a0bde8-82d5-11e7-90e1-a72b762fa27f",
                    "name": "osm_sf",
                }
            ]
        }

        # call the VIM connector
        filter_dict = {"name": "osm_sf", "description": ""}
        result = self.vimconn.get_sf_list(filter_dict.copy())

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_pair_groups.assert_called_with(**filter_dict)
        # assert that the VIM connector successfully
        # translated and returned the OpenStack result
        self.assertEqual(
            result,
            [
                {
                    "sfis": [
                        "08fbdbb0-82d6-11e7-ad95-9bb52fbec2f2",
                        "0d63799c-82d6-11e7-8deb-a746bb3ae9f5",
                    ],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "f4a0bde8-82d5-11e7-90e1-a72b762fa27f",
                    "name": "osm_sf",
                }
            ],
        )

    def _test_get_sfp_list(self, list_sfc_port_chains, correlation, sfc_encap):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_chains.return_value = {
            "port_chains": [
                {
                    "port_pair_groups": [
                        "7d8e3bf8-82d6-11e7-a032-8ff028839d25",
                        "7dc9013e-82d6-11e7-a5a6-a3a8d78a5518",
                    ],
                    "flow_classifiers": [
                        "1333c2f4-82d7-11e7-a5df-9327f33d104e",
                        "1387ab44-82d7-11e7-9bb0-476337183905",
                    ],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "chain_parameters": {"correlation": correlation},
                    "chain_id": 40,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "821bc9be-82d7-11e7-8ce3-23a08a27ab47",
                    "name": "osm_sfp",
                }
            ]
        }

        # call the VIM connector
        filter_dict = {"name": "osm_sfp", "description": ""}
        result = self.vimconn.get_sfp_list(filter_dict.copy())

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_chains.assert_called_with(**filter_dict)
        # assert that the VIM connector successfully
        # translated and returned the OpenStack result
        self.assertEqual(
            result,
            [
                {
                    "service_functions": [
                        "7d8e3bf8-82d6-11e7-a032-8ff028839d25",
                        "7dc9013e-82d6-11e7-a5a6-a3a8d78a5518",
                    ],
                    "classifications": [
                        "1333c2f4-82d7-11e7-a5df-9327f33d104e",
                        "1387ab44-82d7-11e7-9bb0-476337183905",
                    ],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "sfc_encap": sfc_encap,
                    "spi": 40,
                    "id": "821bc9be-82d7-11e7-8ce3-23a08a27ab47",
                    "name": "osm_sfp",
                }
            ],
        )

    @mock.patch.object(Client, "list_sfc_port_chains")
    def test_get_sfp_list_with_sfc_encap(self, list_sfc_port_chains):
        self._test_get_sfp_list(list_sfc_port_chains, "nsh", True)

    @mock.patch.object(Client, "list_sfc_port_chains")
    def test_get_sfp_list_without_sfc_encap(self, list_sfc_port_chains):
        self._test_get_sfp_list(list_sfc_port_chains, None, False)

    @mock.patch.object(Client, "list_sfc_flow_classifiers")
    def test_get_classification(self, list_sfc_flow_classifiers):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_flow_classifiers.return_value = {
            "flow_classifiers": [
                {
                    "source_port_range_min": 2000,
                    "destination_ip_prefix": "192.168.3.0/24",
                    "protocol": "udp",
                    "description": "",
                    "ethertype": "IPv4",
                    "l7_parameters": {},
                    "source_port_range_max": 2000,
                    "destination_port_range_min": 3000,
                    "source_ip_prefix": "192.168.2.0/24",
                    "logical_destination_port": None,
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "destination_port_range_max": None,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
                    "id": "22198366-d4e8-4d6b-b4d2-637d5d6cbb7d",
                    "name": "fc1",
                }
            ]
        }

        # call the VIM connector
        result = self.vimconn.get_classification("22198366-d4e8-4d6b-b4d2-637d5d6cbb7d")

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_flow_classifiers.assert_called_with(
            id="22198366-d4e8-4d6b-b4d2-637d5d6cbb7d"
        )
        # assert that VIM connector successfully returned the OpenStack result
        self.assertEqual(
            result,
            {
                "id": "22198366-d4e8-4d6b-b4d2-637d5d6cbb7d",
                "name": "fc1",
                "description": "",
                "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "ctype": "legacy_flow_classifier",
                "definition": {
                    "source_port_range_min": 2000,
                    "destination_ip_prefix": "192.168.3.0/24",
                    "protocol": "udp",
                    "ethertype": "IPv4",
                    "l7_parameters": {},
                    "source_port_range_max": 2000,
                    "destination_port_range_min": 3000,
                    "source_ip_prefix": "192.168.2.0/24",
                    "logical_destination_port": None,
                    "destination_port_range_max": None,
                    "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
                },
            },
        )

    @mock.patch.object(Client, "list_sfc_flow_classifiers")
    def test_get_classification_many_results(self, list_sfc_flow_classifiers):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_flow_classifiers.return_value = {
            "flow_classifiers": [
                {
                    "source_port_range_min": 2000,
                    "destination_ip_prefix": "192.168.3.0/24",
                    "protocol": "udp",
                    "description": "",
                    "ethertype": "IPv4",
                    "l7_parameters": {},
                    "source_port_range_max": 2000,
                    "destination_port_range_min": 3000,
                    "source_ip_prefix": "192.168.2.0/24",
                    "logical_destination_port": None,
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "destination_port_range_max": None,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
                    "id": "22198366-d4e8-4d6b-b4d2-637d5d6cbb7d",
                    "name": "fc1",
                },
                {
                    "source_port_range_min": 1000,
                    "destination_ip_prefix": "192.168.3.0/24",
                    "protocol": "udp",
                    "description": "",
                    "ethertype": "IPv4",
                    "l7_parameters": {},
                    "source_port_range_max": 1000,
                    "destination_port_range_min": 3000,
                    "source_ip_prefix": "192.168.2.0/24",
                    "logical_destination_port": None,
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "destination_port_range_max": None,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "logical_source_port": "aaab0ab0-1452-4636-bb3b-11dca833fa2b",
                    "id": "3196bafc-82dd-11e7-a205-9bf6c14b0721",
                    "name": "fc2",
                },
            ]
        }

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnConflictException,
            self.vimconn.get_classification,
            "3196bafc-82dd-11e7-a205-9bf6c14b0721",
        )

        # assert the VIM connector called OpenStack with the expected filter
        list_sfc_flow_classifiers.assert_called_with(
            id="3196bafc-82dd-11e7-a205-9bf6c14b0721"
        )

    @mock.patch.object(Client, "list_sfc_flow_classifiers")
    def test_get_classification_no_results(self, list_sfc_flow_classifiers):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_flow_classifiers.return_value = {"flow_classifiers": []}

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnNotFoundException,
            self.vimconn.get_classification,
            "3196bafc-82dd-11e7-a205-9bf6c14b0721",
        )

        # assert the VIM connector called OpenStack with the expected filter
        list_sfc_flow_classifiers.assert_called_with(
            id="3196bafc-82dd-11e7-a205-9bf6c14b0721"
        )

    @mock.patch.object(Client, "list_sfc_port_pairs")
    def test_get_sfi(self, list_sfc_port_pairs):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pairs.return_value = {
            "port_pairs": [
                {
                    "ingress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "egress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "service_function_parameters": {"correlation": "nsh"},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "c121ebdd-7f2d-4213-b933-3325298a6966",
                    "name": "osm_sfi1",
                },
            ]
        }

        # call the VIM connector
        result = self.vimconn.get_sfi("c121ebdd-7f2d-4213-b933-3325298a6966")

        # assert the VIM connector called OpenStack with the expected filter
        list_sfc_port_pairs.assert_called_with(
            id="c121ebdd-7f2d-4213-b933-3325298a6966"
        )
        # assert the VIM connector successfully returned the OpenStack result
        self.assertEqual(
            result,
            {
                "ingress_ports": ["5311c75d-d718-4369-bbda-cdcc6da60fcc"],
                "egress_ports": ["5311c75d-d718-4369-bbda-cdcc6da60fcc"],
                "sfc_encap": True,
                "description": "",
                "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "id": "c121ebdd-7f2d-4213-b933-3325298a6966",
                "name": "osm_sfi1",
            },
        )

    @mock.patch.object(Client, "list_sfc_port_pairs")
    def test_get_sfi_many_results(self, list_sfc_port_pairs):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pairs.return_value = {
            "port_pairs": [
                {
                    "ingress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "egress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "service_function_parameters": {"correlation": "nsh"},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "c121ebdd-7f2d-4213-b933-3325298a6966",
                    "name": "osm_sfi1",
                },
                {
                    "ingress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "egress": "5311c75d-d718-4369-bbda-cdcc6da60fcc",
                    "service_function_parameters": {"correlation": "nsh"},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "c0436d92-82db-11e7-8f9c-5fa535f1261f",
                    "name": "osm_sfi2",
                },
            ]
        }

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnConflictException,
            self.vimconn.get_sfi,
            "c0436d92-82db-11e7-8f9c-5fa535f1261f",
        )

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_pairs.assert_called_with(
            id="c0436d92-82db-11e7-8f9c-5fa535f1261f"
        )

    @mock.patch.object(Client, "list_sfc_port_pairs")
    def test_get_sfi_no_results(self, list_sfc_port_pairs):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pairs.return_value = {"port_pairs": []}

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnNotFoundException,
            self.vimconn.get_sfi,
            "b22892fc-82d9-11e7-ae85-0fea6a3b3757",
        )

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_pairs.assert_called_with(
            id="b22892fc-82d9-11e7-ae85-0fea6a3b3757"
        )

    @mock.patch.object(Client, "list_sfc_port_pair_groups")
    def test_get_sf(self, list_sfc_port_pair_groups):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pair_groups.return_value = {
            "port_pair_groups": [
                {
                    "port_pairs": ["08fbdbb0-82d6-11e7-ad95-9bb52fbec2f2"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "port_pair_group_parameters": {},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "aabba8a6-82d9-11e7-a18a-d3c7719b742d",
                    "name": "osm_sf1",
                }
            ]
        }

        # call the VIM connector
        result = self.vimconn.get_sf("b22892fc-82d9-11e7-ae85-0fea6a3b3757")

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_pair_groups.assert_called_with(
            id="b22892fc-82d9-11e7-ae85-0fea6a3b3757"
        )
        # assert that VIM connector successfully returned the OpenStack result
        self.assertEqual(
            result,
            {
                "description": "",
                "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "sfis": ["08fbdbb0-82d6-11e7-ad95-9bb52fbec2f2"],
                "id": "aabba8a6-82d9-11e7-a18a-d3c7719b742d",
                "name": "osm_sf1",
            },
        )

    @mock.patch.object(Client, "list_sfc_port_pair_groups")
    def test_get_sf_many_results(self, list_sfc_port_pair_groups):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pair_groups.return_value = {
            "port_pair_groups": [
                {
                    "port_pairs": ["08fbdbb0-82d6-11e7-ad95-9bb52fbec2f2"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "port_pair_group_parameters": {},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "aabba8a6-82d9-11e7-a18a-d3c7719b742d",
                    "name": "osm_sf1",
                },
                {
                    "port_pairs": ["0d63799c-82d6-11e7-8deb-a746bb3ae9f5"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "port_pair_group_parameters": {},
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "b22892fc-82d9-11e7-ae85-0fea6a3b3757",
                    "name": "osm_sf2",
                },
            ]
        }

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnConflictException,
            self.vimconn.get_sf,
            "b22892fc-82d9-11e7-ae85-0fea6a3b3757",
        )

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_pair_groups.assert_called_with(
            id="b22892fc-82d9-11e7-ae85-0fea6a3b3757"
        )

    @mock.patch.object(Client, "list_sfc_port_pair_groups")
    def test_get_sf_no_results(self, list_sfc_port_pair_groups):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_pair_groups.return_value = {"port_pair_groups": []}

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnNotFoundException,
            self.vimconn.get_sf,
            "b22892fc-82d9-11e7-ae85-0fea6a3b3757",
        )

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_pair_groups.assert_called_with(
            id="b22892fc-82d9-11e7-ae85-0fea6a3b3757"
        )

    @mock.patch.object(Client, "list_sfc_port_chains")
    def test_get_sfp(self, list_sfc_port_chains):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_chains.return_value = {
            "port_chains": [
                {
                    "port_pair_groups": ["7d8e3bf8-82d6-11e7-a032-8ff028839d25"],
                    "flow_classifiers": ["1333c2f4-82d7-11e7-a5df-9327f33d104e"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "chain_parameters": {"correlation": "nsh"},
                    "chain_id": 40,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "821bc9be-82d7-11e7-8ce3-23a08a27ab47",
                    "name": "osm_sfp1",
                }
            ]
        }

        # call the VIM connector
        result = self.vimconn.get_sfp("821bc9be-82d7-11e7-8ce3-23a08a27ab47")

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_chains.assert_called_with(
            id="821bc9be-82d7-11e7-8ce3-23a08a27ab47"
        )
        # assert that VIM connector successfully returned the OpenStack result
        self.assertEqual(
            result,
            {
                "service_functions": ["7d8e3bf8-82d6-11e7-a032-8ff028839d25"],
                "classifications": ["1333c2f4-82d7-11e7-a5df-9327f33d104e"],
                "description": "",
                "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                "sfc_encap": True,
                "spi": 40,
                "id": "821bc9be-82d7-11e7-8ce3-23a08a27ab47",
                "name": "osm_sfp1",
            },
        )

    @mock.patch.object(Client, "list_sfc_port_chains")
    def test_get_sfp_many_results(self, list_sfc_port_chains):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_chains.return_value = {
            "port_chains": [
                {
                    "port_pair_groups": ["7d8e3bf8-82d6-11e7-a032-8ff028839d25"],
                    "flow_classifiers": ["1333c2f4-82d7-11e7-a5df-9327f33d104e"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "chain_parameters": {"correlation": "nsh"},
                    "chain_id": 40,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "821bc9be-82d7-11e7-8ce3-23a08a27ab47",
                    "name": "osm_sfp1",
                },
                {
                    "port_pair_groups": ["7d8e3bf8-82d6-11e7-a032-8ff028839d25"],
                    "flow_classifiers": ["1333c2f4-82d7-11e7-a5df-9327f33d104e"],
                    "description": "",
                    "tenant_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "chain_parameters": {"correlation": "nsh"},
                    "chain_id": 50,
                    "project_id": "8f3019ef06374fa880a0144ad4bc1d7b",
                    "id": "5d002f38-82de-11e7-a770-f303f11ce66a",
                    "name": "osm_sfp2",
                },
            ]
        }

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnConflictException,
            self.vimconn.get_sfp,
            "5d002f38-82de-11e7-a770-f303f11ce66a",
        )

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_chains.assert_called_with(
            id="5d002f38-82de-11e7-a770-f303f11ce66a"
        )

    @mock.patch.object(Client, "list_sfc_port_chains")
    def test_get_sfp_no_results(self, list_sfc_port_chains):
        # what OpenStack is assumed to return to the VIM connector
        list_sfc_port_chains.return_value = {"port_chains": []}

        # call the VIM connector
        self.assertRaises(
            vimconn.VimConnNotFoundException,
            self.vimconn.get_sfp,
            "5d002f38-82de-11e7-a770-f303f11ce66a",
        )

        # assert that VIM connector called OpenStack with the expected filter
        list_sfc_port_chains.assert_called_with(
            id="5d002f38-82de-11e7-a770-f303f11ce66a"
        )

    @mock.patch.object(Client, "delete_sfc_flow_classifier")
    def test_delete_classification(self, delete_sfc_flow_classifier):
        result = self.vimconn.delete_classification(
            "638f957c-82df-11e7-b7c8-132706021464"
        )
        delete_sfc_flow_classifier.assert_called_with(
            "638f957c-82df-11e7-b7c8-132706021464"
        )
        self.assertEqual(result, "638f957c-82df-11e7-b7c8-132706021464")

    @mock.patch.object(Client, "delete_sfc_port_pair")
    def test_delete_sfi(self, delete_sfc_port_pair):
        result = self.vimconn.delete_sfi("638f957c-82df-11e7-b7c8-132706021464")
        delete_sfc_port_pair.assert_called_with("638f957c-82df-11e7-b7c8-132706021464")
        self.assertEqual(result, "638f957c-82df-11e7-b7c8-132706021464")

    @mock.patch.object(Client, "delete_sfc_port_pair_group")
    def test_delete_sf(self, delete_sfc_port_pair_group):
        result = self.vimconn.delete_sf("638f957c-82df-11e7-b7c8-132706021464")
        delete_sfc_port_pair_group.assert_called_with(
            "638f957c-82df-11e7-b7c8-132706021464"
        )
        self.assertEqual(result, "638f957c-82df-11e7-b7c8-132706021464")

    @mock.patch.object(Client, "delete_sfc_port_chain")
    def test_delete_sfp(self, delete_sfc_port_chain):
        result = self.vimconn.delete_sfp("638f957c-82df-11e7-b7c8-132706021464")
        delete_sfc_port_chain.assert_called_with("638f957c-82df-11e7-b7c8-132706021464")
        self.assertEqual(result, "638f957c-82df-11e7-b7c8-132706021464")


class Status:
    def __init__(self, s):
        self.status = s

    def __str__(self):
        return self.status


class CopyingMock(MagicMock):
    def __call__(self, *args, **kwargs):
        args = deepcopy(args)
        kwargs = deepcopy(kwargs)
        return super(CopyingMock, self).__call__(*args, **kwargs)


class TestNewVmInstance(unittest.TestCase):
    @patch("logging.getLogger", autospec=True)
    def setUp(self, mock_logger):
        # Instantiate dummy VIM connector so we can test it
        # It throws exception because of dummy parameters,
        # We are disabling the logging of exception not to print them to console.
        mock_logger = logging.getLogger()
        mock_logger.disabled = True
        self.vimconn = vimconnector(
            "123",
            "openstackvim",
            "456",
            "789",
            "http://dummy.url",
            None,
            "user",
            "pass",
        )
        self.vimconn.neutron = CopyingMock()
        self.vimconn.nova = CopyingMock()
        self.vimconn.cinder = CopyingMock()
        self.server = MagicMock(object, autospec=True)
        self.server.tenant_id = "408b73-r9cc-5a6a-a270-82cc4811bd4a"
        self.server.id = "908b73-e9cc-5a6a-t270-82cc4811bd4a"
        self.vimconn.config["security_groups"] = "default"
        self.vimconn.config["keypair"] = "my_keypair"
        self.vimconn.security_groups_id = "12345"
        self.vimconn.nova.api_version.get_string.return_value = "2.32"
        self.vimconn.logger = CopyingMock()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_security_groups_exists_in_config(
        self, mock_get_ids
    ):
        """In VIM config security_groups exists, net port_security is True
        no_port_security_extension does not exist.
        """
        self.vimconn.config = {"security_groups": "example_security_group"}
        net = {"port_security": True}
        port_dict = {}
        result_dict = {"security_groups": "12345"}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_not_called()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_security_groups_exists_in_config_no_security_groups_id(
        self, mock_get_ids
    ):
        """In VIM config Security_groups exists, net port_security is True, vim security_groups_id does not exist,
        no_port_security_extension does not exist.
        """
        self.vimconn.config = {"security_groups": "example_security_group"}
        self.vimconn.security_groups_id = None
        net = {"port_security": True}
        port_dict = {}
        result_dict = {"security_groups": None}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_called()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_security_groups_exists_security_extension_true_in_config(
        self, mock_get_ids
    ):
        """In VIM config security_groups exists, net port_security is True, in VIM security_groups_id exists,
        no_port_security_extension set to True.
        """
        self.vimconn.config = {
            "security_groups": "example_security_group",
            "no_port_security_extension": True,
        }
        net = {"port_security": True}
        port_dict = {}
        result_dict = {}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_not_called()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_no_security_groups_in_config(
        self, mock_get_ids
    ):
        """In VIM config security_group does not exist, net port_security True, in VIM security_groups_id exists,
        no_port_security_extension does not exist."""
        self.vimconn.config = {}
        net = {"port_security": True}
        port_dict = {}
        result_dict = {}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_not_called()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_no_security_groups_security_extension_true_in_config(
        self, mock_get_ids
    ):
        """Security_group does not exist, net port_security is True, in VIM security_groups_id exists,
        no_port_security_extension set to True."""
        self.vimconn.config = {"no_port_security_extension": True}
        net = {"port_security": True}
        port_dict = {}
        result_dict = {}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_not_called()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_security_groups_exists_net_port_security_false(
        self, mock_get_ids
    ):
        """In VIM config security_group exists, net port_security False, security_groups_id exists,
        no_port_security_extension does not exist."""
        self.vimconn.config = {"security_groups": "example_security_group"}
        net = {"port_security": False}
        port_dict = {}
        result_dict = {}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_not_called()

    @patch.object(vimconnector, "_get_ids_from_name")
    def test_prepare_port_dict_security_net_port_security_false_port_security_extension_true(
        self, mock_get_ids
    ):
        """In VIM config security_group exists, net port_security False, security_groups_id exists,
        no_port_security_extension set to True."""
        self.vimconn.config = {
            "security_groups": "example_security_group",
            "no_port_security_extension": True,
        }
        net = {"port_security": False}
        port_dict = {}
        result_dict = {}

        self.vimconn._prepare_port_dict_security_groups(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)
        mock_get_ids.assert_not_called()

    def test_prepare_port_dict_binding_net_type_virtual(self):
        """net type is virtual."""
        net = {"type": "virtual"}
        port_dict = {}
        result_dict = {}
        self.vimconn._prepare_port_dict_binding(net, port_dict)
        self.assertDictEqual(result_dict, port_dict)

    def test_prepare_port_dict_binding_net_type_vf(self):
        """net type is VF, vim_type is not VIO."""
        net = {"type": "VF"}
        self.vimconn.vim_type = None
        port_dict = {}
        result_dict = {"binding:vnic_type": "direct"}
        self.vimconn._prepare_port_dict_binding(net, port_dict)
        self.assertDictEqual(port_dict, result_dict)

    def test_prepare_port_dict_binding_net_type_sriov_vim_type_vio(self):
        """net type is SR-IOV, vim_type is VIO."""
        net = {"type": "SR-IOV"}
        self.vimconn.vim_type = "VIO"
        port_dict = {}
        result_dict = {
            "binding:vnic_type": "direct",
            "port_security_enabled": False,
            "provider_security_groups": [],
            "security_groups": [],
        }
        self.vimconn._prepare_port_dict_binding(net, port_dict)
        self.assertDictEqual(port_dict, result_dict)

    def test_prepare_port_dict_binding_net_type_passthrough(self):
        """net type is pci-passthrough."""
        net = {"type": "PCI-PASSTHROUGH"}
        port_dict = {}
        result_dict = {
            "binding:vnic_type": "direct-physical",
        }
        self.vimconn._prepare_port_dict_binding(net, port_dict)
        self.assertDictEqual(port_dict, result_dict)

    def test_prepare_port_dict_binding_no_net_type(self):
        """net type is missing."""
        net = {}
        port_dict = {}
        with self.assertRaises(VimConnException) as err:
            self.vimconn._prepare_port_dict_binding(net, port_dict)
        self.assertEqual(str(err.exception), "Type is missing in the network details.")

    def test_set_fixed_ip(self):
        """new_port has fixed ip."""
        net = {}
        new_port = {
            "port": {
                "fixed_ips": [{"ip_address": "10.1.2.3"}, {"ip_address": "20.1.2.3"}]
            }
        }
        result = {"ip": "10.1.2.3"}
        self.vimconn._set_fixed_ip(new_port, net)
        self.assertDictEqual(net, result)

    def test_set_fixed_ip_no_fixed_ip(self):
        """new_port does not have fixed ip."""
        net = {}
        new_port = {"port": {}}
        result = {"ip": None}
        self.vimconn._set_fixed_ip(new_port, net)
        self.assertDictEqual(net, result)

    def test_set_fixed_ip_raise_exception(self):
        """new_port does not have port details."""
        net = {}
        new_port = {}
        with self.assertRaises(Exception) as err:
            self.vimconn._set_fixed_ip(new_port, net)
        self.assertEqual(type(err.exception), KeyError)

    def test_prepare_port_dict_mac_ip_addr(self):
        """mac address and ip address exist."""
        net = {
            "mac_address": mac_address,
            "ip_address": "10.0.1.5",
        }
        port_dict = {}
        result_dict = {
            "mac_address": mac_address,
            "fixed_ips": [{"ip_address": "10.0.1.5"}],
        }
        self.vimconn._prepare_port_dict_mac_ip_addr(net, port_dict)
        self.assertDictEqual(port_dict, result_dict)

    def test_prepare_port_dict_mac_ip_addr_no_mac_and_ip(self):
        """mac address and ip address does not exist."""
        net = {}
        port_dict = {}
        result_dict = {}
        self.vimconn._prepare_port_dict_mac_ip_addr(net, port_dict)
        self.assertDictEqual(port_dict, result_dict)

    def test_create_new_port(self):
        """new port has id and mac address."""
        new_port = {
            "port": {
                "id": port_id,
                "mac_address": mac_address,
            },
        }
        self.vimconn.neutron.create_port.return_value = new_port
        net, port_dict, created_items = {}, {}, {}
        expected_result = new_port
        expected_net = {
            "mac_adress": mac_address,
            "vim_id": port_id,
        }
        expected_created_items = {f"port:{port_id}": True}
        result = self.vimconn._create_new_port(port_dict, created_items, net)
        self.assertDictEqual(result, expected_result)
        self.assertEqual(net, expected_net)
        self.assertEqual(created_items, expected_created_items)
        self.vimconn.neutron.create_port.assert_called_once_with({"port": port_dict})

    def test_create_new_port_without_mac_or_id(self):
        """new port does not have mac address or ID."""
        new_port = {}
        self.vimconn.neutron.create_port.return_value = new_port
        net, port_dict, created_items = {}, {}, {}
        with self.assertRaises(KeyError):
            self.vimconn._create_new_port(port_dict, created_items, net)
        self.vimconn.neutron.create_port.assert_called_once_with({"port": port_dict})

    def test_create_new_port_neutron_create_port_raises_exception(self):
        """Neutron create port raises exception."""
        self.vimconn.neutron.create_port.side_effect = VimConnException(
            "New port is not created."
        )
        net, port_dict, created_items = {}, {}, {}
        with self.assertRaises(VimConnException):
            self.vimconn._create_new_port(port_dict, created_items, net)
        self.vimconn.neutron.create_port.assert_called_once_with({"port": port_dict})

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """Net has name, type, net-id."""

        net = {
            "net_id": net_id,
            "name": "management",
            "type": "virtual",
        }
        created_items = {}
        new_port = {
            "port": {
                "id": net_id,
                "mac_address": mac_address,
                "name": "management",
                "fixed_ips": [{"ip_address": ip_addr1}],
            },
        }
        mock_create_new_port.return_value = new_port
        expected_port = {
            "port-id": net_id,
            "tag": "management",
        }
        port_dict = {
            "network_id": net_id,
            "name": "management",
            "admin_state_up": True,
        }

        new_port_result, port_result = self.vimconn._create_port(
            net, name, created_items
        )

        self.assertDictEqual(new_port_result, new_port)
        self.assertDictEqual(port_result, expected_port)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_mac_ip_addr.assert_called_once_with(net, port_dict)
        mock_create_new_port.assert_called_once_with(port_dict, created_items, net)
        mock_set_fixed_ip.assert_called_once_with(new_port, net)

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_no_port_name(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """Net has no name."""
        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        new_port = {
            "port": {
                "id": net_id,
                "mac_address": mac_address,
                "name": name,
                "fixed_ips": [{"ip_address": ip_addr1}],
            },
        }
        mock_create_new_port.return_value = new_port
        expected_port = {
            "port-id": net_id,
            "tag": name,
        }
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }

        new_port_result, port_result = self.vimconn._create_port(
            net, name, created_items
        )

        self.assertDictEqual(new_port_result, new_port)
        self.assertDictEqual(port_result, expected_port)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_mac_ip_addr.assert_called_once_with(net, port_dict)
        mock_create_new_port.assert_called_once_with(port_dict, created_items, net)
        mock_set_fixed_ip.assert_called_once_with(new_port, net)

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_nova_api_version_smaller_than_232(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """Nova api version is smaller than 2.32."""
        self.vimconn.nova.api_version.get_string.return_value = "2.30"
        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        new_port = {
            "port": {
                "id": net_id,
                "mac_address": mac_address,
                "name": name,
                "fixed_ips": [{"ip_address": ip_addr1}],
            },
        }
        mock_create_new_port.return_value = new_port
        expected_port = {
            "port-id": net_id,
        }
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }

        new_port_result, port_result = self.vimconn._create_port(
            net, name, created_items
        )

        self.assertDictEqual(new_port_result, new_port)
        self.assertDictEqual(port_result, expected_port)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_mac_ip_addr.assert_called_once_with(net, port_dict)
        mock_create_new_port.assert_called_once_with(port_dict, created_items, net)
        mock_set_fixed_ip.assert_called_once_with(new_port, net)

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_create_new_port_raise_exception(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """_create_new_port method raises exception."""
        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        mock_create_new_port.side_effect = Exception
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }

        with self.assertRaises(Exception):
            self.vimconn._create_port(net, name, created_items)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_mac_ip_addr.assert_called_once_with(net, port_dict)
        mock_create_new_port.assert_called_once_with(port_dict, created_items, net)
        mock_set_fixed_ip.assert_not_called()

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_create_sec_groups_raises_exception(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """_prepare_port_dict_security_groups method raises exception."""
        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        mock_prepare_port_dict_security_groups.side_effect = Exception
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }

        with self.assertRaises(Exception):
            self.vimconn._create_port(net, name, created_items)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)

        mock_prepare_port_dict_binding.assert_not_called()
        mock_prepare_port_dict_mac_ip_addr.assert_not_called()
        mock_create_new_port.assert_not_called()
        mock_set_fixed_ip.assert_not_called()

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_create_port_dict_binding_raise_exception(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """_prepare_port_dict_binding method raises exception."""

        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        mock_prepare_port_dict_binding.side_effect = Exception
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }

        with self.assertRaises(Exception):
            self.vimconn._create_port(net, name, created_items)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)

        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)

        mock_prepare_port_dict_mac_ip_addr.assert_not_called()
        mock_create_new_port.assert_not_called()
        mock_set_fixed_ip.assert_not_called()

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_create_port_mac_ip_addr_raise_exception(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """prepare_port_dict_mac_ip_addr method raises exception."""
        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        mock_prepare_port_dict_mac_ip_addr.side_effect = Exception
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }

        with self.assertRaises(Exception):
            self.vimconn._create_port(net, name, created_items)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_mac_ip_addr.assert_called_once_with(net, port_dict)

        mock_create_new_port.assert_not_called()
        mock_set_fixed_ip.assert_not_called()

    @patch.object(vimconnector, "_prepare_port_dict_security_groups")
    @patch.object(vimconnector, "_prepare_port_dict_binding")
    @patch.object(vimconnector, "_prepare_port_dict_mac_ip_addr")
    @patch.object(vimconnector, "_create_new_port")
    @patch.object(vimconnector, "_set_fixed_ip")
    def test_create_port_create_port_set_fixed_ip_raise_exception(
        self,
        mock_set_fixed_ip,
        mock_create_new_port,
        mock_prepare_port_dict_mac_ip_addr,
        mock_prepare_port_dict_binding,
        mock_prepare_port_dict_security_groups,
    ):
        """_set_fixed_ip method raises exception."""
        net = {
            "net_id": net_id,
            "type": "virtual",
        }
        created_items = {}
        mock_set_fixed_ip.side_effect = VimConnException(
            "Port detail is missing in new_port."
        )
        port_dict = {
            "network_id": net_id,
            "admin_state_up": True,
            "name": name,
        }
        new_port = {
            "port": {
                "id": net_id,
                "mac_address": mac_address,
                "name": name,
                "fixed_ips": [{"ip_address": ip_addr1}],
            },
        }
        mock_create_new_port.return_value = new_port

        with self.assertRaises(VimConnException):
            self.vimconn._create_port(net, name, created_items)

        mock_prepare_port_dict_security_groups.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_binding.assert_called_once_with(net, port_dict)
        mock_prepare_port_dict_mac_ip_addr.assert_called_once_with(net, port_dict)
        mock_create_new_port.assert_called_once_with(port_dict, created_items, net)
        mock_set_fixed_ip.assert_called_once_with(new_port, net)

    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_create_port")
    def test_prepare_network_for_vm_instance_no_net_id(
        self, mock_create_port, mock_reload_connection
    ):
        """Nets do not have net_id"""
        mock_reload_connection.side_effect = None
        created_items = {}
        net_list = [
            {
                "use": "mgmt",
                "port_security": False,
                "exit_on_floating_ip_error": False,
                "port_security_disable_strategy": "full",
            },
            {
                "port_security": True,
                "exit_on_floating_ip_error": False,
                "floating_ip": True,
            },
        ]
        net_list_vim = []
        external_network, no_secured_ports = [], []
        expected_external_network, expected_no_secured_ports = [], []
        expected_net_list_vim = []

        self.vimconn._prepare_network_for_vminstance(
            name,
            net_list,
            created_items,
            net_list_vim,
            external_network,
            no_secured_ports,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

        mock_create_port.assert_not_called()

    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_create_port")
    def test_prepare_network_for_vm_instance_empty_net_list(
        self, mock_create_port, mock_reload_connection
    ):
        """Net list is empty."""
        mock_reload_connection.side_effect = None
        created_items = {}
        net_list_vim = []
        external_network, no_secured_ports = [], []
        expected_external_network, expected_no_secured_ports = [], []
        expected_net_list_vim = []

        self.vimconn._prepare_network_for_vminstance(
            name,
            net_list,
            created_items,
            net_list_vim,
            external_network,
            no_secured_ports,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

        mock_create_port.assert_not_called()

    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_create_port")
    def test_prepare_network_for_vm_instance_use_floating_ip_false_mgmt_net(
        self, mock_create_port, mock_reload_connection
    ):
        """Nets have net-id, floating_ip False, mgmt network."""
        mock_reload_connection.side_effect = None
        created_items = {}
        net_list = [
            {
                "net_id": net2_id,
                "floating_ip": False,
                "use": "mgmt",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = [
            (
                {
                    "port": {
                        "id": port2_id,
                        "mac_address": mac_address,
                        "name": name,
                    },
                },
                {"port-dict": port2_id},
            ),
        ]
        external_network, no_secured_ports = [], []
        expected_external_network, expected_no_secured_ports = [], []
        expected_net_list_vim = [{"port-dict": port2_id}]
        self.vimconn._prepare_network_for_vminstance(
            name,
            net_list,
            created_items,
            net_list_vim,
            external_network,
            no_secured_ports,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

        mock_create_port.assert_called_once_with(
            {
                "net_id": net2_id,
                "floating_ip": False,
                "use": "mgmt",
            },
            name,
            created_items,
        )

    @patch.object(vimconnector, "_reload_connection")
    def test_prepare_network_for_vm_instance_mgmt_net_net_port_security_and_floating_ip_true(
        self, mock_reload_connection
    ):
        """Nets have net-id, use_floating_ip False in VIM config, mgmt network, net floating_ip is True."""
        self.vimconn.config["use_floating_ip"] = False
        mock_create_port = CopyingMock()
        mock_reload_connection.side_effect = None
        created_items = {}
        net_list = [
            {
                "net_id": net2_id,
                "floating_ip": True,
                "use": "mgmt",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = [
            (
                {
                    "port": {
                        "id": port2_id,
                        "mac_address": mac_address,
                        "name": name,
                    },
                },
                {"port-dict": port2_id},
            ),
        ]
        external_network, no_secured_ports = [], []
        expected_external_network = [
            {
                "net_id": net2_id,
                "floating_ip": True,
                "use": "mgmt",
                "exit_on_floating_ip_error": True,
            },
        ]
        expected_no_secured_ports = []
        expected_net_list_vim = [{"port-dict": port2_id}]
        with patch.object(vimconnector, "_create_port", mock_create_port):
            self.vimconn._prepare_network_for_vminstance(
                name,
                net_list,
                created_items,
                net_list_vim,
                external_network,
                no_secured_ports,
            )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

        mock_create_port.assert_called_once_with(
            {
                "net_id": net2_id,
                "floating_ip": True,
                "use": "mgmt",
            },
            name,
            created_items,
        )

    @patch.object(vimconnector, "_reload_connection")
    def test_prepare_network_for_vm_instance_use_floating_ip_true_mgmt_net_port_security_false(
        self, mock_reload_connection
    ):
        """Nets have net-id, use_floating_ip is True in VIM config, mgmt network, net port security is False."""
        mock_create_port = CopyingMock()
        self.vimconn.config["use_floating_ip"] = True
        self.vimconn.config["no_port_security_extension"] = False
        mock_reload_connection.side_effect = None
        created_items = {}

        net_list = [
            {
                "net_id": net2_id,
                "use": "mgmt",
                "port_security": False,
                "exit_on_floating_ip_error": False,
                "port_security_disable_strategy": "full",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = [
            (
                {
                    "port": {
                        "id": port2_id,
                        "mac_address": mac_address,
                        "name": name,
                    },
                },
                {"port-dict": port2_id},
            ),
        ]
        external_network, no_secured_ports = [], []
        expected_external_network = [
            {
                "net_id": net2_id,
                "use": "mgmt",
                "port_security": False,
                "exit_on_floating_ip_error": False,
                "port_security_disable_strategy": "full",
                "floating_ip": True,
            },
        ]
        expected_no_secured_ports = [(port2_id, "full")]
        expected_net_list_vim = [{"port-dict": port2_id}]
        with patch.object(vimconnector, "_create_port", mock_create_port):
            self.vimconn._prepare_network_for_vminstance(
                name,
                net_list,
                created_items,
                net_list_vim,
                external_network,
                no_secured_ports,
            )

        mock_create_port.assert_called_once_with(
            {
                "net_id": net2_id,
                "use": "mgmt",
                "port_security": False,
                "exit_on_floating_ip_error": False,
                "port_security_disable_strategy": "full",
            },
            name,
            created_items,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

    @patch.object(vimconnector, "_reload_connection")
    def test_prepare_network_for_vm_instance_use_fip_true_non_mgmt_net_port_security_false(
        self, mock_reload_connection
    ):
        """Nets have net-id, use_floating_ip True in VIM config, non-mgmt network, port security is False."""
        mock_create_port = CopyingMock()
        self.vimconn.config["use_floating_ip"] = True
        self.vimconn.config["no_port_security_extension"] = False
        mock_reload_connection.side_effect = None
        created_items = {}

        net_list = [
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": False,
                "port_security_disable_strategy": "full",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = [
            (
                {
                    "port": {
                        "id": port2_id,
                        "mac_address": mac_address,
                        "name": name,
                    },
                },
                {"port-dict": port2_id},
            ),
        ]
        external_network, no_secured_ports = [], []
        expected_external_network = []
        expected_no_secured_ports = [(port2_id, "full")]
        expected_net_list_vim = [{"port-dict": port2_id}]
        with patch.object(vimconnector, "_create_port", mock_create_port):
            self.vimconn._prepare_network_for_vminstance(
                name,
                net_list,
                created_items,
                net_list_vim,
                external_network,
                no_secured_ports,
            )

        mock_create_port.assert_called_once_with(
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": False,
                "port_security_disable_strategy": "full",
            },
            name,
            created_items,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

    @patch.object(vimconnector, "_reload_connection")
    def test_prepare_network_for_vm_instance_use_fip_true_non_mgmt_net_port_security_true(
        self, mock_reload_connection
    ):
        """Nets have net-id, use_floating_ip is True in VIM config, non-mgmt network, net port security is True."""
        mock_create_port = CopyingMock()
        self.vimconn.config["use_floating_ip"] = True
        self.vimconn.config["no_port_security_extension"] = True
        mock_reload_connection.side_effect = None
        created_items = {}

        net_list = [
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": True,
                "port_security_disable_strategy": "full",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = [
            (
                {
                    "port": {
                        "id": port2_id,
                        "mac_address": mac_address,
                        "name": name,
                    },
                },
                {"port-dict": port2_id},
            ),
        ]
        external_network, no_secured_ports = [], []
        expected_external_network = []
        expected_no_secured_ports = []
        expected_net_list_vim = [{"port-dict": port2_id}]
        with patch.object(vimconnector, "_create_port", mock_create_port):
            self.vimconn._prepare_network_for_vminstance(
                name,
                net_list,
                created_items,
                net_list_vim,
                external_network,
                no_secured_ports,
            )

        mock_create_port.assert_called_once_with(
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": True,
                "port_security_disable_strategy": "full",
            },
            name,
            created_items,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

    @patch.object(vimconnector, "_reload_connection")
    def test_prepare_network_for_vm_instance_create_port_raise_exception(
        self, mock_reload_connection
    ):
        """_create_port method raise exception."""
        mock_create_port = CopyingMock()
        self.vimconn.config["use_floating_ip"] = True
        self.vimconn.config["no_port_security_extension"] = True
        mock_reload_connection.side_effect = None
        created_items = {}

        net_list = [
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": True,
                "port_security_disable_strategy": "full",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = KeyError
        external_network, no_secured_ports = [], []
        expected_external_network = []
        expected_no_secured_ports = []
        expected_net_list_vim = []
        with patch.object(vimconnector, "_create_port", mock_create_port):
            with self.assertRaises(Exception) as err:
                self.vimconn._prepare_network_for_vminstance(
                    name,
                    net_list,
                    created_items,
                    net_list_vim,
                    external_network,
                    no_secured_ports,
                )

        self.assertEqual(type(err.exception), KeyError)

        mock_create_port.assert_called_once_with(
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": True,
                "port_security_disable_strategy": "full",
            },
            name,
            created_items,
        )
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

    @patch.object(vimconnector, "_reload_connection")
    def test_prepare_network_for_vm_instance_reload_connection_raise_exception(
        self, mock_reload_connection
    ):
        """_reload_connection method raises exception."""
        mock_create_port = CopyingMock()
        mock_reload_connection.side_effect = VimConnConnectionException(
            "Connection failed."
        )
        self.vimconn.config["use_floating_ip"] = True
        self.vimconn.config["no_port_security_extension"] = True
        created_items = {}

        net_list = [
            {
                "net_id": net2_id,
                "use": "other",
                "port_security": True,
                "port_security_disable_strategy": "full",
            }
        ]
        net_list_vim = []
        mock_create_port.side_effect = None
        external_network, no_secured_ports = [], []
        expected_external_network = []
        expected_no_secured_ports = []
        expected_net_list_vim = []
        with patch.object(vimconnector, "_create_port", mock_create_port):
            with self.assertRaises(Exception) as err:
                self.vimconn._prepare_network_for_vminstance(
                    name,
                    net_list,
                    created_items,
                    net_list_vim,
                    external_network,
                    no_secured_ports,
                )

        self.assertEqual(type(err.exception), VimConnConnectionException)
        self.assertEqual(str(err.exception), "Connection failed.")
        mock_reload_connection.assert_called_once()
        mock_create_port.assert_not_called()
        self.assertEqual(expected_net_list_vim, net_list_vim)
        self.assertEqual(external_network, expected_external_network)
        self.assertEqual(expected_no_secured_ports, no_secured_ports)

    def test_prepare_persistent_root_volumes_vim_using_volume_id(self):
        """Existing persistent root volume with vim_volume_id."""
        vm_av_zone = ["nova"]
        base_disk_index = ord("a")
        disk = {"vim_volume_id": volume_id}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}
        expected_boot_vol_id = None
        expected_block_device_mapping = {"vda": volume_id}
        expected_existing_vim_volumes = [{"id": volume_id}]
        boot_volume_id = self.vimconn._prepare_persistent_root_volumes(
            name,
            vm_av_zone,
            disk,
            base_disk_index,
            block_device_mapping,
            existing_vim_volumes,
            created_items,
        )
        self.assertEqual(boot_volume_id, expected_boot_vol_id)
        self.assertDictEqual(block_device_mapping, expected_block_device_mapping)
        self.assertEqual(existing_vim_volumes, expected_existing_vim_volumes)
        self.vimconn.cinder.volumes.create.assert_not_called()

    def test_prepare_persistent_non_root_volumes_vim_using_volume_id(self):
        """Existing persistent non root volume with vim_volume_id."""
        vm_av_zone = ["nova"]
        base_disk_index = ord("b")
        disk = {"vim_volume_id": volume_id}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}
        expected_block_device_mapping = {"vdb": volume_id}
        expected_existing_vim_volumes = [{"id": volume_id}]
        self.vimconn._prepare_non_root_persistent_volumes(
            name,
            disk,
            vm_av_zone,
            block_device_mapping,
            base_disk_index,
            existing_vim_volumes,
            created_items,
        )
        self.assertDictEqual(block_device_mapping, expected_block_device_mapping)
        self.assertEqual(existing_vim_volumes, expected_existing_vim_volumes)
        self.vimconn.cinder.volumes.create.assert_not_called()

    def test_prepare_persistent_root_volumes_using_vim_id(self):
        """Existing persistent root volume with vim_id."""
        vm_av_zone = ["nova"]
        base_disk_index = ord("a")
        disk = {"vim_id": volume_id}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}
        expected_boot_vol_id = None
        expected_block_device_mapping = {"vda": volume_id}
        expected_existing_vim_volumes = [{"id": volume_id}]
        boot_volume_id = self.vimconn._prepare_persistent_root_volumes(
            name,
            vm_av_zone,
            disk,
            base_disk_index,
            block_device_mapping,
            existing_vim_volumes,
            created_items,
        )
        self.assertEqual(boot_volume_id, expected_boot_vol_id)
        self.assertDictEqual(block_device_mapping, expected_block_device_mapping)
        self.assertEqual(existing_vim_volumes, expected_existing_vim_volumes)
        self.vimconn.cinder.volumes.create.assert_not_called()

    def test_prepare_persistent_non_root_volumes_using_vim_id(self):
        """Existing persistent root volume with vim_id."""
        vm_av_zone = ["nova"]
        base_disk_index = ord("b")
        disk = {"vim_id": volume_id}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}

        expected_block_device_mapping = {"vdb": volume_id}
        expected_existing_vim_volumes = [{"id": volume_id}]
        self.vimconn._prepare_non_root_persistent_volumes(
            name,
            disk,
            vm_av_zone,
            block_device_mapping,
            base_disk_index,
            existing_vim_volumes,
            created_items,
        )

        self.assertDictEqual(block_device_mapping, expected_block_device_mapping)
        self.assertEqual(existing_vim_volumes, expected_existing_vim_volumes)
        self.vimconn.cinder.volumes.create.assert_not_called()

    def test_prepare_persistent_root_volumes_create(self):
        """Create persistent root volume."""
        self.vimconn.cinder.volumes.create.return_value.id = volume_id2
        vm_av_zone = ["nova"]
        base_disk_index = ord("a")
        disk = {"size": 10, "image_id": image_id}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}
        expected_boot_vol_id = volume_id2
        expected_block_device_mapping = {"vda": volume_id2}
        expected_existing_vim_volumes = []
        boot_volume_id = self.vimconn._prepare_persistent_root_volumes(
            name,
            vm_av_zone,
            disk,
            base_disk_index,
            block_device_mapping,
            existing_vim_volumes,
            created_items,
        )
        self.assertEqual(boot_volume_id, expected_boot_vol_id)
        self.assertDictEqual(block_device_mapping, expected_block_device_mapping)
        self.assertEqual(existing_vim_volumes, expected_existing_vim_volumes)
        self.vimconn.cinder.volumes.create.assert_called_once_with(
            size=10,
            name="basicvmvda",
            imageRef=image_id,
            availability_zone=["nova"],
        )
        self.assertEqual(created_items, {f"volume:{volume_id2}": True})

    def test_prepare_persistent_non_root_volumes_create(self):
        """Create persistent non-root volume."""
        self.vimconn.cinder = CopyingMock()
        self.vimconn.cinder.volumes.create.return_value.id = volume_id2
        vm_av_zone = ["nova"]
        base_disk_index = ord("a")
        disk = {"size": 10}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}
        expected_block_device_mapping = {"vda": volume_id2}
        expected_existing_vim_volumes = []
        self.vimconn._prepare_non_root_persistent_volumes(
            name,
            disk,
            vm_av_zone,
            block_device_mapping,
            base_disk_index,
            existing_vim_volumes,
            created_items,
        )

        self.assertDictEqual(block_device_mapping, expected_block_device_mapping)
        self.assertEqual(existing_vim_volumes, expected_existing_vim_volumes)
        self.vimconn.cinder.volumes.create.assert_called_once_with(
            size=10, name="basicvmvda", availability_zone=["nova"]
        )
        self.assertEqual(created_items, {f"volume:{volume_id2}": True})

    def test_prepare_persistent_root_volumes_create_raise_exception(self):
        """Create persistent root volume raise exception."""
        self.vimconn.cinder.volumes.create.side_effect = Exception
        vm_av_zone = ["nova"]
        base_disk_index = ord("a")
        disk = {"size": 10, "image_id": image_id}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}

        with self.assertRaises(Exception):
            result = self.vimconn._prepare_persistent_root_volumes(
                name,
                vm_av_zone,
                disk,
                base_disk_index,
                block_device_mapping,
                existing_vim_volumes,
                created_items,
            )

            self.assertEqual(result, None)

        self.vimconn.cinder.volumes.create.assert_called_once_with(
            size=10,
            name="basicvmvda",
            imageRef=image_id,
            availability_zone=["nova"],
        )
        self.assertEqual(existing_vim_volumes, [])
        self.assertEqual(block_device_mapping, {})
        self.assertEqual(created_items, {})

    def test_prepare_persistent_non_root_volumes_create_raise_exception(self):
        """Create persistent non-root volume raise exception."""
        self.vimconn.cinder.volumes.create.side_effect = Exception
        vm_av_zone = ["nova"]
        base_disk_index = ord("b")
        disk = {"size": 10}
        block_device_mapping = {}
        existing_vim_volumes = []
        created_items = {}

        with self.assertRaises(Exception):
            self.vimconn._prepare_non_root_persistent_volumes(
                name,
                disk,
                vm_av_zone,
                block_device_mapping,
                base_disk_index,
                existing_vim_volumes,
                created_items,
            )

        self.vimconn.cinder.volumes.create.assert_called_once_with(
            size=10, name="basicvmvdb", availability_zone=["nova"]
        )
        self.assertEqual(existing_vim_volumes, [])
        self.assertEqual(block_device_mapping, {})
        self.assertEqual(created_items, {})

    @patch("time.sleep")
    def test_wait_for_created_volumes_availability_volume_status_available(
        self, mock_sleep
    ):
        """Created volume status is available."""
        elapsed_time = 5
        created_items = {f"volume:{volume_id2}": True}
        self.vimconn.cinder.volumes.get.return_value.status = "available"

        result = self.vimconn._wait_for_created_volumes_availability(
            elapsed_time, created_items
        )
        self.assertEqual(result, elapsed_time)
        self.vimconn.cinder.volumes.get.assert_called_with(volume_id2)
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_existing_volumes_availability_volume_status_available(
        self, mock_sleep
    ):
        """Existing volume status is available."""
        elapsed_time = 5
        existing_vim_volumes = [{"id": volume_id2}]
        self.vimconn.cinder.volumes.get.return_value.status = "available"

        result = self.vimconn._wait_for_existing_volumes_availability(
            elapsed_time, existing_vim_volumes
        )
        self.assertEqual(result, elapsed_time)
        self.vimconn.cinder.volumes.get.assert_called_with(volume_id2)
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_created_volumes_availability_status_processing_multiple_volumes(
        self, mock_sleep
    ):
        """Created volume status is processing."""
        elapsed_time = 5
        created_items = {
            f"volume:{volume_id2}": True,
            f"volume:{volume_id3}": True,
        }
        self.vimconn.cinder.volumes.get.side_effect = [
            Status("processing"),
            Status("available"),
            Status("available"),
        ]

        result = self.vimconn._wait_for_created_volumes_availability(
            elapsed_time, created_items
        )
        self.assertEqual(result, 10)
        _call_mock_get_volumes = self.vimconn.cinder.volumes.get.call_args_list
        self.assertEqual(_call_mock_get_volumes[0][0], (volume_id2,))
        self.assertEqual(_call_mock_get_volumes[1][0], (volume_id2,))
        self.assertEqual(_call_mock_get_volumes[2][0], (volume_id3,))
        mock_sleep.assert_called_with(5)
        self.assertEqual(1, mock_sleep.call_count)

    @patch("time.sleep")
    def test_wait_for_existing_volumes_availability_status_processing_multiple_volumes(
        self, mock_sleep
    ):
        """Existing volume status is processing."""
        elapsed_time = 5
        existing_vim_volumes = [
            {"id": volume_id2},
            {"id": "44e0e83-b9uu-4akk-t234-p9cc4811bd4a"},
        ]
        self.vimconn.cinder.volumes.get.side_effect = [
            Status("processing"),
            Status("available"),
            Status("available"),
        ]

        result = self.vimconn._wait_for_existing_volumes_availability(
            elapsed_time, existing_vim_volumes
        )
        self.assertEqual(result, 10)
        _call_mock_get_volumes = self.vimconn.cinder.volumes.get.call_args_list
        self.assertEqual(_call_mock_get_volumes[0][0], (volume_id2,))
        self.assertEqual(_call_mock_get_volumes[1][0], (volume_id2,))
        self.assertEqual(
            _call_mock_get_volumes[2][0], ("44e0e83-b9uu-4akk-t234-p9cc4811bd4a",)
        )
        mock_sleep.assert_called_with(5)
        self.assertEqual(1, mock_sleep.call_count)

    @patch("time.sleep")
    def test_wait_for_created_volumes_availability_volume_status_processing_timeout(
        self, mock_sleep
    ):
        """Created volume status is processing, elapsed time greater than timeout (1800)."""
        elapsed_time = 1805
        created_items = {f"volume:{volume_id2}": True}
        self.vimconn.cinder.volumes.get.side_effect = [
            Status("processing"),
            Status("processing"),
        ]
        with patch("time.sleep", mock_sleep):
            result = self.vimconn._wait_for_created_volumes_availability(
                elapsed_time, created_items
            )
            self.assertEqual(result, 1805)
        self.vimconn.cinder.volumes.get.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_existing_volumes_availability_volume_status_processing_timeout(
        self, mock_sleep
    ):
        """Exsiting volume status is processing, elapsed time greater than timeout (1800)."""
        elapsed_time = 1805
        existing_vim_volumes = [{"id": volume_id2}]
        self.vimconn.cinder.volumes.get.side_effect = [
            Status("processing"),
            Status("processing"),
        ]

        result = self.vimconn._wait_for_existing_volumes_availability(
            elapsed_time, existing_vim_volumes
        )
        self.assertEqual(result, 1805)
        self.vimconn.cinder.volumes.get.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_created_volumes_availability_cinder_raise_exception(
        self, mock_sleep
    ):
        """Cinder get volumes raises exception for created volumes."""
        elapsed_time = 1000
        created_items = {f"volume:{volume_id2}": True}
        self.vimconn.cinder.volumes.get.side_effect = Exception
        with self.assertRaises(Exception):
            result = self.vimconn._wait_for_created_volumes_availability(
                elapsed_time, created_items
            )
            self.assertEqual(result, 1000)
        self.vimconn.cinder.volumes.get.assert_called_with(volume_id2)
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_existing_volumes_availability_cinder_raise_exception(
        self, mock_sleep
    ):
        """Cinder get volumes raises exception for existing volumes."""
        elapsed_time = 1000
        existing_vim_volumes = [{"id": volume_id2}]
        self.vimconn.cinder.volumes.get.side_effect = Exception
        with self.assertRaises(Exception):
            result = self.vimconn._wait_for_existing_volumes_availability(
                elapsed_time, existing_vim_volumes
            )
            self.assertEqual(result, 1000)
        self.vimconn.cinder.volumes.get.assert_called_with(volume_id2)
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_created_volumes_availability_no_volume_in_created_items(
        self, mock_sleep
    ):
        """Created_items dict does not have volume-id."""
        elapsed_time = 10
        created_items = {}

        self.vimconn.cinder.volumes.get.side_effect = [None]

        result = self.vimconn._wait_for_created_volumes_availability(
            elapsed_time, created_items
        )
        self.assertEqual(result, 10)
        self.vimconn.cinder.volumes.get.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_wait_for_existing_volumes_availability_no_volume_in_existing_vim_volumes(
        self, mock_sleep
    ):
        """Existing_vim_volumes list does not have volume."""
        elapsed_time = 10
        existing_vim_volumes = []

        self.vimconn.cinder.volumes.get.side_effect = [None]

        result = self.vimconn._wait_for_existing_volumes_availability(
            elapsed_time, existing_vim_volumes
        )
        self.assertEqual(result, 10)
        self.vimconn.cinder.volumes.get.assert_not_called()
        mock_sleep.assert_not_called()

    @patch.object(vimconnector, "_prepare_persistent_root_volumes")
    @patch.object(vimconnector, "_prepare_non_root_persistent_volumes")
    @patch.object(vimconnector, "_wait_for_created_volumes_availability")
    @patch.object(vimconnector, "_wait_for_existing_volumes_availability")
    def test_prepare_disk_for_vm_instance(
        self,
        mock_existing_vol_availability,
        mock_created_vol_availability,
        mock_non_root_volumes,
        mock_root_volumes,
    ):
        """Prepare disks for VM instance successfully."""
        existing_vim_volumes = []
        created_items = {}
        vm_av_zone = ["nova"]

        mock_root_volumes.return_value = root_vol_id
        mock_created_vol_availability.return_value = 10
        mock_existing_vol_availability.return_value = 15
        self.vimconn.cinder = CopyingMock()

        self.vimconn._prepare_disk_for_vminstance(
            name, existing_vim_volumes, created_items, vm_av_zone, disk_list2
        )
        self.vimconn.cinder.volumes.set_bootable.assert_called_once_with(
            root_vol_id, True
        )
        mock_created_vol_availability.assert_called_once_with(0, created_items)
        mock_existing_vol_availability.assert_called_once_with(10, existing_vim_volumes)
        self.assertEqual(mock_root_volumes.call_count, 1)
        self.assertEqual(mock_non_root_volumes.call_count, 1)
        mock_root_volumes.assert_called_once_with(
            name="basicvm",
            vm_av_zone=["nova"],
            disk={"size": 10, "image_id": image_id},
            base_disk_index=97,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )
        mock_non_root_volumes.assert_called_once_with(
            name="basicvm",
            disk={"size": 20},
            vm_av_zone=["nova"],
            base_disk_index=98,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )

    @patch.object(vimconnector, "_prepare_persistent_root_volumes")
    @patch.object(vimconnector, "_prepare_non_root_persistent_volumes")
    @patch.object(vimconnector, "_wait_for_created_volumes_availability")
    @patch.object(vimconnector, "_wait_for_existing_volumes_availability")
    def test_prepare_disk_for_vm_instance_timeout_exceeded(
        self,
        mock_existing_vol_availability,
        mock_created_vol_availability,
        mock_non_root_volumes,
        mock_root_volumes,
    ):
        """Timeout exceeded while waiting for disks."""
        existing_vim_volumes = []
        created_items = {}
        vm_av_zone = ["nova"]

        mock_root_volumes.return_value = root_vol_id
        mock_created_vol_availability.return_value = 1700
        mock_existing_vol_availability.return_value = 1900

        with self.assertRaises(VimConnException) as err:
            self.vimconn._prepare_disk_for_vminstance(
                name, existing_vim_volumes, created_items, vm_av_zone, disk_list2
            )
        self.assertEqual(
            str(err.exception), "Timeout creating volumes for instance basicvm"
        )
        self.vimconn.cinder.volumes.set_bootable.assert_not_called()
        mock_created_vol_availability.assert_called_once_with(0, created_items)
        mock_existing_vol_availability.assert_called_once_with(
            1700, existing_vim_volumes
        )
        self.assertEqual(mock_root_volumes.call_count, 1)
        self.assertEqual(mock_non_root_volumes.call_count, 1)
        mock_root_volumes.assert_called_once_with(
            name="basicvm",
            vm_av_zone=["nova"],
            disk={"size": 10, "image_id": image_id},
            base_disk_index=97,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )
        mock_non_root_volumes.assert_called_once_with(
            name="basicvm",
            disk={"size": 20},
            vm_av_zone=["nova"],
            base_disk_index=98,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )

    @patch.object(vimconnector, "_prepare_persistent_root_volumes")
    @patch.object(vimconnector, "_prepare_non_root_persistent_volumes")
    @patch.object(vimconnector, "_wait_for_created_volumes_availability")
    @patch.object(vimconnector, "_wait_for_existing_volumes_availability")
    def test_prepare_disk_for_vm_instance_empty_disk_list(
        self,
        mock_existing_vol_availability,
        mock_created_vol_availability,
        mock_non_root_volumes,
        mock_root_volumes,
    ):
        """Disk list is empty."""
        existing_vim_volumes = []
        created_items = {}
        vm_av_zone = ["nova"]
        mock_created_vol_availability.return_value = 2
        mock_existing_vol_availability.return_value = 3

        self.vimconn._prepare_disk_for_vminstance(
            name, existing_vim_volumes, created_items, vm_av_zone, disk_list
        )
        self.vimconn.cinder.volumes.set_bootable.assert_not_called()
        mock_created_vol_availability.assert_called_once_with(0, created_items)
        mock_existing_vol_availability.assert_called_once_with(2, existing_vim_volumes)
        mock_root_volumes.assert_not_called()
        mock_non_root_volumes.assert_not_called()

    @patch.object(vimconnector, "_prepare_persistent_root_volumes")
    @patch.object(vimconnector, "_prepare_non_root_persistent_volumes")
    @patch.object(vimconnector, "_wait_for_created_volumes_availability")
    @patch.object(vimconnector, "_wait_for_existing_volumes_availability")
    def test_prepare_disk_for_vm_instance_persistent_root_volume_error(
        self,
        mock_existing_vol_availability,
        mock_created_vol_availability,
        mock_non_root_volumes,
        mock_root_volumes,
    ):
        """Persistent root volumes preparation raises error."""
        existing_vim_volumes = []
        created_items = {}
        vm_av_zone = ["nova"]

        mock_root_volumes.side_effect = Exception()
        mock_created_vol_availability.return_value = 10
        mock_existing_vol_availability.return_value = 15

        with self.assertRaises(Exception):
            self.vimconn._prepare_disk_for_vminstance(
                name, existing_vim_volumes, created_items, vm_av_zone, disk_list2
            )
        self.vimconn.cinder.volumes.set_bootable.assert_not_called()
        mock_created_vol_availability.assert_not_called()
        mock_existing_vol_availability.assert_not_called()
        mock_root_volumes.assert_called_once_with(
            name="basicvm",
            vm_av_zone=["nova"],
            disk={"size": 10, "image_id": image_id},
            base_disk_index=97,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )
        mock_non_root_volumes.assert_not_called()

    @patch.object(vimconnector, "_prepare_persistent_root_volumes")
    @patch.object(vimconnector, "_prepare_non_root_persistent_volumes")
    @patch.object(vimconnector, "_wait_for_created_volumes_availability")
    @patch.object(vimconnector, "_wait_for_existing_volumes_availability")
    def test_prepare_disk_for_vm_instance_non_root_volume_error(
        self,
        mock_existing_vol_availability,
        mock_created_vol_availability,
        mock_non_root_volumes,
        mock_root_volumes,
    ):
        """Non-root volumes preparation raises error."""
        existing_vim_volumes = []
        created_items = {}
        vm_av_zone = ["nova"]

        mock_root_volumes.return_value = root_vol_id
        mock_non_root_volumes.side_effect = Exception

        with self.assertRaises(Exception):
            self.vimconn._prepare_disk_for_vminstance(
                name, existing_vim_volumes, created_items, vm_av_zone, disk_list2
            )
        self.vimconn.cinder.volumes.set_bootable.assert_not_called()
        mock_created_vol_availability.assert_not_called()
        mock_existing_vol_availability.assert_not_called()
        self.assertEqual(mock_root_volumes.call_count, 1)
        self.assertEqual(mock_non_root_volumes.call_count, 1)
        mock_root_volumes.assert_called_once_with(
            name="basicvm",
            vm_av_zone=["nova"],
            disk={"size": 10, "image_id": image_id},
            base_disk_index=97,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )
        mock_non_root_volumes.assert_called_once_with(
            name="basicvm",
            disk={"size": 20},
            vm_av_zone=["nova"],
            base_disk_index=98,
            block_device_mapping={},
            existing_vim_volumes=[],
            created_items={},
        )

    def test_find_external_network_for_floating_ip_no_external_network(self):
        """External network could not be found."""
        self.vimconn.neutron.list_networks.return_value = {
            "networks": [
                {"id": "408b73-r9cc-5a6a-a270-82cc4811bd4a", "router:external": False}
            ]
        }
        with self.assertRaises(VimConnException) as err:
            self.vimconn._find_the_external_network_for_floating_ip()
        self.assertEqual(
            str(err.exception),
            "Cannot create floating_ip automatically since no external network is present",
        )

    def test_find_external_network_for_floating_one_external_network(self):
        """One external network has been found."""
        self.vimconn.neutron.list_networks.return_value = {
            "networks": [
                {"id": "408b73-r9cc-5a6a-a270-82cc4811bd4a", "router:external": True}
            ]
        }
        expected_result = "408b73-r9cc-5a6a-a270-82cc4811bd4a"
        result = self.vimconn._find_the_external_network_for_floating_ip()
        self.assertEqual(result, expected_result)

    def test_find_external_network_for_floating_neutron_raises_exception(self):
        """Neutron list networks raises exception."""
        self.vimconn.neutron.list_networks.side_effect = Exception
        with self.assertRaises(Exception):
            self.vimconn._find_the_external_network_for_floating_ip()

    def test_find_external_network_for_floating_several_external_network(self):
        """Several exernal networks has been found."""
        self.vimconn.neutron.list_networks.return_value = {
            "networks": [
                {"id": "408b73-r9cc-5a6a-a270-82cc4811bd4a", "router:external": True},
                {"id": "608b73-y9cc-5a6a-a270-12cc4811bd4a", "router:external": True},
            ]
        }
        with self.assertRaises(VimConnException) as err:
            self.vimconn._find_the_external_network_for_floating_ip()
        self.assertEqual(
            str(err.exception),
            "Cannot create floating_ip automatically since multiple external networks are present",
        )

    def test_neutron_create_float_ip(self):
        """Floating ip creation is successful."""
        param = {"net_id": "408b73-r9cc-5a6a-a270-p2cc4811bd9a"}
        created_items = {}
        self.vimconn.neutron.create_floatingip.return_value = {
            "floatingip": {"id": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        }
        expected_created_items = {
            "floating_ip:308b73-t9cc-1a6a-a270-12cc4811bd4a": True
        }
        self.vimconn._neutron_create_float_ip(param, created_items)
        self.assertEqual(created_items, expected_created_items)

    def test_neutron_create_float_ip_exception_occured(self):
        """Floating ip could not be created."""
        param = {
            "floatingip": {
                "floating_network_id": "408b73-r9cc-5a6a-a270-p2cc4811bd9a",
                "tenant_id": "308b73-19cc-8a6a-a270-02cc4811bd9a",
            }
        }
        created_items = {}
        self.vimconn.neutron = CopyingMock()
        self.vimconn.neutron.create_floatingip.side_effect = Exception(
            "Neutron floating ip create exception occured."
        )
        with self.assertRaises(VimConnException) as err:
            self.vimconn._neutron_create_float_ip(param, created_items)
        self.assertEqual(created_items, {})
        self.assertEqual(
            str(err.exception),
            "Exception: Cannot create new floating_ip Neutron floating ip create exception occured.",
        )

    @patch.object(vimconnector, "_neutron_create_float_ip")
    @patch.object(vimconnector, "_find_the_external_network_for_floating_ip")
    def test_create_floating_ip_pool_id_available(
        self, mock_find_ext_network, mock_create_float_ip
    ):
        """Floating ip creation, ip pool is available."""
        floating_network = {"floating_ip": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        created_items = {}
        expected_param = {
            "floatingip": {
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "tenant_id": "408b73-r9cc-5a6a-a270-82cc4811bd4a",
            }
        }
        self.vimconn._create_floating_ip(floating_network, self.server, created_items)
        mock_find_ext_network.assert_not_called()
        mock_create_float_ip.assert_called_once_with(expected_param, {})

    @patch.object(vimconnector, "_neutron_create_float_ip")
    @patch.object(vimconnector, "_find_the_external_network_for_floating_ip")
    def test_create_floating_ip_finding_pool_id(
        self, mock_find_ext_network, mock_create_float_ip
    ):
        """Floating ip creation, pool id need to be found."""
        floating_network = {"floating_ip": True}
        created_items = {}
        mock_find_ext_network.return_value = "308b73-t9cc-1a6a-a270-12cc4811bd4a"
        expected_param = {
            "floatingip": {
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "tenant_id": "408b73-r9cc-5a6a-a270-82cc4811bd4a",
            }
        }
        self.vimconn._create_floating_ip(floating_network, self.server, created_items)
        mock_find_ext_network.assert_called_once()
        mock_create_float_ip.assert_called_once_with(expected_param, {})

    @patch.object(vimconnector, "_neutron_create_float_ip")
    @patch.object(vimconnector, "_find_the_external_network_for_floating_ip")
    def test_create_floating_ip_neutron_create_floating_ip_exception(
        self, mock_find_ext_network, mock_create_float_ip
    ):
        """Neutron creat floating ip raises error."""
        floating_network = {"floating_ip": True}
        created_items = {}
        mock_create_float_ip.side_effect = VimConnException(
            "Can not create floating ip."
        )
        mock_find_ext_network.return_value = "308b73-t9cc-1a6a-a270-12cc4811bd4a"
        expected_param = {
            "floatingip": {
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "tenant_id": "408b73-r9cc-5a6a-a270-82cc4811bd4a",
            }
        }

        with self.assertRaises(VimConnException) as err:
            self.vimconn._create_floating_ip(
                floating_network, self.server, created_items
            )
        self.assertEqual(str(err.exception), "Can not create floating ip.")
        mock_find_ext_network.assert_called_once()
        mock_create_float_ip.assert_called_once_with(expected_param, {})

    @patch.object(vimconnector, "_neutron_create_float_ip")
    @patch.object(vimconnector, "_find_the_external_network_for_floating_ip")
    def test_create_floating_ip_can_not_find_pool_id(
        self, mock_find_ext_network, mock_create_float_ip
    ):
        """Floating ip creation, pool id could not be found."""
        floating_network = {"floating_ip": True}
        created_items = {}
        mock_find_ext_network.side_effect = VimConnException(
            "Cannot create floating_ip automatically since no external network is present"
        )
        with self.assertRaises(VimConnException) as err:
            self.vimconn._create_floating_ip(
                floating_network, self.server, created_items
            )
        self.assertEqual(
            str(err.exception),
            "Cannot create floating_ip automatically since no external network is present",
        )
        mock_find_ext_network.assert_called_once()
        mock_create_float_ip.assert_not_called()

    def test_find_floating_ip_get_free_floating_ip(self):
        """Get free floating ips successfully."""
        floating_ips = [
            {
                "tenant_id": "408b73-r9cc-5a6a-a270-82cc4811bd4a",
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "508b73-o9cc-5a6a-a270-72cc4811bd8",
            }
        ]
        floating_network = {"floating_ip": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        expected_result = "508b73-o9cc-5a6a-a270-72cc4811bd8"

        result = self.vimconn._find_floating_ip(
            self.server, floating_ips, floating_network
        )
        self.assertEqual(result, expected_result)

    def test_find_floating_ip_different_floating_network_id(self):
        """Floating network id is different with floating_ip of floating network."""
        floating_ips = [
            {
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "508b73-o9cc-5a6a-a270-72cc4811bd8",
            }
        ]
        floating_network = {"floating_ip": "508b73-t9cc-1a6a-a270-12cc4811bd4a"}

        result = self.vimconn._find_floating_ip(
            self.server, floating_ips, floating_network
        )
        self.assertEqual(result, None)

    def test_find_floating_ip_different_fip_tenant(self):
        """Items in floating_ips has port_id, tenant_is is not same with server tenant id."""
        floating_ips = [
            {
                "port_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "508b73-o9cc-5a6a-a270-72cc4811bd8",
                "tenant_id": self.server.id,
            }
        ]
        floating_network = {"floating_ip": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        mock_create_floating_ip = CopyingMock()
        with patch.object(vimconnector, "_create_floating_ip", mock_create_floating_ip):
            result = self.vimconn._find_floating_ip(
                self.server, floating_ips, floating_network
            )
            self.assertEqual(result, None)

    @patch("time.sleep")
    def test_assign_floating_ip(self, mock_sleep):
        """Assign floating ip successfully."""
        free_floating_ip = "508b73-o9cc-5a6a-a270-72cc4811bd8"
        floating_network = {"vim_id": floating_network_vim_id}
        fip = {
            "port_id": floating_network_vim_id,
            "floating_network_id": "p08b73-e9cc-5a6a-t270-82cc4811bd4a",
            "id": "508b73-o9cc-5a6a-a270-72cc4811bd8",
            "tenant_id": "k08b73-e9cc-5a6a-t270-82cc4811bd4a",
        }
        self.vimconn.neutron.update_floatingip.side_effect = None
        self.vimconn.neutron.show_floatingip.return_value = fip
        expected_result = fip

        result = self.vimconn._assign_floating_ip(free_floating_ip, floating_network)
        self.assertEqual(result, expected_result)
        self.vimconn.neutron.update_floatingip.assert_called_once_with(
            free_floating_ip,
            {"floatingip": {"port_id": floating_network_vim_id}},
        )
        mock_sleep.assert_called_once_with(5)
        self.vimconn.neutron.show_floatingip.assert_called_once_with(free_floating_ip)

    @patch("time.sleep")
    def test_assign_floating_ip_update_floating_ip_exception(self, mock_sleep):
        """Neutron update floating ip raises exception."""
        free_floating_ip = "508b73-o9cc-5a6a-a270-72cc4811bd8"
        floating_network = {"vim_id": floating_network_vim_id}
        self.vimconn.neutron = CopyingMock()
        self.vimconn.neutron.update_floatingip.side_effect = Exception(
            "Floating ip is not updated."
        )

        with self.assertRaises(Exception) as err:
            result = self.vimconn._assign_floating_ip(
                free_floating_ip, floating_network
            )
            self.assertEqual(result, None)
        self.assertEqual(str(err.exception), "Floating ip is not updated.")

        self.vimconn.neutron.update_floatingip.assert_called_once_with(
            free_floating_ip,
            {"floatingip": {"port_id": floating_network_vim_id}},
        )
        mock_sleep.assert_not_called()
        self.vimconn.neutron.show_floatingip.assert_not_called()

    @patch("time.sleep")
    def test_assign_floating_ip_show_floating_ip_exception(self, mock_sleep):
        """Neutron show floating ip raises exception."""
        free_floating_ip = "508b73-o9cc-5a6a-a270-72cc4811bd8"
        floating_network = {"vim_id": floating_network_vim_id}
        self.vimconn.neutron.update_floatingip.side_effect = None
        self.vimconn.neutron.show_floatingip.side_effect = Exception(
            "Floating ip could not be shown."
        )

        with self.assertRaises(Exception) as err:
            result = self.vimconn._assign_floating_ip(
                free_floating_ip, floating_network
            )
            self.assertEqual(result, None)
            self.assertEqual(str(err.exception), "Floating ip could not be shown.")
        self.vimconn.neutron.update_floatingip.assert_called_once_with(
            free_floating_ip,
            {"floatingip": {"port_id": floating_network_vim_id}},
        )
        mock_sleep.assert_called_once_with(5)
        self.vimconn.neutron.show_floatingip.assert_called_once_with(free_floating_ip)

    @patch("random.shuffle")
    @patch.object(vimconnector, "_find_floating_ip")
    def test_get_free_floating_ip(self, mock_find_floating_ip, mock_shuffle):
        """Get free floating ip successfully."""
        floating_network = {"floating_ip": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        floating_ips = [
            {
                "port_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "508b73-o9cc-5a6a-a270-72cc4811bd8",
                "tenant_id": "208b73-e9cc-5a6a-t270-82cc4811bd4a",
            },
            {
                "port_id": "508b73-r9cc-5a6a-5270-o2cc4811bd4a",
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "208b73-o9cc-5a6a-a270-52cc4811bd8",
                "tenant_id": "208b73-e9cc-5a6a-t270-82cc4811bd4a",
            },
        ]
        self.vimconn.neutron.list_floatingips.return_value = {
            "floatingips": floating_ips
        }
        mock_find_floating_ip.return_value = "508b73-o9cc-5a6a-a270-72cc4811bd8"
        expected_result = "508b73-o9cc-5a6a-a270-72cc4811bd8"

        result = self.vimconn._get_free_floating_ip(self.server, floating_network)
        self.assertEqual(result, expected_result)
        mock_shuffle.assert_called_once_with(floating_ips)
        mock_find_floating_ip.assert_called_once_with(
            self.server, floating_ips, floating_network
        )

    @patch("random.shuffle")
    @patch.object(vimconnector, "_find_floating_ip")
    def test_get_free_floating_ip_list_floating_ip_exception(
        self, mock_find_floating_ip, mock_shuffle
    ):
        """Neutron list floating IPs raises exception."""
        floating_network = {"floating_ip": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        self.vimconn.neutron = CopyingMock()
        self.vimconn.neutron.list_floatingips.side_effect = Exception(
            "Floating ips could not be listed."
        )
        with self.assertRaises(Exception) as err:
            result = self.vimconn._get_free_floating_ip(self.server, floating_network)
            self.assertEqual(result, None)
            self.assertEqual(str(err.exception), "Floating ips could not be listed.")
        mock_shuffle.assert_not_called()
        mock_find_floating_ip.assert_not_called()

    @patch("random.shuffle")
    @patch.object(vimconnector, "_find_floating_ip")
    def test_get_free_floating_ip_find_floating_ip_exception(
        self, mock_find_floating_ip, mock_shuffle
    ):
        """_find_floating_ip method raises exception."""
        floating_network = {"floating_ip": "308b73-t9cc-1a6a-a270-12cc4811bd4a"}
        floating_ips = [
            {
                "port_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "508b73-o9cc-5a6a-a270-72cc4811bd8",
                "tenant_id": "208b73-e9cc-5a6a-t270-82cc4811bd4a",
            },
            {
                "port_id": "508b73-r9cc-5a6a-5270-o2cc4811bd4a",
                "floating_network_id": "308b73-t9cc-1a6a-a270-12cc4811bd4a",
                "id": "208b73-o9cc-5a6a-a270-52cc4811bd8",
                "tenant_id": "208b73-e9cc-5a6a-t270-82cc4811bd4a",
            },
        ]
        self.vimconn.neutron = CopyingMock()
        self.vimconn.neutron.list_floatingips.return_value = {
            "floatingips": floating_ips
        }
        mock_find_floating_ip.side_effect = Exception(
            "Free floating ip could not be found."
        )

        with self.assertRaises(Exception) as err:
            result = self.vimconn._get_free_floating_ip(self.server, floating_network)
            self.assertEqual(result, None)
            self.assertEqual(str(err.exception), "Free floating ip could not be found.")
        mock_shuffle.assert_called_once_with(floating_ips)
        mock_find_floating_ip.assert_called_once_with(
            self.server, floating_ips, floating_network
        )

    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
    ):
        """Prepare external network successfully."""
        external_network = [
            {
                "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
                "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            },
        ]
        created_items = {}
        vm_start_time = time_return_value
        mock_get_free_floating_ip.side_effect = ["y08b73-o9cc-1a6a-a270-12cc4811bd4u"]
        mock_assign_floating_ip.return_value = {
            "floatingip": {"port_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a"}
        }
        self.vimconn.neutron = CopyingMock()
        self.vimconn.nova = CopyingMock()
        self.vimconn.neutron.show_floatingip.return_value = {
            "floatingip": {"port_id": ""}
        }

        self.vimconn._prepare_external_network_for_vminstance(
            external_network, self.server, created_items, vm_start_time
        )

        self.assertEqual(mock_get_free_floating_ip.call_count, 1)
        mock_get_free_floating_ip.assert_called_once_with(
            self.server,
            {
                "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
                "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            },
        )
        self.vimconn.neutron.show_floatingip.assert_called_once_with(
            "y08b73-o9cc-1a6a-a270-12cc4811bd4u"
        )
        self.vimconn.nova.servers.get.assert_not_called()
        mock_create_floating_ip.assert_not_called()
        mock_assign_floating_ip.assert_called_once_with(
            "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            {
                "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
                "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            },
        )

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_no_free_floating_ip(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """There is not any free floating ip."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
        }
        external_network = [floating_network]

        created_items = {}
        vm_start_time = time_return_value
        mock_get_free_floating_ip.return_value = None
        mock_assign_floating_ip.return_value = {}
        self.vimconn.nova.servers.get.return_value.status = "ERROR"
        self.vimconn.neutron.show_floatingip.return_value = {}

        with self.assertRaises(KeyError):
            self.vimconn._prepare_external_network_for_vminstance(
                external_network, self.server, created_items, vm_start_time
            )

        self.assertEqual(mock_get_free_floating_ip.call_count, 4)
        mock_get_free_floating_ip.assert_called_with(
            self.server,
            {
                "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
                "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            },
        )
        self.vimconn.neutron.show_floatingip.assert_called_with(None)
        mock_sleep.assert_not_called()
        mock_time.assert_not_called()
        self.assertEqual(self.vimconn.nova.servers.get.call_count, 4)
        mock_create_floating_ip.assert_called_with(
            floating_network, self.server, created_items
        )
        self.assertEqual(mock_create_floating_ip.call_count, 4)
        mock_assign_floating_ip.assert_not_called()
        self.vimconn.nova.servers.get.assert_called_with(self.server.id)

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_no_free_fip_can_not_create_fip_exit_on_error_false(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """There is not any free floating ip, create_floating ip method raise exception
        exit_on_floating_ip_error set to False."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            "exit_on_floating_ip_error": False,
        }
        external_network = [floating_network]

        created_items = {}
        vm_start_time = time_return_value
        mock_get_free_floating_ip.return_value = None
        mock_assign_floating_ip.return_value = {}
        mock_create_floating_ip.side_effect = VimConnException(
            "Can not create floating ip."
        )
        self.vimconn.nova.servers.get.return_value.status = "ERROR"
        self.vimconn.neutron.show_floatingip.return_value = {}

        self.vimconn._prepare_external_network_for_vminstance(
            external_network, self.server, created_items, vm_start_time
        )
        self.assertEqual(mock_get_free_floating_ip.call_count, 1)
        mock_get_free_floating_ip.assert_called_with(
            self.server,
            {
                "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
                "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
                "exit_on_floating_ip_error": False,
            },
        )
        self.vimconn.neutron.show_floatingip.assert_not_called()
        mock_sleep.assert_not_called()
        mock_time.assert_not_called()
        self.vimconn.nova.servers.get.assert_not_called()
        mock_create_floating_ip.assert_called_with(
            floating_network, self.server, created_items
        )
        self.assertEqual(mock_create_floating_ip.call_count, 1)
        mock_assign_floating_ip.assert_not_called()

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_no_free_fip_can_not_create_fip_exit_on_error_true(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """There is not any free floating ip, create_floating ip method raise exception
        exit_on_floating_ip_error set to False."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            "exit_on_floating_ip_error": True,
        }
        external_network = [floating_network]

        created_items = {}
        vm_start_time = time_return_value
        mock_get_free_floating_ip.return_value = None
        mock_assign_floating_ip.return_value = {}
        mock_create_floating_ip.side_effect = VimConnException(
            "Can not create floating ip."
        )
        self.vimconn.nova.servers.get.return_value.status = "ERROR"
        self.vimconn.neutron.show_floatingip.return_value = {}
        with self.assertRaises(VimConnException):
            self.vimconn._prepare_external_network_for_vminstance(
                external_network, self.server, created_items, vm_start_time
            )
        self.assertEqual(mock_get_free_floating_ip.call_count, 1)
        mock_get_free_floating_ip.assert_called_with(
            self.server,
            {
                "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
                "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
                "exit_on_floating_ip_error": True,
            },
        )
        self.vimconn.neutron.show_floatingip.assert_not_called()
        mock_sleep.assert_not_called()
        mock_time.assert_not_called()
        self.vimconn.nova.servers.get.assert_not_called()
        mock_create_floating_ip.assert_called_with(
            floating_network, self.server, created_items
        )
        self.assertEqual(mock_create_floating_ip.call_count, 1)
        mock_assign_floating_ip.assert_not_called()

    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_fip_has_port_id(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
    ):
        """Neutron show floating ip return the fip with port_id and floating network vim_id
        is different from port_id."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
        }
        external_network = [floating_network]
        created_items = {}
        vm_start_time = 150
        mock_get_free_floating_ip.side_effect = [
            "t08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "r08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
        ]
        mock_assign_floating_ip.side_effect = [
            {"floatingip": {"port_id": "k08b73-r9cc-5a6a-a270-82cc4811bd4a"}},
            {"floatingip": {"port_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a"}},
        ]
        self.vimconn.neutron = CopyingMock()
        self.vimconn.nova = CopyingMock()
        self.vimconn.neutron.show_floatingip.side_effect = [
            {"floatingip": {"port_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a"}},
            {"floatingip": {"port_id": ""}},
            {"floatingip": {"port_id": ""}},
        ]
        self.vimconn._prepare_external_network_for_vminstance(
            external_network, self.server, created_items, vm_start_time
        )
        self.assertEqual(mock_get_free_floating_ip.call_count, 3)
        _call_mock_get_free_floating_ip = mock_get_free_floating_ip.call_args_list
        self.assertEqual(
            _call_mock_get_free_floating_ip[0][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[1][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[2][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(self.vimconn.neutron.show_floatingip.call_count, 3)
        self.vimconn.nova.servers.get.assert_not_called()
        mock_create_floating_ip.assert_not_called()
        self.assertEqual(mock_assign_floating_ip.call_count, 2)
        _call_mock_assign_floating_ip = mock_assign_floating_ip.call_args_list
        self.assertEqual(
            _call_mock_assign_floating_ip[0][0],
            ("r08b73-o9cc-1a6a-a270-12cc4811bd4u", floating_network),
        )
        self.assertEqual(
            _call_mock_assign_floating_ip[1][0],
            ("y08b73-o9cc-1a6a-a270-12cc4811bd4u", floating_network),
        )

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_neutron_show_fip_exception_vm_status_in_error(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """Neutron show floating ip gives exception, exit_on_floating_ip_error set to True,
        VM status is in error."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            "exit_on_floating_ip_error": True,
        }
        external_network = [floating_network]
        created_items = {}
        vm_start_time = time_return_value

        mock_time.side_effect = [156570150, 156570800, 156571200]

        self.vimconn.nova.servers.get.return_value.status = "ERROR"
        self.vimconn.neutron.show_floatingip.side_effect = [
            Exception("Floating ip could not be shown.")
        ] * 4
        with self.assertRaises(Exception) as err:
            self.vimconn._prepare_external_network_for_vminstance(
                external_network, self.server, created_items, vm_start_time
            )
            self.assertEqual(
                str(err.exception),
                "Cannot create floating_ip: Exception Floating ip could not be shown.",
            )

        self.assertEqual(mock_get_free_floating_ip.call_count, 4)
        _call_mock_get_free_floating_ip = mock_get_free_floating_ip.call_args_list
        self.assertEqual(
            _call_mock_get_free_floating_ip[0][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[1][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[2][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[3][0],
            (
                self.server,
                floating_network,
            ),
        )

        self.assertEqual(self.vimconn.neutron.show_floatingip.call_count, 4)
        self.vimconn.nova.servers.get.assert_called_with(self.server.id)
        mock_create_floating_ip.assert_not_called()
        mock_assign_floating_ip.assert_not_called()
        mock_time.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_neutron_show_fip_exception_vm_status_in_active(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """Neutron show floating ip gives exception, exit_on_floating_ip_error is set to False,
        VM status is in active."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            "exit_on_floating_ip_error": False,
        }
        external_network = [floating_network]
        created_items = {}
        vm_start_time = time_return_value

        mock_time.side_effect = [156570150, 156570800, 156571200]

        self.vimconn.nova.servers.get.return_value.status = "ACTIVE"
        self.vimconn.neutron.show_floatingip.side_effect = [
            Exception("Floating ip could not be shown.")
        ] * 4

        self.vimconn._prepare_external_network_for_vminstance(
            external_network, self.server, created_items, vm_start_time
        )
        # self.assertEqual(str(err.exception), "Cannot create floating_ip")

        self.assertEqual(mock_get_free_floating_ip.call_count, 4)
        _call_mock_get_free_floating_ip = mock_get_free_floating_ip.call_args_list
        self.assertEqual(
            _call_mock_get_free_floating_ip[0][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[1][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[2][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[3][0],
            (
                self.server,
                floating_network,
            ),
        )

        self.assertEqual(self.vimconn.neutron.show_floatingip.call_count, 4)
        self.vimconn.nova.servers.get.assert_called_with(self.server.id)
        mock_create_floating_ip.assert_not_called()
        mock_assign_floating_ip.assert_not_called()
        mock_time.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_neutron_show_fip_exception_exit_on_error(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """Neutron show floating ip gives exception, but exit_on_floating_ip_error is set to True.
        VM status is not ACTIVE or ERROR, server timeout happened."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            "exit_on_floating_ip_error": True,
        }
        external_network = [floating_network]
        created_items = {}
        vm_start_time = time_return_value
        mock_get_free_floating_ip.side_effect = None
        mock_time.side_effect = [156571790, 156571795, 156571800, 156571805]
        self.vimconn.nova.servers.get.return_value.status = "OTHER"
        self.vimconn.neutron.show_floatingip.side_effect = [
            Exception("Floating ip could not be shown.")
        ] * 5

        with self.assertRaises(VimConnException) as err:
            self.vimconn._prepare_external_network_for_vminstance(
                external_network, self.server, created_items, vm_start_time
            )
        self.assertEqual(
            str(err.exception),
            "Cannot create floating_ip: Exception Floating ip could not be shown.",
        )

        self.assertEqual(mock_get_free_floating_ip.call_count, 3)
        _call_mock_get_free_floating_ip = mock_get_free_floating_ip.call_args_list
        self.assertEqual(
            _call_mock_get_free_floating_ip[0][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[1][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[2][0],
            (
                self.server,
                floating_network,
            ),
        )

        self.assertEqual(self.vimconn.neutron.show_floatingip.call_count, 3)
        self.vimconn.nova.servers.get.assert_called_with(self.server.id)
        mock_create_floating_ip.assert_not_called()
        mock_assign_floating_ip.assert_not_called()
        self.assertEqual(mock_time.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_assign_floating_ip_exception_exit_on_error(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """Assign floating ip method gives exception, exit_on_floating_ip_error is set to True.
        VM status is in ERROR."""
        floating_network = {
            "floating_ip": "y08b73-o9cc-1a6a-a270-12cc4811bd4u",
            "vim_id": "608b73-r9cc-5a6a-a270-82cc4811bd4a",
            "exit_on_floating_ip_error": True,
        }
        external_network = [floating_network]
        created_items = {}
        vm_start_time = time_return_value

        mock_get_free_floating_ip.side_effect = [
            "y08b73-o9cc-1a6a-a270-12cc4811bd4u"
        ] * 4

        mock_time.side_effect = [156571790, 156571795, 156571800, 156571805]

        mock_assign_floating_ip.side_effect = [
            Exception("Floating ip could not be assigned.")
        ] * 4

        self.vimconn.nova.servers.get.return_value.status = "ERROR"
        self.vimconn.neutron.show_floatingip.side_effect = [
            {"floatingip": {"port_id": ""}}
        ] * 4

        with self.assertRaises(VimConnException) as err:
            self.vimconn._prepare_external_network_for_vminstance(
                external_network, self.server, created_items, vm_start_time
            )
        self.assertEqual(
            str(err.exception),
            "Cannot create floating_ip: Exception Floating ip could not be assigned.",
        )

        self.assertEqual(mock_get_free_floating_ip.call_count, 4)
        _call_mock_get_free_floating_ip = mock_get_free_floating_ip.call_args_list
        self.assertEqual(
            _call_mock_get_free_floating_ip[0][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[1][0],
            (
                self.server,
                floating_network,
            ),
        )
        self.assertEqual(
            _call_mock_get_free_floating_ip[2][0],
            (
                self.server,
                floating_network,
            ),
        )

        self.assertEqual(self.vimconn.neutron.show_floatingip.call_count, 4)
        self.vimconn.neutron.show_floatingip.assert_called_with(
            "y08b73-o9cc-1a6a-a270-12cc4811bd4u"
        )
        self.assertEqual(self.vimconn.nova.servers.get.call_count, 4)
        self.vimconn.nova.servers.get.assert_called_with(self.server.id)
        mock_time.assert_not_called()
        mock_sleep.assert_not_called()
        mock_create_floating_ip.assert_not_called()

    @patch("time.time")
    @patch("time.sleep")
    @patch.object(vimconnector, "_create_floating_ip")
    @patch.object(vimconnector, "_get_free_floating_ip")
    @patch.object(vimconnector, "_assign_floating_ip")
    def test_prepare_external_network_for_vm_instance_empty_external_network_list(
        self,
        mock_assign_floating_ip,
        mock_get_free_floating_ip,
        mock_create_floating_ip,
        mock_sleep,
        mock_time,
    ):
        """External network list is empty."""
        external_network = []
        created_items = {}
        vm_start_time = time_return_value

        self.vimconn._prepare_external_network_for_vminstance(
            external_network, self.server, created_items, vm_start_time
        )
        mock_create_floating_ip.assert_not_called()
        mock_time.assert_not_called()
        mock_sleep.assert_not_called()
        mock_assign_floating_ip.assert_not_called()
        mock_get_free_floating_ip.assert_not_called()
        self.vimconn.neutron.show.show_floatingip.assert_not_called()
        self.vimconn.nova.servers.get.assert_not_called()

    @patch.object(vimconnector, "_vimconnector__wait_for_vm")
    def test_update_port_security_for_vm_instance(self, mock_wait_for_vm):
        """no_secured_ports has port and the port has allow-address-pairs."""
        no_secured_ports = [(port2_id, "allow-address-pairs")]

        self.vimconn._update_port_security_for_vminstance(no_secured_ports, self.server)

        mock_wait_for_vm.assert_called_once_with(self.server.id, "ACTIVE")

        self.vimconn.neutron.update_port.assert_called_once_with(
            port2_id,
            {"port": {"allowed_address_pairs": [{"ip_address": "0.0.0.0/0"}]}},
        )

    @patch.object(vimconnector, "_vimconnector__wait_for_vm")
    def test_update_port_security_for_vm_instance_no_allowed_address_pairs(
        self, mock_wait_for_vm
    ):
        """no_secured_ports has port and the port does not have allow-address-pairs."""
        no_secured_ports = [(port2_id, "something")]

        self.vimconn._update_port_security_for_vminstance(no_secured_ports, self.server)

        mock_wait_for_vm.assert_called_once_with(self.server.id, "ACTIVE")

        self.vimconn.neutron.update_port.assert_called_once_with(
            port2_id,
            {"port": {"port_security_enabled": False, "security_groups": None}},
        )

    @patch.object(vimconnector, "_vimconnector__wait_for_vm")
    def test_update_port_security_for_vm_instance_wait_for_vm_raise_exception(
        self, mock_wait_for_vm
    ):
        """__wait_for_vm raises timeout exception."""
        no_secured_ports = [(port2_id, "something")]

        mock_wait_for_vm.side_effect = VimConnException("Timeout waiting for instance.")

        with self.assertRaises(VimConnException) as err:
            self.vimconn._update_port_security_for_vminstance(
                no_secured_ports, self.server
            )
        self.assertEqual(str(err.exception), "Timeout waiting for instance.")

        mock_wait_for_vm.assert_called_once_with(self.server.id, "ACTIVE")

        self.vimconn.neutron.update_port.assert_not_called()

    @patch.object(vimconnector, "_vimconnector__wait_for_vm")
    def test_update_port_security_for_vm_instance_neutron_update_port_raise_exception(
        self, mock_wait_for_vm
    ):
        """neutron_update_port method raises exception."""
        no_secured_ports = [(port2_id, "something")]

        self.vimconn.neutron.update_port.side_effect = Exception(
            "Port security could not be updated."
        )

        with self.assertRaises(VimConnException) as err:
            self.vimconn._update_port_security_for_vminstance(
                no_secured_ports, self.server
            )
        self.assertEqual(
            str(err.exception),
            "It was not possible to disable port security for port 17472685-f67f-49fd-8722-eabb7692fc22",
        )
        mock_wait_for_vm.assert_called_once_with(self.server.id, "ACTIVE")

        self.vimconn.neutron.update_port.assert_called_once_with(
            port2_id,
            {"port": {"port_security_enabled": False, "security_groups": None}},
        )

    @patch.object(vimconnector, "_vimconnector__wait_for_vm")
    def test_update_port_security_for_vm_instance_empty_port_list(
        self, mock_wait_for_vm
    ):
        """no_secured_ports list does not have any ports."""
        no_secured_ports = []

        self.vimconn._update_port_security_for_vminstance(no_secured_ports, self.server)

        mock_wait_for_vm.assert_not_called()

        self.vimconn.neutron.update_port.assert_not_called()

    @patch("time.time")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_prepare_network_for_vminstance")
    @patch.object(vimconnector, "_create_user_data")
    @patch.object(vimconnector, "_get_vm_availability_zone")
    @patch.object(vimconnector, "_prepare_disk_for_vminstance")
    @patch.object(vimconnector, "_update_port_security_for_vminstance")
    @patch.object(vimconnector, "_prepare_external_network_for_vminstance")
    @patch.object(vimconnector, "delete_vminstance")
    @patch.object(vimconnector, "_format_exception")
    def test_new_vm_instance(
        self,
        mock_format_exception,
        mock_delete_vm_instance,
        mock_prepare_external_network,
        mock_update_port_security,
        mock_prepare_disk_for_vm_instance,
        mock_get_vm_availability_zone,
        mock_create_user_data,
        mock_prepare_network_for_vm_instance,
        mock_reload_connection,
        mock_time,
    ):
        """New VM instance creation is successful."""

        mock_create_user_data.return_value = True, "userdata"

        mock_get_vm_availability_zone.return_value = "nova"

        self.vimconn.nova.servers.create.return_value = self.server

        mock_time.return_value = time_return_value

        expected_result = self.server.id, {}

        result = self.vimconn.new_vminstance(
            name,
            description,
            start,
            image_id,
            flavor_id,
            affinity_group_list,
            net_list,
            cloud_config,
            disk_list2,
            availability_zone_index,
            availability_zone_list,
        )
        self.assertEqual(result, expected_result)

        mock_reload_connection.assert_called_once()
        mock_prepare_network_for_vm_instance.assert_called_once_with(
            name=name,
            net_list=net_list,
            created_items={},
            net_list_vim=[],
            external_network=[],
            no_secured_ports=[],
        )
        mock_create_user_data.assert_called_once_with(cloud_config)
        mock_get_vm_availability_zone.assert_called_once_with(
            availability_zone_index, availability_zone_list
        )
        mock_prepare_disk_for_vm_instance.assert_called_once_with(
            name=name,
            existing_vim_volumes=[],
            created_items={},
            vm_av_zone="nova",
            disk_list=disk_list2,
        )
        self.vimconn.nova.servers.create.assert_called_once_with(
            name=name,
            image=image_id,
            flavor=flavor_id,
            nics=[],
            security_groups="default",
            availability_zone="nova",
            key_name="my_keypair",
            userdata="userdata",
            config_drive=True,
            block_device_mapping=None,
            scheduler_hints={},
        )
        mock_time.assert_called_once()
        mock_update_port_security.assert_called_once_with([], self.server)
        mock_prepare_external_network.assert_called_once_with(
            external_network=[],
            server=self.server,
            created_items={},
            vm_start_time=time_return_value,
        )
        mock_delete_vm_instance.assert_not_called()
        mock_format_exception.assert_not_called()

    @patch("time.time")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_prepare_network_for_vminstance")
    @patch.object(vimconnector, "_create_user_data")
    @patch.object(vimconnector, "_get_vm_availability_zone")
    @patch.object(vimconnector, "_prepare_disk_for_vminstance")
    @patch.object(vimconnector, "_update_port_security_for_vminstance")
    @patch.object(vimconnector, "_prepare_external_network_for_vminstance")
    @patch.object(vimconnector, "delete_vminstance")
    @patch.object(vimconnector, "_format_exception")
    def test_new_vm_instance_create_user_data_fails(
        self,
        mock_format_exception,
        mock_delete_vm_instance,
        mock_prepare_external_network,
        mock_update_port_security,
        mock_prepare_disk_for_vm_instance,
        mock_get_vm_availability_zone,
        mock_create_user_data,
        mock_prepare_network_for_vm_instance,
        mock_reload_connection,
        mock_time,
    ):
        """New VM instance creation failed because of user data creation failure."""

        mock_create_user_data.side_effect = Exception(
            "User data could not be retrieved."
        )

        mock_get_vm_availability_zone.return_value = "nova"

        self.vimconn.nova.servers.create.return_value = self.server

        mock_time.return_value = time_return_value

        self.vimconn.new_vminstance(
            name,
            description,
            start,
            image_id,
            flavor_id,
            affinity_group_list,
            net_list,
            cloud_config,
            disk_list,
            availability_zone_index,
            availability_zone_list,
        )

        mock_reload_connection.assert_called_once()
        mock_prepare_network_for_vm_instance.assert_called_once_with(
            name=name,
            net_list=net_list,
            created_items={},
            net_list_vim=[],
            external_network=[],
            no_secured_ports=[],
        )
        mock_create_user_data.assert_called_once_with(cloud_config)
        mock_get_vm_availability_zone.assert_not_called()
        mock_prepare_disk_for_vm_instance.assert_not_called()
        self.vimconn.nova.servers.create.assert_not_called()
        mock_time.assert_not_called()
        mock_update_port_security.assert_not_called()
        mock_prepare_external_network.assert_not_called()
        mock_delete_vm_instance.assert_called_once_with(None, {})
        mock_format_exception.assert_called_once()
        arg = mock_format_exception.call_args[0][0]
        self.assertEqual(str(arg), "User data could not be retrieved.")

    @patch("time.time")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_prepare_network_for_vminstance")
    @patch.object(vimconnector, "_create_user_data")
    @patch.object(vimconnector, "_get_vm_availability_zone")
    @patch.object(vimconnector, "_prepare_disk_for_vminstance")
    @patch.object(vimconnector, "_update_port_security_for_vminstance")
    @patch.object(vimconnector, "_prepare_external_network_for_vminstance")
    @patch.object(vimconnector, "delete_vminstance")
    @patch.object(vimconnector, "_format_exception")
    def test_new_vm_instance_external_network_exception(
        self,
        mock_format_exception,
        mock_delete_vm_instance,
        mock_prepare_external_network,
        mock_update_port_security,
        mock_prepare_disk_for_vm_instance,
        mock_get_vm_availability_zone,
        mock_create_user_data,
        mock_prepare_network_for_vm_instance,
        mock_reload_connection,
        mock_time,
    ):
        """New VM instance creation, external network connection has failed as floating
        ip could not be created."""

        mock_create_user_data.return_value = True, "userdata"

        mock_get_vm_availability_zone.return_value = "nova"

        self.vimconn.nova.servers.create.return_value = self.server

        mock_time.return_value = time_return_value

        mock_prepare_external_network.side_effect = VimConnException(
            "Can not create floating ip."
        )

        self.vimconn.new_vminstance(
            name,
            description,
            start,
            image_id,
            flavor_id,
            affinity_group_list,
            net_list,
            cloud_config,
            disk_list2,
            availability_zone_index,
            availability_zone_list,
        )

        mock_reload_connection.assert_called_once()
        mock_prepare_network_for_vm_instance.assert_called_once_with(
            name=name,
            net_list=net_list,
            created_items={},
            net_list_vim=[],
            external_network=[],
            no_secured_ports=[],
        )
        mock_create_user_data.assert_called_once_with(cloud_config)
        mock_get_vm_availability_zone.assert_called_once_with(
            availability_zone_index, availability_zone_list
        )
        mock_prepare_disk_for_vm_instance.assert_called_once_with(
            name=name,
            existing_vim_volumes=[],
            created_items={},
            vm_av_zone="nova",
            disk_list=disk_list2,
        )
        self.vimconn.nova.servers.create.assert_called_once_with(
            name=name,
            image=image_id,
            flavor=flavor_id,
            nics=[],
            security_groups="default",
            availability_zone="nova",
            key_name="my_keypair",
            userdata="userdata",
            config_drive=True,
            block_device_mapping=None,
            scheduler_hints={},
        )
        mock_time.assert_called_once()
        mock_update_port_security.assert_called_once_with([], self.server)
        mock_prepare_external_network.assert_called_once_with(
            external_network=[],
            server=self.server,
            created_items={},
            vm_start_time=time_return_value,
        )
        mock_delete_vm_instance.assert_called_once_with(self.server.id, {})
        mock_format_exception.assert_called_once()
        arg = mock_format_exception.call_args[0][0]
        self.assertEqual(str(arg), "Can not create floating ip.")

    @patch("time.time")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_prepare_network_for_vminstance")
    @patch.object(vimconnector, "_create_user_data")
    @patch.object(vimconnector, "_get_vm_availability_zone")
    @patch.object(vimconnector, "_prepare_disk_for_vminstance")
    @patch.object(vimconnector, "_update_port_security_for_vminstance")
    @patch.object(vimconnector, "_prepare_external_network_for_vminstance")
    @patch.object(vimconnector, "delete_vminstance")
    @patch.object(vimconnector, "_format_exception")
    def test_new_vm_instance_with_affinity_group(
        self,
        mock_format_exception,
        mock_delete_vm_instance,
        mock_prepare_external_network,
        mock_update_port_security,
        mock_prepare_disk_for_vm_instance,
        mock_get_vm_availability_zone,
        mock_create_user_data,
        mock_prepare_network_for_vm_instance,
        mock_reload_connection,
        mock_time,
    ):
        """New VM creation with affinity group."""
        affinity_group_list = [
            {"affinity_group_id": "38b73-e9cc-5a6a-t270-82cc4811bd4a"}
        ]
        mock_create_user_data.return_value = True, "userdata"
        mock_get_vm_availability_zone.return_value = "nova"
        self.vimconn.nova.servers.create.return_value = self.server
        mock_time.return_value = time_return_value
        expected_result = self.server.id, {}

        result = self.vimconn.new_vminstance(
            name,
            description,
            start,
            image_id,
            flavor_id,
            affinity_group_list,
            net_list,
            cloud_config,
            disk_list2,
            availability_zone_index,
            availability_zone_list,
        )
        self.assertEqual(result, expected_result)

        mock_reload_connection.assert_called_once()
        mock_prepare_network_for_vm_instance.assert_called_once_with(
            name=name,
            net_list=net_list,
            created_items={},
            net_list_vim=[],
            external_network=[],
            no_secured_ports=[],
        )
        mock_create_user_data.assert_called_once_with(cloud_config)
        mock_get_vm_availability_zone.assert_called_once_with(
            availability_zone_index, availability_zone_list
        )
        mock_prepare_disk_for_vm_instance.assert_called_once_with(
            name=name,
            existing_vim_volumes=[],
            created_items={},
            vm_av_zone="nova",
            disk_list=disk_list2,
        )
        self.vimconn.nova.servers.create.assert_called_once_with(
            name=name,
            image=image_id,
            flavor=flavor_id,
            nics=[],
            security_groups="default",
            availability_zone="nova",
            key_name="my_keypair",
            userdata="userdata",
            config_drive=True,
            block_device_mapping=None,
            scheduler_hints={"group": "38b73-e9cc-5a6a-t270-82cc4811bd4a"},
        )
        mock_time.assert_called_once()
        mock_update_port_security.assert_called_once_with([], self.server)
        mock_prepare_external_network.assert_called_once_with(
            external_network=[],
            server=self.server,
            created_items={},
            vm_start_time=time_return_value,
        )
        mock_delete_vm_instance.assert_not_called()
        mock_format_exception.assert_not_called()

    @patch("time.time")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_prepare_network_for_vminstance")
    @patch.object(vimconnector, "_create_user_data")
    @patch.object(vimconnector, "_get_vm_availability_zone")
    @patch.object(vimconnector, "_prepare_disk_for_vminstance")
    @patch.object(vimconnector, "_update_port_security_for_vminstance")
    @patch.object(vimconnector, "_prepare_external_network_for_vminstance")
    @patch.object(vimconnector, "delete_vminstance")
    @patch.object(vimconnector, "_format_exception")
    def test_new_vm_instance_nova_server_create_failed(
        self,
        mock_format_exception,
        mock_delete_vm_instance,
        mock_prepare_external_network,
        mock_update_port_security,
        mock_prepare_disk_for_vm_instance,
        mock_get_vm_availability_zone,
        mock_create_user_data,
        mock_prepare_network_for_vm_instance,
        mock_reload_connection,
        mock_time,
    ):
        """New VM(server) creation failed."""

        mock_create_user_data.return_value = True, "userdata"

        mock_get_vm_availability_zone.return_value = "nova"

        self.vimconn.nova.servers.create.side_effect = Exception(
            "Server could not be created."
        )

        mock_time.return_value = time_return_value

        self.vimconn.new_vminstance(
            name,
            description,
            start,
            image_id,
            flavor_id,
            affinity_group_list,
            net_list,
            cloud_config,
            disk_list2,
            availability_zone_index,
            availability_zone_list,
        )

        mock_reload_connection.assert_called_once()
        mock_prepare_network_for_vm_instance.assert_called_once_with(
            name=name,
            net_list=net_list,
            created_items={},
            net_list_vim=[],
            external_network=[],
            no_secured_ports=[],
        )
        mock_create_user_data.assert_called_once_with(cloud_config)
        mock_get_vm_availability_zone.assert_called_once_with(
            availability_zone_index, availability_zone_list
        )
        mock_prepare_disk_for_vm_instance.assert_called_once_with(
            name=name,
            existing_vim_volumes=[],
            created_items={},
            vm_av_zone="nova",
            disk_list=disk_list2,
        )

        self.vimconn.nova.servers.create.assert_called_once_with(
            name=name,
            image=image_id,
            flavor=flavor_id,
            nics=[],
            security_groups="default",
            availability_zone="nova",
            key_name="my_keypair",
            userdata="userdata",
            config_drive=True,
            block_device_mapping=None,
            scheduler_hints={},
        )
        mock_time.assert_not_called()
        mock_update_port_security.assert_not_called()
        mock_prepare_external_network.assert_not_called()
        mock_delete_vm_instance.assert_called_once_with(None, {})
        mock_format_exception.assert_called_once()
        arg = mock_format_exception.call_args[0][0]
        self.assertEqual(str(arg), "Server could not be created.")

    @patch("time.time")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_prepare_network_for_vminstance")
    @patch.object(vimconnector, "_create_user_data")
    @patch.object(vimconnector, "_get_vm_availability_zone")
    @patch.object(vimconnector, "_prepare_disk_for_vminstance")
    @patch.object(vimconnector, "_update_port_security_for_vminstance")
    @patch.object(vimconnector, "_prepare_external_network_for_vminstance")
    @patch.object(vimconnector, "delete_vminstance")
    @patch.object(vimconnector, "_format_exception")
    def test_new_vm_instance_connection_exception(
        self,
        mock_format_exception,
        mock_delete_vm_instance,
        mock_prepare_external_network,
        mock_update_port_security,
        mock_prepare_disk_for_vm_instance,
        mock_get_vm_availability_zone,
        mock_create_user_data,
        mock_prepare_network_for_vm_instance,
        mock_reload_connection,
        mock_time,
    ):
        """Connection to Cloud API has failed."""
        mock_reload_connection.side_effect = Exception("Can not connect to Cloud APIs.")
        mock_create_user_data.return_value = True, "userdata"
        mock_get_vm_availability_zone.return_value = "nova"
        self.vimconn.nova.servers.create.return_value = self.server
        mock_time.return_value = time_return_value

        self.vimconn.new_vminstance(
            name,
            description,
            start,
            image_id,
            flavor_id,
            affinity_group_list,
            net_list,
            cloud_config,
            disk_list,
            availability_zone_index,
            availability_zone_list,
        )
        mock_format_exception.assert_called_once()
        arg = mock_format_exception.call_args[0][0]
        self.assertEqual(str(arg), "Can not connect to Cloud APIs.")
        mock_reload_connection.assert_called_once()
        mock_prepare_network_for_vm_instance.assert_not_called()
        mock_create_user_data.assert_not_called()
        mock_get_vm_availability_zone.assert_not_called()
        mock_prepare_disk_for_vm_instance.assert_not_called()
        self.vimconn.nova.servers.create.assert_not_called()
        mock_time.assert_not_called()
        mock_update_port_security.assert_not_called()
        mock_prepare_external_network.assert_not_called()
        mock_delete_vm_instance.assert_called_once_with(None, {})

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network_empty_created_items(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        """Created_items is emtpty."""
        created_items = {}
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        self.vimconn.neutron.list_ports.assert_not_called()
        self.vimconn.neutron.delete_port.assert_not_called()
        mock_delete_ports_by_id_wth_neutron.assert_not_called()

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        created_items = {
            "floating_ip:308b73-t9cc-1a6a-a270-12cc4811bd4a": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": True,
        }
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        mock_delete_ports_by_id_wth_neutron.assert_called_once_with(f"{port_id}")
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network_wthout_port(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        """Created_items does not have port."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
        }
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        mock_delete_ports_by_id_wth_neutron.assert_not_called()
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network_delete_port_raise_vimconnexception(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        """_delete_ports_by_id_wth_neutron raises vimconnexception."""
        created_items = deepcopy(created_items_all_true)
        mock_delete_ports_by_id_wth_neutron.side_effect = VimConnException(
            "Can not delete port"
        )
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        mock_delete_ports_by_id_wth_neutron.assert_called_once_with(f"{port_id}")
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting port: VimConnException: Can not delete port"
        )

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network_delete_port_raise_nvexception(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        """_delete_ports_by_id_wth_neutron raises nvExceptions.ClientException."""
        created_items = deepcopy(created_items_all_true)
        mock_delete_ports_by_id_wth_neutron.side_effect = nvExceptions.ClientException(
            "Connection aborted."
        )
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        mock_delete_ports_by_id_wth_neutron.assert_called_once_with(f"{port_id}")
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting port: ClientException: Unknown Error (HTTP Connection aborted.)"
        )

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network_delete_port_invalid_port_item(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        """port item is invalid."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}:": True,
        }
        mock_delete_ports_by_id_wth_neutron.side_effect = VimConnException(
            "Port is not valid."
        )
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        mock_delete_ports_by_id_wth_neutron.assert_called_once_with(f"{port_id}:")
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting port: VimConnException: Port is not valid."
        )

    @patch.object(vimconnector, "_delete_ports_by_id_wth_neutron")
    def test_delete_vm_ports_attached_to_network_delete_port_already_deleted(
        self, mock_delete_ports_by_id_wth_neutron
    ):
        """port is already deleted."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": None,
            f"port:{port_id}": None,
        }
        self.vimconn._delete_vm_ports_attached_to_network(created_items)
        mock_delete_ports_by_id_wth_neutron.assert_not_called()
        self.vimconn.logger.error.assert_not_called()

    def test_delete_floating_ip_by_id(self):
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"port:{port_id}": True,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": None,
            f"port:{port_id}": True,
        }
        k_id = floating_network_vim_id
        k = f"floating_ip:{floating_network_vim_id}"
        self.vimconn._delete_floating_ip_by_id(k, k_id, created_items)
        self.vimconn.neutron.delete_floatingip.assert_called_once_with(k_id)
        self.assertEqual(created_items, expected_created_items)

    def test_delete_floating_ip_by_id_floating_ip_already_deleted(self):
        """floating ip is already deleted."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": None,
            f"port:{port_id}": True,
        }
        k_id = floating_network_vim_id
        k = f"floating_ip:{floating_network_vim_id}"
        self.vimconn._delete_floating_ip_by_id(k, k_id, created_items)
        self.vimconn.neutron.delete_floatingip.assert_called_once_with(k_id)
        self.assertEqual(
            created_items,
            {
                f"floating_ip:{floating_network_vim_id}": None,
                f"port:{port_id}": True,
            },
        )

    def test_delete_floating_ip_by_id_floating_ip_raises_nvexception(self):
        """netron delete floating ip raises nvExceptions.ClientException."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"port:{port_id}": True,
        }
        k_id = floating_network_vim_id
        k = f"floating_ip:{floating_network_vim_id}"
        self.vimconn.neutron.delete_floatingip.side_effect = (
            nvExceptions.ClientException("Client exception occured.")
        )
        self.vimconn._delete_floating_ip_by_id(k, k_id, created_items)
        self.vimconn.neutron.delete_floatingip.assert_called_once_with(k_id)
        self.assertEqual(
            created_items,
            {
                f"floating_ip:{floating_network_vim_id}": True,
                f"port:{port_id}": True,
            },
        )
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting floating ip: ClientException: Unknown Error (HTTP Client exception occured.)"
        )

    def test_delete_floating_ip_by_id_floating_ip_raises_vimconnexception(self):
        """netron delete floating ip raises VimConnNotFoundException."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"port:{port_id}": True,
        }
        k_id = floating_network_vim_id
        k = f"floating_ip:{floating_network_vim_id}"
        self.vimconn.neutron.delete_floatingip.side_effect = VimConnNotFoundException(
            "Port id could not found."
        )
        self.vimconn._delete_floating_ip_by_id(k, k_id, created_items)
        self.vimconn.neutron.delete_floatingip.assert_called_once_with(k_id)
        self.assertEqual(
            created_items,
            {
                f"floating_ip:{floating_network_vim_id}": True,
                f"port:{port_id}": True,
            },
        )
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting floating ip: VimConnNotFoundException: Port id could not found."
        )

    def test_delete_floating_ip_by_id_floating_ip_invalid_k_item(self):
        """invalid floating ip item."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"port:{port_id}": True,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}::": None,
            f"floating_ip:{floating_network_vim_id}": True,
            f"port:{port_id}": True,
        }
        k_id = floating_network_vim_id
        k = f"floating_ip:{floating_network_vim_id}::"
        self.vimconn._delete_floating_ip_by_id(k, k_id, created_items)
        self.vimconn.neutron.delete_floatingip.assert_called_once_with(k_id)
        self.assertEqual(created_items, expected_created_items)

    def test_delete_volumes_by_id_with_cinder_volume_status_available(self):
        """volume status is available."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": None,
            f"port:{port_id}": None,
        }
        volumes_to_hold = []
        k = f"volume:{volume_id}"
        k_id = volume_id
        self.vimconn.cinder.volumes.get.return_value.status = "available"
        result = self.vimconn._delete_volumes_by_id_wth_cinder(
            k, k_id, volumes_to_hold, created_items
        )
        self.assertEqual(result, None)
        self.vimconn.cinder.volumes.get.assert_called_once_with(k_id)
        self.vimconn.cinder.volumes.delete.assert_called_once_with(k_id)
        self.vimconn.logger.error.assert_not_called()
        self.assertEqual(created_items, expected_created_items)

    def test_delete_volumes_by_id_with_cinder_volume_already_deleted(self):
        """volume is already deleted."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": None,
            f"port:{port_id}": None,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": None,
            f"port:{port_id}": None,
        }
        volumes_to_hold = []
        k = f"volume:{volume_id}"
        k_id = volume_id
        self.vimconn.cinder.volumes.get.return_value.status = "available"
        result = self.vimconn._delete_volumes_by_id_wth_cinder(
            k, k_id, volumes_to_hold, created_items
        )
        self.assertEqual(result, None)
        self.vimconn.cinder.volumes.get.assert_called_once_with(k_id)
        self.vimconn.cinder.volumes.delete.assert_called_once_with(k_id)
        self.vimconn.logger.error.assert_not_called()
        self.assertEqual(created_items, expected_created_items)

    def test_delete_volumes_by_id_with_cinder_get_volume_raise_exception(self):
        """cinder get volume raises exception."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        volumes_to_hold = []
        k = f"volume:{volume_id}"
        k_id = volume_id
        self.vimconn.cinder.volumes.get.side_effect = Exception(
            "Can not get volume status."
        )
        result = self.vimconn._delete_volumes_by_id_wth_cinder(
            k, k_id, volumes_to_hold, created_items
        )
        self.assertEqual(result, None)
        self.vimconn.cinder.volumes.get.assert_called_once_with(k_id)
        self.vimconn.cinder.volumes.delete.assert_not_called()
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting volume: Exception: Can not get volume status."
        )
        self.assertEqual(created_items, expected_created_items)

    def test_delete_volumes_by_id_with_cinder_delete_volume_raise_exception(self):
        """cinder delete volume raises exception."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        volumes_to_hold = []
        k = f"volume:{volume_id}"
        k_id = volume_id
        self.vimconn.cinder.volumes.get.return_value.status = "available"
        self.vimconn.cinder.volumes.delete.side_effect = nvExceptions.ClientException(
            "Connection aborted."
        )
        result = self.vimconn._delete_volumes_by_id_wth_cinder(
            k, k_id, volumes_to_hold, created_items
        )
        self.assertEqual(result, None)
        self.vimconn.cinder.volumes.get.assert_called_once_with(k_id)
        self.vimconn.cinder.volumes.delete.assert_called_once_with(k_id)
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting volume: ClientException: Unknown Error (HTTP Connection aborted.)"
        )
        self.assertEqual(created_items, expected_created_items)

    def test_delete_volumes_by_id_with_cinder_volume_to_be_hold(self):
        """volume_to_hold has item."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        volumes_to_hold = [volume_id]
        k = f"volume:{volume_id}"
        k_id = volume_id
        result = self.vimconn._delete_volumes_by_id_wth_cinder(
            k, k_id, volumes_to_hold, created_items
        )
        self.assertEqual(result, None)
        self.vimconn.cinder.volumes.get.assert_not_called()
        self.vimconn.cinder.volumes.delete.assert_not_called()
        self.vimconn.logger.error.assert_not_called()
        self.assertEqual(created_items, expected_created_items)

    def test_delete_volumes_by_id_with_cinder_volume_status_not_available(self):
        """volume status is not available."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        expected_created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id2}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        volumes_to_hold = []
        k = f"volume:{volume_id}"
        k_id = volume_id
        self.vimconn.cinder.volumes.get.return_value.status = "unavailable"
        result = self.vimconn._delete_volumes_by_id_wth_cinder(
            k, k_id, volumes_to_hold, created_items
        )
        self.assertEqual(result, True)
        self.vimconn.cinder.volumes.get.assert_called_once_with(k_id)
        self.vimconn.cinder.volumes.delete.assert_not_called()
        self.vimconn.logger.error.assert_not_called()
        self.assertEqual(created_items, expected_created_items)

    def test_delete_ports_by_id_by_neutron(self):
        """neutron delete ports."""
        k_id = port_id
        self.vimconn.neutron.list_ports.return_value = {
            "ports": [{"id": port_id}, {"id": port2_id}]
        }

        self.vimconn._delete_ports_by_id_wth_neutron(k_id)
        self.vimconn.neutron.list_ports.assert_called_once()
        self.vimconn.neutron.delete_port.assert_called_once_with(k_id)
        self.vimconn.logger.error.assert_not_called()

    def test_delete_ports_by_id_by_neutron_id_not_in_port_list(self):
        """port id not in the port list."""
        k_id = volume_id
        self.vimconn.neutron.list_ports.return_value = {
            "ports": [{"id": port_id}, {"id": port2_id}]
        }

        self.vimconn._delete_ports_by_id_wth_neutron(k_id)
        self.vimconn.neutron.list_ports.assert_called_once()
        self.vimconn.neutron.delete_port.assert_not_called()
        self.vimconn.logger.error.assert_not_called()

    def test_delete_ports_by_id_by_neutron_list_port_raise_exception(self):
        """neutron list port raises exception."""
        k_id = port_id
        self.vimconn.neutron.list_ports.side_effect = nvExceptions.ClientException(
            "Connection aborted."
        )
        self.vimconn._delete_ports_by_id_wth_neutron(k_id)
        self.vimconn.neutron.list_ports.assert_called_once()
        self.vimconn.neutron.delete_port.assert_not_called()
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting port: ClientException: Unknown Error (HTTP Connection aborted.)"
        )

    def test_delete_ports_by_id_by_neutron_delete_port_raise_exception(self):
        """neutron delete port raises exception."""
        k_id = port_id
        self.vimconn.neutron.list_ports.return_value = {
            "ports": [{"id": port_id}, {"id": port2_id}]
        }
        self.vimconn.neutron.delete_port.side_effect = nvExceptions.ClientException(
            "Connection aborted."
        )
        self.vimconn._delete_ports_by_id_wth_neutron(k_id)
        self.vimconn.neutron.list_ports.assert_called_once()
        self.vimconn.neutron.delete_port.assert_called_once_with(k_id)
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting port: ClientException: Unknown Error (HTTP Connection aborted.)"
        )

    def test_get_item_name_id(self):
        """Get name and id successfully."""
        k = f"some:{port_id}"
        result = self.vimconn._get_item_name_id(k)
        self.assertEqual(result, ("some", f"{port_id}"))

    def test_get_item_name_id_wthout_semicolon(self):
        """Does not have seperator."""
        k = f"some{port_id}"
        result = self.vimconn._get_item_name_id(k)
        self.assertEqual(result, (f"some{port_id}", ""))

    def test_get_item_name_id_empty_string(self):
        """Empty string."""
        k = ""
        result = self.vimconn._get_item_name_id(k)
        self.assertEqual(result, ("", ""))

    def test_get_item_name_id_k_is_none(self):
        """item is None."""
        k = None
        with self.assertRaises(AttributeError):
            self.vimconn._get_item_name_id(k)

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Created items has floating ip and volume."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            ("floating_ip", f"{floating_network_vim_id}"),
            ("volume", f"{volume_id}"),
        ]
        mock_delete_volumes_by_id_wth_cinder.return_value = True
        volumes_to_hold = []
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, True)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_called_once_with(
            f"volume:{volume_id}", f"{volume_id}", [], created_items
        )
        mock_delete_floating_ip_by_id.assert_called_once_with(
            f"floating_ip:{floating_network_vim_id}",
            f"{floating_network_vim_id}",
            created_items,
        )
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_wth_volumes_to_hold(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Created items has floating ip and volume and volumes_to_hold has items."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            ("floating_ip", f"{floating_network_vim_id}"),
            ("volume", f"{volume_id}"),
        ]
        mock_delete_volumes_by_id_wth_cinder.return_value = True
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, True)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_called_once_with(
            f"volume:{volume_id}", f"{volume_id}", volumes_to_hold, created_items
        )
        mock_delete_floating_ip_by_id.assert_called_once_with(
            f"floating_ip:{floating_network_vim_id}",
            f"{floating_network_vim_id}",
            created_items,
        )
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_wth_keep_waiting_true(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Keep waiting initial value is True."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            ("floating_ip", f"{floating_network_vim_id}"),
            ("volume", f"{volume_id}"),
        ]
        mock_delete_volumes_by_id_wth_cinder.return_value = False
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        keep_waiting = True
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, True)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_called_once_with(
            f"volume:{volume_id}", f"{volume_id}", volumes_to_hold, created_items
        )
        mock_delete_floating_ip_by_id.assert_called_once_with(
            f"floating_ip:{floating_network_vim_id}",
            f"{floating_network_vim_id}",
            created_items,
        )
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_delete_vol_raises(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Delete volume raises exception."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            ("floating_ip", f"{floating_network_vim_id}"),
            ("volume", f"{volume_id}"),
        ]
        mock_delete_volumes_by_id_wth_cinder.side_effect = ConnectionError(
            "Connection failed."
        )
        volumes_to_hold = []
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, False)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_called_once_with(
            f"volume:{volume_id}", f"{volume_id}", [], created_items
        )
        mock_delete_floating_ip_by_id.assert_called_once_with(
            f"floating_ip:{floating_network_vim_id}",
            f"{floating_network_vim_id}",
            created_items,
        )
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting volume:ac408b73-b9cc-4a6a-a270-82cc4811bd4a: Connection failed."
        )

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_delete_fip_raises(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Delete floating ip raises exception."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"volume:{volume_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            ("floating_ip", f"{floating_network_vim_id}"),
            ("volume", f"{volume_id}"),
        ]
        mock_delete_volumes_by_id_wth_cinder.return_value = False
        mock_delete_floating_ip_by_id.side_effect = ConnectionError(
            "Connection failed."
        )
        volumes_to_hold = []
        keep_waiting = True
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, True)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_called_once_with(
            f"volume:{volume_id}", f"{volume_id}", [], created_items
        )
        mock_delete_floating_ip_by_id.assert_called_once_with(
            f"floating_ip:{floating_network_vim_id}",
            f"{floating_network_vim_id}",
            created_items,
        )
        self.vimconn.logger.error.assert_called_once_with(
            "Error deleting floating_ip:108b73-e9cc-5a6a-t270-82cc4811bd4a: Connection failed."
        )

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_get_item_name_raises(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Get item, name raises exception."""
        created_items = {
            3: True,
            f"volume{volume_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            TypeError("Invalid Type"),
            AttributeError("Invalid attribute"),
        ]
        volumes_to_hold = []
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, False)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_not_called()
        mock_delete_floating_ip_by_id.assert_not_called()
        _call_logger = self.vimconn.logger.error.call_args_list
        self.assertEqual(_call_logger[0][0], ("Error deleting 3: Invalid Type",))
        self.assertEqual(
            _call_logger[1][0],
            (f"Error deleting volume{volume_id}: Invalid attribute",),
        )

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_no_fip_wth_port(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Created items has port, does not have floating ip."""
        created_items = {
            f"volume:{volume_id}": True,
            f"port:{port_id}": True,
        }
        mock_get_item_name_id.side_effect = [
            ("volume", f"{volume_id}"),
            ("port", f"{port_id}"),
        ]
        mock_delete_volumes_by_id_wth_cinder.return_value = False
        volumes_to_hold = []
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, False)
        self.assertEqual(mock_get_item_name_id.call_count, 2)
        mock_delete_volumes_by_id_wth_cinder.assert_called_once_with(
            f"volume:{volume_id}", f"{volume_id}", [], created_items
        )
        mock_delete_floating_ip_by_id.assert_not_called()
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_no_volume(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """Created items does not have volume."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": True,
            f"port:{port_id}": None,
        }
        mock_get_item_name_id.side_effect = [
            ("floating_ip", f"{floating_network_vim_id}")
        ]
        volumes_to_hold = []
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, False)
        self.assertEqual(mock_get_item_name_id.call_count, 1)
        mock_delete_volumes_by_id_wth_cinder.assert_not_called()
        mock_delete_floating_ip_by_id.assert_called_once_with(
            f"floating_ip:{floating_network_vim_id}",
            f"{floating_network_vim_id}",
            created_items,
        )
        self.vimconn.logger.error.assert_not_called()

    @patch.object(vimconnector, "_get_item_name_id")
    @patch.object(vimconnector, "_delete_volumes_by_id_wth_cinder")
    @patch.object(vimconnector, "_delete_floating_ip_by_id")
    def test_delete_created_items_already_deleted(
        self,
        mock_delete_floating_ip_by_id,
        mock_delete_volumes_by_id_wth_cinder,
        mock_get_item_name_id,
    ):
        """All created items are alerady deleted."""
        created_items = {
            f"floating_ip:{floating_network_vim_id}": None,
            f"volume:{volume_id}": None,
            f"port:{port_id}": None,
        }
        volumes_to_hold = []
        keep_waiting = False
        result = self.vimconn._delete_created_items(
            created_items, volumes_to_hold, keep_waiting
        )
        self.assertEqual(result, False)
        mock_get_item_name_id.assert_not_called()
        mock_delete_volumes_by_id_wth_cinder.assert_not_called()
        mock_delete_floating_ip_by_id.assert_not_called()
        self.vimconn.logger.error.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_successfully(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        vm_id = f"{virtual_mac_id}"
        created_items = deepcopy(created_items_all_true)
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        mock_delete_created_items.return_value = False
        self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_called_once_with(created_items)
        self.vimconn.nova.servers.delete.assert_called_once_with(vm_id)
        mock_delete_created_items.assert_called_once_with(
            created_items, volumes_to_hold, False
        )
        mock_sleep.assert_not_called()
        mock_format_exception.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_delete_created_items_raises(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """Delete creted items raises exception."""
        vm_id = f"{virtual_mac_id}"
        created_items = deepcopy(created_items_all_true)
        mock_sleep = MagicMock()
        volumes_to_hold = []
        err = ConnectionError("ClientException occured.")
        mock_delete_created_items.side_effect = err
        with self.assertRaises(ConnectionError) as err:
            self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
            self.assertEqual(str(err), "ClientException occured.")
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_called_once_with(created_items)
        self.vimconn.nova.servers.delete.assert_called_once_with(vm_id)
        mock_delete_created_items.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_delete_vm_ports_raises(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """Delete vm ports raises exception."""
        vm_id = f"{virtual_mac_id}"
        created_items = deepcopy(created_items_all_true)
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        err = ConnectionError("ClientException occured.")
        mock_delete_vm_ports_attached_to_network.side_effect = err
        mock_delete_created_items.side_effect = err
        with self.assertRaises(ConnectionError) as err:
            self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
            self.assertEqual(str(err), "ClientException occured.")
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_called_once_with(created_items)
        self.vimconn.nova.servers.delete.assert_not_called()
        mock_delete_created_items.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_nova_server_delete_raises(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """Nova server delete raises exception."""
        vm_id = f"{virtual_mac_id}"
        created_items = deepcopy(created_items_all_true)
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        err = VimConnConnectionException("ClientException occured.")
        self.vimconn.nova.servers.delete.side_effect = err
        mock_delete_created_items.side_effect = err
        with self.assertRaises(VimConnConnectionException) as err:
            self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
            self.assertEqual(str(err), "ClientException occured.")
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_called_once_with(created_items)
        self.vimconn.nova.servers.delete.assert_called_once_with(vm_id)
        mock_delete_created_items.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_reload_connection_raises(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """Reload connection raises exception."""
        vm_id = f"{virtual_mac_id}"
        created_items = deepcopy(created_items_all_true)
        mock_sleep = MagicMock()
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        err = ConnectionError("ClientException occured.")
        mock_delete_created_items.return_value = False
        mock_reload_connection.side_effect = err
        with self.assertRaises(ConnectionError) as err:
            self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
            self.assertEqual(str(err), "ClientException occured.")
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_not_called()
        self.vimconn.nova.servers.delete.assert_not_called()
        mock_delete_created_items.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_created_item_vol_to_hold_are_none(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """created_items and volumes_to_hold are None."""
        vm_id = f"{virtual_mac_id}"
        created_items = None
        volumes_to_hold = None
        mock_delete_created_items.return_value = False
        self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_not_called()
        self.vimconn.nova.servers.delete.assert_called_once_with(vm_id)
        mock_delete_created_items.assert_called_once_with({}, [], False)
        mock_sleep.assert_not_called()
        mock_format_exception.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_vm_id_is_none(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """vm_id is None."""
        vm_id = None
        created_items = deepcopy(created_items_all_true)
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        mock_delete_created_items.side_effect = [True, True, False]
        self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_called_once_with(created_items)
        self.vimconn.nova.servers.delete.assert_not_called()
        self.assertEqual(mock_delete_created_items.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)
        mock_format_exception.assert_not_called()

    @patch("time.sleep")
    @patch.object(vimconnector, "_format_exception")
    @patch.object(vimconnector, "_reload_connection")
    @patch.object(vimconnector, "_delete_vm_ports_attached_to_network")
    @patch.object(vimconnector, "_delete_created_items")
    def test_delete_vminstance_delete_created_items_return_true(
        self,
        mock_delete_created_items,
        mock_delete_vm_ports_attached_to_network,
        mock_reload_connection,
        mock_format_exception,
        mock_sleep,
    ):
        """Delete created items always return True."""
        vm_id = None
        created_items = deepcopy(created_items_all_true)
        volumes_to_hold = [f"{volume_id}", f"{volume_id2}"]
        mock_delete_created_items.side_effect = [True] * 1800
        self.vimconn.delete_vminstance(vm_id, created_items, volumes_to_hold)
        mock_reload_connection.assert_called_once()
        mock_delete_vm_ports_attached_to_network.assert_called_once_with(created_items)
        self.vimconn.nova.servers.delete.assert_not_called()
        self.assertEqual(mock_delete_created_items.call_count, 1800)
        self.assertEqual(mock_sleep.call_count, 1800)
        mock_format_exception.assert_not_called()


if __name__ == "__main__":
    unittest.main()
