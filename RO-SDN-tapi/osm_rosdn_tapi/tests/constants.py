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

"""This file contains the WIM settings for the unit test used to validate the
Transport API (TAPI) WIM connector."""


from osm_rosdn_tapi.tests.tools import wim_port_mapping


WIM_HOST_PORT = ("127.0.0.127", 49000)

# WIM_URL should be populated with the WIM url provided for the WIM connector during its instantiation
WIM_URL = "http://{:s}:{:d}".format(*WIM_HOST_PORT)

# WIM_ACCOUNT should be populated with the WIM credentials provided for the WIM connector during its instantiation
WIM_ACCOUNT = {"user": "admin", "password": "admin"}

# WIM_PORT_MAPPING should be populated with the port mapping provided for the WIM connector during its instantiation
# In this example, SIPs are taken from mock_tapi_handler.py file.
WIM_PORT_MAPPING = [
    wim_port_mapping(
        "dc1",
        "dc1r1",
        "eth0",
        "R1-eth0",
        service_mapping_info={},
    ),
    wim_port_mapping(
        "dc2",
        "dc2r2",
        "eth0",
        "R2-eth0",
        service_mapping_info={},
    ),
    wim_port_mapping(
        "dc3",
        "dc3r3",
        "eth0",
        "R3-opt1",
        service_mapping_info={
            "sip_input": "R3-opt1-rx",
            "sip_output": "R3-opt1-tx",
        },
    ),
    wim_port_mapping(
        "dc4",
        "dc4r4",
        "eth0",
        "R4-opt1",
        service_mapping_info={
            "sip_input": "R4-opt1-rx",
            "sip_output": "R4-opt1-tx",
        },
    ),
]
