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

"""This file contains the template JSON-encoded messages used to compose the Transport
API (TAPI) messages sent by the TAPI WIM connector to the WIM."""

REQUESTED_CAPACITY_TEMPLATE = {"total-size": {"value": None, "unit": "GBPS"}}

VLAN_CONSTRAINT_TEMPLATE = {"vlan-id": None}

ENDPOINT_TEMPLATE = {
    "service-interface-point": {"service-interface-point-uuid": None},
    "layer-protocol-name": None,
    "layer-protocol-qualifier": None,
    "local-id": None,
}

CREATE_TEMPLATE = {
    "tapi-connectivity:connectivity-service": [
        {
            "uuid": None,
            # "requested-capacity": REQUESTED_CAPACITY_TEMPLATE,
            "connectivity-direction": "UNIDIRECTIONAL",
            "end-point": [],
            # "vlan-constraint": VLAN_CONSTRAINT_TEMPLATE,
        }
    ]
}

DELETE_TEMPLATE = {"tapi-connectivity:input": {"uuid": None}}
