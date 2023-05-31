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

"""This file contains the methods to compose the conn_info data structures for the
Transport API (TAPI) WIM connector."""


def conn_info_compose_unidirectional(
    service_az_uuid,
    service_az_endpoints,
    service_za_uuid,
    service_za_endpoints,
    requested_capacity=None,
    vlan_constraint=None,
):
    conn_info_az = {
        "uuid": service_az_uuid,
        "endpoints": service_az_endpoints,
    }
    conn_info_za = {
        "uuid": service_za_uuid,
        "endpoints": service_za_endpoints,
    }
    if requested_capacity is not None:
        conn_info_az["requested_capacity"] = requested_capacity
        conn_info_za["requested_capacity"] = requested_capacity
    if vlan_constraint is not None:
        conn_info_az["vlan_constraint"] = vlan_constraint
        conn_info_za["vlan_constraint"] = vlan_constraint
    conn_info = {
        "az": conn_info_az,
        "za": conn_info_za,
        "bidirectional": False,
    }
    return conn_info


def conn_info_compose_bidirectional(
    service_uuid,
    service_endpoints,
    requested_capacity=None,
    vlan_constraint=None,
):
    conn_info = {
        "uuid": service_uuid,
        "endpoints": service_endpoints,
        "bidirectional": True,
    }
    if requested_capacity is not None:
        conn_info["requested_capacity"] = requested_capacity
    if vlan_constraint is not None:
        conn_info["vlan_constraint"] = vlan_constraint
    return conn_info
