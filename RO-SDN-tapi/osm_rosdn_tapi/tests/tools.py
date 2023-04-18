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

"""This file contains a helper methods for the Mock OSM RO component that can be used
for rapid unit testing.

This code is based on code taken with permission from ETSI TeraFlowSDN project at:
  https://labs.etsi.org/rep/tfs/controller
"""

from typing import Dict, Optional


# Ref: https://osm.etsi.org/wikipub/index.php/WIM
# Fields defined according to from osm_ro_plugin.sdnconn import SdnConnectorBase
def wim_port_mapping(
    datacenter_id: str,
    device_id: str,
    device_interface_id: str,
    service_endpoint_id: str,
    switch_dpid: Optional[str] = None,
    switch_port: Optional[str] = None,
    service_mapping_info: Dict = {},
):
    mapping = {
        "datacenter_id": datacenter_id,
        "device_id": device_id,
        "device_interface_id": device_interface_id,
        "service_endpoint_id": service_endpoint_id,
        "service_mapping_info": service_mapping_info,
    }
    if switch_dpid is not None:
        mapping["switch_dpid"] = switch_dpid
    if switch_port is not None:
        mapping["switch_port"] = switch_port
    return mapping
