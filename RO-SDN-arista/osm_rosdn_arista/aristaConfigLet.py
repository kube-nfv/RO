# -*- coding: utf-8 -*-
##
# Copyright 2019 Atos - CoE Telco NFV Team
# All Rights Reserved.
#
# Contributors: Oscar Luis Peral, Atos
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
# contact with: <oscarluis.peral@atos.net>
#
# Neither the name of Atos nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# This work has been performed in the context of Arista Telefonica OSM PoC.
##


class AristaSDNConfigLet:
    _configLet_SRIOV = """
!# service: {}
interface {}
   switchport
   switchport mode trunk
   switchport trunk group {}{}
!
"""

    def _get_sriov(self, uuid, interface, vlan_id, s_type, index):
        return self._configLet_SRIOV.format(uuid, interface, s_type, vlan_id)

    def getElan_sriov(self, uuid, interface, vlan_id, index):
        return self._get_sriov(uuid, interface, vlan_id, "ELAN", index)

    def getEline_sriov(self, uuid, interface, vlan_id, index):
        return self._get_sriov(uuid, interface, vlan_id, "ELINE", index)

    _configLet_PASSTROUGH = """
!# service: {}
interface {}
   switchport
   switchport mode access
   switchport access vlan {}
!
"""

    def _get_passthrough(self, uuid, interface, vlan_id, s_type, index):
        return self._configLet_PASSTROUGH.format(uuid, interface, vlan_id)

    def getElan_passthrough(self, uuid, interface, vlan_id, index):
        return self._get_passthrough(uuid, interface, vlan_id, "ELAN", index)

    def getEline_passthrough(self, uuid, interface, vlan_id, index):
        return self._get_passthrough(uuid, interface, vlan_id, "ELINE", index)

    _configLet_VLAN = """
!## service: {service} {vlan} {uuid}
vlan {vlan}
   name {service}{vlan}
   trunk group {service}{vlan}
   trunk group MLAGPEER

interface VXLAN1
   VXLAN vlan {vlan} vni {vni}
!
"""

    def _get_vlan(self, uuid, vlan_id, vni_id, s_type):
        return self._configLet_VLAN.format(service=s_type, vlan=vlan_id, uuid=uuid, vni=vni_id)

    def getElan_vlan(self, uuid, vlan_id, vni_id):
        return self._get_vlan(uuid, vlan_id, vni_id, "ELAN")

    def getEline_vlan(self, uuid, vlan_id, vni_id):
        return self._get_vlan(uuid, vlan_id, vni_id, "ELINE")

    _configLet_BGP = """
!# service: {uuid}
router bgp {bgp}
    vlan {vlan}
        rd {loopback}:{vni}
        route-target both {vni}:{vni}
        redistribute learned
!
"""

    def _get_bgp(self, uuid, vlan_id, vni_id, loopback0, bgp, s_type):
        return self._configLet_BGP.format(uuid=uuid, bgp=bgp, vlan=vlan_id, loopback=loopback0, vni=vni_id)

    def getElan_bgp(self, uuid, vlan_id, vni_id, loopback0, bgp):
        return self._get_bgp(uuid, vlan_id, vni_id, loopback0, bgp, "ELAN")

    def getEline_bgp(self, uuid, vlan_id, vni_id, loopback0, bgp):
        return self._get_bgp(uuid, vlan_id, vni_id, loopback0, bgp, "ELINE")
