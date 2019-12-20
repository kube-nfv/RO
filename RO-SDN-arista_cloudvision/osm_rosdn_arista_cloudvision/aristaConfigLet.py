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
    _VLAN = "VLAN"
    _VXLAN = "VXLAN"
    _VLAN_MLAG = "VLAN-MLAG"
    _VXLAN_MLAG = "VXLAN-MLAG"
    topology = _VXLAN_MLAG

    def __init__(self, topology=_VXLAN_MLAG):
        self.topology = topology

    _basic_int ="""
interface {interface}
   !! service: {uuid}
   switchport
   switchport mode {type}
   switchport {switchport_def}
!
"""
    _int_SRIOV = "trunk group {service}{vlan_id}"
    _int_PASSTROUGH = "access vlan {vlan_id}"

    def _get_interface(self, uuid, interface, vlan_id, s_type, index, i_type):
        if i_type == "trunk":
            switchport_def = self._int_SRIOV.format(service=s_type, vlan_id=vlan_id)
        else:
            switchport_def = self._int_PASSTROUGH.format(vlan_id=vlan_id)
        return self._basic_int.format(uuid=uuid,
                                      interface=interface,
                                      type=i_type,
                                      switchport_def=switchport_def)

    def getElan_sriov(self, uuid, interface, vlan_id, index):
        return self._get_interface(uuid, interface, vlan_id, "ELAN", index, "trunk")

    def getEline_sriov(self, uuid, interface, vlan_id, index):
        return self._get_interface(uuid, interface, vlan_id, "ELINE", index, "trunk")

    def getElan_passthrough(self, uuid, interface, vlan_id, index):
        return self._get_interface(uuid, interface, vlan_id, "ELAN", index, "dot1q-tunnel")

    def getEline_passthrough(self, uuid, interface, vlan_id, index):
        return self._get_interface(uuid, interface, vlan_id, "ELINE", index, "dot1q-tunnel")

    _basic_vlan ="""
vlan {vlan}
   !! service: {service} {vlan} {uuid}
   name {service}{vlan}
   trunk group {service}{vlan}
"""
    _basic_mlag ="""   trunk group MLAGPEER
"""
    _basic_vxlan ="""interface VXLAN1
   VXLAN vlan {vlan} vni {vni}
"""
    _basic_end ="!"

    _configLet_VLAN = _basic_vlan + _basic_end
    _configLet_VXLAN = _basic_vlan + _basic_vxlan + _basic_end
    _configLet_VLAN_MLAG = _basic_vlan + _basic_mlag + _basic_end
    _configLet_VXLAN_MLAG = _basic_vlan + _basic_mlag + _basic_vxlan + _basic_end

    def _get_vlan(self, uuid, vlan_id, vni_id, s_type):
        if self.topology == self._VLAN:
            return self._configLet_VLAN.format(service=s_type, vlan=vlan_id, uuid=uuid)
        if self.topology == self._VLAN_MLAG:
            return self._configLet_VLAN_MLAG.format(service=s_type, vlan=vlan_id, uuid=uuid)
        if self.topology == self._VXLAN:
            return self._configLet_VXLAN.format(service=s_type, vlan=vlan_id, uuid=uuid, vni=vni_id)
        if self.topology == self._VXLAN_MLAG:
            return self._configLet_VXLAN_MLAG.format(service=s_type, vlan=vlan_id, uuid=uuid, vni=vni_id)

    def getElan_vlan(self, uuid, vlan_id, vni_id):
        return self._get_vlan(uuid, vlan_id, vni_id, "ELAN")

    def getEline_vlan(self, uuid, vlan_id, vni_id):
        return self._get_vlan(uuid, vlan_id, vni_id, "ELINE")

    _configLet_BGP = """
router bgp {bgp}
    vlan {vlan}
    !! service: {uuid}
        rd {loopback}:{vni}
        route-target both {vni}:{vni}
        redistribute learned
!
"""

    def _get_bgp(self, uuid, vlan_id, vni_id, loopback0, bgp, s_type):
        if self.topology == self._VXLAN or self.topology == self._VXLAN_MLAG:
            return self._configLet_BGP.format(uuid=uuid,
                                              bgp=bgp,
                                              vlan=vlan_id,
                                              loopback=loopback0,
                                              vni=vni_id)


    def getElan_bgp(self, uuid, vlan_id, vni_id, loopback0, bgp):
        return self._get_bgp(uuid, vlan_id, vni_id, loopback0, bgp, "ELAN")

    def getEline_bgp(self, uuid, vlan_id, vni_id, loopback0, bgp):
        return self._get_bgp(uuid, vlan_id, vni_id, loopback0, bgp, "ELINE")
