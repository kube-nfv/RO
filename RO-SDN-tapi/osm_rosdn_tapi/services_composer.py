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

"""This file contains the ServiceComposer class used by the Transport API (TAPI) WIM
connector to compose the services based on the service_endpoint_ids and their
directionality."""

from .exceptions import (
    WimTapiIncongruentDirectionality,
    WimTapiIncongruentEndPoints,
    WimTapiMissingMappingField,
    WimTapiSipNotFound,
)
from .message_composers import (
    compose_endpoint,
    compose_requested_capacity,
    # compose_vlan_constraint,
)


class ServicesComposer:
    def __init__(self, service_interface_points) -> None:
        self.sips = service_interface_points

        # if unidirectional
        #   - a single service_endpoint item is created
        #   - the service_endpoint item contains with the 2 bidirectional SIPs
        # if bidirectional
        #   - two service_endpoint items are created
        #   - each service_endpoint item containing a list of 2 unidirectional SIPs (in, out)
        self.services = list()

        # TODO: populate dynamically capacity of the connection
        self.requested_capacity = compose_requested_capacity(1, unit="GBPS")

        self.vlan_constraint = None
        # TODO: VLAN needs to be processed by connection point; by now deactivated
        # if connection_point.get("service_endpoint_encapsulation_type") == "dot1q":
        #    encap_info = connection_point.get("service_endpoint_encapsulation_info", {})
        #    vlan_id = encap_info.get("vlan")
        #    if vlan_id is not None:
        #        vlan_constraint = compose_vlan_constraint(vlan_id)

    def add_bidirectional(self, service_endpoint_id):
        if len(self.services) == 0:
            # assume bidirectional, SIP is service_endpoint_id
            service_interface_point = self.sips[service_endpoint_id]
            self.services.append([compose_endpoint(service_interface_point)])
        elif len(self.services) == 1:
            # is bidirectional, SIP is service_endpoint_id
            if len(self.services[0]) > 1:
                # too much endpoints per service
                raise WimTapiIncongruentEndPoints(self.services, service_endpoint_id)
            self.services[0].append(compose_endpoint(self.sips[service_endpoint_id]))
        else:
            raise WimTapiIncongruentDirectionality(self.services, service_endpoint_id)

    def add_unidirectional(self, service_endpoint_id, sip_input, sip_output):
        if len(self.services) == 0:
            # assume unidirectional
            self.services.append([compose_endpoint(self.sips[sip_output])])  # AZ
            self.services.append([compose_endpoint(self.sips[sip_input])])  # ZA
        elif len(self.services) == 2:
            # is unidirectional

            if len(self.services[0]) > 1:
                # too much endpoints per service
                raise WimTapiIncongruentEndPoints(self.services[0], service_endpoint_id)
            self.services[0].append(compose_endpoint(self.sips[sip_input]))  # AZ

            if len(self.services[1]) > 1:
                # too much endpoints per service
                raise WimTapiIncongruentEndPoints(self.services[1], service_endpoint_id)
            self.services[1].insert(0, compose_endpoint(self.sips[sip_output]))  # ZA
        else:
            raise WimTapiIncongruentDirectionality(self.services, service_endpoint_id)

    def add_service_endpoint(self, service_endpoint_id, mapping):
        service_mapping_info = mapping.get("service_mapping_info", {})

        if (
            len(service_mapping_info) == 0
            or "sip_input" not in service_mapping_info
            or "sip_output" not in service_mapping_info
        ):
            # bidirectional (no mapping or no sip_input or no sip_output)
            if service_endpoint_id not in self.sips:
                raise WimTapiSipNotFound(service_endpoint_id, self.sips)
            self.add_bidirectional(service_endpoint_id)

        else:
            # unidirectional, sip_input and sip_output provided in mapping

            sip_input = service_mapping_info.get("sip_input")
            if sip_input is None:
                raise WimTapiMissingMappingField(
                    mapping, "service_mapping_info.sip_input"
                )

            if sip_input not in self.sips:
                raise WimTapiSipNotFound(sip_input, self.sips)

            sip_output = service_mapping_info.get("sip_output")
            if sip_output is None:
                raise WimTapiMissingMappingField(
                    mapping, "service_mapping_info.sip_output"
                )

            if sip_output not in self.sips:
                raise WimTapiSipNotFound(sip_output, self.sips)

            self.add_unidirectional(service_endpoint_id, sip_input, sip_output)

    def is_bidirectional(self):
        return len(self.services) == 1

    def dump(self, logger):
        str_data = "\n".join(
            [
                "services_composer {",
                "  services={:s}".format(str(self.services)),
                "  requested_capacity={:s}".format(str(self.requested_capacity)),
                "  vlan_constraint={:s}".format(str(self.vlan_constraint)),
                "}",
            ]
        )
        logger.debug(str_data)
