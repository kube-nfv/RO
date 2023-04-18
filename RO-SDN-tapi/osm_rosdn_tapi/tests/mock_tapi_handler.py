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

"""This file contains a minimalistic Mock Transport API (TAPI) WIM server."""

import http.server
import json
import uuid


PHOTONIC_PROTOCOL_QUALIFIER = "tapi-photonic-media:PHOTONIC_LAYER_QUALIFIER_NMC"
DSR_PROTOCOL_QUALIFIER = "tapi-dsr:DIGITAL_SIGNAL_TYPE"


def compose_sip(
    uuid, layer_protocol_name, supported_layer_protocol_qualifier, direction
):
    return {
        "uuid": uuid,
        "layer-protocol-name": layer_protocol_name,
        "supported-layer-protocol-qualifier": [supported_layer_protocol_qualifier],
        "administrative-state": "UNLOCKED",
        "operational-state": "ENABLED",
        "direction": direction,
    }


def compose_sip_dsr(uuid):
    return compose_sip(uuid, "DSR", DSR_PROTOCOL_QUALIFIER, "BIDIRECTIONAL")


def compose_sip_photonic_input(uuid):
    return compose_sip(uuid, "PHOTONIC_MEDIA", PHOTONIC_PROTOCOL_QUALIFIER, "INPUT")


def compose_sip_photonic_output(uuid):
    return compose_sip(uuid, "PHOTONIC_MEDIA", PHOTONIC_PROTOCOL_QUALIFIER, "OUTPUT")


CONTEXT = {
    "uuid": str(uuid.uuid4()),
    "service-interface-point": [
        compose_sip_dsr("R1-eth0"),
        compose_sip_dsr("R2-eth0"),
        compose_sip_photonic_input("R3-opt1-rx"),
        compose_sip_photonic_output("R3-opt1-tx"),
        compose_sip_photonic_input("R4-opt1-rx"),
        compose_sip_photonic_output("R4-opt1-tx"),
    ],
    # topology details not used by the WIM connector
    "topology-context": {},
    "connectivity-context": {"connectivity-service": [], "connection": []},
}


class MockTapiRequestHandler(http.server.BaseHTTPRequestHandler):
    """Mock TAPI Request Handler for the unit tests"""

    def do_GET(self):  # pylint: disable=invalid-name
        """Handle GET requests"""
        path = self.path.replace("tapi-common:", "").replace("tapi-connectivity:", "")

        if path == "/restconf/data/context":
            status = 200  # ok
            headers = {"Content-Type": "application/json"}
            data = CONTEXT
        elif path == "/restconf/data/context/service-interface-point":
            status = 200  # ok
            headers = {"Content-Type": "application/json"}
            data = CONTEXT["service-interface-point"]
            data = {"tapi-common:service-interface-point": data}
        elif path == "/restconf/data/context/connectivity-context/connectivity-service":
            status = 200  # ok
            headers = {"Content-Type": "application/json"}
            data = CONTEXT["connectivity-context"]["connectivity-service"]
            data = {"tapi-connectivity:connectivity-service": data}
        else:
            status = 404  # not found
            headers = {}
            data = {"error": "Not found"}

        self.send_response(status)
        for header_name, header_value in headers.items():
            self.send_header(header_name, header_value)
        self.end_headers()
        data = json.dumps(data)
        self.wfile.write(data.encode("UTF-8"))

    def do_POST(self):  # pylint: disable=invalid-name
        """Handle POST requests"""
        path = self.path.replace("tapi-common:", "").replace("tapi-connectivity:", "")
        length = int(self.headers["content-length"])
        data = json.loads(self.rfile.read(length))

        if path == "/restconf/data/context/connectivity-context":
            if "tapi-connectivity:connectivity-service" in data:
                data["connectivity-service"] = data.pop(
                    "tapi-connectivity:connectivity-service"
                )

            if (
                isinstance(data["connectivity-service"], list)
                and len(data["connectivity-service"]) > 0
            ):
                data["connectivity-service"] = data["connectivity-service"][0]

            conn_svc = data["connectivity-service"]
            if "connectivity-constraint" in conn_svc:
                conn_constr = conn_svc.pop("connectivity-constraint")
                if "requested-capacity" in conn_constr:
                    req_cap = conn_constr.pop("requested-capacity")
                    conn_svc["requested-capacity"] = req_cap
                if "connectivity-direction" in conn_constr:
                    conn_dir = conn_constr.pop("connectivity-direction")
                    conn_svc["connectivity-direction"] = conn_dir

            connection = {"uuid": conn_svc["uuid"], "connection-end-point": []}
            conn_svc["connection"] = [{"connection_uuid": conn_svc["uuid"]}]

            CONTEXT["connectivity-context"]["connection"].append(connection)
            CONTEXT["connectivity-context"]["connectivity-service"].append(conn_svc)

            status = 201  # created
            headers = {}
        elif path == "/restconf/operations/delete-connectivity-service":
            if "tapi-connectivity:input" in data:
                data["input"] = data.pop("tapi-connectivity:input")
            conn_svc_uuid = data["input"]["uuid"]
            conn_ctx = CONTEXT["connectivity-context"]

            # keep connectivity services and connections with different uuid
            conn_ctx["connection"] = [
                conn for conn in conn_ctx["connection"] if conn["uuid"] != conn_svc_uuid
            ]
            conn_ctx["connectivity-service"] = [
                conn_svc
                for conn_svc in conn_ctx["connectivity-service"]
                if conn_svc["uuid"] != conn_svc_uuid
            ]

            status = 204  # ok, no content
            headers = {}
        else:
            status = 404  # not found
            headers = {}

        self.send_response(status)
        for header_name, header_value in headers.items():
            self.send_header(header_name, header_value)
        self.end_headers()
