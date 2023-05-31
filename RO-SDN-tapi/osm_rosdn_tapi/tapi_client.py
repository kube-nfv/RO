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

"""This file contains the TransportApiClient class used by the Transport API
(TAPI) WIM connector to interact with the underlying WIM."""

import requests

from .exceptions import (
    WimTapiConnectivityServiceCreateFailed,
    WimTapiConnectivityServiceDeleteFailed,
    WimTapiConnectivityServiceGetStatusFailed,
    WimTapiServerNotAvailable,
    WimTapiServerRequestFailed,
)
from .log_messages import (
    LOG_MSG_CREATE_REPLY,
    LOG_MSG_CREATE_REQUEST,
    LOG_MSG_DELETE_REPLY,
    LOG_MSG_DELETE_REQUEST,
    LOG_MSG_GET_STATUS_REPLY,
    LOG_MSG_GET_STATUS_REQUEST,
)
from .message_composers import (
    compose_create_request,
    compose_delete_request,
)

DEFAULT_TIMEOUT = 30

SUCCESS_HTTP_CODES = {
    requests.codes.ok,  # pylint: disable=no-member
    requests.codes.created,  # pylint: disable=no-member
    requests.codes.accepted,  # pylint: disable=no-member
    requests.codes.no_content,  # pylint: disable=no-member
}

RESTCONF_DATA_URL = "{:s}/restconf/data"
RESTCONF_OPER_URL = "{:s}/restconf/operations"

CONTEXT_URL = RESTCONF_DATA_URL + "/tapi-common:context"
CTX_SIPS_URL = CONTEXT_URL + "/service-interface-point"
CONN_CTX_URL = CONTEXT_URL + "/tapi-connectivity:connectivity-context"
CONN_SVC_URL = CONN_CTX_URL + "/connectivity-service"
DELETE_URL = RESTCONF_OPER_URL + "/tapi-connectivity:delete-connectivity-service"


class TransportApiClient:
    def __init__(self, logger, wim, wim_account, config) -> None:
        self.logger = logger
        self.wim_url = wim["wim_url"]

        user = wim_account.get("user")
        password = wim_account.get("password")
        self.auth = (
            None
            if user is None or user == "" or password is None or password == ""
            else (user, password)
        )

        self.headers = {"Content-Type": "application/json"}
        self.timeout = int(config.get("timeout", DEFAULT_TIMEOUT))

    def get_root_context(self):
        context_url = CONTEXT_URL.format(self.wim_url)

        try:
            response = requests.get(
                context_url, auth=self.auth, headers=self.headers, timeout=self.timeout
            )
            http_code = response.status_code
        except requests.exceptions.RequestException as e:
            raise WimTapiServerNotAvailable(str(e))

        if http_code != 200:
            raise WimTapiServerRequestFailed(
                "Unexpected status code", http_code=http_code
            )

        return response.json()

    def get_service_interface_points(self):
        get_sips_url = CTX_SIPS_URL.format(self.wim_url)

        try:
            response = requests.get(
                get_sips_url, auth=self.auth, headers=self.headers, timeout=self.timeout
            )
            http_code = response.status_code
        except requests.exceptions.RequestException as e:
            raise WimTapiServerNotAvailable(str(e))

        if http_code != 200:
            raise WimTapiServerRequestFailed(
                "Unexpected status code", http_code=http_code
            )

        response = response.json()
        response = response.get("tapi-common:service-interface-point", [])
        return {sip["uuid"]: sip for sip in response}

    def get_service_status(self, name, service_uuid):
        self.logger.debug(LOG_MSG_GET_STATUS_REQUEST.format(name, service_uuid))

        try:
            services_url = CONN_SVC_URL.format(self.wim_url)
            response = requests.get(
                services_url, auth=self.auth, headers=self.headers, timeout=self.timeout
            )
            self.logger.debug(
                LOG_MSG_GET_STATUS_REPLY.format(
                    name, service_uuid, response.status_code, response.text
                )
            )
        except requests.exceptions.ConnectionError as e:
            status_code = e.response.status_code if e.response is not None else 500
            content = e.response.text if e.response is not None else ""
            raise WimTapiConnectivityServiceGetStatusFailed(
                name, service_uuid, status_code, content
            )

        if response.status_code not in SUCCESS_HTTP_CODES:
            raise WimTapiConnectivityServiceGetStatusFailed(
                name, service_uuid, response.status_code, response.text
            )

        json_response = response.json()
        connectivity_services = json_response.get(
            "tapi-connectivity:connectivity-service", []
        )
        connectivity_service = next(
            iter(
                [
                    connectivity_service
                    for connectivity_service in connectivity_services
                    if connectivity_service.get("uuid") == service_uuid
                ]
            ),
            None,
        )

        if connectivity_service is None:
            service_status = {"sdn_status": "ERROR"}
        else:
            service_status = {"sdn_status": "ACTIVE"}
        return service_status

    def create_service(
        self,
        name,
        service_uuid,
        service_endpoints,
        bidirectional=False,
        requested_capacity=None,
        vlan_constraint=None,
    ):
        request_create = compose_create_request(
            service_uuid,
            service_endpoints,
            bidirectional=bidirectional,
            requested_capacity=requested_capacity,
            vlan_constraint=vlan_constraint,
        )
        self.logger.debug(
            LOG_MSG_CREATE_REQUEST.format(name, service_uuid, str(request_create))
        )

        try:
            create_url = CONN_CTX_URL.format(self.wim_url)
            response = requests.post(
                create_url, headers=self.headers, json=request_create, auth=self.auth
            )
            self.logger.debug(
                LOG_MSG_CREATE_REPLY.format(
                    name, service_uuid, response.status_code, response.text
                )
            )
        except requests.exceptions.ConnectionError as e:
            status_code = e.response.status_code if e.response is not None else 500
            content = e.response.text if e.response is not None else ""
            raise WimTapiConnectivityServiceCreateFailed(
                name, service_uuid, status_code, content
            )

        if response.status_code not in SUCCESS_HTTP_CODES:
            raise WimTapiConnectivityServiceCreateFailed(
                name, service_uuid, response.status_code, response.text
            )

    def delete_service(self, name, service_uuid):
        request_delete = compose_delete_request(service_uuid)
        self.logger.debug(
            LOG_MSG_DELETE_REQUEST.format(name, service_uuid, str(request_delete))
        )

        try:
            delete_url = DELETE_URL.format(self.wim_url)
            response = requests.post(
                delete_url, headers=self.headers, json=request_delete, auth=self.auth
            )
            self.logger.debug(
                LOG_MSG_DELETE_REPLY.format(
                    name, service_uuid, response.status_code, response.text
                )
            )
        except requests.exceptions.ConnectionError as e:
            status_code = e.response.status_code if e.response is not None else 500
            content = e.response.text if e.response is not None else ""
            raise WimTapiConnectivityServiceDeleteFailed(
                name, service_uuid, status_code, content
            )

        if response.status_code not in SUCCESS_HTTP_CODES:
            raise WimTapiConnectivityServiceDeleteFailed(
                name, service_uuid, response.status_code, response.text
            )
