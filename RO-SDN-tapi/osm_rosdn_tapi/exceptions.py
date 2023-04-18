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

"""This file contains the exception classes the Transport API (TAPI) WIM connector
can raise in case of error."""


from http import HTTPStatus

from osm_ro_plugin.sdnconn import SdnConnectorError

from .log_messages import (
    _PREFIX,
)


class WimTapiError(SdnConnectorError):
    """Base Exception for all WIM TAPI related errors."""

    def __init__(self, message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR.value):
        super().__init__(_PREFIX + message)
        self.http_code = http_code


class WimTapiConnectionPointsBadFormat(SdnConnectorError):
    def __init__(self, connection_points):
        MESSAGE = "ConnectionPoints({:s}) must be a list or tuple of length 2"
        message = MESSAGE.format(str(connection_points))
        super().__init__(message, http_code=HTTPStatus.BAD_REQUEST)


class WimTapiIncongruentDirectionality(WimTapiError):
    def __init__(self, services, service_endpoint_id):
        MESSAGE = "Incongruent directionality: services={:s} service_endpoint_id={:s}"
        message = MESSAGE.format(str(services), str(service_endpoint_id))
        super().__init__(message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR)


class WimTapiIncongruentEndPoints(WimTapiError):
    def __init__(self, services, service_endpoint_id):
        MESSAGE = "Incongruent endpoints: services={:s} service_endpoint_id={:s}"
        message = MESSAGE.format(str(services), str(service_endpoint_id))
        super().__init__(message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR)


class WimTapiMissingConnPointField(WimTapiError):
    def __init__(self, connection_point, field_name):
        MESSAGE = "ConnectionPoint({:s}) has no field '{:s}'"
        message = MESSAGE.format(str(connection_point), str(field_name))
        super().__init__(message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR)


class WimTapiMissingMappingField(WimTapiError):
    def __init__(self, mapping, field_name):
        MESSAGE = "Mapping({:s}) has no field '{:s}'"
        message = MESSAGE.format(str(mapping), str(field_name))
        super().__init__(message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR)


class WimTapiServerNotAvailable(WimTapiError):
    def __init__(self, message):
        message = "Server not available: " + message
        super().__init__(message, http_code=HTTPStatus.SERVICE_UNAVAILABLE)


class WimTapiServerRequestFailed(WimTapiError):
    def __init__(self, message, http_code):
        message = "Server request failed: " + message
        super().__init__(message, http_code=http_code)


class WimTapiSipNotFound(WimTapiError):
    def __init__(self, sip_id, sips):
        MESSAGE = "SIP({:s}) not found in context SIPs({:s})"
        message = MESSAGE.format(str(sip_id), str(sips))
        super().__init__(message, http_code=HTTPStatus.INTERNAL_SERVER_ERROR)


class WimTapiConnectivityServiceCreateFailed(WimTapiError):
    def __init__(self, name, service_id, status_code, reply):
        MESSAGE = "Create ConnectivityService({:s}, {:s}) Failed: reply={:s}"
        message = MESSAGE.format(str(name), str(service_id), str(reply))
        super().__init__(message, http_code=status_code)


class WimTapiConnectivityServiceGetStatusFailed(WimTapiError):
    def __init__(self, name, service_id, status_code, reply):
        MESSAGE = "Get Status of ConnectivityService({:s}, {:s}) Failed: reply={:s}"
        message = MESSAGE.format(str(name), str(service_id), str(reply))
        super().__init__(message, http_code=status_code)


class WimTapiConnectivityServiceDeleteFailed(WimTapiError):
    def __init__(self, name, service_id, status_code, reply):
        MESSAGE = "Delete ConnectivityService({:s}, {:s}) Failed: reply={:s}"
        message = MESSAGE.format(str(name), str(service_id), str(reply))
        super().__init__(message, http_code=status_code)


class WimTapiUnsupportedServiceType(SdnConnectorError):
    def __init__(self, service_type, supported_service_types):
        MESSAGE = "Unsupported ServiceType({:s}). Supported ServiceTypes({:s})"
        message = MESSAGE.format(str(service_type), str(supported_service_types))
        super().__init__(message, http_code=HTTPStatus.BAD_REQUEST)
