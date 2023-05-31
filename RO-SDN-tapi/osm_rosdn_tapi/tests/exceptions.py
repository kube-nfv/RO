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

"""This file contains the exception classes the Mock OSM RO module can raise."""


_PREFIX = "Mock OSM RO: "


class MockOsmRoError(Exception):
    """Base Exception for all Mock OSM RO related errors."""

    def __init__(self, message):
        super().__init__(_PREFIX + message)


class MockOsmRoServiceNotFound(MockOsmRoError):
    def __init__(self, service_id):
        MESSAGE = "ServiceId({:s}) not found"
        message = MESSAGE.format(str(service_id))
        super().__init__(message)
