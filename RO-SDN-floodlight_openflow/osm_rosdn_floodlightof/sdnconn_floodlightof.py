##
# Copyright 2019 Telefonica Investigacion y Desarrollo, S.A.U.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
##
"""The SdnConnectorFloodLightOf connector is responsible for creating services using pro active operflow rules.
"""

import logging

from osm_ro_plugin.openflow_conn import SdnConnectorOpenFlow

from .floodlight_of import OfConnFloodLight


class SdnConnectorFloodLightOf(SdnConnectorOpenFlow):
    def __init__(self, wim, wim_account, config=None, logger=None):
        """Creates a connectivity based on pro-active openflow rules"""
        self.logger = logging.getLogger("ro.sdn.floodlightof")
        super().__init__(wim, wim_account, config, logger)
        of_params = {
            "of_url": wim["wim_url"],
            "of_dpid": config.get("dpid") or config.get("switch_id"),
            "of_user": wim_account["user"],
            "of_password": wim_account["password"],
        }
        self.openflow_conn = OfConnFloodLight(of_params)
        super().__init__(wim, wim_account, config, logger, self.openflow_conn)
