# -*- coding: utf-8 -*-
# Copyright 2025 Indra
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
"""
Utility class to deal with NSX in vcenter
"""
import logging
import os

from osm_ro_plugin import vimconn
import requests
from requests.auth import HTTPBasicAuth


class NsxClient:
    """
    Class that handles interactions with vcenter NSX
    """

    NSX_POLICY_V1_API_PREFIX = "/policy/api/v1"

    def __init__(
        self, nsx_manager_url, user, password, verify_ssl=False, log_level=None
    ):
        self.nsx_manager_url = nsx_manager_url
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl

        self.logger = logging.getLogger("ro.vim.vcenter.vms")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

        self.logger.info("verify_ssl: %s", self.verify_ssl)
        if not self.verify_ssl:
            self.logger.info("Insecure access to nsx is configured")

    def get_nsx_segment_dhcp_config(self, segment_path):
        """
        Obtain nsx subnet config from segment path
        """
        self.logger.debug("Obtain nsx segment dhcp configuration: %s", segment_path)
        url = f"{self.nsx_manager_url}{self.NSX_POLICY_V1_API_PREFIX}{segment_path}"
        response_json = self._process_http_get_request(url)
        subnets = response_json.get("subnets")
        self.logger.debug("Subnets recovered: %s", subnets)
        return subnets

    def _process_http_get_request(self, get_request_url):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        auth = self._get_auth()
        if isinstance(auth, dict):  # Token-based or API-key authentication
            headers.update(auth)

        response = requests.get(
            get_request_url,
            headers=headers,
            auth=auth if not isinstance(auth, dict) else None,
            verify=self.verify_ssl,
        )
        try:
            if not response.ok:
                raise vimconn.VimConnException(
                    f"Error nsx get request, text: {response.text}",
                    http_code=response.status_code,
                )
            else:
                return response.json()
        except requests.RequestException as e:
            self.logger.error(f"Error nsx get request, url: {get_request_url}", e)
            raise vimconn.VimConnException(
                f"Error nsx get request, url: {get_request_url}, error: {str(e)}"
            )

    def _get_auth(self):
        # Obtain authentication, by the moment it will be basic authentication,
        # it could be modified to support other authentication methods
        return HTTPBasicAuth(self.user, self.password)


if __name__ == "__main__":
    # Init logger
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    logging.basicConfig(
        level=logging.DEBUG,  # Set the logging level
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # Set the log message format
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[
            logging.StreamHandler(),  # Log to the console
        ],
    )
    logger = logging.getLogger("ro.vim.vmware.test_nsx")
    logger.setLevel(level=logging.DEBUG)

    test_nsx_url = os.getenv("NSX_URL")
    test_nsx_user = os.getenv("NSX_USER")
    test_nsx_password = os.getenv("NSX_PASSWORD")
    if os.getenv("NSX_CACERT"):
        test_verify_ssl = os.getenv("NSX_CACERT")
    else:
        test_verify_ssl = False

    logger.debug("Create nsx client")
    nsx_client = NsxClient(
        test_nsx_url,
        test_nsx_user,
        test_nsx_password,
        verify_ssl=test_verify_ssl,
        log_level="DEBUG",
    )
    test_segment_path = "/infra/segments/b5a27856-e7ef-49ab-a09e-e4d3416db3d2"
    nsx_client.get_nsx_segment_dhcp_config(test_segment_path)
