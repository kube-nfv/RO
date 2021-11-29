# -*- coding: utf-8 -*-

##
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
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact with: nfvlabs@tid.es
##

"""
This module contains unit tests for the OpenStack VIM connector
Run this directly with python2 or python3.
"""

import logging
import json

from osm_rovim_gcp.vimconn_gcp import vimconnector
from datetime import datetime


__author__ = "Sergio G.R."
__date__ = "$05-nov-2021 12:00:00$"


class TestGCPOperations:

    gcp_conn = None
    time_id = datetime.today().strftime("%Y%m%d%H%M%S")
    vim_id = "gcp-test-" + time_id
    vim_name = vim_id
    vm_name = "gcp-test-vm-" + time_id
    net_name = "gcp-test-net-" + time_id
    cloud_config = None
    config = {}
    credentials_file = None
    image_id = None
    image_connector_id = None
    flavor_id = None

    def setUp(
        self,
        project_name,
        region_name,
        credentials_file,
        image_id,
        image_connector_id,
        flavor_id,
    ):
        self.config["project_name"] = project_name
        self.config["region_name"] = region_name
        try:
            with open(credentials_file) as file:
                self.config["credentials"] = json.load(file)
        except ValueError:
            raise Exception(
                "Not possible to read credentials JSON file %s",
                self.config["credentials"],
            )
        self.image_id = image_id
        self.image_connector_id = image_connector_id
        self.flavor_id = flavor_id

        # instantiate dummy VIM connector so we can test it
        self.gcp_conn = vimconnector(
            uuid=self.vim_id,
            name=self.vim_name,
            tenant_id=project_name,
            tenant_name=project_name,
            url=None,
            url_admin=None,
            user=None,
            passwd=None,
            log_level=None,
            config=self.config,
        )

    def test_networks(self):
        net_id_1 = self.gcp_conn.new_network(
            self.net_name, None, {"subnet_address": "10.0.0.0/25"}
        )
        net_id_2 = self.gcp_conn.new_network(
            self.net_name, None, {"subnet_address": "10.9.0.0/25"}
        )
        _ = self.gcp_conn.delete_network(net_id_1[0])
        _ = self.gcp_conn.delete_network(net_id_2[0])

    def test_vminstances_default(self):
        vm_id_1 = self.gcp_conn.new_vminstance(
            name=self.vm_name,
            description="testvm",
            start=True,
            image_id=self.image_id,
            flavor_id=self.flavor_id,
            net_list=[{"name": "default", "use": "mgmt"}],
            cloud_config=self.cloud_config,
        )
        _ = self.gcp_conn.delete_vminstance(vm_id_1[0])

    def test_vminstances_2_nets(self):
        net_id_1 = self.gcp_conn.new_network(
            self.net_name, None, {"subnet_address": "10.0.0.0/25"}
        )
        net_id_2 = self.gcp_conn.new_network(
            self.net_name, None, {"subnet_address": "10.9.0.0/25"}
        )

        vm_id_1 = self.gcp_conn.new_vminstance(
            name=self.vm_name,
            description="testvm",
            start=True,
            image_id=self.image_id,
            flavor_id=self.flavor_id,
            net_list=[
                {"net_id": net_id_1[0], "use": "mgmt"},
                {"net_id": net_id_2[0], "use": "internal"},
            ],
            cloud_config=self.cloud_config,
        )
        _ = self.gcp_conn.delete_vminstance(vm_id_1[0])

        _ = self.gcp_conn.delete_network(net_id_1[0])
        _ = self.gcp_conn.delete_network(net_id_2[0])

    def test_vminstances_image_connector_id(self):
        image_id = self.gcp_conn.get_image_list({"name": self.image_connector_id})
        vm_id_1 = self.gcp_conn.new_vminstance(
            name=self.vm_name,
            description="testvm",
            start=True,
            image_id=image_id[0].get("id"),
            flavor_id=self.flavor_id,
            net_list=[{"name": "default", "use": "mgmt"}],
            cloud_config=self.cloud_config,
        )
        _ = self.gcp_conn.delete_vminstance(vm_id_1[0])

    def test_vminstances_flavor(self):
        machine_type = self.gcp_conn.get_flavor_id_from_data(
            {
                "disk": 10,
                "ram": 2048,
                "vcpus": 1,
                "extended": {
                    "mempage-size": "LARGE",
                    "numas": [
                        {
                            "threads": 1,
                        }
                    ],
                },
            }
        )
        vm_id_1 = self.gcp_conn.new_vminstance(
            name=self.vm_name,
            description="testvm",
            start=True,
            image_id=self.image_id,
            flavor_id=machine_type,
            net_list=[{"name": "default", "use": "mgmt"}],
            cloud_config=self.cloud_config,
        )
        _ = self.gcp_conn.delete_vminstance(vm_id_1[0])


if __name__ == "__main__":
    # Setting logging parameters:
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    log_formatter = logging.Formatter(log_format, datefmt="%Y-%m-%dT%H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(log_formatter)
    logger = logging.getLogger("ro.vim.gcp")
    logger.setLevel(level=logging.DEBUG)
    logger.addHandler(handler)

    # Setting relevant values for the tests from environment file
    gcp_env_file = "gcp.env"

    try:
        with open(gcp_env_file) as f:
            for line in f:
                var, value = line.replace("\n", "").split("=")
                if var == "GCP_PROJECT":
                    project_name = value
                elif var == "GCP_REGION":
                    region_name = value
                elif var == "GCP_CREDENTIALS":
                    credentials_file = value
                elif var == "GCP_IMAGE":
                    image_id = value
                elif var == "GCP_IMAGE_CONNECTOR_ID":
                    image_connector_id = value
                elif var == "GCP_FLAVOR":
                    flavor_id = value
    except ValueError:
        raise Exception("Wrong format of GCP test environment file")

    if (
        project_name is None
        or region_name is None
        or credentials_file is None
        or image_id is None
        or image_connector_id is None
        or flavor_id is None
    ):
        raise Exception(
            "GCP test environment file must include at least GCP_PROJECT, GCP_REGION, "
            "GCP_CREDENTIALS, GCP_IMAGE, GCP_IMAGE_PATTERN and GCP_FLAVOR"
        )

    test_gcp = TestGCPOperations()
    test_gcp.setUp(
        project_name,
        region_name,
        credentials_file,
        image_id,
        image_connector_id,
        flavor_id,
    )
    test_gcp.test_networks()
    test_gcp.test_vminstances_default()
    test_gcp.test_vminstances_2_nets()
    test_gcp.test_vminstances_connector_id()
    test_gcp.test_vminstances_flavor()
