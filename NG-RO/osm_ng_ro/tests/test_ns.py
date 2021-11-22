#######################################################################################
# Copyright ETSI Contributors and Others.
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
#######################################################################################

import unittest
from unittest.mock import patch, Mock

from osm_ng_ro.ns import Ns


__author__ = "Eduardo Sousa"
__date__ = "$19-NOV-2021 00:00:00$"


class TestNs(unittest.TestCase):
    def setUp(self):
        pass

    def test__create_task_without_extra_dict(self):
        expected_result = {
            "target_id": "vim_openstack_1",
            "action_id": "123456",
            "nsr_id": "654321",
            "task_id": "123456:1",
            "status": "SCHEDULED",
            "action": "CREATE",
            "item": "test_item",
            "target_record": "test_target_record",
            "target_record_id": "test_target_record_id",
        }
        deployment_info = {
            "action_id": "123456",
            "nsr_id": "654321",
            "task_index": 1,
        }

        task = Ns._create_task(
            deployment_info=deployment_info,
            target_id="vim_openstack_1",
            item="test_item",
            action="CREATE",
            target_record="test_target_record",
            target_record_id="test_target_record_id",
        )

        self.assertEqual(deployment_info.get("task_index"), 2)
        self.assertDictEqual(task, expected_result)

    def test__create_task(self):
        expected_result = {
            "target_id": "vim_openstack_1",
            "action_id": "123456",
            "nsr_id": "654321",
            "task_id": "123456:1",
            "status": "SCHEDULED",
            "action": "CREATE",
            "item": "test_item",
            "target_record": "test_target_record",
            "target_record_id": "test_target_record_id",
            # values coming from extra_dict
            "params": "test_params",
            "find_params": "test_find_params",
            "depends_on": "test_depends_on",
        }
        deployment_info = {
            "action_id": "123456",
            "nsr_id": "654321",
            "task_index": 1,
        }

        task = Ns._create_task(
            deployment_info=deployment_info,
            target_id="vim_openstack_1",
            item="test_item",
            action="CREATE",
            target_record="test_target_record",
            target_record_id="test_target_record_id",
            extra_dict={
                "params": "test_params",
                "find_params": "test_find_params",
                "depends_on": "test_depends_on",
            },
        )

        self.assertEqual(deployment_info.get("task_index"), 2)
        self.assertDictEqual(task, expected_result)

    @patch("osm_ng_ro.ns.time")
    def test__create_ro_task(self, mock_time: Mock):
        now = 1637324838.994551
        mock_time.return_value = now
        task = {
            "target_id": "vim_openstack_1",
            "action_id": "123456",
            "nsr_id": "654321",
            "task_id": "123456:1",
            "status": "SCHEDULED",
            "action": "CREATE",
            "item": "test_item",
            "target_record": "test_target_record",
            "target_record_id": "test_target_record_id",
            # values coming from extra_dict
            "params": "test_params",
            "find_params": "test_find_params",
            "depends_on": "test_depends_on",
        }
        expected_result = {
            "_id": "123456:1",
            "locked_by": None,
            "locked_at": 0.0,
            "target_id": "vim_openstack_1",
            "vim_info": {
                "created": False,
                "created_items": None,
                "vim_id": None,
                "vim_name": None,
                "vim_status": None,
                "vim_details": None,
                "refresh_at": None,
            },
            "modified_at": now,
            "created_at": now,
            "to_check_at": now,
            "tasks": [task],
        }

        ro_task = Ns._create_ro_task(
            target_id="vim_openstack_1",
            task=task,
        )

        self.assertDictEqual(ro_task, expected_result)

    def test__process_image_params_with_empty_target_image(self):
        expected_result = {
            "find_params": {},
        }
        target_image = {}

        result = Ns._process_image_params(
            target_image=target_image,
            vim_info=None,
            target_record_id=None,
        )

        self.assertDictEqual(expected_result, result)

    def test__process_image_params_with_wrong_target_image(self):
        expected_result = {
            "find_params": {},
        }
        target_image = {
            "no_image": "to_see_here",
        }

        result = Ns._process_image_params(
            target_image=target_image,
            vim_info=None,
            target_record_id=None,
        )

        self.assertDictEqual(expected_result, result)

    def test__process_image_params_with_image(self):
        expected_result = {
            "find_params": {
                "filter_dict": {
                    "name": "cirros",
                },
            },
        }
        target_image = {
            "image": "cirros",
        }

        result = Ns._process_image_params(
            target_image=target_image,
            vim_info=None,
            target_record_id=None,
        )

        self.assertDictEqual(expected_result, result)

    def test__process_image_params_with_vim_image_id(self):
        expected_result = {
            "find_params": {
                "filter_dict": {
                    "id": "123456",
                },
            },
        }
        target_image = {
            "vim_image_id": "123456",
        }

        result = Ns._process_image_params(
            target_image=target_image,
            vim_info=None,
            target_record_id=None,
        )

        self.assertDictEqual(expected_result, result)

    def test__process_image_params_with_image_checksum(self):
        expected_result = {
            "find_params": {
                "filter_dict": {
                    "checksum": "e3fc50a88d0a364313df4b21ef20c29e",
                },
            },
        }
        target_image = {
            "image_checksum": "e3fc50a88d0a364313df4b21ef20c29e",
        }

        result = Ns._process_image_params(
            target_image=target_image,
            vim_info=None,
            target_record_id=None,
        )

        self.assertDictEqual(expected_result, result)

    def test__get_resource_allocation_params_with_empty_target_image(self):
        expected_result = {}
        quota_descriptor = {}

        result = Ns._get_resource_allocation_params(
            quota_descriptor=quota_descriptor,
        )

        self.assertDictEqual(expected_result, result)

    def test__get_resource_allocation_params_with_wrong_target_image(self):
        expected_result = {}
        quota_descriptor = {
            "no_quota": "present_here",
        }

        result = Ns._get_resource_allocation_params(
            quota_descriptor=quota_descriptor,
        )

        self.assertDictEqual(expected_result, result)

    def test__get_resource_allocation_params_with_limit(self):
        expected_result = {
            "limit": 10,
        }
        quota_descriptor = {
            "limit": "10",
        }

        result = Ns._get_resource_allocation_params(
            quota_descriptor=quota_descriptor,
        )

        self.assertDictEqual(expected_result, result)

    def test__get_resource_allocation_params_with_reserve(self):
        expected_result = {
            "reserve": 20,
        }
        quota_descriptor = {
            "reserve": "20",
        }

        result = Ns._get_resource_allocation_params(
            quota_descriptor=quota_descriptor,
        )

        self.assertDictEqual(expected_result, result)

    def test__get_resource_allocation_params_with_shares(self):
        expected_result = {
            "shares": 30,
        }
        quota_descriptor = {
            "shares": "30",
        }

        result = Ns._get_resource_allocation_params(
            quota_descriptor=quota_descriptor,
        )

        self.assertDictEqual(expected_result, result)

    def test__get_resource_allocation_params(self):
        expected_result = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }
        quota_descriptor = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }

        result = Ns._get_resource_allocation_params(
            quota_descriptor=quota_descriptor,
        )

        self.assertDictEqual(expected_result, result)
