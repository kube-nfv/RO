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
from unittest.mock import MagicMock, Mock, patch

from jinja2 import TemplateError, TemplateNotFound, UndefinedError
from osm_ng_ro.ns import Ns, NsException


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
            indata=None,
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
            indata=None,
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
            indata=None,
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
            indata=None,
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
            indata=None,
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

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_empty_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {}
        guest_epa_quota = {}
        epa_vcpu_set = True

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(resource_allocation.called)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_empty_quota_false_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {}
        guest_epa_quota = {}
        epa_vcpu_set = False

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(resource_allocation.called)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_wrong_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {}
        guest_epa_quota = {
            "no-quota": "nothing",
        }
        epa_vcpu_set = True

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(resource_allocation.called)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_wrong_quota_false_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {}
        guest_epa_quota = {
            "no-quota": "nothing",
        }
        epa_vcpu_set = False

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(resource_allocation.called)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_cpu_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {}
        guest_epa_quota = {
            "cpu-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = True

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(resource_allocation.called)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_cpu_quota_false_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "cpu-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "cpu-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = False

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_mem_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "mem-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "mem-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = True

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_mem_quota_false_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "mem-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "mem-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = False

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_disk_io_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "disk-io-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "disk-io-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = True

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_disk_io_quota_false_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "disk-io-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "disk-io-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = False

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_vif_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "vif-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "vif-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = True

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_vif_quota_false_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "vif-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "vif-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = False

        resource_allocation_param = {
            "limit": "10",
            "reserve": "20",
            "shares": "30",
        }
        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        resource_allocation.assert_called_once_with(resource_allocation_param)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_quota_epa_cpu(
        self,
        resource_allocation,
    ):
        expected_result = {
            "mem-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "disk-io-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "vif-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "cpu-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
            "mem-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
            "disk-io-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
            "vif-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = True

        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertTrue(resource_allocation.called)
        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._get_resource_allocation_params")
    def test__process_guest_epa_quota_params_with_quota_epa_cpu_no_set(
        self,
        resource_allocation,
    ):
        expected_result = {
            "cpu-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "mem-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "disk-io-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "vif-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }
        guest_epa_quota = {
            "cpu-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
            "mem-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
            "disk-io-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
            "vif-quota": {
                "limit": "10",
                "reserve": "20",
                "shares": "30",
            },
        }
        epa_vcpu_set = False

        resource_allocation.return_value = {
            "limit": 10,
            "reserve": 20,
            "shares": 30,
        }

        result = Ns._process_guest_epa_quota_params(
            guest_epa_quota=guest_epa_quota,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertTrue(resource_allocation.called)
        self.assertDictEqual(expected_result, result)

    def test__process_guest_epa_numa_params_with_empty_numa_params(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {}

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_wrong_numa_params(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {"no_nume": "here"}

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_numa_node_policy(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {"numa-node-policy": {}}

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_no_node(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_1_node_num_cores(self):
        expected_numa_result = {"cores": 3}
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "num-cores": 3,
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_1_node_paired_threads(self):
        expected_numa_result = {"paired-threads": 3}
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "paired-threads": {"num-paired-threads": "3"},
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_1_node_paired_threads_ids(self):
        expected_numa_result = {
            "paired-threads-id": [("0", "1"), ("4", "5")],
        }
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "paired-threads": {
                            "paired-thread-ids": [
                                {
                                    "thread-a": 0,
                                    "thread-b": 1,
                                },
                                {
                                    "thread-a": 4,
                                    "thread-b": 5,
                                },
                            ],
                        },
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_1_node_num_threads(self):
        expected_numa_result = {"threads": 3}
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "num-threads": "3",
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_1_node_memory_mb(self):
        expected_numa_result = {"memory": 2}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "memory-mb": 2048,
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_1_node(self):
        expected_numa_result = {
            "cores": 3,
            "paired-threads": 3,
            "paired-threads-id": [("0", "1"), ("4", "5")],
            "threads": 3,
            "memory": 2,
        }
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "num-cores": 3,
                        "paired-threads": {
                            "num-paired-threads": "3",
                            "paired-thread-ids": [
                                {
                                    "thread-a": 0,
                                    "thread-b": 1,
                                },
                                {
                                    "thread-a": 4,
                                    "thread-b": 5,
                                },
                            ],
                        },
                        "num-threads": "3",
                        "memory-mb": 2048,
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_numa_params_with_2_nodes(self):
        expected_numa_result = {
            "cores": 3,
            "paired-threads": 3,
            "paired-threads-id": [("0", "1"), ("4", "5")],
            "threads": 3,
            "memory": 2,
        }
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "numa-node-policy": {
                "node": [
                    {
                        "num-cores": 3,
                        "paired-threads": {
                            "num-paired-threads": "3",
                            "paired-thread-ids": [
                                {
                                    "thread-a": 0,
                                    "thread-b": 1,
                                },
                                {
                                    "thread-a": 4,
                                    "thread-b": 5,
                                },
                            ],
                        },
                        "num-threads": "3",
                        "memory-mb": 2048,
                    },
                    {
                        "num-cores": 7,
                        "paired-threads": {
                            "num-paired-threads": "7",
                            "paired-thread-ids": [
                                {
                                    "thread-a": 2,
                                    "thread-b": 3,
                                },
                                {
                                    "thread-a": 5,
                                    "thread-b": 6,
                                },
                            ],
                        },
                        "num-threads": "4",
                        "memory-mb": 4096,
                    },
                ],
            },
        }

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_numa_params(
            guest_epa_quota=guest_epa_quota,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_cpu_pinning_params_with_empty_params(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {}
        vcpu_count = 0
        epa_vcpu_set = False

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_cpu_pinning_params(
            guest_epa_quota=guest_epa_quota,
            vcpu_count=vcpu_count,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_cpu_pinning_params_with_wrong_params(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = False
        guest_epa_quota = {
            "no-cpu-pinning-policy": "here",
        }
        vcpu_count = 0
        epa_vcpu_set = False

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_cpu_pinning_params(
            guest_epa_quota=guest_epa_quota,
            vcpu_count=vcpu_count,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_cpu_pinning_params_with_epa_vcpu_set(self):
        expected_numa_result = {}
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "cpu-pinning-policy": "DEDICATED",
        }
        vcpu_count = 0
        epa_vcpu_set = True

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_cpu_pinning_params(
            guest_epa_quota=guest_epa_quota,
            vcpu_count=vcpu_count,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_cpu_pinning_params_with_threads(self):
        expected_numa_result = {"threads": 3}
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "cpu-pinning-policy": "DEDICATED",
            "cpu-thread-pinning-policy": "PREFER",
        }
        vcpu_count = 3
        epa_vcpu_set = False

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_cpu_pinning_params(
            guest_epa_quota=guest_epa_quota,
            vcpu_count=vcpu_count,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    def test__process_guest_epa_cpu_pinning_params(self):
        expected_numa_result = {"cores": 3}
        expected_epa_vcpu_set_result = True
        guest_epa_quota = {
            "cpu-pinning-policy": "DEDICATED",
        }
        vcpu_count = 3
        epa_vcpu_set = False

        numa_result, epa_vcpu_set_result = Ns._process_guest_epa_cpu_pinning_params(
            guest_epa_quota=guest_epa_quota,
            vcpu_count=vcpu_count,
            epa_vcpu_set=epa_vcpu_set,
        )

        self.assertDictEqual(expected_numa_result, numa_result)
        self.assertEqual(expected_epa_vcpu_set_result, epa_vcpu_set_result)

    @patch("osm_ng_ro.ns.Ns._process_guest_epa_quota_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_cpu_pinning_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_numa_params")
    def test__process_guest_epa_params_with_empty_params(
        self,
        guest_epa_numa_params,
        guest_epa_cpu_pinning_params,
        guest_epa_quota_params,
    ):
        expected_result = {}
        target_flavor = {}

        result = Ns._process_epa_params(
            target_flavor=target_flavor,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(guest_epa_numa_params.called)
        self.assertFalse(guest_epa_cpu_pinning_params.called)
        self.assertFalse(guest_epa_quota_params.called)

    @patch("osm_ng_ro.ns.Ns._process_guest_epa_quota_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_cpu_pinning_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_numa_params")
    def test__process_guest_epa_params_with_wrong_params(
        self,
        guest_epa_numa_params,
        guest_epa_cpu_pinning_params,
        guest_epa_quota_params,
    ):
        expected_result = {}
        target_flavor = {
            "no-guest-epa": "here",
        }

        result = Ns._process_epa_params(
            target_flavor=target_flavor,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(guest_epa_numa_params.called)
        self.assertFalse(guest_epa_cpu_pinning_params.called)
        self.assertFalse(guest_epa_quota_params.called)

    @patch("osm_ng_ro.ns.Ns._process_guest_epa_quota_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_cpu_pinning_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_numa_params")
    def test__process_guest_epa_params(
        self,
        guest_epa_numa_params,
        guest_epa_cpu_pinning_params,
        guest_epa_quota_params,
    ):
        expected_result = {}
        target_flavor = {
            "guest-epa": {
                "vcpu-count": 1,
            },
        }

        guest_epa_numa_params.return_value = ({}, False)
        guest_epa_cpu_pinning_params.return_value = ({}, False)
        guest_epa_quota_params.return_value = {}

        result = Ns._process_epa_params(
            target_flavor=target_flavor,
        )

        self.assertDictEqual(expected_result, result)
        self.assertTrue(guest_epa_numa_params.called)
        self.assertTrue(guest_epa_cpu_pinning_params.called)
        self.assertTrue(guest_epa_quota_params.called)

    @patch("osm_ng_ro.ns.Ns._process_guest_epa_quota_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_cpu_pinning_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_numa_params")
    def test__process_guest_epa_params_with_mempage_size(
        self,
        guest_epa_numa_params,
        guest_epa_cpu_pinning_params,
        guest_epa_quota_params,
    ):
        expected_result = {
            "mempage-size": "1G",
        }
        target_flavor = {
            "guest-epa": {"vcpu-count": 1, "mempage-size": "1G"},
        }

        guest_epa_numa_params.return_value = ({}, False)
        guest_epa_cpu_pinning_params.return_value = ({}, False)
        guest_epa_quota_params.return_value = {}

        result = Ns._process_epa_params(
            target_flavor=target_flavor,
        )

        self.assertDictEqual(expected_result, result)
        self.assertTrue(guest_epa_numa_params.called)
        self.assertTrue(guest_epa_cpu_pinning_params.called)
        self.assertTrue(guest_epa_quota_params.called)

    @patch("osm_ng_ro.ns.Ns._process_guest_epa_quota_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_cpu_pinning_params")
    @patch("osm_ng_ro.ns.Ns._process_guest_epa_numa_params")
    def test__process_guest_epa_params_with_numa(
        self,
        guest_epa_numa_params,
        guest_epa_cpu_pinning_params,
        guest_epa_quota_params,
    ):
        expected_result = {
            "mempage-size": "1G",
            "numas": [
                {
                    "cores": 3,
                    "memory": 2,
                    "paired-threads": 3,
                    "paired-threads-id": [("0", "1"), ("4", "5")],
                    "threads": 3,
                }
            ],
            "cpu-quota": {"limit": 10, "reserve": 20, "shares": 30},
            "disk-io-quota": {"limit": 10, "reserve": 20, "shares": 30},
            "mem-quota": {"limit": 10, "reserve": 20, "shares": 30},
            "vif-quota": {"limit": 10, "reserve": 20, "shares": 30},
        }
        target_flavor = {
            "guest-epa": {
                "vcpu-count": 1,
                "mempage-size": "1G",
                "cpu-pinning-policy": "DEDICATED",
                "cpu-thread-pinning-policy": "PREFER",
                "numa-node-policy": {
                    "node": [
                        {
                            "num-cores": 3,
                            "paired-threads": {
                                "num-paired-threads": "3",
                                "paired-thread-ids": [
                                    {
                                        "thread-a": 0,
                                        "thread-b": 1,
                                    },
                                    {
                                        "thread-a": 4,
                                        "thread-b": 5,
                                    },
                                ],
                            },
                            "num-threads": "3",
                            "memory-mb": 2048,
                        },
                    ],
                },
                "cpu-quota": {
                    "limit": "10",
                    "reserve": "20",
                    "shares": "30",
                },
                "mem-quota": {
                    "limit": "10",
                    "reserve": "20",
                    "shares": "30",
                },
                "disk-io-quota": {
                    "limit": "10",
                    "reserve": "20",
                    "shares": "30",
                },
                "vif-quota": {
                    "limit": "10",
                    "reserve": "20",
                    "shares": "30",
                },
            },
        }

        guest_epa_numa_params.return_value = (
            {
                "cores": 3,
                "paired-threads": 3,
                "paired-threads-id": [("0", "1"), ("4", "5")],
                "threads": 3,
                "memory": 2,
            },
            True,
        )
        guest_epa_cpu_pinning_params.return_value = (
            {
                "threads": 3,
            },
            True,
        )
        guest_epa_quota_params.return_value = {
            "cpu-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "mem-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "disk-io-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
            "vif-quota": {
                "limit": 10,
                "reserve": 20,
                "shares": 30,
            },
        }

        result = Ns._process_epa_params(
            target_flavor=target_flavor,
        )

        self.assertDictEqual(expected_result, result)
        self.assertTrue(guest_epa_numa_params.called)
        self.assertTrue(guest_epa_cpu_pinning_params.called)
        self.assertTrue(guest_epa_quota_params.called)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_empty_target_flavor(
        self,
        epa_params,
    ):
        target_flavor = {}
        indata = {}
        vim_info = {}
        target_record_id = ""

        with self.assertRaises(KeyError):
            Ns._process_flavor_params(
                target_flavor=target_flavor,
                indata=indata,
                vim_info=vim_info,
                target_record_id=target_record_id,
            )

        self.assertFalse(epa_params.called)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_wrong_target_flavor(
        self,
        epa_params,
    ):
        target_flavor = {
            "no-target-flavor": "here",
        }
        indata = {}
        vim_info = {}
        target_record_id = ""

        with self.assertRaises(KeyError):
            Ns._process_flavor_params(
                target_flavor=target_flavor,
                indata=indata,
                vim_info=vim_info,
                target_record_id=target_record_id,
            )

        self.assertFalse(epa_params.called)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_empty_indata(
        self,
        epa_params,
    ):
        expected_result = {
            "find_params": {
                "flavor_data": {
                    "disk": 10,
                    "ram": 1024,
                    "vcpus": 2,
                },
            },
            "params": {
                "flavor_data": {
                    "disk": 10,
                    "name": "test",
                    "ram": 1024,
                    "vcpus": 2,
                },
            },
        }
        target_flavor = {
            "name": "test",
            "storage-gb": "10",
            "memory-mb": "1024",
            "vcpu-count": "2",
        }
        indata = {}
        vim_info = {}
        target_record_id = ""

        epa_params.return_value = {}

        result = Ns._process_flavor_params(
            target_flavor=target_flavor,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertTrue(epa_params.called)
        self.assertDictEqual(result, expected_result)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_wrong_indata(
        self,
        epa_params,
    ):
        expected_result = {
            "find_params": {
                "flavor_data": {
                    "disk": 10,
                    "ram": 1024,
                    "vcpus": 2,
                },
            },
            "params": {
                "flavor_data": {
                    "disk": 10,
                    "name": "test",
                    "ram": 1024,
                    "vcpus": 2,
                },
            },
        }
        target_flavor = {
            "name": "test",
            "storage-gb": "10",
            "memory-mb": "1024",
            "vcpu-count": "2",
        }
        indata = {
            "no-vnf": "here",
        }
        vim_info = {}
        target_record_id = ""

        epa_params.return_value = {}

        result = Ns._process_flavor_params(
            target_flavor=target_flavor,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertTrue(epa_params.called)
        self.assertDictEqual(result, expected_result)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_ephemeral_disk(
        self,
        epa_params,
    ):
        expected_result = {
            "find_params": {
                "flavor_data": {
                    "disk": 10,
                    "ram": 1024,
                    "vcpus": 2,
                    "ephemeral": 10,
                },
            },
            "params": {
                "flavor_data": {
                    "disk": 10,
                    "name": "test",
                    "ram": 1024,
                    "vcpus": 2,
                    "ephemeral": 10,
                },
            },
        }
        target_flavor = {
            "id": "test_id",
            "name": "test",
            "storage-gb": "10",
            "memory-mb": "1024",
            "vcpu-count": "2",
        }
        indata = {
            "vnf": [
                {
                    "vdur": [
                        {
                            "ns-flavor-id": "test_id",
                            "virtual-storages": [
                                {
                                    "type-of-storage": "etsi-nfv-descriptors:ephemeral-storage",
                                    "size-of-storage": "10",
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        vim_info = {}
        target_record_id = ""

        epa_params.return_value = {}

        result = Ns._process_flavor_params(
            target_flavor=target_flavor,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertTrue(epa_params.called)
        self.assertDictEqual(result, expected_result)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_swap_disk(
        self,
        epa_params,
    ):
        expected_result = {
            "find_params": {
                "flavor_data": {
                    "disk": 10,
                    "ram": 1024,
                    "vcpus": 2,
                    "swap": 20,
                },
            },
            "params": {
                "flavor_data": {
                    "disk": 10,
                    "name": "test",
                    "ram": 1024,
                    "vcpus": 2,
                    "swap": 20,
                },
            },
        }
        target_flavor = {
            "id": "test_id",
            "name": "test",
            "storage-gb": "10",
            "memory-mb": "1024",
            "vcpu-count": "2",
        }
        indata = {
            "vnf": [
                {
                    "vdur": [
                        {
                            "ns-flavor-id": "test_id",
                            "virtual-storages": [
                                {
                                    "type-of-storage": "etsi-nfv-descriptors:swap-storage",
                                    "size-of-storage": "20",
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        vim_info = {}
        target_record_id = ""

        epa_params.return_value = {}

        result = Ns._process_flavor_params(
            target_flavor=target_flavor,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertTrue(epa_params.called)
        self.assertDictEqual(result, expected_result)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params_with_epa_params(
        self,
        epa_params,
    ):
        expected_result = {
            "find_params": {
                "flavor_data": {
                    "disk": 10,
                    "ram": 1024,
                    "vcpus": 2,
                    "extended": {
                        "numa": "there-is-numa-here",
                    },
                },
            },
            "params": {
                "flavor_data": {
                    "disk": 10,
                    "name": "test",
                    "ram": 1024,
                    "vcpus": 2,
                    "extended": {
                        "numa": "there-is-numa-here",
                    },
                },
            },
        }
        target_flavor = {
            "id": "test_id",
            "name": "test",
            "storage-gb": "10",
            "memory-mb": "1024",
            "vcpu-count": "2",
        }
        indata = {}
        vim_info = {}
        target_record_id = ""

        epa_params.return_value = {
            "numa": "there-is-numa-here",
        }

        result = Ns._process_flavor_params(
            target_flavor=target_flavor,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertTrue(epa_params.called)
        self.assertDictEqual(result, expected_result)

    @patch("osm_ng_ro.ns.Ns._process_epa_params")
    def test__process_flavor_params(
        self,
        epa_params,
    ):
        expected_result = {
            "find_params": {
                "flavor_data": {
                    "disk": 10,
                    "ram": 1024,
                    "vcpus": 2,
                    "ephemeral": 10,
                    "swap": 20,
                    "extended": {
                        "numa": "there-is-numa-here",
                    },
                },
            },
            "params": {
                "flavor_data": {
                    "disk": 10,
                    "name": "test",
                    "ram": 1024,
                    "vcpus": 2,
                    "ephemeral": 10,
                    "swap": 20,
                    "extended": {
                        "numa": "there-is-numa-here",
                    },
                },
            },
        }
        target_flavor = {
            "id": "test_id",
            "name": "test",
            "storage-gb": "10",
            "memory-mb": "1024",
            "vcpu-count": "2",
        }
        indata = {
            "vnf": [
                {
                    "vdur": [
                        {
                            "ns-flavor-id": "test_id",
                            "virtual-storages": [
                                {
                                    "type-of-storage": "etsi-nfv-descriptors:ephemeral-storage",
                                    "size-of-storage": "10",
                                },
                                {
                                    "type-of-storage": "etsi-nfv-descriptors:swap-storage",
                                    "size-of-storage": "20",
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        vim_info = {}
        target_record_id = ""

        epa_params.return_value = {
            "numa": "there-is-numa-here",
        }

        result = Ns._process_flavor_params(
            target_flavor=target_flavor,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertTrue(epa_params.called)
        self.assertDictEqual(result, expected_result)

    def test__ip_profile_to_ro_with_none(self):
        ip_profile = None

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertIsNone(result)

    def test__ip_profile_to_ro_with_empty_profile(self):
        ip_profile = {}

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertIsNone(result)

    def test__ip_profile_to_ro_with_wrong_profile(self):
        ip_profile = {
            "no-profile": "here",
        }
        expected_result = {
            "ip_version": "IPv4",
            "subnet_address": None,
            "gateway_address": None,
            "dhcp_enabled": False,
            "dhcp_start_address": None,
            "dhcp_count": None,
        }

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertDictEqual(expected_result, result)

    def test__ip_profile_to_ro_with_ipv4_profile(self):
        ip_profile = {
            "ip-version": "ipv4",
            "subnet-address": "192.168.0.0/24",
            "gateway-address": "192.168.0.254",
            "dhcp-params": {
                "enabled": True,
                "start-address": "192.168.0.10",
                "count": 25,
            },
        }
        expected_result = {
            "ip_version": "IPv4",
            "subnet_address": "192.168.0.0/24",
            "gateway_address": "192.168.0.254",
            "dhcp_enabled": True,
            "dhcp_start_address": "192.168.0.10",
            "dhcp_count": 25,
        }

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertDictEqual(expected_result, result)

    def test__ip_profile_to_ro_with_ipv6_profile(self):
        ip_profile = {
            "ip-version": "ipv6",
            "subnet-address": "2001:0200:0001::/48",
            "gateway-address": "2001:0200:0001:ffff:ffff:ffff:ffff:fffe",
            "dhcp-params": {
                "enabled": True,
                "start-address": "2001:0200:0001::0010",
                "count": 25,
            },
        }
        expected_result = {
            "ip_version": "IPv6",
            "subnet_address": "2001:0200:0001::/48",
            "gateway_address": "2001:0200:0001:ffff:ffff:ffff:ffff:fffe",
            "dhcp_enabled": True,
            "dhcp_start_address": "2001:0200:0001::0010",
            "dhcp_count": 25,
        }

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertDictEqual(expected_result, result)

    def test__ip_profile_to_ro_with_dns_server(self):
        ip_profile = {
            "ip-version": "ipv4",
            "subnet-address": "192.168.0.0/24",
            "gateway-address": "192.168.0.254",
            "dhcp-params": {
                "enabled": True,
                "start-address": "192.168.0.10",
                "count": 25,
            },
            "dns-server": [
                {
                    "address": "8.8.8.8",
                },
                {
                    "address": "1.1.1.1",
                },
                {
                    "address": "1.0.0.1",
                },
            ],
        }
        expected_result = {
            "ip_version": "IPv4",
            "subnet_address": "192.168.0.0/24",
            "gateway_address": "192.168.0.254",
            "dhcp_enabled": True,
            "dhcp_start_address": "192.168.0.10",
            "dhcp_count": 25,
            "dns_address": "8.8.8.8;1.1.1.1;1.0.0.1",
        }

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertDictEqual(expected_result, result)

    def test__ip_profile_to_ro_with_security_group(self):
        ip_profile = {
            "ip-version": "ipv4",
            "subnet-address": "192.168.0.0/24",
            "gateway-address": "192.168.0.254",
            "dhcp-params": {
                "enabled": True,
                "start-address": "192.168.0.10",
                "count": 25,
            },
            "security-group": {
                "some-security-group": "here",
            },
        }
        expected_result = {
            "ip_version": "IPv4",
            "subnet_address": "192.168.0.0/24",
            "gateway_address": "192.168.0.254",
            "dhcp_enabled": True,
            "dhcp_start_address": "192.168.0.10",
            "dhcp_count": 25,
            "security_group": {
                "some-security-group": "here",
            },
        }

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertDictEqual(expected_result, result)

    def test__ip_profile_to_ro(self):
        ip_profile = {
            "ip-version": "ipv4",
            "subnet-address": "192.168.0.0/24",
            "gateway-address": "192.168.0.254",
            "dhcp-params": {
                "enabled": True,
                "start-address": "192.168.0.10",
                "count": 25,
            },
            "dns-server": [
                {
                    "address": "8.8.8.8",
                },
                {
                    "address": "1.1.1.1",
                },
                {
                    "address": "1.0.0.1",
                },
            ],
            "security-group": {
                "some-security-group": "here",
            },
        }
        expected_result = {
            "ip_version": "IPv4",
            "subnet_address": "192.168.0.0/24",
            "gateway_address": "192.168.0.254",
            "dhcp_enabled": True,
            "dhcp_start_address": "192.168.0.10",
            "dhcp_count": 25,
            "dns_address": "8.8.8.8;1.1.1.1;1.0.0.1",
            "security_group": {
                "some-security-group": "here",
            },
        }

        result = Ns._ip_profile_to_ro(
            ip_profile=ip_profile,
        )

        self.assertDictEqual(expected_result, result)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_empty_params(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "provider_network": "some-profile-here",
        }
        target_record_id = ""
        expected_result = {
            "params": {
                "net_name": "ns-name-vld-name",
                "net_type": "bridge",
                "ip_profile": {
                    "some_ip_profile": "here",
                },
                "provider_network_profile": "some-profile-here",
            }
        }

        ip_profile_to_ro.return_value = {
            "some_ip_profile": "here",
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertTrue(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_vim_info_sdn(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "sdn": "some-sdn",
            "sdn-ports": ["some", "ports", "here"],
            "vlds": ["some", "vlds", "here"],
            "type": "sdn-type",
        }
        target_record_id = "vld.sdn.something"
        expected_result = {
            "params": {
                "sdn-ports": ["some", "ports", "here"],
                "vlds": ["some", "vlds", "here"],
                "type": "sdn-type",
            }
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_vim_info_sdn_target_vim(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "sdn": "some-sdn",
            "sdn-ports": ["some", "ports", "here"],
            "vlds": ["some", "vlds", "here"],
            "target_vim": "some-vim",
            "type": "sdn-type",
        }
        target_record_id = "vld.sdn.something"
        expected_result = {
            "depends_on": ["some-vim vld.sdn"],
            "params": {
                "sdn-ports": ["some", "ports", "here"],
                "vlds": ["some", "vlds", "here"],
                "target_vim": "some-vim",
                "type": "sdn-type",
            },
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_vim_network_name(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "vim_network_name": "some-network-name",
        }
        target_record_id = "vld.sdn.something"
        expected_result = {
            "find_params": {
                "filter_dict": {
                    "name": "some-network-name",
                },
            },
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_vim_network_id(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "vim_network_id": "some-network-id",
        }
        target_record_id = "vld.sdn.something"
        expected_result = {
            "find_params": {
                "filter_dict": {
                    "id": "some-network-id",
                },
            },
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_mgmt_network(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "id": "vld-id",
            "name": "vld-name",
            "mgmt-network": "some-mgmt-network",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {}
        target_record_id = "vld.sdn.something"
        expected_result = {
            "find_params": {
                "mgmt": True,
                "name": "vld-id",
            },
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertFalse(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_underlay_eline(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
            "underlay": "some-underlay-here",
            "type": "ELINE",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "provider_network": "some-profile-here",
        }
        target_record_id = ""
        expected_result = {
            "params": {
                "ip_profile": {
                    "some_ip_profile": "here",
                },
                "net_name": "ns-name-vld-name",
                "net_type": "ptp",
                "provider_network_profile": "some-profile-here",
            }
        }

        ip_profile_to_ro.return_value = {
            "some_ip_profile": "here",
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertTrue(ip_profile_to_ro.called)

    @patch("osm_ng_ro.ns.Ns._ip_profile_to_ro")
    def test__process_net_params_with_underlay_elan(
        self,
        ip_profile_to_ro,
    ):
        target_vld = {
            "name": "vld-name",
            "underlay": "some-underlay-here",
            "type": "ELAN",
        }
        indata = {
            "name": "ns-name",
        }
        vim_info = {
            "provider_network": "some-profile-here",
        }
        target_record_id = ""
        expected_result = {
            "params": {
                "ip_profile": {
                    "some_ip_profile": "here",
                },
                "net_name": "ns-name-vld-name",
                "net_type": "data",
                "provider_network_profile": "some-profile-here",
            }
        }

        ip_profile_to_ro.return_value = {
            "some_ip_profile": "here",
        }

        result = Ns._process_net_params(
            target_vld=target_vld,
            indata=indata,
            vim_info=vim_info,
            target_record_id=target_record_id,
        )

        self.assertDictEqual(expected_result, result)
        self.assertTrue(ip_profile_to_ro.called)

    def test__get_cloud_init_exception(self):
        db_mock = MagicMock(name="database mock")
        fs_mock = None

        location = ""

        with self.assertRaises(NsException):
            Ns._get_cloud_init(db=db_mock, fs=fs_mock, location=location)

    def test__get_cloud_init_file_fs_exception(self):
        db_mock = MagicMock(name="database mock")
        fs_mock = None

        location = "vnfr_id_123456:file:test_file"
        db_mock.get_one.return_value = {
            "_admin": {
                "storage": {
                    "folder": "/home/osm",
                    "pkg-dir": "vnfr_test_dir",
                },
            },
        }

        with self.assertRaises(NsException):
            Ns._get_cloud_init(db=db_mock, fs=fs_mock, location=location)

    def test__get_cloud_init_file(self):
        db_mock = MagicMock(name="database mock")
        fs_mock = MagicMock(name="filesystem mock")
        file_mock = MagicMock(name="file mock")

        location = "vnfr_id_123456:file:test_file"
        cloud_init_content = "this is a cloud init file content"

        db_mock.get_one.return_value = {
            "_admin": {
                "storage": {
                    "folder": "/home/osm",
                    "pkg-dir": "vnfr_test_dir",
                },
            },
        }
        fs_mock.file_open.return_value = file_mock
        file_mock.__enter__.return_value.read.return_value = cloud_init_content

        result = Ns._get_cloud_init(db=db_mock, fs=fs_mock, location=location)

        self.assertEqual(cloud_init_content, result)

    def test__get_cloud_init_vdu(self):
        db_mock = MagicMock(name="database mock")
        fs_mock = None

        location = "vnfr_id_123456:vdu:0"
        cloud_init_content = "this is a cloud init file content"

        db_mock.get_one.return_value = {
            "vdu": {
                0: {
                    "cloud-init": cloud_init_content,
                },
            },
        }

        result = Ns._get_cloud_init(db=db_mock, fs=fs_mock, location=location)

        self.assertEqual(cloud_init_content, result)

    @patch("jinja2.Environment.__init__")
    def test__parse_jinja2_undefined_error(self, env_mock: Mock):
        cloud_init_content = None
        params = None
        context = None

        env_mock.side_effect = UndefinedError("UndefinedError occurred.")

        with self.assertRaises(NsException):
            Ns._parse_jinja2(
                cloud_init_content=cloud_init_content, params=params, context=context
            )

    @patch("jinja2.Environment.__init__")
    def test__parse_jinja2_template_error(self, env_mock: Mock):
        cloud_init_content = None
        params = None
        context = None

        env_mock.side_effect = TemplateError("TemplateError occurred.")

        with self.assertRaises(NsException):
            Ns._parse_jinja2(
                cloud_init_content=cloud_init_content, params=params, context=context
            )

    @patch("jinja2.Environment.__init__")
    def test__parse_jinja2_template_not_found(self, env_mock: Mock):
        cloud_init_content = None
        params = None
        context = None

        env_mock.side_effect = TemplateNotFound("TemplateNotFound occurred.")

        with self.assertRaises(NsException):
            Ns._parse_jinja2(
                cloud_init_content=cloud_init_content, params=params, context=context
            )

    def test__parse_jinja2(self):
        pass

    def test__process_vdu_params_empty_kargs(self):
        pass

    def test__process_vdu_params_interface_ns_vld_id(self):
        pass

    def test__process_vdu_params_interface_vnf_vld_id(self):
        pass

    def test__process_vdu_params_interface_unknown(self):
        pass

    def test__process_vdu_params_interface_port_security_enabled(self):
        pass

    def test__process_vdu_params_interface_port_security_disable_strategy(self):
        pass

    def test__process_vdu_params_interface_sriov(self):
        pass

    def test__process_vdu_params_interface_pci_passthrough(self):
        pass

    def test__process_vdu_params_interface_om_mgmt(self):
        pass

    def test__process_vdu_params_interface_mgmt_interface(self):
        pass

    def test__process_vdu_params_interface_mgmt_vnf(self):
        pass

    def test__process_vdu_params_interface_bridge(self):
        pass

    def test__process_vdu_params_interface_ip_address(self):
        pass

    def test__process_vdu_params_interface_mac_address(self):
        pass

    def test__process_vdu_params_vdu_cloud_init_missing(self):
        pass

    def test__process_vdu_params_vdu_cloud_init_present(self):
        pass

    def test__process_vdu_params_vdu_boot_data_drive(self):
        pass

    def test__process_vdu_params_vdu_ssh_keys(self):
        pass

    def test__process_vdu_params_vdu_ssh_access_required(self):
        pass

    @patch("osm_ng_ro.ns.Ns._get_cloud_init")
    @patch("osm_ng_ro.ns.Ns._parse_jinja2")
    def test__process_vdu_params_vdu_persistent_root_volume(
        self, get_cloud_init, parse_jinja2
    ):
        db = MagicMock(name="database mock")
        kwargs = {
            "db": db,
            "vdu2cloud_init": {},
            "vnfr": {
                "vnfd-id": "ad6356e3-698c-43bf-9901-3aae9e9b9d18",
                "member-vnf-index-ref": "vnf-several-volumes",
            },
        }
        get_cloud_init.return_value = {}
        parse_jinja2.return_value = {}
        db.get_one.return_value = {
            "_id": "ad6356e3-698c-43bf-9901-3aae9e9b9d18",
            "df": [
                {
                    "id": "default-df",
                    "vdu-profile": [
                        {"id": "several_volumes-VM", "min-number-of-instances": 1}
                    ],
                }
            ],
            "id": "several_volumes-vnf",
            "product-name": "several_volumes-vnf",
            "vdu": [
                {
                    "id": "several_volumes-VM",
                    "name": "several_volumes-VM",
                    "sw-image-desc": "ubuntu20.04",
                    "alternative-sw-image-desc": [
                        "ubuntu20.04-aws",
                        "ubuntu20.04-azure",
                    ],
                    "virtual-storage-desc": [
                        "persistent-root-volume",
                        "persistent-volume2",
                        "ephemeral-volume",
                    ],
                }
            ],
            "version": "1.0",
            "virtual-storage-desc": [
                {
                    "id": "persistent-volume2",
                    "type-of-storage": "persistent-storage:persistent-storage",
                    "size-of-storage": "10",
                },
                {
                    "id": "persistent-root-volume",
                    "type-of-storage": "persistent-storage:persistent-storage",
                    "size-of-storage": "10",
                },
                {
                    "id": "ephemeral-volume",
                    "type-of-storage": "etsi-nfv-descriptors:ephemeral-storage",
                    "size-of-storage": "1",
                },
            ],
            "_admin": {
                "storage": {
                    "fs": "mongo",
                    "path": "/app/storage/",
                },
                "type": "vnfd",
            },
        }

        target_vdu = {
            "_id": "09a0baa7-b7cb-4924-bd63-9f04a1c23960",
            "ns-flavor-id": "0",
            "ns-image-id": "0",
            "vdu-name": "several_volumes-VM",
            "interfaces": [
                {
                    "name": "vdu-eth0",
                    "ns-vld-id": "mgmtnet",
                }
            ],
            "virtual-storages": [
                {
                    "id": "persistent-volume2",
                    "size-of-storage": "10",
                    "type-of-storage": "persistent-storage:persistent-storage",
                },
                {
                    "id": "persistent-root-volume",
                    "size-of-storage": "10",
                    "type-of-storage": "persistent-storage:persistent-storage",
                },
                {
                    "id": "ephemeral-volume",
                    "size-of-storage": "1",
                    "type-of-storage": "etsi-nfv-descriptors:ephemeral-storage",
                },
            ],
        }
        indata = {
            "name": "sample_name",
        }
        expected_result = [{"image_id": "ubuntu20.04", "size": "10"}, {"size": "10"}]
        result = Ns._process_vdu_params(
            target_vdu, indata, vim_info=None, target_record_id=None, **kwargs
        )
        self.assertEqual(
            expected_result, result["params"]["disk_list"], "Wrong Disk List"
        )

    @patch("osm_ng_ro.ns.Ns._get_cloud_init")
    @patch("osm_ng_ro.ns.Ns._parse_jinja2")
    def test__process_vdu_params_vdu_without_persistent_storage(
        self, get_cloud_init, parse_jinja2
    ):
        db = MagicMock(name="database mock")
        kwargs = {
            "db": db,
            "vdu2cloud_init": {},
            "vnfr": {
                "vnfd-id": "ad6356e3-698c-43bf-9901-3aae9e9b9d18",
                "member-vnf-index-ref": "vnf-several-volumes",
            },
        }
        get_cloud_init.return_value = {}
        parse_jinja2.return_value = {}
        db.get_one.return_value = {
            "_id": "ad6356e3-698c-43bf-9901-3aae9e9b9d18",
            "df": [
                {
                    "id": "default-df",
                    "vdu-profile": [
                        {"id": "without_volumes-VM", "min-number-of-instances": 1}
                    ],
                }
            ],
            "id": "without_volumes-vnf",
            "product-name": "without_volumes-vnf",
            "vdu": [
                {
                    "id": "without_volumes-VM",
                    "name": "without_volumes-VM",
                    "sw-image-desc": "ubuntu20.04",
                    "alternative-sw-image-desc": [
                        "ubuntu20.04-aws",
                        "ubuntu20.04-azure",
                    ],
                    "virtual-storage-desc": ["root-volume", "ephemeral-volume"],
                }
            ],
            "version": "1.0",
            "virtual-storage-desc": [
                {"id": "root-volume", "size-of-storage": "10"},
                {
                    "id": "ephemeral-volume",
                    "type-of-storage": "etsi-nfv-descriptors:ephemeral-storage",
                    "size-of-storage": "1",
                },
            ],
            "_admin": {
                "storage": {
                    "fs": "mongo",
                    "path": "/app/storage/",
                },
                "type": "vnfd",
            },
        }

        target_vdu = {
            "_id": "09a0baa7-b7cb-4924-bd63-9f04a1c23960",
            "ns-flavor-id": "0",
            "ns-image-id": "0",
            "vdu-name": "without_volumes-VM",
            "interfaces": [
                {
                    "name": "vdu-eth0",
                    "ns-vld-id": "mgmtnet",
                }
            ],
            "virtual-storages": [
                {
                    "id": "root-volume",
                    "size-of-storage": "10",
                },
                {
                    "id": "ephemeral-volume",
                    "size-of-storage": "1",
                    "type-of-storage": "etsi-nfv-descriptors:ephemeral-storage",
                },
            ],
        }
        indata = {
            "name": "sample_name",
        }
        expected_result = []
        result = Ns._process_vdu_params(
            target_vdu, indata, vim_info=None, target_record_id=None, **kwargs
        )
        self.assertEqual(
            expected_result, result["params"]["disk_list"], "Wrong Disk List"
        )

    def test__process_vdu_params(self):
        pass
