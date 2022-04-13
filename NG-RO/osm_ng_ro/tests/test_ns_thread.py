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

import logging
import unittest
from unittest.mock import MagicMock, patch

from osm_ng_ro.ns_thread import VimInteractionAffinityGroup


class TestVimInteractionAffinityGroup(unittest.TestCase):
    def setUp(self):
        module_name = "osm_ro_plugin"
        self.target_vim = MagicMock(name=f"{module_name}.vimconn.VimConnector")
        self.task_depends = None

        patches = [patch(f"{module_name}.vimconn.VimConnector", self.target_vim)]

        # Enabling mocks and add cleanups
        for mock in patches:
            mock.start()
            self.addCleanup(mock.stop)

    def test__new_affinity_group_ok(self):
        """
        create affinity group with attributes set in params
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionAffinityGroup(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_1": {
                        "target_id": 0,
                        "action_id": "123456",
                        "nsr_id": "654321",
                        "task_id": "123456:1",
                        "status": "SCHEDULED",
                        "action": "CREATE",
                        "item": "test_item",
                        "target_record": "test_target_record",
                        "target_record_id": "test_target_record_id",
                        # values coming from extra_dict
                        "params": {
                            "affinity_group_data": {
                                "name": "affinity_group_1",
                                "type": "affinity",
                                "scope": "nfvi-node",
                            }
                        },
                        "find_params": {},
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_1"
            self.target_vim.new_affinity_group.return_value = (
                "sample_affinity_group_id_1"
            )
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_id"), "sample_affinity_group_id_1")
            self.assertEqual(result[1].get("created"), True)
            self.assertEqual(result[1].get("vim_status"), "DONE")

    def test__new_affinity_group_failed(self):
        """
        create affinity group with no attributes set in params
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionAffinityGroup(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_2": {
                        "target_id": 0,
                        "action_id": "123456",
                        "nsr_id": "654321",
                        "task_id": "123456:1",
                        "status": "SCHEDULED",
                        "action": "CREATE",
                        "item": "test_item",
                        "target_record": "test_target_record",
                        "target_record_id": "test_target_record_id",
                        # values coming from extra_dict
                        "params": {},
                        "find_params": {},
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_2"
            self.target_vim.new_affinity_group.return_value = (
                "sample_affinity_group_id_1"
            )
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_id"), None)
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "DONE")

    def test__delete_affinity_group_ok(self):
        """
        delete affinity group with a proper vim_id
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionAffinityGroup(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_3": {
                        "target_id": 0,
                        "task_id": "123456:1",
                    },
                },
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "sample_affinity_group_id_3",
                    "vim_name": "sample_affinity_group_id_3",
                    "vim_status": None,
                    "vim_details": "some-details",
                    "refresh_at": None,
                },
            }

            task_index = "task_index_3"
            self.target_vim.delete_affinity_group.return_value = (
                "sample_affinity_group_id_3"
            )
            result = instance.delete(ro_task, task_index)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_details"), "DELETED")
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "DELETED")

    def test__delete_affinity_group_failed(self):
        """
        delete affinity group with missing vim_id
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionAffinityGroup(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_4": {
                        "target_id": 0,
                        "task_id": "123456:1",
                    },
                },
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": None,
                    "vim_name": None,
                    "vim_status": None,
                    "vim_details": "some-details",
                    "refresh_at": None,
                },
            }

            task_index = "task_index_4"
            self.target_vim.delete_affinity_group.return_value = ""
            result = instance.delete(ro_task, task_index)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_details"), "DELETED")
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "DELETED")
