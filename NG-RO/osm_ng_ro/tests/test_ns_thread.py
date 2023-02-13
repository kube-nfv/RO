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
from unittest.mock import MagicMock, Mock, patch

from osm_common.dbmemory import DbMemory
from osm_ng_ro.ns_thread import (
    ConfigValidate,
    NsWorker,
    VimInteractionAffinityGroup,
)

# Variables used in tests
db_vims_openstack = {
    "my_target_vim": {"vim_type": "openstack"},
}
db_vims_aws = {
    "my_target_vim": {"vim_type": "aws"},
}


class TestConfigValidate(unittest.TestCase):
    def setUp(self):
        self.config_dict = {
            "period": {
                "refresh_active": 65,
                "refresh_build": 20,
                "refresh_image": 3600,
                "refresh_error": 300,
                "queue_size": 50,
            }
        }

    def test_get_configuration(self):
        with self.subTest(i=1, t="Get config attributes with config input"):
            configuration = ConfigValidate(self.config_dict)
            self.assertEqual(configuration.active, 65)
            self.assertEqual(configuration.build, 20)
            self.assertEqual(configuration.image, 3600)
            self.assertEqual(configuration.error, 300)
            self.assertEqual(configuration.queue_size, 50)

        with self.subTest(i=2, t="Unallowed refresh active input"):
            # > 60  (except -1) is not allowed to set, so it should return default value 60
            self.config_dict["period"]["refresh_active"] = 20
            configuration = ConfigValidate(self.config_dict)
            self.assertEqual(configuration.active, 60)

        with self.subTest(i=3, t="Config to disable VM status periodic checks"):
            # -1 is allowed to set to disable VM status updates
            self.config_dict["period"]["refresh_active"] = -1
            configuration = ConfigValidate(self.config_dict)
            self.assertEqual(configuration.active, -1)


class TestNsWorker(unittest.TestCase):
    @patch("logging.getLogger", autospec=True)
    def setUp(self, mock_logger):
        mock_logger = logging.getLogger()
        mock_logger.disabled = True
        self.task_depends = None
        self.plugins = {}
        self.db_vims = db_vims_openstack
        self.db = Mock(DbMemory())
        self.worker_index = "worker-3"
        self.config = {
            "period": {
                "refresh_active": 60,
                "refresh_build": 20,
                "refresh_image": 3600,
                "refresh_error": 600,
                "queue_size": 100,
            },
            "process_id": "343435353",
            "global": {"task_locked_time": 16373242100.994312},
        }

        self.ro_task = {
            "_id": "122436:1",
            "locked_by": None,
            "locked_at": 0.0,
            "target_id": "my_target_vim",
            "vim_info": {
                "created": False,
                "created_items": None,
                "vim_id": "test-vim-id",
                "vim_name": "test-vim",
                "vim_status": "DONE",
                "vim_details": "",
                "vim_message": None,
                "refresh_at": None,
            },
            "modified_at": 1637324200.994312,
            "created_at": 1637324200.994312,
            "to_check_at": 16373242400.994312,
            "tasks": [
                {
                    "target_id": 0,
                    "action_id": "123456",
                    "nsr_id": "654321",
                    "task_id": "123456:1",
                    "status": "DONE",
                    "action": "CREATE",
                    "item": "test_item",
                    "target_record": "test_target_record",
                    "target_record_id": "test_target_record_id",
                },
            ],
        }
        self.instance = NsWorker(self.worker_index, self.config, self.plugins, self.db)
        self.instance.db_vims = db_vims_openstack
        self.instance.refresh_config = Mock()

    def get_disabled_tasks(self, db, status):
        db_disabled_tasks = db.get_list(
            "ro_tasks",
            q_filter={
                "tasks.status": status,
                "to_check_at.lt": 0,
            },
        )
        return db_disabled_tasks

    def test_update_vm_refresh_disabled_task_with_status_build_vim_openstack_with_refresh(
        self,
    ):
        """1 disabled task with status BUILD in DB, refresh_active parameter is not equal to -1."""
        # Disabled task with status build is not enabled again
        db = DbMemory()
        self.ro_task["tasks"][0]["status"] = "BUILD"
        self.config["period"]["refresh_active"] = 70
        self.ro_task["to_check_at"] = -1
        db.create("ro_tasks", self.ro_task)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "BUILD"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        instance.update_vm_refresh(self.ro_task)
        self.assertEqual(
            len(self.get_disabled_tasks(db, "BUILD")), disabled_tasks_count
        )

    def test_update_vm_refresh_disabled_task_with_status_done_vim_openstack_no_refresh(
        self,
    ):
        """1 disabled task with status DONE in DB, refresh_active parameter is equal to -1."""
        # As refresh_active parameter is equal to -1, task is not be enabled to process again
        db = DbMemory()
        self.config["period"]["refresh_active"] = -1
        self.ro_task["tasks"][0]["status"] = "DONE"
        self.ro_task["to_check_at"] = -1
        db.create("ro_tasks", self.ro_task)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "DONE"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        instance.update_vm_refresh(self.ro_task)
        self.assertEqual(len(self.get_disabled_tasks(db, "DONE")), disabled_tasks_count)

    def test_update_vm_refresh_disabled_task_with_status_done_vim_aws_with_refresh(
        self,
    ):
        """2 disabled task with status DONE in DB, refresh_active parameter is not equal to -1."""
        # Disabled tasks should be enabled to process again as vim type aws
        db = DbMemory()
        self.config["period"]["refresh_active"] = 66
        self.ro_task["tasks"][0]["status"] = "DONE"
        self.ro_task["to_check_at"] = -1
        db.create("ro_tasks", self.ro_task)
        self.ro_task2 = self.ro_task
        self.ro_task2["_id"] = "122437:1"
        db.create("ro_tasks", self.ro_task2)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "DONE"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        with patch.object(instance, "db_vims", db_vims_aws):
            instance.update_vm_refresh(self.ro_task)
            self.assertEqual(
                len(self.get_disabled_tasks(db, "DONE")), disabled_tasks_count - 2
            )

    def test_update_vm_refresh_no_disabled_task_with_status_done_vim_openstack_with_refresh(
        self,
    ):
        """No disabled task with status DONE in DB, refresh_active parameter is not equal to -1."""
        # There is not any disabled task, method does not change anything
        db = DbMemory()
        self.config["period"]["refresh_active"] = 66
        self.ro_task["tasks"][0]["status"] = "DONE"
        self.ro_task["to_check_at"] = 16373242400.994312
        db.create("ro_tasks", self.ro_task)
        self.ro_task2 = self.ro_task
        self.ro_task2["_id"] = "122437:1"
        db.create("ro_tasks", self.ro_task2)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "DONE"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        instance.update_vm_refresh(self.ro_task)
        self.assertEqual(len(self.get_disabled_tasks(db, "DONE")), disabled_tasks_count)

    def test_update_vm_refresh_disabled_task_with_status_done_vim_openstack_with_refresh(
        self,
    ):
        """1 disabled task with status DONE in DB, refresh_active parameter is equal to -1, vim type is Openstack."""
        # Disabled task with status done is not enabled again as vim type is openstack
        db = DbMemory()
        self.ro_task["tasks"][0]["status"] = "DONE"
        self.ro_task["to_check_at"] = -1
        db.create("ro_tasks", self.ro_task)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "DONE"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        instance.update_vm_refresh(self.ro_task)
        self.assertEqual(len(self.get_disabled_tasks(db, "DONE")), disabled_tasks_count)

    def test_process_pending_tasks_status_done_vim_aws_no_refresh(self):
        """Refresh_active parameter is equal to -1, task status is DONE."""
        # Task should be disabled to process again
        db = DbMemory()
        self.config["period"]["refresh_active"] = -1
        self.ro_task["tasks"][0]["status"] = "DONE"
        self.ro_task["to_check_at"] = 16373242400.994312
        db.create("ro_tasks", self.ro_task)
        # Number of disabled tasks in DB
        disabled_tasks_count = len(self.get_disabled_tasks(db, "DONE"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        with patch.object(instance, "db_vims", db_vims_aws):
            instance._process_pending_tasks(self.ro_task)
            self.assertEqual(
                len(self.get_disabled_tasks(db, "DONE")), disabled_tasks_count + 1
            )

    def test_process_pending_tasks_status_failed_vim_aws_no_refresh(self):
        """Refresh_active parameter is equal to -1, task status is FAILED."""
        # Task is not disabled to process as task status is not DONE
        db = DbMemory()
        self.config["period"]["refresh_active"] = -1
        self.ro_task["tasks"][0]["status"] = "FAILED"
        self.ro_task["to_check_at"] = 16373242400.994312
        db.create("ro_tasks", self.ro_task)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "FAILED"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        with patch.object(instance, "db_vims", db_vims_aws):
            instance._process_pending_tasks(self.ro_task)
            self.assertEqual(
                len(self.get_disabled_tasks(db, "FAILED")), disabled_tasks_count
            )

    def test_process_pending_tasks_status_done_vim_aws_with_refresh(self):
        """Refresh_active parameter is not equal to -1, task status is DONE."""
        # Task is not disabled to process as refresh_active parameter is not -1
        db = DbMemory()
        self.config["period"]["refresh_active"] = 70
        self.ro_task["tasks"][0]["status"] = "DONE"
        self.ro_task["to_check_at"] = 16373242400.994312
        db.create("ro_tasks", self.ro_task)
        disabled_tasks_count = len(self.get_disabled_tasks(db, "DONE"))
        instance = NsWorker(self.worker_index, self.config, self.plugins, db)
        with patch.object(instance, "db_vims", db_vims_aws):
            instance._process_pending_tasks(self.ro_task)
            self.assertEqual(
                len(self.get_disabled_tasks(db, "DONE")), disabled_tasks_count
            )


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
