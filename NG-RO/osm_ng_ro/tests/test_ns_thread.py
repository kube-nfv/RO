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
from unittest.mock import MagicMock, Mock, mock_open, patch

from osm_common.dbmemory import DbMemory
from osm_ng_ro.ns_thread import (
    ConfigValidate,
    NsWorker,
    NsWorkerException,
    VimInteractionAffinityGroup,
    VimInteractionMigration,
    VimInteractionNet,
    VimInteractionResize,
    VimInteractionSharedVolume,
)
from osm_ro_plugin.vimconn import VimConnConnectionException, VimConnException

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

    def test__get_configuration(self):
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

    @patch("osm_ng_ro.ns_thread.makedirs", return_value="")
    def test_create_file_cert(self, mock_makedirs):
        vim_config = {"config": {"ca_cert_content": "test"}}
        target_id = "1234"
        db = Mock()

        with patch("builtins.open", mock_open()) as mocked_file:
            nsw = NsWorker(self.worker_index, self.config, self.plugins, db)
            nsw._process_vim_config(target_id, vim_config)
            mocked_file.assert_called_once_with(
                f"/app/osm_ro/certs/{target_id}:{self.worker_index}/ca_cert", "w"
            )
            assert (
                vim_config["config"]["ca_cert"]
                == f"/app/osm_ro/certs/{target_id}:{self.worker_index}/ca_cert"
            )

    @patch("osm_ng_ro.ns_thread.makedirs")
    @patch("osm_ng_ro.ns_thread.path")
    def test_create_file_cert_exists(self, mock_path, mock_makedirs):
        vim_config = {"config": {"ca_cert_content": "test"}}
        target_id = "1234"
        db = Mock()
        mock_path.isdir.return_value = True

        with patch("builtins.open", mock_open()) as mocked_file:
            nsw = NsWorker(self.worker_index, self.config, self.plugins, db)
            nsw._process_vim_config(target_id, vim_config)
            mock_makedirs.assert_not_called()
            mocked_file.assert_called_once_with(
                f"/app/osm_ro/certs/{target_id}:{self.worker_index}/ca_cert", "w"
            )
            assert (
                vim_config["config"]["ca_cert"]
                == f"/app/osm_ro/certs/{target_id}:{self.worker_index}/ca_cert"
            )

    @patch("osm_ng_ro.ns_thread.path")
    @patch("osm_ng_ro.ns_thread.makedirs", side_effect=Exception)
    def test_create_file_cert_makedirs_except(self, mock_makedirs, mock_path):
        vim_config = {"config": {"ca_cert_content": "test"}}
        target_id = "1234"
        db = Mock()
        mock_path.isdir.return_value = False

        with patch("builtins.open", mock_open()) as mocked_file:
            nsw = NsWorker(self.worker_index, self.config, self.plugins, db)
            with self.assertRaises(NsWorkerException):
                nsw._process_vim_config(target_id, vim_config)
            mocked_file.assert_not_called()
            assert vim_config["config"]["ca_cert_content"] == "test"

    @patch("osm_ng_ro.ns_thread.makedirs", return_value="")
    def test_create_file_cert_open_excepts(self, mock_makedirs):
        vim_config = {"config": {"ca_cert_content": "test"}}
        target_id = "1234"
        db = Mock()

        with patch("builtins.open", mock_open()) as mocked_file:
            mocked_file.side_effect = Exception
            nsw = NsWorker(self.worker_index, self.config, self.plugins, db)
            with self.assertRaises(NsWorkerException):
                nsw._process_vim_config(target_id, vim_config)
            mocked_file.assert_called_once_with(
                f"/app/osm_ro/certs/{target_id}:{self.worker_index}/ca_cert", "w"
            )
            assert vim_config["config"]["ca_cert_content"] == "test"

    def test_get_next_refresh_vim_type_openstack(self):
        next_refresh = 163535353434.3434
        result = self.instance._get_next_refresh(self.ro_task, next_refresh)
        self.assertEqual(result, -1)

    def test_get_next_refresh_vim_type_openstack_refresh_disabled(self):
        next_refresh = 163535353434.3434
        self.instance.refresh_config.active = -1
        result = self.instance._get_next_refresh(self.ro_task, next_refresh)
        self.assertEqual(result, -1)

    def test_get_next_refresh_vim_type_aws_refresh_disabled(self):
        self.db_vims = db_vims_aws
        next_refresh = 163535353434.3434
        self.instance.refresh_config.active = -1
        result = self.instance._get_next_refresh(self.ro_task, next_refresh)
        self.assertEqual(result, -1)

    def test_get_next_refresh_vim_type_aws(self):
        self.instance.db_vims = db_vims_aws
        next_refresh = 163535353434.3434
        self.instance.refresh_config.active = 140
        result = self.instance._get_next_refresh(self.ro_task, next_refresh)
        self.assertEqual(result, next_refresh + 140)


class TestVimInteractionNet(unittest.TestCase):
    def setUp(self):
        module_name = "osm_ro_plugin"
        self.target_vim = MagicMock(name=f"{module_name}.vimconn.VimConnector")
        self.task_depends = None

        patches = [patch(f"{module_name}.vimconn.VimConnector", self.target_vim)]

        # Enabling mocks and add cleanups
        for mock in patches:
            mock.start()
            self.addCleanup(mock.stop)

    def test__mgmt_net_id_in_find_params_mgmt_several_vim_nets(self):
        """
        mgmt network is set in find_params
        management_network_id in vim config
        More than one network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_id": "test_mgmt_id",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
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
                        "find_params": {
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_2"
            self.target_vim.get_network_list.return_value = [
                {"id": "existing_net_1"},
                {"id": "existing_net_2"},
            ]
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "More than one network found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_id_in_find_params_mgmt_no_vim_nets(self):
        """
        mgmt network is set in find_params
        management_network_id in vim config
        The network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_id": "test_mgmt_id",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "db_vims", db_vims
        ), patch.object(instance, "logger", logging):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_3": {
                        "target_id": 0,
                        "action_id": "123456",
                        "nsr_id": "654321",
                        "task_id": "123456:1",
                        "status": "SCHEDULED",
                        "action": "CREATE",
                        "item": "test_item",
                        "target_record": "test_target_record",
                        "target_record_id": "test_target_record_id",
                        "params": {},
                        # values coming from extra_dict
                        "find_params": {
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_3"
            self.target_vim.get_network_list.return_value = []
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "Network not found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_in_find_params_no_vim_config_no_vim_nets(self):
        """
        mgmt network is set in find_params
        vim config does not have management_network_id or management_network_id
        The network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "db_vims", db_vims
        ), patch.object(instance, "logger", logging):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_3": {
                        "target_id": 0,
                        "action_id": "123456",
                        "nsr_id": "654321",
                        "task_id": "123456:1",
                        "status": "SCHEDULED",
                        "action": "CREATE",
                        "item": "test_item",
                        "target_record": "test_target_record",
                        "target_record_id": "test_target_record_id",
                        "params": {},
                        # values coming from extra_dict
                        "find_params": {
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_3"
            self.target_vim.get_network_list.return_value = []
            self.target_vim.new_network.return_value = "sample_net_id", {
                "item1": "sample_created_item"
            }
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "BUILD")
            self.assertEqual(result[1].get("vim_id"), "sample_net_id")
            self.assertEqual(result[1].get("created"), True)
            self.assertDictEqual(
                result[1].get("created_items"), {"item1": "sample_created_item"}
            )
            self.assertEqual(result[1].get("vim_status"), "BUILD")

    def test__mgmt_net_name_in_find_params_mgmt_several_vim_nets(self):
        """
        mgmt network is set in find_params
        management_network_name in vim config
        More than one network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_4": {
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
                        "find_params": {
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_4"
            self.target_vim.get_network_list.return_value = [
                {"id": "existing_net_1"},
                {"id": "existing_net_2"},
            ]
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "More than one network found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_name_in_find_params_mgmt_no_vim_nets(self):
        """
        mgmt network is set in find_params
        management_network_name in vim config
        The network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_5": {
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
                        "find_params": {
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_5"
            self.target_vim.get_network_list.return_value = []
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "Network not found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_name_in_find_params_filterdict_several_vim_nets(self):
        """
        mgmt network is set in find_params
        management_network_name in vim config
        network_name is set in find_params.get('filterdict')
        More than one network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_6": {
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
                        "find_params": {
                            "filter_dict": {
                                "name": "some-network-name",
                            },
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_6"
            self.target_vim.get_network_list.return_value = [
                {"id": "existing_net_1"},
                {"id": "existing_net_2"},
            ]
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "More than one network found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_name_in_find_params_no_filterdict_no_mgmt(self):
        """
        There is find_params in the task
        No mgmt in find_params
        No filter_dict in find_params
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_4": {
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
                        "find_params": {"wrong_param": "wrong_value"},
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_4"
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "Invalid find_params for new_net"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_name_in_find_params_filterdict_no_vim_nets_params_in_task(self):
        """
        management_network_name in find_params.get('filterdict')
        The network could not be found in the VIM
        There are items in the task.get(params)
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_8": {
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
                            "net_name": "test_params",
                        },
                        "find_params": {
                            "filter_dict": {
                                "name": "some-network-name",
                            },
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_8"
            self.target_vim.get_network_list.return_value = []
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "BUILD")
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_id"), None)
            self.assertEqual(result[1].get("created_items"), {})
            self.assertEqual(result[1].get("vim_status"), "BUILD")

    def test__mgmt_net_name_in_find_params_filterdict_no_vim_nets(self):
        """
        mgmt network is set in find_params
        management_network_name in vim config
        network_name is set in find_params.get('filterdict')
        Any network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_9": {
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
                        "params": "",
                        "find_params": {
                            "filter_dict": {
                                "name": "some-network-name",
                            },
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_9"
            self.target_vim.get_network_list.return_value = []
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "Network not found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_in_find_params_filterdict_no_config_no_vim_nets(self):
        """
        mgmt network is set in find_params
        vim config is empty
        network_name is set in find_params.get('filterdict')
        Any network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_9": {
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
                        "find_params": {
                            "filter_dict": {
                                "name": "some-network-name",
                            },
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_9"
            self.target_vim.get_network_list.return_value = []
            with self.assertLogs() as captured:
                result = instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(len(captured.records), 1)
                self.assertTrue(
                    "Network not found with this criteria"
                    in captured.records[0].getMessage()
                )
                self.assertEqual(captured.records[0].levelname, "ERROR")
                self.assertEqual(result[0], "FAILED")
                self.assertEqual(result[1].get("created"), False)
                self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__mgmt_net_name_in_find_params_mgmt_no_config_one_vim_net(self):
        """
        mgmt network is set in find_params
        management_network_name is not in db_vims.get('config')
        One network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
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
                        "find_params": {
                            "mgmt": True,
                            "name": "some_mgmt_name",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_2"
            self.target_vim.get_network_list.return_value = [
                {"id": "4d83a7c9-3ef4-4a45-99c8-aca3550490dd"}
            ]
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "BUILD")
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "BUILD")

    def test__params_in_task_no_find_params(self):
        """
        params in the task
        find_params does not exist in the task
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_11": {
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
                            "net_name": "test-network",
                            "net_type": "vlan",
                        },
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_11"
            self.target_vim.new_network.return_value = "sample_net_id", {
                "item1": "sample_created_item"
            }
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "BUILD")
            self.assertEqual(result[1].get("vim_id"), "sample_net_id")
            self.assertEqual(result[1].get("created"), True)
            self.assertEqual(
                result[1].get("created_items"), {"item1": "sample_created_item"}
            )
            self.assertEqual(result[1].get("vim_status"), "BUILD")

    def test__no_params_in_task_no_find_params(self):
        """
        empty params in the task
        find_params does not exist in the task
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_12": {
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
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_12"
            self.target_vim.new_network.side_effect = VimConnConnectionException(
                "VimConnConnectionException occurred."
            )
            with self.assertLogs() as captured:
                instance.new(ro_task, task_index, self.task_depends)
                self.assertEqual(captured.records[0].levelname, "ERROR")

    def test__refresh_ro_task_vim_status_active(self):
        """
        vim_info.get('status') is ACTIVE
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_1": {
                "config": {},
                "vim_type": "openstack",
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging), patch.object(
            instance, "db_vims", db_vims
        ):
            ro_task = {
                "_id": "122436:1",
                "locked_by": None,
                "locked_at": 0.0,
                "target_id": "vim_openstack_1",
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "test-vim-id",
                    "vim_name": "test-vim",
                    "vim_status": None,
                    "vim_details": "some-details",
                    "vim_message": None,
                    "refresh_at": None,
                },
                "modified_at": 1637324200.994312,
                "created_at": 1637324200.994312,
                "to_check_at": 1637324200.994312,
                "tasks": {},
            }

            self.target_vim.refresh_nets_status.return_value = {
                "test-vim-id": {
                    "vim_info": "some-details",
                    "status": "ACTIVE",
                    "name": "test-vim",
                    "error_msg": "",
                }
            }
            task_status = "DONE"
            ro_vim_item_update = {
                "vim_status": "ACTIVE",
            }
            result = instance.refresh(ro_task)
            self.assertEqual(result[0], task_status)
            self.assertDictEqual(result[1], ro_vim_item_update)

    def test__refresh_ro_task_vim_status_build(self):
        """
        vim_info.get('status') is BUILD
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_1": {
                "config": {},
                "vim_type": "openstack",
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging), patch.object(
            instance, "db_vims", db_vims
        ):
            ro_task = {
                "_id": "122436:1",
                "locked_by": None,
                "locked_at": 0.0,
                "target_id": "vim_openstack_1",
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "test-vim-id",
                    "vim_name": "test-vim",
                    "vim_status": "BUILD",
                    "vim_details": "",
                    "vim_message": None,
                    "refresh_at": None,
                },
                "modified_at": 1637324200.994312,
                "created_at": 1637324200.994312,
                "to_check_at": 1637324200.994312,
                "tasks": {},
            }

            self.target_vim.refresh_nets_status.return_value = {
                "test-vim-id": {
                    "vim_info": "some-details",
                    "status": "BUILD",
                    "name": "other-vim",
                    "error_msg": "",
                }
            }
            task_status = "BUILD"
            ro_vim_item_update = {
                "vim_name": "other-vim",
                "vim_details": "some-details",
            }
            result = instance.refresh(ro_task)
            self.assertEqual(result[0], task_status)
            self.assertDictEqual(result[1], ro_vim_item_update)

    def test__refresh_ro_task_vim_status_error(self):
        """
        vim_info.get('status') is ERROR
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_1": {
                "config": {},
                "vim_type": "openstack",
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging), patch.object(
            instance, "db_vims", db_vims
        ):
            ro_task = {
                "_id": "122436:1",
                "locked_by": None,
                "locked_at": 0.0,
                "target_id": "vim_openstack_1",
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "test-vim-id",
                    "vim_name": "test-vim",
                    "vim_status": "BUILD",
                    "vim_details": "",
                    "vim_message": None,
                    "refresh_at": None,
                },
                "modified_at": 1637324200.994312,
                "created_at": 1637324200.994312,
                "to_check_at": 1637324200.994312,
                "tasks": {},
            }

            self.target_vim.refresh_nets_status.return_value = {
                "test-vim-id": {
                    "vim_info": "some-details",
                    "status": "ERROR",
                    "name": "test-vim",
                    "error_msg": "some error message",
                }
            }
            task_status = "FAILED"
            ro_vim_item_update = {
                "vim_status": "ERROR",
                "vim_message": "some error message",
            }
            result = instance.refresh(ro_task)
            self.assertEqual(result[0], task_status)
            self.assertDictEqual(result[1], ro_vim_item_update)

    def test__refresh_ro_task_VimConnException_occurred(self):
        """
        vimconn.VimConnException has occured
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_1": {
                "config": {},
                "vim_type": "openstack",
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging), patch.object(
            instance, "db_vims", db_vims
        ):
            ro_task = {
                "_id": "122436:1",
                "locked_by": None,
                "locked_at": 0.0,
                "target_id": "vim_openstack_1",
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "test-vim-id",
                    "vim_name": "test-vim",
                    "vim_status": "BUILD",
                    "vim_details": "",
                    "vim_message": None,
                    "refresh_at": None,
                },
                "modified_at": 1637324200.994312,
                "created_at": 1637324200.994312,
                "to_check_at": 1637324200.994312,
                "tasks": {},
            }
            self.target_vim.refresh_nets_status.side_effect = VimConnException(
                "VimConnException occurred."
            )
            with self.assertLogs() as captured:
                instance.refresh(ro_task)
                self.assertEqual(captured.records[0].levelname, "ERROR")

    def test__refresh_ro_task_vim_status_deleted(self):
        """
        vim_info.get('status') is DELETED
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_1": {
                "config": {},
                "vim_type": "openstack",
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging), patch.object(
            instance, "db_vims", db_vims
        ):
            ro_task = {
                "_id": "122436:1",
                "locked_by": None,
                "locked_at": 0.0,
                "target_id": "vim_openstack_1",
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "test-vim-id",
                    "vim_name": "test-vim",
                    "vim_status": "BUILD",
                    "vim_details": "",
                    "vim_message": None,
                    "refresh_at": None,
                },
                "modified_at": 163724200.994312,
                "created_at": 1637324200.994312,
                "to_check_at": 1637324200.994312,
                "tasks": {},
            }
            self.target_vim.refresh_nets_status.return_value = {
                "test-vim-id": {
                    "vim_info": "some-details",
                    "status": "DELETED",
                    "name": "test-vim",
                    "error_msg": "some error message",
                }
            }
            task_status = "FAILED"
            ro_vim_item_update = {
                "vim_status": "DELETED",
                "vim_message": "Deleted externally",
                "vim_id": None,
            }
            result = instance.refresh(ro_task)
            self.assertEqual(result[0], task_status)
            self.assertDictEqual(result[1], ro_vim_item_update)

    def test__refresh_ro_task_empty_vim_dict(self):
        """
        vim_dict does not include vim_id key
        Raises KeyError
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_2": {
                "config": {},
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_2": self.target_vim}
        ), patch.object(instance, "logger", logging), patch.object(
            instance, "db_vims", db_vims
        ):
            ro_task = {
                "_id": "128436:1",
                "locked_by": None,
                "locked_at": 0.0,
                "target_id": "vim_openstack_2",
                "vim_info": {
                    "created": False,
                    "created_items": None,
                    "vim_id": "test-vim-id",
                    "vim_name": "test-vim",
                    "vim_status": "BUILD",
                    "vim_details": "",
                    "vim_message": None,
                    "refresh_at": None,
                },
                "modified_at": 163724211.994312,
                "created_at": 1637324211.994312,
                "to_check_at": 1637324211.994312,
                "tasks": {},
            }
            self.target_vim.refresh_nets_status.return_value = {}
            with self.assertRaises(KeyError):
                instance.refresh(ro_task)


class TestVimInteractionSharedVolume(unittest.TestCase):
    def setUp(self):
        module_name = "osm_ro_plugin"
        self.target_vim = MagicMock(name=f"{module_name}.vimconn.VimConnector")
        self.task_depends = None

        patches = [patch(f"{module_name}.vimconn.VimConnector", self.target_vim)]

        # Enabling mocks and add cleanups
        for mock in patches:
            mock.start()
            self.addCleanup(mock.stop)

    def test__new_shared_volume_ok(self):
        """
        create a shared volume with attributes set in params
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionSharedVolume(db, logger, my_vims, db_vims)
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
                            "shared_volume_data": {
                                "size": "10",
                                "name": "shared-volume",
                                "type": "multiattach",
                            }
                        },
                        "find_params": {},
                        "depends_on": "test_depends_on",
                    },
                },
            }
            task_index = "task_index_1"
            self.target_vim.new_shared_volumes.return_value = ("", "shared-volume")
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_id"), "shared-volume")
            self.assertEqual(result[1].get("created"), True)
            self.assertEqual(result[1].get("vim_status"), "ACTIVE")

    def test__new_shared_volume_failed(self):
        """
        create a shared volume with attributes set in params failed
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionSharedVolume(db, logger, my_vims, db_vims)
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
                            "shared_volume_data": {
                                "size": "10",
                                "name": "shared-volume",
                                "type": "multiattach",
                            }
                        },
                        "find_params": {},
                        "depends_on": "test_depends_on",
                    },
                },
            }
            task_index = "task_index_1"
            self.target_vim.new_shared_volumes.side_effect = VimConnException(
                "Connection failed."
            )
            result = instance.new(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "FAILED")
            self.assertEqual(result[1].get("vim_message"), "Connection failed.")
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")

    def test__delete_shared_volume_ok(self):
        """
        Delete a shared volume with attributes set in params
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionSharedVolume(db, logger, my_vims, db_vims)
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
                    "vim_id": "sample_shared_volume_id_3",
                    "vim_name": "sample_shared_volume_3",
                    "vim_status": None,
                    "vim_details": "some-details",
                    "vim_message": None,
                    "refresh_at": None,
                },
            }

            task_index = "task_index_3"
            self.target_vim.delete_shared_volumes.return_value = True
            result = instance.delete(ro_task, task_index)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_id"), None)
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "DELETED")

    def test__delete_shared_volume_failed(self):
        """
        Delete a shared volume with attributes set in params failed
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }

        instance = VimInteractionSharedVolume(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "_id": "122436:1",
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
                    "vim_id": "sample_shared_volume_id_3",
                    "vim_name": "sample_shared_volume_3",
                    "vim_status": None,
                    "vim_details": "some-details",
                    "vim_message": None,
                    "refresh_at": None,
                },
            }

            task_index = "task_index_3"
            self.target_vim.delete_shared_volumes.side_effect = VimConnException(
                "Connection failed."
            )
            result = instance.delete(ro_task, task_index)
            self.assertEqual(result[0], "FAILED")
            self.assertEqual(
                result[1].get("vim_message"), "Error while deleting: Connection failed."
            )
            self.assertEqual(result[1].get("vim_status"), "VIM_ERROR")


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
            self.assertEqual(result[1].get("vim_status"), "ACTIVE")

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
            self.assertEqual(result[1].get("vim_status"), "ACTIVE")

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
                    "vim_message": None,
                    "refresh_at": None,
                },
            }

            task_index = "task_index_3"
            self.target_vim.delete_affinity_group.return_value = (
                "sample_affinity_group_id_3"
            )
            result = instance.delete(ro_task, task_index)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_message"), "DELETED")
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
                    "vim_message": None,
                    "refresh_at": None,
                },
            }

            task_index = "task_index_4"
            self.target_vim.delete_affinity_group.return_value = ""
            result = instance.delete(ro_task, task_index)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_message"), "DELETED")
            self.assertEqual(result[1].get("created"), False)
            self.assertEqual(result[1].get("vim_status"), "DELETED")


class TestVimInteractionResize(unittest.TestCase):
    def setUp(self):
        module_name = "osm_ro_plugin"
        self.target_vim = MagicMock(name=f"{module_name}.vimconn.VimConnector")
        self.task_depends = None

        patches = [patch(f"{module_name}.vimconn.VimConnector", self.target_vim)]

        # Enabling mocks and add cleanups
        for mock in patches:
            mock.start()
            self.addCleanup(mock.stop)

    def test__exec_resize_done(self):
        """
        create verticalscale task
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }
        target_record_id = (
            "vnfrs:665b4165-ce24-4320-bf19-b9a45bade49f:"
            "vdur.bb9c43f9-10a2-4569-a8a8-957c3528b6d1"
        )

        instance = VimInteractionResize(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_1": {
                        "target_id": 0,
                        "action_id": "bb937f49-3870-4169-b758-9732e1ff40f3",
                        "nsr_id": "993166fe-723e-4680-ac4b-b1af2541ae31",
                        "task_id": "bb937f49-3870-4169-b758-9732e1ff40f3:0",
                        "status": "SCHEDULED",
                        "action": "EXEC",
                        "item": "verticalscale",
                        "target_record": "vnfrs:665b4165-ce24-4320-bf19-b9a45bade49f:vdur.0",
                        "target_record_id": target_record_id,
                        "params": {
                            "vim_vm_id": "f37b18ef-3caa-4dc9-ab91-15c669b16396",
                            "flavor_dict": "flavor_dict",
                            "flavor_id": "TASK-nsrs:993166fe-723e-4680-ac4b-b1af2541ae31:flavor.0",
                        },
                    }
                },
            }
            task_depends = {
                "TASK-nsrs:993166fe-723e-4680-ac4b-b1af2541ae31:flavor.0": "1"
            }
            task_index = "task_index_1"
            result = instance.exec(ro_task, task_index, task_depends)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_status"), "ACTIVE")


class TestVimInteractionMigration(unittest.TestCase):
    def setUp(self):
        module_name = "osm_ro_plugin"
        self.target_vim = MagicMock(name=f"{module_name}.vimconn.VimConnector")
        self.task_depends = None

        patches = [patch(f"{module_name}.vimconn.VimConnector", self.target_vim)]

        # Enabling mocks and add cleanups
        for mock in patches:
            mock.start()
            self.addCleanup(mock.stop)

    def test__exec_migration_done(self):
        """
        create migrate task
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            0: {
                "config": {},
            },
        }
        target_record_id = (
            "vnfrs:665b4165-ce24-4320-bf19-b9a45bade49f:"
            "vdur.bb9c43f9-10a2-4569-a8a8-957c3528b6d1"
        )

        instance = VimInteractionMigration(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ), patch.object(instance, "db_vims", db_vims):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_1": {
                        "target_id": 0,
                        "action_id": "bb937f49-3870-4169-b758-9732e1ff40f3",
                        "nsr_id": "993166fe-723e-4680-ac4b-b1af2541ae31",
                        "task_id": "bb937f49-3870-4169-b758-9732e1ff40f3:0",
                        "status": "SCHEDULED",
                        "action": "EXEC",
                        "item": "migrate",
                        "target_record": "vnfrs:665b4165-ce24-4320-bf19-b9a45bade49f:vdur.0",
                        "target_record_id": target_record_id,
                        "params": {
                            "vim_vm_id": "f37b18ef-3caa-4dc9-ab91-15c669b16396",
                            "migrate_host": "osm-test2",
                            "vdu_vim_info": {0: {"interfaces": []}},
                        },
                    }
                },
            }
            self.target_vim.migrate_instance.return_value = "ACTIVE", "test"

            task_index = "task_index_1"
            result = instance.exec(ro_task, task_index, self.task_depends)
            self.assertEqual(result[0], "DONE")
            self.assertEqual(result[1].get("vim_status"), "ACTIVE")
