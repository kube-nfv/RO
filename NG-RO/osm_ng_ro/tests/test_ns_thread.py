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
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from osm_ng_ro.ns_thread import VimInteractionNet


class TestVimInteractionNet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module_name = "osm_ro_plugin"
        osm_ro_plugin = ModuleType(module_name)
        osm_ro_plugin.vimconn = Mock(name=module_name + ".vimconn")
        osm_ro_plugin.vimconn.VimConnector = Mock(
            name=module_name + "vimconn.VimConnector"
        )
        osm_ro_plugin.vimconn.VimConnException = Mock(
            name=module_name + ".vimconn.VimConnException"
        )
        cls.target_vim = osm_ro_plugin.vimconn.VimConnector
        cls.VimConnException = osm_ro_plugin.vimconn.VimConnException
        cls.task_depends = None

    @classmethod
    def tearDownClass(cls):
        del cls.target_vim
        del cls.task_depends
        del cls.VimConnException

    def test__mgmt_net_id_in_find_params_mgmt_several_vim_nets(self):
        """
        management_network_id in find_params.get('mgmt')
        More than one network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_2": {
                "config": {
                    "management_network_id": "test_mgmt_id",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_2": {
                        "target_id": "vim_openstack_2",
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
        management_network_id in find_params.get('mgmt')
        The network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_3": {
                "config": {
                    "management_network_id": "test_mgmt_id",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_3": {
                        "target_id": "vim_openstack_3",
                        "action_id": "123456",
                        "nsr_id": "654321",
                        "task_id": "123456:1",
                        "status": "SCHEDULED",
                        "action": "CREATE",
                        "item": "test_item",
                        "target_record": "test_target_record",
                        "target_record_id": "test_target_record_id",
                        "params": "",
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

    def test__mgmt_net_name_in_find_params_mgmt_several_vim_nets(self):
        """
        management_network_name in find_params.get('mgmt')
        More than one network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_4": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_4": {
                        "target_id": "vim_openstack_4",
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
        management_network_name in find_params.get('mgmt')
        The network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_5": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }

        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_5": {
                        "target_id": "vim_openstack_5",
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
        management_network_name in find_params.get('filterdict')
        More than one network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_6": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_6": {
                        "target_id": "vim_openstack_6",
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
            "vim_openstack_7": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_4": {
                        "target_id": "vim_openstack_7",
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
            "vim_openstack_8": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_8": {
                        "target_id": "vim_openstack_8",
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
        management_network_name in find_params.get('filterdict')
        Any network could not be found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_9": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_9": {
                        "target_id": "vim_openstack_9",
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

    def test__mgmt_net_name_in_find_params_mgmt_no_config_one_vim_net(self):
        """
        name in find_params
        management_network_name is not in db_vims.get('config')
        One network found in the VIM
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_10": {
                "config": {},
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_2": {
                        "target_id": "vim_openstack_10",
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
            "vim_openstack_11": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_11": {
                        "target_id": "vim_openstack_11",
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
            "vim_openstack_13": {
                "config": {
                    "management_network_name": "test_mgmt_name",
                },
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(instance, "my_vims", [self.target_vim]), patch.object(
            instance, "logger", logging
        ):
            ro_task = {
                "target_id": 0,
                "tasks": {
                    "task_index_12": {
                        "target_id": "vim_openstack_13",
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
                        "depends_on": "test_depends_on",
                    },
                },
            }

            task_index = "task_index_12"
            with self.assertRaises(TypeError):
                instance.new(ro_task, task_index, self.task_depends)

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
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging):
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
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging):
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
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging):
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
                "vim_details": "some error message",
            }
            result = instance.refresh(ro_task)
            self.assertEqual(result[0], task_status)
            self.assertDictEqual(result[1], ro_vim_item_update)

    def test__refresh_ro_task_VimConnException_occured(self):
        """
        vimconn.VimConnException has occured
        """
        db = "test_db"
        logger = "test_logger"
        my_vims = "test-vim"
        db_vims = {
            "vim_openstack_1": {
                "config": {},
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging):
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
                    "refresh_at": None,
                },
                "modified_at": 1637324200.994312,
                "created_at": 1637324200.994312,
                "to_check_at": 1637324200.994312,
                "tasks": {},
            }
            self.target_vim.refresh_nets_status.side_effect = Mock(
                side_effect=self.VimConnException("VimConnException occured")
            )
            with self.assertRaises(TypeError):
                instance.refresh(ro_task)
            self.target_vim.refresh_nets_status.side_effect = None

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
            },
        }
        instance = VimInteractionNet(db, logger, my_vims, db_vims)
        with patch.object(
            instance, "my_vims", {"vim_openstack_1": self.target_vim}
        ), patch.object(instance, "logger", logging):
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
                "vim_details": "Deleted externally",
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
        ), patch.object(instance, "logger", logging):
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
