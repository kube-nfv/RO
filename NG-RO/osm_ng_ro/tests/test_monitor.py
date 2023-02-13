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
from copy import deepcopy
import logging
import threading
import unittest
from unittest.mock import MagicMock, mock_open, patch

from novaclient.v2.servers import Server as NovaServer
from osm_common import dbmongo
from osm_common.dbbase import DbException
from osm_ng_ro.monitor import (
    MonitorDbException,
    MonitorVimException,
    MonitorVms,
    MonitorVmsException,
    start_monitoring,
    stop_monitoring,
    VimToMonitor,
    VmToMonitor,
)
from osm_ng_ro.tests.sample_data import (
    config,
    db_vim_cacert,
    db_vim_collection,
    deleted_externally,
    file_name,
    interface_info2,
    interface_with_binding,
    ip1_addr,
    mac1_addr,
    mac2_addr,
    net1_id,
    old_interface,
    old_interface2,
    plugin_name,
    port1,
    port2,
    ro_task1,
    ro_task2,
    sample_vim,
    sample_vim_info,
    sample_vnfr,
    serialized_interface_info,
    serialized_server_info,
    server_other_info,
    target_id,
    target_record,
    target_record2,
    vdur_path,
    vim1_id,
    vim2_id,
    vim3_id,
    vim4_id,
    vim_info_path,
    vims,
    vims_to_monitor,
    vm1_id,
    vm2_id,
    vnfr_id,
    wrong_ro_task,
)
from osm_ro_plugin.vimconn import VimConnector
import yaml


def create_server(id: str, name: str, status: str = "ACTIVE", info: dict = {}):
    instance = NovaServer(manager="manager", info=info)
    instance.id = id
    instance.name = name
    instance.status = status
    return instance


# The preparation for the tests
sample_vim_connector_instance = VimConnector(
    uuid=sample_vim["_id"],
    name=sample_vim["name"],
    tenant_id=sample_vim.get("vim_tenant_id"),
    tenant_name=sample_vim.get("vim_tenant_name"),
    url=sample_vim["vim_url"],
)
sample_vm = VmToMonitor(vm1_id, target_record)
sample_vm2 = VmToMonitor(vm2_id, target_record)
sample_vm3 = VmToMonitor("deleted-vm-id", target_record)
server1 = create_server(vm1_id, "server1")
server2 = create_server(vm2_id, "server2")
server3 = create_server("other-vm-id3", "other-vm3")
server4 = create_server("other-vm-id4", "other-vm4")
all_server_info = deepcopy(server_other_info)
server7 = create_server(vm1_id, "server7", info=all_server_info)


class CopyingMock(MagicMock):
    def __call__(self, *args, **kwargs):
        args = deepcopy(args)
        kwargs = deepcopy(kwargs)
        return super(CopyingMock, self).__call__(*args, **kwargs)


def check_if_assert_not_called(mocks: list):
    for mocking in mocks:
        mocking.assert_not_called()


class TestMonitorVms(unittest.TestCase):
    @patch("osm_ng_ro.monitor.MonitorVms.__init__")
    @patch("osm_ng_ro.ns_thread.ConfigValidate")
    @patch("osm_ng_ro.monitor.MonitorVms.get_db_vims")
    @patch("osm_ng_ro.monitor.MonitorVms.load_vims")
    @patch("logging.getLogger", autospec=True)
    def setUp(
        self,
        mock_logger,
        mock_load_vims,
        mock_get_db_vims,
        mock_config_validate,
        mock_init,
    ):
        # We are disabling the logging of exception not to print them to console.
        mock_logger = logging.getLogger()
        mock_logger.disabled = True
        mock_init.return_value = None
        self.monitor = MonitorVms(config=config)
        self.monitor.db_vims = []
        self.monitor.db = CopyingMock(dbmongo.DbMongo(), autospec=True)
        self.monitor.config = config
        self.monitor.logger = mock_logger
        self.monitor.my_vims = {}
        self.monitor.refresh_config = mock_config_validate

    @patch("osm_ng_ro.ns_thread.ConfigValidate.__init__")
    @patch("osm_ng_ro.monitor.MonitorVms.get_db_vims")
    @patch("osm_ng_ro.monitor.MonitorVms.load_vims")
    @patch("logging.getLogger", autospec=True)
    @patch("osm_ng_ro.monitor.MonitorVms.connect_db")
    def test_init(
        self,
        mock_connect_db,
        mock_logger,
        mock_load_vims,
        mock_get_db_vims,
        mock_config_validate_init,
    ):
        mock_config_validate_init.return_value = None
        mock_get_db_vims.return_value = vims
        instance = MonitorVms(config)
        mock_config_validate_init.assert_called_once_with(config)
        self.assertDictEqual(instance.config, config)
        mock_load_vims.assert_called_once()
        self.assertEqual(instance.db_vims, vims)
        mock_connect_db.assert_called_once()
        self.assertIsNone(instance.db)
        self.assertIsNotNone(instance.db_vims)
        mock_logger.assert_called_once_with("ro.monitor")

    @patch("osm_ng_ro.monitor.MonitorVms._load_vim")
    def test_load_vims_empty_db_vims(self, mock_load_vim):
        self.monitor.load_vims()
        mock_load_vim.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms._load_vim")
    def test_load_vims_vim_id_not_in_my_vims(self, mock_load_vim):
        self.monitor.db_vims = vims
        self.monitor.my_vims = {vim3_id: "vim-obj3"}
        self.monitor.load_vims()
        _call_mock_load_vim = mock_load_vim.call_args_list
        self.assertEqual(mock_load_vim.call_count, 2)
        self.assertEqual(
            _call_mock_load_vim[0][0],
            (vim1_id,),
        )
        self.assertEqual(
            _call_mock_load_vim[1][0],
            (vim2_id,),
        )

    @patch("osm_ng_ro.monitor.MonitorVms._load_vim")
    def test_load_vims_vim_id_in_my_vims(self, mock_load_vim):
        self.monitor.db_vims = vims
        self.monitor.my_vims = {vim1_id: "vim-obj1", vim2_id: "vim-obj2"}
        self.monitor.load_vims()
        mock_load_vim.assert_not_called()

    @patch("osm_common.dbmongo.DbMongo.db_connect")
    @patch("osm_common.dbmongo.DbMongo.__init__")
    @patch("osm_common.dbmemory.DbMemory.db_connect")
    @patch("osm_common.dbmemory.DbMemory.__init__")
    def test_connect_db_type_mongo(
        self,
        mock_dbmemory_init,
        mock_dbmemory_connect,
        mock_dbmongo_init,
        mock_dbmongo_connect,
    ):
        self.monitor.db = None
        self.monitor.config["database"]["driver"] = "mongo"
        mock_dbmongo_init.return_value = None
        self.monitor.connect_db()
        mock_dbmongo_init.assert_called_once()
        mock_dbmongo_connect.assert_called_once()
        self.monitor.db.db_connect.assert_called_once_with(
            self.monitor.config["database"]
        )
        check_if_assert_not_called([mock_dbmemory_init, mock_dbmemory_connect])

    @patch("osm_common.dbmongo.DbMongo.db_connect")
    @patch("osm_common.dbmongo.DbMongo.__init__")
    @patch("osm_common.dbmemory.DbMemory.db_connect")
    @patch("osm_common.dbmemory.DbMemory.__init__")
    def test_connect_db_type_mongo_initialize_exception(
        self,
        mock_dbmemory_init,
        mock_dbmemory_connect,
        mock_dbmongo_init,
        mock_dbmongo_connect,
    ):
        self.monitor.db = None
        self.monitor.config["database"]["driver"] = "mongo"
        mock_dbmongo_init.side_effect = ValueError("Db object could not be created.")
        with self.assertRaises(MonitorDbException) as err:
            self.monitor.connect_db()
        self.assertEqual(str(err.exception), "Db object could not be created.")
        mock_dbmongo_init.assert_called_once()
        check_if_assert_not_called(
            [mock_dbmongo_connect, mock_dbmemory_init, mock_dbmemory_connect]
        )

    @patch("osm_common.dbmongo.DbMongo.db_connect")
    @patch("osm_common.dbmongo.DbMongo.__init__")
    @patch("osm_common.dbmemory.DbMemory.db_connect")
    @patch("osm_common.dbmemory.DbMemory.__init__")
    def test_connect_db_type_mongo_connection_exception(
        self,
        mock_dbmemory_init,
        mock_dbmemory_connect,
        mock_dbmongo_init,
        mock_dbmongo_connect,
    ):
        self.monitor.db = None
        self.monitor.config["database"]["driver"] = "mongo"
        mock_dbmongo_init.return_value = None
        mock_dbmongo_connect.side_effect = DbException("Connection failed")
        with self.assertRaises(MonitorDbException) as err:
            self.monitor.connect_db()
        self.assertEqual(str(err.exception), "database exception Connection failed")
        mock_dbmongo_init.assert_called_once()
        mock_dbmongo_connect.assert_called_once_with(self.monitor.config["database"])
        check_if_assert_not_called([mock_dbmemory_init, mock_dbmemory_connect])

    @patch("osm_common.dbmongo.DbMongo.db_connect")
    @patch("osm_common.dbmongo.DbMongo.__init__")
    @patch("osm_common.dbmemory.DbMemory.db_connect")
    @patch("osm_common.dbmemory.DbMemory.__init__")
    def test_connect_db_type_memory(
        self,
        mock_dbmemory_init,
        mock_dbmemory_connect,
        mock_dbmongo_init,
        mock_dbmongo_connect,
    ):
        self.monitor.db = None
        self.monitor.config["database"]["driver"] = "memory"
        mock_dbmemory_init.return_value = None
        self.monitor.connect_db()
        mock_dbmemory_init.assert_called_once()
        mock_dbmemory_connect.assert_called_once_with(self.monitor.config["database"])
        check_if_assert_not_called([mock_dbmongo_init, mock_dbmongo_connect])

    @patch("osm_common.dbmongo.DbMongo.db_connect")
    @patch("osm_common.dbmongo.DbMongo.__init__")
    @patch("osm_common.dbmemory.DbMemory.db_connect")
    @patch("osm_common.dbmemory.DbMemory.__init__")
    def test_connect_db_existing_db(
        self,
        mock_dbmemory_init,
        mock_dbmemory_connect,
        mock_dbmongo_init,
        mock_dbmongo_connect,
    ):
        self.monitor.connect_db()
        check_if_assert_not_called(
            [
                mock_dbmemory_init,
                mock_dbmongo_init,
                mock_dbmemory_connect,
                mock_dbmongo_connect,
            ]
        )

    @patch("osm_common.dbmongo.DbMongo.db_connect")
    @patch("osm_common.dbmongo.DbMongo.__init__")
    @patch("osm_common.dbmemory.DbMemory.db_connect")
    @patch("osm_common.dbmemory.DbMemory.__init__")
    def test_connect_db_wrong_driver_type(
        self,
        mock_dbmemory_init,
        mock_dbmemory_connect,
        mock_dbmongo_init,
        mock_dbmongo_connect,
    ):
        self.monitor.db = None
        self.monitor.config["database"]["driver"] = "posgresql"
        with self.assertRaises(MonitorDbException) as err:
            self.monitor.connect_db()
        self.assertEqual(
            str(err.exception),
            "Invalid configuration param 'posgresql' at '[database]':'driver'",
        )
        check_if_assert_not_called(
            [
                mock_dbmemory_init,
                mock_dbmongo_init,
                mock_dbmemory_connect,
                mock_dbmongo_connect,
            ]
        )

    def test_get_db_vims(self):
        self.monitor.db.get_list.return_value = vims
        result = self.monitor.get_db_vims()
        self.assertEqual(result, vims)
        self.monitor.db.get_list.assert_called_once_with(
            "vim_accounts", {"vim_type": "openstack"}
        )

    def test_get_db_vims_db_raises(self):
        self.monitor.db.get_list.side_effect = DbException("Connection failed.")
        with self.assertRaises(DbException) as err:
            result = self.monitor.get_db_vims()
            self.assertEqual(result, None)
        self.assertEqual(str(err.exception), "database exception Connection failed.")
        self.monitor.db.get_list.assert_called_once_with(
            "vim_accounts", {"vim_type": "openstack"}
        )

    def test_find_ro_tasks_to_monitor(self):
        self.monitor.db.get_list.return_value = [ro_task1]
        result = self.monitor.find_ro_tasks_to_monitor()
        self.assertEqual(result, [ro_task1])
        self.monitor.db.get_list.assert_called_once_with(
            "ro_tasks",
            q_filter={
                "tasks.status": ["DONE"],
                "tasks.item": ["vdu"],
            },
        )

    def test_find_ro_tasks_to_monitor_db_exception(self):
        self.monitor.db.get_list.side_effect = DbException("Wrong database status")
        with self.assertRaises(DbException) as err:
            result = self.monitor.find_ro_tasks_to_monitor()
            self.assertEqual(result, None)
        self.assertEqual(str(err.exception), "database exception Wrong database status")
        self.monitor.db.get_list.assert_called_once_with(
            "ro_tasks",
            q_filter={
                "tasks.status": ["DONE"],
                "tasks.item": ["vdu"],
            },
        )

    def test_initialize_target_vim(self):
        vim_module_conn = VimConnector
        vim_connector_instance = self.monitor._initialize_target_vim(
            vim_module_conn, sample_vim
        )
        self.assertIsInstance(vim_connector_instance, VimConnector)
        self.assertListEqual(
            [vim_connector_instance.id, vim_connector_instance.name],
            [target_id, "openstackETSI1"],
        )

    def test_initialize_target_vim_invalid_vim_connector_input(self):
        vim_module_conn = "openstack_vim_connector"
        with self.assertRaises(TypeError) as err:
            self.monitor._initialize_target_vim(vim_module_conn, sample_vim)
        self.assertEqual(str(err.exception), "'str' object is not callable")

    def test_initialize_target_vim_missing_vim_keys(self):
        vim_module_conn = VimConnector
        sample_vim = {
            "_id": target_id,
            "name": "openstackETSI1",
            "vim_type": "openstack",
        }
        with self.assertRaises(KeyError) as err:
            self.monitor._initialize_target_vim(vim_module_conn, sample_vim)
        self.assertEqual(str(err.exception.args[0]), "vim_url")

    def test_initialize_target_vim_invalid_vim_input_type(self):
        vim_module_conn = VimConnector
        sample_vim = [target_id, "openstackETSI1"]
        with self.assertRaises(TypeError) as err:
            self.monitor._initialize_target_vim(vim_module_conn, sample_vim)
        self.assertEqual(
            str(err.exception), "list indices must be integers or slices, not str"
        )

    @patch("osm_ng_ro.monitor.MonitorVms._process_vim_config")
    @patch("osm_ng_ro.monitor.MonitorVms._load_plugin")
    @patch("osm_ng_ro.monitor.MonitorVms._initialize_target_vim")
    def test_load_vim(self, mock_target_vim, mock_load_plugin, mock_vim_config):
        self.monitor.my_vims = {}
        sample_vim["schema_version"] = "1.11"
        self.monitor.db.get_one.return_value = sample_vim
        mock_load_plugin.return_value = VimConnector
        mock_target_vim.return_value = sample_vim_connector_instance
        self.monitor._load_vim(target_id)
        self.assertEqual(self.monitor.my_vims[target_id], sample_vim_connector_instance)
        mock_vim_config.assert_called_once()
        self.monitor.db.get_one.assert_called_once_with(
            db_vim_collection, {"_id": target_id}
        )
        self.monitor.db.encrypt_decrypt_fields.assert_called_once_with(
            sample_vim,
            "decrypt",
            fields=("password", "secret"),
            schema_version="1.11",
            salt=target_id,
        )
        mock_vim_config.assert_called_once_with(target_id, sample_vim)
        mock_load_plugin.assert_called_once_with(plugin_name)
        mock_target_vim.assert_called_once_with(VimConnector, sample_vim)

    @patch("osm_ng_ro.monitor.MonitorVms._process_vim_config")
    @patch("osm_ng_ro.monitor.MonitorVms._load_plugin")
    @patch("osm_ng_ro.monitor.MonitorVms._initialize_target_vim")
    def test_load_vim_target_vim_not_found(
        self, mock_target_vim, mock_load_plugin, mock_vim_config
    ):
        self.monitor.my_vims = {}
        self.monitor.db.get_one.return_value = None
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._load_vim(target_id)
        self.assertEqual(
            str(err.exception),
            "Cannot load 55b2219a-7bb9-4644-9612-980dada84e83 plugin=rovim_openstack: "
            "'NoneType' object has no attribute 'get'",
        )
        self.monitor.db.get_one.assert_called_once_with(
            db_vim_collection, {"_id": target_id}
        )
        check_if_assert_not_called(
            [
                self.monitor.db.encrypt_decrypt_fields,
                mock_vim_config,
                mock_load_plugin,
                mock_target_vim,
            ]
        )

    @patch("osm_ng_ro.monitor.MonitorVms._process_vim_config")
    @patch("osm_ng_ro.monitor.MonitorVms._load_plugin")
    @patch("osm_ng_ro.monitor.MonitorVms._initialize_target_vim")
    def test_load_vim_decrypt_fields_raises(
        self, mock_target_vim, mock_load_plugin, mock_vim_config
    ):
        self.monitor.my_vims = {}
        sample_vim["schema_version"] = "1.11"
        self.monitor.db.get_one.return_value = sample_vim
        self.monitor.db.encrypt_decrypt_fields.side_effect = DbException(
            "Value could not decrypted."
        )
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._load_vim(target_id)
        self.assertEqual(
            str(err.exception),
            "Cannot load 55b2219a-7bb9-4644-9612-980dada84e83 plugin=rovim_openstack: "
            "database exception Value could not decrypted.",
        )
        self.monitor.db.get_one.assert_called_once_with(
            db_vim_collection, {"_id": target_id}
        )
        self.monitor.db.encrypt_decrypt_fields.assert_called_once_with(
            sample_vim,
            "decrypt",
            fields=("password", "secret"),
            schema_version="1.11",
            salt=target_id,
        )
        check_if_assert_not_called([mock_vim_config, mock_load_plugin, mock_target_vim])

    @patch("osm_ng_ro.monitor.MonitorVms._process_vim_config")
    @patch("osm_ng_ro.monitor.MonitorVms._load_plugin")
    @patch("osm_ng_ro.monitor.MonitorVms._initialize_target_vim")
    def test_load_vim_process_vim_config_raises(
        self, mock_target_vim, mock_load_plugin, mock_vim_config
    ):
        self.monitor.my_vims = {}
        sample_vim["schema_version"] = "1.11"
        self.monitor.db.get_one.return_value = sample_vim
        mock_vim_config.side_effect = MonitorVimException(
            "Error writing file config_1234"
        )
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._load_vim(target_id)
        self.assertEqual(
            str(err.exception),
            "Cannot load 55b2219a-7bb9-4644-9612-980dada84e83 plugin=rovim_openstack: "
            "Error writing file config_1234",
        )
        self.monitor.db.get_one.assert_called_once_with(
            db_vim_collection, {"_id": target_id}
        )
        self.monitor.db.encrypt_decrypt_fields.assert_called_once_with(
            sample_vim,
            "decrypt",
            fields=("password", "secret"),
            schema_version="1.11",
            salt=target_id,
        )
        mock_vim_config.assert_called_once_with(target_id, sample_vim)
        check_if_assert_not_called([mock_load_plugin, mock_target_vim])

    @patch("osm_ng_ro.monitor.MonitorVms._process_vim_config")
    @patch("osm_ng_ro.monitor.MonitorVms._load_plugin")
    @patch("osm_ng_ro.monitor.MonitorVms._initialize_target_vim")
    def test_load_vim_load_plugin_raises(
        self, mock_target_vim, mock_load_plugin, mock_vim_config
    ):
        self.monitor.my_vims = {}
        sample_vim["schema_version"] = "1.11"
        self.monitor.db.get_one.return_value = sample_vim
        mock_load_plugin.side_effect = MonitorVimException(
            "Cannot load plugin osm_rovim_openstack"
        )
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._load_vim(target_id)
        self.assertEqual(
            str(err.exception),
            "Cannot load 55b2219a-7bb9-4644-9612-980dada84e83 plugin=rovim_openstack: "
            "Cannot load plugin osm_rovim_openstack",
        )
        self.monitor.db.get_one.assert_called_once_with(
            db_vim_collection, {"_id": target_id}
        )
        self.monitor.db.encrypt_decrypt_fields.assert_called_once_with(
            sample_vim,
            "decrypt",
            fields=("password", "secret"),
            schema_version="1.11",
            salt=target_id,
        )
        mock_vim_config.assert_called_once_with(target_id, sample_vim)
        mock_load_plugin.assert_called_once_with(plugin_name)
        mock_target_vim.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms._process_vim_config")
    @patch("osm_ng_ro.monitor.MonitorVms._load_plugin")
    @patch("osm_ng_ro.monitor.MonitorVms._initialize_target_vim")
    def test_load_vim_initialize_target_vim_raises(
        self, mock_target_vim, mock_load_plugin, mock_vim_config
    ):
        self.monitor.my_vims = {}
        self.monitor.db.get_one.return_value = sample_vim
        sample_vim["schema_version"] = "1.0"
        mock_load_plugin.return_value = VimConnector
        mock_target_vim.side_effect = TypeError("'module' object is not callable")
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._load_vim(target_id)
        self.assertEqual(
            str(err.exception),
            "Cannot load 55b2219a-7bb9-4644-9612-980dada84e83 plugin=rovim_openstack: "
            "'module' object is not callable",
        )
        self.monitor.db.get_one.assert_called_once_with(
            db_vim_collection, {"_id": target_id}
        )
        self.monitor.db.encrypt_decrypt_fields.assert_called_once_with(
            sample_vim,
            "decrypt",
            fields=("password", "secret"),
            schema_version="1.0",
            salt=target_id,
        )
        mock_vim_config.assert_called_once_with(target_id, sample_vim)
        mock_load_plugin.assert_called_once_with(plugin_name)
        mock_target_vim.assert_called_once_with(VimConnector, sample_vim)

    @patch("osm_ng_ro.monitor.makedirs")
    @patch("osm_ng_ro.monitor.path")
    @patch("builtins.open", new_callable=mock_open())
    def test_process_vim_config_vim_without_config(
        self, mock_open, mock_path, mock_makedirs
    ):
        db_vim = {}
        self.monitor._process_vim_config(target_id, db_vim)
        check_if_assert_not_called([mock_open, mock_path.isdir, mock_makedirs])

    @patch("osm_ng_ro.monitor.random")
    @patch("osm_ng_ro.monitor.makedirs")
    @patch("osm_ng_ro.monitor.path")
    @patch("builtins.open", new_callable=mock_open())
    def test_process_vim_config_vim_with_ca_cert(
        self, mock_open, mock_path, mock_makedirs, mock_random
    ):
        db_vim = {"config": {"ca_cert_content": "my_vim_cert"}}
        mock_path.isdir.return_value = False
        mock_random.randint.return_value = 23242
        self.monitor._process_vim_config(target_id, db_vim)
        self.assertEqual(db_vim["config"].get("ca_cert_content"), None)
        self.assertEqual(
            db_vim["config"].get("ca_cert"),
            db_vim_cacert,
        )
        mock_path.isdir.asssert_called_once_with(file_name)
        mock_makedirs.assert_called_once_with(file_name)
        mock_random.randint.assert_called_once()
        mock_open.assert_called_once_with(file_name + "/ca_cert", "w")

    @patch("osm_ng_ro.monitor.random")
    @patch("osm_ng_ro.monitor.makedirs")
    @patch("osm_ng_ro.monitor.path")
    @patch("builtins.open", new_callable=mock_open())
    def test_process_vim_config_vim_with_cacert_path_is_dir(
        self, mock_open, mock_path, mock_makedirs, mock_random
    ):
        db_vim = {"config": {"ca_cert_content": "my_vim_cert"}}
        mock_path.isdir.return_value = True
        mock_random.randint.return_value = 23242
        self.monitor._process_vim_config(target_id, db_vim)
        self.assertEqual(db_vim["config"].get("ca_cert_content"), None)
        self.assertEqual(
            db_vim["config"].get("ca_cert"),
            db_vim_cacert,
        )
        mock_path.isdir.asssert_called_once_with(file_name)
        mock_makedirs.assert_not_called()
        mock_random.randint.assert_called_once()
        mock_open.assert_called_once_with(file_name + "/ca_cert", "w")

    @patch("osm_ng_ro.monitor.random")
    @patch("osm_ng_ro.monitor.makedirs")
    @patch("osm_ng_ro.monitor.path")
    @patch("builtins.open", new_callable=mock_open())
    def test_process_vim_config_vim_with_cacert_makedir_raises(
        self, mock_open, mock_path, mock_makedirs, mock_random
    ):
        db_vim = {"config": {"ca_cert_content": "my_vim_cert"}}
        mock_path.isdir.return_value = False
        mock_random.randint.return_value = 23242
        mock_makedirs.side_effect = OSError("Can not create directory")
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._process_vim_config(target_id, db_vim)
        self.assertEqual(
            str(err.exception),
            "Error writing to file '/app/osm_ro/certs/55b2219a-7bb9-4644-9612-980dada84e83:23242': "
            "Can not create directory",
        )
        self.assertEqual(db_vim["config"].get("ca_cert_content"), "my_vim_cert")
        self.assertEqual(db_vim["config"].get("ca_cert"), None)
        mock_path.isdir.asssert_called_once_with(file_name)
        mock_makedirs.assert_called_once_with(file_name)
        mock_random.randint.assert_called_once()
        mock_open.assert_not_called()

    @patch("osm_ng_ro.monitor.random")
    @patch("osm_ng_ro.monitor.makedirs")
    @patch("osm_ng_ro.monitor.path")
    @patch("builtins.open", new_callable=mock_open())
    def test_process_vim_config_vim_with_cacert_mock_open_raises(
        self, mock_open, mock_path, mock_makedirs, mock_random
    ):
        db_vim = {"config": {"ca_cert_content": "my_vim_cert"}}
        mock_path.isdir.return_value = False
        mock_random.randint.return_value = 23242
        mock_open.side_effect = FileNotFoundError("File is not found.")
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._process_vim_config(target_id, db_vim)
        self.assertEqual(
            str(err.exception),
            "Error writing to file '/app/osm_ro/certs/55b2219a-7bb9-4644-9612-980dada84e83:23242/ca_cert': "
            "File is not found.",
        )
        self.assertEqual(db_vim["config"].get("ca_cert_content"), "my_vim_cert")
        self.assertEqual(db_vim["config"].get("ca_cert"), None)
        mock_path.isdir.asssert_called_once_with(file_name)
        mock_makedirs.assert_called_once_with(file_name)
        mock_random.randint.assert_called_once()
        mock_open.assert_called_once_with(file_name + "/ca_cert", "w")

    @patch("osm_ng_ro.monitor.random")
    @patch("osm_ng_ro.monitor.makedirs")
    @patch("osm_ng_ro.monitor.path")
    @patch("builtins.open", new_callable=mock_open())
    def test_process_vim_config_vim_without_cacert(
        self, mock_open, mock_path, mock_makedirs, mock_random
    ):
        db_vim = {"config": {}}
        self.monitor._process_vim_config(target_id, db_vim)
        self.assertEqual(db_vim["config"].get("ca_cert"), None)
        check_if_assert_not_called(
            [mock_path.isdir, mock_makedirs, mock_random.randint, mock_open]
        )

    @patch("osm_ng_ro.monitor.entry_points")
    def test_load_plugin_name_exists(self, mock_entry_points):
        self.monitor.plugins = {plugin_name: VimConnector}
        result = self.monitor._load_plugin(plugin_name)
        mock_entry_points.assert_not_called()
        self.assertEqual(self.monitor.plugins, {plugin_name: VimConnector})
        self.assertEqual(result, VimConnector)

    @patch("osm_ng_ro.monitor.entry_points")
    def test_load_plugin_name_does_not_exist(self, mock_entry_points):
        self.monitor.plugins = {}
        mock_ep = MagicMock()
        mock_ep.load.return_value = sample_vim_connector_instance
        mock_entry_points.return_value = [mock_ep]
        result = self.monitor._load_plugin(plugin_name)
        self.assertEqual(mock_entry_points.call_count, 1)
        mock_entry_points.assert_called_once_with(
            group="osm_rovim.plugins", name=plugin_name
        )
        self.assertEqual(
            self.monitor.plugins, {plugin_name: sample_vim_connector_instance}
        )
        self.assertEqual(result, sample_vim_connector_instance)

    @patch("osm_ng_ro.monitor.entry_points")
    def test_load_plugin_load_raises(self, mock_entry_points):
        self.monitor.plugins = {}
        mock_entry_points.return_value = None
        with self.assertRaises(MonitorVimException) as err:
            self.monitor._load_plugin(plugin_name)
        self.assertEqual(
            str(err.exception),
            "Cannot load plugin osm_rovim_openstack: 'NoneType' object is not iterable",
        )
        self.assertEqual(mock_entry_points.call_count, 1)
        mock_entry_points.assert_called_once_with(
            group="osm_rovim.plugins", name=plugin_name
        )
        self.assertEqual(self.monitor.plugins, {})

    @patch("osm_ng_ro.monitor.VmToMonitor")
    def test_create_vm_to_monitor_empty_ro_task(self, mock_vm_to_monitor):
        ro_task = {}
        result = self.monitor.create_vm_to_monitor(ro_task)
        self.assertEqual(result, None)
        mock_vm_to_monitor.assert_not_called()

    @patch("osm_ng_ro.monitor.VmToMonitor")
    def test_create_vm_to_monitor(self, mock_vm_to_monitor):
        sample_vm = VmToMonitor("sample_id", "sample_target_record")
        mock_vm_to_monitor.return_value = sample_vm
        result = self.monitor.create_vm_to_monitor(ro_task1)
        self.assertEqual(result, sample_vm)
        mock_vm_to_monitor.assert_called_once_with(
            "ebd39f37-e607-4bce-9f10-ea4c5635f726", target_record
        )

    @patch("osm_ng_ro.monitor.VmToMonitor")
    def test_create_vm_to_monitor_wrong_ro_task_format(self, mock_vm_to_monitor):
        mock_vm_to_monitor.return_value = "VmtoMonitor"
        with self.assertRaises(KeyError) as err:
            self.monitor.create_vm_to_monitor(wrong_ro_task)
        self.assertEqual(str(err.exception.args[0]), "vim_info")
        mock_vm_to_monitor.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    def test_add_vm_to_existing_vim(self, mock_create_vm_to_monitor):
        sample_vim1 = VimToMonitor(vim1_id, [vm1_id])
        vims_to_monitor = [sample_vim1]
        result = self.monitor.add_vm_to_existing_vim(vims_to_monitor, ro_task2, vim1_id)
        self.assertEqual(result, True)
        mock_create_vm_to_monitor.assert_called_once_with(ro_task2)
        self.assertEqual(2, len(sample_vim1.vms))

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    def test_add_vm_to_existing_vim_empty_vims_list(self, mock_create_vm_to_monitor):
        vims_to_monitor = []
        result = self.monitor.add_vm_to_existing_vim(vims_to_monitor, ro_task1, vim1_id)
        self.assertEqual(result, False)
        mock_create_vm_to_monitor.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    def test_add_vm_to_existing_vim_different_target_vim_id(
        self, mock_create_vm_to_monitor
    ):
        sample_vim1 = VimToMonitor(vim1_id, [vm1_id])
        vims_to_monitor = [sample_vim1]
        result = self.monitor.add_vm_to_existing_vim(vims_to_monitor, ro_task2, vim2_id)
        self.assertEqual(result, False)
        mock_create_vm_to_monitor.assert_not_called()
        self.assertEqual(1, len(sample_vim1.vms))

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    def test_add_vm_to_existing_vim_create_vm_to_monitor_raises(
        self, mock_create_vm_to_monitor
    ):
        sample_vim1 = VimToMonitor(vim1_id, [vm1_id])
        vims_to_monitor = [sample_vim1]
        mock_create_vm_to_monitor.side_effect = KeyError(
            "target_record does not exist."
        )
        with self.assertRaises(KeyError) as err:
            self.monitor.add_vm_to_existing_vim(vims_to_monitor, ro_task2, vim1_id)
        self.assertEqual(str(err.exception.args[0]), "target_record does not exist.")
        mock_create_vm_to_monitor.assert_called_once_with(ro_task2)
        self.assertEqual(1, len(sample_vim1.vms))

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    @patch("osm_ng_ro.monitor.VimToMonitor")
    def test_add_new_vim_for_monitoring(
        self, mock_vim_to_monitor, mock_create_vm_to_monitor
    ):
        sample_vim = VimToMonitor(vim1_id, [])
        mock_vim_to_monitor.return_value = sample_vim
        self.monitor.add_new_vim_for_monitoring(vims_to_monitor, ro_task1, vim1_id)
        mock_vim_to_monitor.assert_called_once_with(vim1_id, [])
        mock_create_vm_to_monitor.assert_called_once_with(ro_task1)
        self.assertEqual(len(sample_vim.vms), 1)
        self.assertEqual(len(vims_to_monitor), 1)

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    @patch("osm_ng_ro.monitor.VimToMonitor")
    def test_add_new_vim_for_monitoring_vim_to_monitor_raises(
        self, mock_vim_to_monitor, mock_create_vm_to_monitor
    ):
        vims_to_monitor = []
        mock_vim_to_monitor.side_effect = TypeError(
            "Missing required positional arguments"
        )
        with self.assertRaises(TypeError) as err:
            self.monitor.add_new_vim_for_monitoring(vims_to_monitor, ro_task1, None)
        self.assertEqual(
            str(err.exception.args[0]), "Missing required positional arguments"
        )
        mock_vim_to_monitor.assert_called_once_with(None, [])
        mock_create_vm_to_monitor.assert_not_called()
        self.assertEqual(len(vims_to_monitor), 0)

    @patch("osm_ng_ro.monitor.MonitorVms.create_vm_to_monitor")
    @patch("osm_ng_ro.monitor.VimToMonitor")
    def test_add_new_vim_for_monitoring_create_vm_to_monitor_raises(
        self, mock_vim_to_monitor, mock_create_vm_to_monitor
    ):
        vims_to_monitor = []
        mock_create_vm_to_monitor.side_effect = KeyError("target_record is not found.")
        with self.assertRaises(KeyError) as err:
            self.monitor.add_new_vim_for_monitoring(vims_to_monitor, ro_task1, vim1_id)
        self.assertEqual(str(err.exception.args[0]), "target_record is not found.")
        mock_vim_to_monitor.assert_called_once_with(vim1_id, [])
        mock_create_vm_to_monitor.assert_called_once_with(ro_task1)
        self.assertEqual(len(vims_to_monitor), 0)

    @patch("osm_ng_ro.monitor.MonitorVms.add_vm_to_existing_vim")
    @patch("osm_ng_ro.monitor.MonitorVms.add_new_vim_for_monitoring")
    def test_prepare_vims_to_monitor_no_proper_existing_vim(
        self, mock_add_new_vim_for_monitoring, mock_add_vm_to_existing_vim
    ):
        mock_add_vm_to_existing_vim.return_value = False
        self.monitor.prepare_vims_to_monitor(vims_to_monitor, ro_task1, vim1_id)
        mock_add_vm_to_existing_vim.assert_called_once_with(
            vims_to_monitor, ro_task1, vim1_id
        )
        mock_add_new_vim_for_monitoring.assert_called_once_with(
            vims_to_monitor, ro_task1, vim1_id
        )

    @patch("osm_ng_ro.monitor.MonitorVms.add_vm_to_existing_vim")
    @patch("osm_ng_ro.monitor.MonitorVms.add_new_vim_for_monitoring")
    def test_prepare_vims_to_monitor_proper_existing_vim(
        self, mock_add_new_vim_for_monitoring, mock_add_vm_to_existing_vim
    ):
        mock_add_vm_to_existing_vim.return_value = True
        self.monitor.prepare_vims_to_monitor(vims_to_monitor, ro_task1, vim1_id)
        mock_add_vm_to_existing_vim.assert_called_once_with(
            vims_to_monitor, ro_task1, vim1_id
        )
        mock_add_new_vim_for_monitoring.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.add_vm_to_existing_vim")
    @patch("osm_ng_ro.monitor.MonitorVms.add_new_vim_for_monitoring")
    def test_prepare_vims_to_monitor_add_vm_to_existing_vim_raises(
        self, mock_add_new_vim_for_monitoring, mock_add_vm_to_existing_vim
    ):
        mock_add_vm_to_existing_vim.side_effect = KeyError(
            "target_record is not found."
        )
        with self.assertRaises(KeyError) as err:
            self.monitor.prepare_vims_to_monitor(vims_to_monitor, ro_task1, vim1_id)
        self.assertEqual(str(err.exception.args[0]), "target_record is not found.")
        mock_add_vm_to_existing_vim.assert_called_once_with(
            vims_to_monitor, ro_task1, vim1_id
        )
        mock_add_new_vim_for_monitoring.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.add_vm_to_existing_vim")
    @patch("osm_ng_ro.monitor.MonitorVms.add_new_vim_for_monitoring")
    def test_prepare_vims_to_monitor_add_new_vim_for_monitoring_raises(
        self, mock_add_new_vim_for_monitoring, mock_add_vm_to_existing_vim
    ):
        mock_add_vm_to_existing_vim.return_value = False
        mock_add_new_vim_for_monitoring.side_effect = KeyError(
            "target_record is not found."
        )
        with self.assertRaises(KeyError) as err:
            self.monitor.prepare_vims_to_monitor(vims_to_monitor, ro_task1, vim1_id)
        self.assertEqual(str(err.exception.args[0]), "target_record is not found.")
        mock_add_vm_to_existing_vim.assert_called_once_with(
            vims_to_monitor, ro_task1, vim1_id
        )
        mock_add_new_vim_for_monitoring.assert_called_once_with(
            vims_to_monitor, ro_task1, vim1_id
        )

    def test_get_db_paths(self):
        self.monitor.db.get_one.return_value = sample_vnfr
        (
            vim_info_path,
            vim_id,
            vnfr_id,
            vdur_path,
            vdur_index,
            db_vnfr,
        ) = self.monitor._get_db_paths(target_record)
        self.assertEqual(
            vim_info_path, "vdur.0.vim_info.vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7"
        )
        self.assertEqual(vim_id, vim4_id)
        self.assertEqual(vdur_path, "vdur.0")
        self.assertEqual(vdur_index, 0)
        self.assertEqual(vnfr_id, vnfr_id)
        self.assertDictEqual(db_vnfr, sample_vnfr)
        self.monitor.db.get_one.assert_called_once_with(
            "vnfrs",
            {"_id": vnfr_id},
            fail_on_empty=False,
        )

    def test_get_db_paths_empty_vnfr(self):
        self.monitor.db.get_one.return_value = None
        (
            vim_info_path,
            vim_id,
            vnfr_id,
            vdur_path,
            vdur_index,
            db_vnfr,
        ) = self.monitor._get_db_paths(target_record)
        self.assertEqual(
            vim_info_path, "vdur.0.vim_info.vim:f239ed93-756b-408e-89f8-fcbf47a9d8f7"
        )
        self.assertEqual(vim_id, vim4_id)
        self.assertEqual(vdur_path, "vdur.0")
        self.assertEqual(vdur_index, 0)
        self.assertEqual(vnfr_id, vnfr_id)
        self.assertEqual(db_vnfr, None)
        self.monitor.db.get_one.assert_called_once_with(
            "vnfrs",
            {"_id": vnfr_id},
            fail_on_empty=False,
        )

    def test_get_db_paths_invalid_target_record(self):
        invalid_target_record = "vnfrs:35c034cc-8c5b-48c4-bfa2-17a71577ef19:f239ed93-756b-408e-89f8-fcbf47a9d8f7"
        with self.assertRaises(MonitorVmsException) as err:
            self.monitor._get_db_paths(invalid_target_record)
        self.assertEqual(
            str(err.exception.args[0]),
            "not enough values to unpack (expected 4, got 3)",
        )
        self.monitor.db.get_one.assert_not_called()

    def test_get_db_paths_db_raises(self):
        self.monitor.db.get_one.side_effect = DbException("Connection Failed.")
        with self.assertRaises(MonitorVmsException) as err:
            self.monitor._get_db_paths(target_record)
        self.assertEqual(
            str(err.exception.args[0]), "database exception Connection Failed."
        )
        self.monitor.db.get_one.assert_called_once_with(
            "vnfrs",
            {"_id": vnfr_id},
            fail_on_empty=False,
        )

    def test_check_if_vdur_vim_info_exists(self):
        vdur_index = 0
        result = self.monitor._check_if_vdur_vim_info_exists(sample_vnfr, vdur_index)
        self.assertEqual(result, True)

    def test_check_if_vdur_vim_info_exists_wrong_vdur_index(self):
        vdur_index = 3
        result = self.monitor._check_if_vdur_vim_info_exists(sample_vnfr, vdur_index)
        self.assertEqual(result, None)

    def test_check_if_vdur_vim_info_exists_empty_vnfr(self):
        vdur_index = 2
        result = self.monitor._check_if_vdur_vim_info_exists({}, vdur_index)
        self.assertEqual(result, None)

    def test_check_if_vdur_vim_info_exists_str_vdur_index(self):
        vdur_index = "2"
        result = self.monitor._check_if_vdur_vim_info_exists({}, vdur_index)
        self.assertEqual(result, None)

    def test_check_if_vdur_vim_info_exists_none_vnfr(self):
        vdur_index = 2
        result = self.monitor._check_if_vdur_vim_info_exists(None, vdur_index)
        self.assertEqual(result, None)

    @patch("osm_ng_ro.monitor.MonitorVms._get_db_paths")
    @patch("osm_ng_ro.monitor.MonitorVms._check_if_vdur_vim_info_exists")
    @patch("osm_ng_ro.monitor.deepcopy")
    def test_get_vm_data_from_db(
        self, mock_deepcopy, mock_vim_info_exists, mock_get_db_paths
    ):
        vim_id = vim4_id
        vdur_index = 0
        db_vnfr = sample_vnfr
        mock_get_db_paths.return_value = (
            vim_info_path,
            vim_id,
            vnfr_id,
            vdur_path,
            vdur_index,
            db_vnfr,
        )
        mock_vim_info_exists.return_value = True
        mock_deepcopy.return_value = sample_vim_info
        (
            vdur_path_result,
            vdur_vim_info_update_result,
            db_vnfr_result,
            existing_vim_info_result,
            vnfr_id_result,
            vim_info_path_result,
        ) = self.monitor._get_vm_data_from_db(sample_vm)
        self.assertEqual(vdur_path_result, vdur_path)
        self.assertEqual(vdur_vim_info_update_result, sample_vim_info)
        self.assertEqual(db_vnfr_result, db_vnfr)
        self.assertEqual(existing_vim_info_result, sample_vim_info)
        self.assertEqual(vnfr_id_result, vnfr_id)
        self.assertEqual(vim_info_path_result, vim_info_path)
        mock_deepcopy.assert_called_once_with(sample_vim_info)
        mock_get_db_paths.assert_called_once_with(target_record)
        mock_vim_info_exists.assert_called_once_with(db_vnfr, vdur_index)

    @patch("osm_ng_ro.monitor.MonitorVms._get_db_paths")
    @patch("osm_ng_ro.monitor.MonitorVms._check_if_vdur_vim_info_exists")
    @patch("osm_ng_ro.monitor.deepcopy")
    def test_get_vm_data_from_db_no_vim_info(
        self, mock_deepcopy, mock_vim_info_exists, mock_get_db_paths
    ):
        vim_id = vim4_id
        vdur_index = 0
        db_vnfr = sample_vnfr
        mock_get_db_paths.return_value = (
            vim_info_path,
            vim_id,
            vnfr_id,
            vdur_path,
            vdur_index,
            db_vnfr,
        )
        mock_vim_info_exists.return_value = False
        result = self.monitor._get_vm_data_from_db(sample_vm)
        self.assertEqual(result, None)
        mock_deepcopy.assert_not_called()
        mock_get_db_paths.assert_called_once_with(target_record)
        mock_vim_info_exists.assert_called_once_with(db_vnfr, vdur_index)

    @patch("osm_ng_ro.monitor.MonitorVms._get_db_paths")
    @patch("osm_ng_ro.monitor.MonitorVms._check_if_vdur_vim_info_exists")
    @patch("osm_ng_ro.monitor.deepcopy")
    def test_get_vm_data_from_db_get_db_path_raises(
        self, mock_deepcopy, mock_vim_info_exists, mock_get_db_paths
    ):
        mock_get_db_paths.side_effect = DbException("Connection failed.")
        with self.assertRaises(DbException) as err:
            self.monitor._get_vm_data_from_db(sample_vm)
        self.assertEqual(
            str(err.exception.args[0]), "database exception Connection failed."
        )
        mock_get_db_paths.assert_called_once_with(target_record)
        check_if_assert_not_called([mock_deepcopy, mock_vim_info_exists])

    @patch("osm_ng_ro.monitor.MonitorVms._get_db_paths")
    @patch("osm_ng_ro.monitor.MonitorVms._check_if_vdur_vim_info_exists")
    @patch("osm_ng_ro.monitor.deepcopy")
    def test_get_vm_data_from_db_vnfr_without_correct_vdur_index(
        self, mock_deepcopy, mock_vim_info_exists, mock_get_db_paths
    ):
        vim_id = vim4_id
        vdur_index = 2
        db_vnfr = sample_vnfr
        mock_get_db_paths.return_value = (
            vim_info_path,
            vim_id,
            vnfr_id,
            vdur_path,
            vdur_index,
            db_vnfr,
        )
        mock_vim_info_exists.return_value = True
        with self.assertRaises(IndexError) as err:
            self.monitor._get_vm_data_from_db(sample_vm)
        self.assertEqual(str(err.exception.args[0]), "list index out of range")
        mock_deepcopy.assert_not_called()
        mock_get_db_paths.assert_called_once_with(target_record)
        mock_vim_info_exists.assert_called_once_with(db_vnfr, vdur_index)

    @patch("osm_ng_ro.monitor.MonitorVms._get_db_paths")
    @patch("osm_ng_ro.monitor.MonitorVms._check_if_vdur_vim_info_exists")
    @patch("osm_ng_ro.monitor.deepcopy")
    def test_get_vm_data_from_db_vnfr_without_proper_vim_id(
        self, mock_deepcopy, mock_vim_info_exists, mock_get_db_paths
    ):
        vim_id = "5239ed93-756b-408e-89f8-fcbf47a9d8f7"
        vdur_index = 0
        db_vnfr = sample_vnfr
        mock_get_db_paths.return_value = (
            vim_info_path,
            vim_id,
            vnfr_id,
            vdur_path,
            vdur_index,
            db_vnfr,
        )
        mock_vim_info_exists.return_value = True
        self.monitor._get_vm_data_from_db(sample_vm)
        mock_deepcopy.assert_not_called()
        mock_get_db_paths.assert_called_once_with(target_record)
        mock_vim_info_exists.assert_called_once_with(db_vnfr, vdur_index)

    def test_update_vim_info_for_deleted_vm_empty_input_dict(self):
        vdur_vim_info_update = {}
        self.monitor.update_vim_info_for_deleted_vm(vdur_vim_info_update)
        self.assertEqual(
            vdur_vim_info_update,
            deleted_externally,
        )

    def test_update_vim_info_for_deleted_vm_update_existing_info(self):
        vdur_vim_info_update = {
            "vim_status": "ACTIVE",
            "vim_message": None,
            "vim_details": None,
            "vim_id": vm1_id,
            "vim_name": "test7-vnf-hackfest_basic-VM-000000",
        }
        self.monitor.update_vim_info_for_deleted_vm(vdur_vim_info_update)
        self.assertEqual(
            vdur_vim_info_update,
            deleted_externally,
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vim_info_for_deleted_vm")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_deleted_vdur_no_vm_data_in_db(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_update_vim_info_for_deleted_vm,
        mock_get_vm_data_from_db,
    ):
        mock_get_vm_data_from_db.return_value = None
        self.monitor.report_deleted_vdur(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        check_if_assert_not_called(
            [
                mock_update_in_database,
                mock_backup_vdu_interfaces,
                mock_update_vim_info_for_deleted_vm,
            ]
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vim_info_for_deleted_vm")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_deleted_vdur(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_update_vim_info_for_deleted_vm,
        mock_get_vm_data_from_db,
    ):
        existing_vim_info = sample_vim_info
        vdur_vim_info_update = deleted_externally
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        vdur_update = {
            vdur_path + ".status": "DELETED",
        }
        self.monitor.report_deleted_vdur(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        mock_update_vim_info_for_deleted_vm.assert_called_once_with(
            vdur_vim_info_update
        )
        mock_backup_vdu_interfaces.assert_called_once_with(vdur_vim_info_update)
        mock_update_in_database.assert_called_once_with(
            [vdur_update, {vim_info_path: vdur_vim_info_update}], vnfr_id
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vim_info_for_deleted_vm")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_deleted_vdur_vm_db_already_updated(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_update_vim_info_for_deleted_vm,
        mock_get_vm_data_from_db,
    ):
        vdur_vim_info_update = existing_vim_info = deleted_externally
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        self.monitor.report_deleted_vdur(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        mock_update_vim_info_for_deleted_vm.assert_called_once_with(
            vdur_vim_info_update
        )
        check_if_assert_not_called(
            [mock_backup_vdu_interfaces, mock_update_in_database]
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vim_info_for_deleted_vm")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_deleted_vdur_get_vm_data_raises(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_update_vim_info_for_deleted_vm,
        mock_get_vm_data_from_db,
    ):
        mock_get_vm_data_from_db.side_effect = IndexError("list index out of range.")
        with self.assertRaises(IndexError) as err:
            self.monitor.report_deleted_vdur(sample_vm)
        self.assertEqual(str(err.exception.args[0]), "list index out of range.")
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        check_if_assert_not_called(
            [
                mock_update_vim_info_for_deleted_vm,
                mock_backup_vdu_interfaces,
                mock_update_in_database,
            ]
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vim_info_for_deleted_vm")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_deleted_vdur_update_in_database_raises(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_update_vim_info_for_deleted_vm,
        mock_get_vm_data_from_db,
    ):
        existing_vim_info = sample_vim_info
        vdur_vim_info_update = deleted_externally
        mock_update_in_database.side_effect = MonitorDbException(
            "Error while updating differences in VNFR."
        )
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        vdur_update = {
            vdur_path + ".status": "DELETED",
        }
        with self.assertRaises(MonitorDbException) as err:
            self.monitor.report_deleted_vdur(sample_vm)
        self.assertEqual(
            str(err.exception.args[0]), "Error while updating differences in VNFR."
        )
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        mock_update_vim_info_for_deleted_vm.assert_called_once_with(
            vdur_vim_info_update
        )
        mock_backup_vdu_interfaces.assert_called_once_with(vdur_vim_info_update)
        mock_update_in_database.assert_called_once_with(
            [vdur_update, {vim_info_path: vdur_vim_info_update}], vnfr_id
        )

    @patch("osm_ng_ro.monitor.MonitorVms.report_vdur_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.report_deleted_vdur")
    def test_update_vnfrs(self, mock_report_deleted_vdur, mock_report_vdur_updates):
        vms_to_monitor = [sample_vm, sample_vm2, sample_vm3]
        servers = [server1, server2, server3, server4]
        ports = {"ports": [port1, port2]}
        self.monitor.update_vnfrs(servers, ports, vms_to_monitor)
        self.assertEqual(mock_report_vdur_updates.call_count, 2)
        mock_report_deleted_vdur.assert_called_once_with(sample_vm3)
        _call_mock_report_vdur_updates = mock_report_vdur_updates.call_args_list
        self.assertEqual(
            _call_mock_report_vdur_updates[0].args,
            (server1, sample_vm, ports),
        )
        self.assertEqual(
            _call_mock_report_vdur_updates[1].args,
            (server2, sample_vm2, ports),
        )

    @patch("osm_ng_ro.monitor.MonitorVms.report_vdur_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.report_deleted_vdur")
    def test_update_vnfrs_empty_vms_to_monitor(
        self, mock_report_deleted_vdur, mock_report_vdur_updates
    ):
        vms_to_monitor = []
        servers = [server1, server2, server3, server4]
        ports = {"ports": [port1, port2]}
        self.monitor.update_vnfrs(servers, ports, vms_to_monitor)
        check_if_assert_not_called([mock_report_deleted_vdur, mock_report_vdur_updates])

    @patch("osm_ng_ro.monitor.MonitorVms.report_vdur_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.report_deleted_vdur")
    def test_update_vnfrs_empty_servers(
        self, mock_report_deleted_vdur, mock_report_vdur_updates
    ):
        vms_to_monitor = [sample_vm, sample_vm2, sample_vm3]
        servers = []
        ports = {"ports": [port1, port2]}
        self.monitor.update_vnfrs(servers, ports, vms_to_monitor)
        mock_report_vdur_updates.assert_not_called()
        self.assertEqual(mock_report_deleted_vdur.call_count, 3)
        _call_mock_report_deleted_vdur = mock_report_deleted_vdur.call_args_list
        self.assertEqual(
            _call_mock_report_deleted_vdur[0].args[0],
            (sample_vm),
        )
        self.assertEqual(
            _call_mock_report_deleted_vdur[1].args[0],
            (sample_vm2),
        )
        self.assertEqual(
            _call_mock_report_deleted_vdur[2].args[0],
            (sample_vm3),
        )

    @patch("osm_ng_ro.monitor.MonitorVms.report_vdur_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.report_deleted_vdur")
    def test_update_vnfrs_report_vdur_updates_raises(
        self, mock_report_deleted_vdur, mock_report_vdur_updates
    ):
        vms_to_monitor = [sample_vm, sample_vm2, sample_vm3]
        servers = [server1, server2, server3, server4]
        ports = {"ports": [port1, port2]}
        mock_report_vdur_updates.side_effect = IndexError("list index out of range.")
        with self.assertRaises(IndexError) as err:
            self.monitor.update_vnfrs(servers, ports, vms_to_monitor)
        self.assertEqual(str(err.exception.args[0]), "list index out of range.")
        self.assertEqual(mock_report_vdur_updates.call_count, 1)
        mock_report_deleted_vdur.assert_not_called()
        _call_mock_report_vdur_updates = mock_report_vdur_updates.call_args_list
        self.assertEqual(
            _call_mock_report_vdur_updates[0].args,
            (server1, sample_vm, ports),
        )

    @patch("osm_ng_ro.monitor.MonitorVms.report_vdur_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.report_deleted_vdur")
    def test_update_vnfrs_report_deleted_vdur_raises(
        self, mock_report_deleted_vdur, mock_report_vdur_updates
    ):
        vms_to_monitor = [sample_vm, sample_vm2, sample_vm3]
        servers = [server1, server2, server3, server4]
        ports = {"ports": [port1, port2]}
        mock_report_deleted_vdur.side_effect = DbException("DB is not in active state.")
        with self.assertRaises(DbException) as err:
            self.monitor.update_vnfrs(servers, ports, vms_to_monitor)
        self.assertEqual(
            str(err.exception.args[0]), "database exception DB is not in active state."
        )
        self.assertEqual(mock_report_vdur_updates.call_count, 2)
        mock_report_deleted_vdur.assert_called_once_with(sample_vm3)
        _call_mock_report_vdur_updates = mock_report_vdur_updates.call_args_list
        self.assertEqual(
            _call_mock_report_vdur_updates[0].args,
            (server1, sample_vm, ports),
        )
        self.assertEqual(
            _call_mock_report_vdur_updates[1].args,
            (server2, sample_vm2, ports),
        )

    @patch("osm_ng_ro.monitor.yaml")
    def test_serialize_string_value(self, mock_yaml):
        value = "some string"
        result = self.monitor.serialize(value)
        mock_yaml.dump.assert_not_called()
        self.assertEqual(result, value)

    @patch("osm_ng_ro.monitor.yaml")
    def test_serialize_list_value(self, mock_yaml):
        value = [
            {"version": 3.4},
            ["image", "ghcr.io/foo/mysvc"],
            {"MYSVC_ENV": "to_nice_yaml"},
        ]
        output = [
            {"version": 3.4},
            ["image", "ghcr.io/foo/mysvc"],
            {"MYSVC_ENV": "to_nice_yaml"},
        ]
        mock_yaml.dump.return_value = output
        result = self.monitor.serialize(value)
        mock_yaml.dump.assert_called_once()
        self.assertEqual(result, output)

    @patch("osm_ng_ro.monitor.yaml")
    def test_serialize_dict_value(self, mock_yaml):
        value = {
            "version": 3.4,
            "MYSVC_ENV": "to_nice_yaml_to_nice_yaml_to_nice_yaml_to_nice_yaml_to_nice_yaml",
        }
        output = {
            "MYSVC_ENV": "to_nice_yaml_to_nice_yaml_to_nice_yaml_to_nice_yaml_to_nice_yaml",
            "version": 3.4,
        }
        mock_yaml.dump.return_value = output
        result = self.monitor.serialize(value)
        mock_yaml.dump.assert_called_once()
        self.assertEqual(result, output)

    @patch("osm_ng_ro.monitor.yaml")
    def test_serialize_raise_representer_error(self, mock_yaml):
        value = {
            "name": {"firstname": str, "lastname": str},
            "age": int,
        }
        mock_yaml.dump.side_effect = yaml.representer.RepresenterError(
            "cannot represent an object"
        )
        result = self.monitor.serialize(value)
        mock_yaml.dump.assert_called_once()
        self.assertEqual(result, str(value))

    @patch("osm_ng_ro.monitor.yaml")
    def test_serialize_raise_yaml_error(self, mock_yaml):
        value = {
            "name": {"firstname": str, "lastname": str},
            "age": int,
        }

        mock_yaml.dump.side_effect = yaml.YAMLError("cannot represent an object.")
        with self.assertRaises(yaml.YAMLError) as err:
            result = self.monitor.serialize(value)
            self.assertEqual(result, None)
        self.assertEqual(str(err.exception.args[0]), "cannot represent an object.")
        mock_yaml.dump.assert_called_once()

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_get_server_info_with_user_data(self, mock_serialize):
        all_server_info = deepcopy(server_other_info)
        user_data = {
            "OS-EXT-SRV-ATTR:user_data": "EXT-USER-DATA",
            "user_data": "some-data",
        }
        mock_serialize.return_value = serialized_server_info
        all_server_info.update(user_data)
        server5 = create_server(vm1_id, "server5", info=all_server_info)
        result = self.monitor._get_server_info(server5)
        self.assertEqual(result, serialized_server_info)
        mock_serialize.assert_called_once_with(server_other_info)

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_get_server_info_without_user_data(self, mock_serialize):
        mock_serialize.return_value = serialized_server_info
        server5 = create_server(vm1_id, "server5", info=server_other_info)
        result = self.monitor._get_server_info(server5)
        self.assertEqual(result, serialized_server_info)
        mock_serialize.assert_called_once_with(server_other_info)

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_get_server_info_empty_server_info(self, mock_serialize):
        server_other_info = {}
        expected_result = {}
        mock_serialize.return_value = expected_result
        server5 = create_server(vm1_id, "server5", info=server_other_info)
        result = self.monitor._get_server_info(server5)
        self.assertEqual(result, expected_result)
        mock_serialize.assert_called_once_with(server_other_info)

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_get_server_info_serialize_raises(self, mock_serialize):
        server_other_info = {
            "admin_state_up": "true",
            "binding:host_id": int,
            "binding:profile": {},
            "binding:vif_type": str,
            "binding:vnic_type": "normal",
            "created_at": "2023-02-22T05:35:46Z",
        }
        mock_serialize.side_effect = yaml.YAMLError("cannot represent an object.")
        server5 = create_server(vm1_id, "server5", info=server_other_info)
        with self.assertRaises(yaml.YAMLError) as err:
            self.monitor._get_server_info(server5)
        self.assertEqual(str(err.exception.args[0]), "cannot represent an object.")
        mock_serialize.assert_called_once_with(server_other_info)

    @patch("osm_ng_ro.monitor.MonitorVms._get_server_info")
    def test_check_vm_status_updates_server_status_ok(self, mock_server_info):
        server6 = create_server("server6-id", "server6", status="PAUSED")
        mock_server_info.return_value = serialized_server_info
        vdur_vim_info_update = {}
        vdur_update = {}
        expected_vdur_vim_info_update = {
            "vim_status": "PAUSED",
            "vim_details": serialized_server_info,
            "vim_id": server6.id,
            "vim_name": server6.name,
        }
        expected_vdur_update = {
            "vdur.0.status": "PAUSED",
            "vdur.0.name": server6.name,
        }
        self.monitor.check_vm_status_updates(
            vdur_vim_info_update, vdur_update, server6, vdur_path
        )
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info_update)
        self.assertDictEqual(vdur_update, expected_vdur_update)
        mock_server_info.assert_called_once_with(server6)

    @patch("osm_ng_ro.monitor.MonitorVms._get_server_info")
    def test_check_vm_status_updates_server_status_nok(self, mock_server_info):
        server8 = create_server("server8-id", "server8", status="FAILED")
        mock_server_info.return_value = serialized_server_info
        vdur_vim_info_update = {}
        vdur_update = {}
        expected_vdur_vim_info_update = {
            "vim_status": "FAILED",
            "vim_details": serialized_server_info,
            "vim_id": server8.id,
            "vim_name": server8.name,
            "vim_message": "VIM status reported FAILED",
        }
        expected_vdur_update = {
            "vdur.0.status": "FAILED",
            "vdur.0.name": server8.name,
        }
        self.monitor.check_vm_status_updates(
            vdur_vim_info_update, vdur_update, server8, vdur_path
        )
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info_update)
        self.assertDictEqual(vdur_update, expected_vdur_update)
        mock_server_info.assert_called_once_with(server8)

    @patch("osm_ng_ro.monitor.MonitorVms._get_server_info")
    def test_check_vm_status_updates_get_server_info_raises(self, mock_server_info):
        server8 = create_server("server8-id", "server8", status="FAILED")
        mock_server_info.side_effect = yaml.YAMLError("Cannot represent an object.")
        vdur_vim_info_update = {}
        vdur_update = {}
        expected_vdur_vim_info_update = {
            "vim_status": "FAILED",
            "vim_message": "VIM status reported FAILED",
        }
        expected_vdur_update = {
            "vdur.0.status": "FAILED",
        }
        with self.assertRaises(yaml.YAMLError) as err:
            self.monitor.check_vm_status_updates(
                vdur_vim_info_update, vdur_update, server8, vdur_path
            )
        self.assertEqual(str(err.exception.args[0]), "Cannot represent an object.")
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info_update)
        self.assertDictEqual(vdur_update, expected_vdur_update)
        mock_server_info.assert_called_once_with(server8)

    def test_get_interface_info(self):
        interface = {"vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013"}
        ports = {"ports": [port1, port2]}
        result = self.monitor.get_interface_info(ports, interface, server1)
        self.assertEqual(result, port1)

    def test_get_interface_info_port_id_mismatch(self):
        interface = {"vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013"}
        ports = {"ports": [port2]}
        result = self.monitor.get_interface_info(ports, interface, server1)
        self.assertEqual(result, None)

    def test_get_interface_info_device_id_mismatch(self):
        interface = {"vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013"}
        ports = {"ports": [port1, port2]}
        result = self.monitor.get_interface_info(ports, interface, server2)
        self.assertEqual(result, None)

    def test_get_interface_info_empty_ports(self):
        interface = {"vim_interface_id": "4d081f50-e13a-4306-a67e-1edb28d76013"}
        ports = {"ports": []}
        result = self.monitor.get_interface_info(ports, interface, server2)
        self.assertEqual(result, None)

    def test_check_vlan_pci_update(self):
        interface_info = interface_with_binding
        index = 1
        vdur_vim_info_update = {"interfaces": [{}, {}]}
        expected_vdur_vim_info_update = {
            "interfaces": [{}, {"pci": "0000:86:17.4", "vlan": 400}]
        }
        self.monitor.check_vlan_pci_updates(interface_info, index, vdur_vim_info_update)
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info_update)

    def test_check_vlan_pci_update_empty_interface_info(self):
        interface_info = {}
        index = 1
        vdur_vim_info_update = {"interfaces": [{}, {}]}
        expected_vdur_vim_info_update = {"interfaces": [{}, {}]}
        self.monitor.check_vlan_pci_updates(interface_info, index, vdur_vim_info_update)
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info_update)

    def test_check_vlan_pci_update_index_out_of_range(self):
        interface_info = interface_with_binding
        index = 3
        vdur_vim_info_update = {"interfaces": [{}]}
        expected_vdur_vim_info_update = {"interfaces": [{}]}
        with self.assertRaises(IndexError) as err:
            self.monitor.check_vlan_pci_updates(
                interface_info, index, vdur_vim_info_update
            )
        self.assertEqual(str(err.exception.args[0]), "list index out of range")
        self.assertEqual(vdur_vim_info_update, expected_vdur_vim_info_update)

    def test_check_vlan_pci_update_empty_vdur_vim_info_update(self):
        interface_info = interface_with_binding
        index = 0
        vdur_vim_info_update = {}
        expected_vdur_vim_info_update = {}
        with self.assertRaises(KeyError) as err:
            self.monitor.check_vlan_pci_updates(
                interface_info, index, vdur_vim_info_update
            )
        self.assertEqual(str(err.exception.args[0]), "interfaces")
        self.assertEqual(vdur_vim_info_update, expected_vdur_vim_info_update)

    @patch("osm_ng_ro.monitor.MonitorVms._get_current_ip_address")
    def test_check_vdur_interface_updates(self, mock_get_current_ip_address):
        vdur_update, vnfr_update = {}, {}
        index = 0
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac1_addr,
        }
        mock_get_current_ip_address.return_value = ip1_addr
        expected_vdur_update = {
            "vdur.0.interfaces.0.ip-address": ip1_addr,
            "vdur.0.ip-address": ip1_addr,
            "vdur.0.interfaces.0.mac-address": mac1_addr,
        }
        expected_vnfr_update = {
            "35c034cc-8c5b-48c4-bfa2-17a71577ef19.ip-address": ip1_addr
        }
        self.monitor.check_vdur_interface_updates(
            vdur_update,
            vdur_path,
            index,
            interface_info,
            old_interface2,
            vnfr_update,
            vnfr_id,
        )
        self.assertEqual(vnfr_update, expected_vnfr_update)
        self.assertEqual(vdur_update, expected_vdur_update)
        mock_get_current_ip_address.assert_called_once_with(interface_info)

    @patch("osm_ng_ro.monitor.MonitorVms._get_current_ip_address")
    def test_check_vdur_interface_updates_not_mgmt_interface(
        self, mock_get_current_ip_address
    ):
        vdur_update, vnfr_update = {}, {}
        index = 0
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac1_addr,
        }
        mock_get_current_ip_address.return_value = ip1_addr
        old_interface = {}
        expected_vdur_update = {
            "vdur.0.interfaces.0.ip-address": ip1_addr,
            "vdur.0.interfaces.0.mac-address": mac1_addr,
        }
        self.monitor.check_vdur_interface_updates(
            vdur_update,
            vdur_path,
            index,
            interface_info,
            old_interface,
            vnfr_update,
            vnfr_id,
        )
        self.assertEqual(vnfr_update, {})
        self.assertEqual(vdur_update, expected_vdur_update)
        mock_get_current_ip_address.assert_called_once_with(interface_info)

    @patch("osm_ng_ro.monitor.MonitorVms._get_current_ip_address")
    def test_check_vdur_interface_updates_without_mac_address(
        self, mock_get_current_ip_address
    ):
        vdur_update, vnfr_update = {}, {}
        index = 0
        interface_info = {"fixed_ips": [{"ip_address": ip1_addr}]}
        mock_get_current_ip_address.return_value = ip1_addr
        expected_vdur_update = {
            "vdur.0.interfaces.0.ip-address": ip1_addr,
            "vdur.0.ip-address": ip1_addr,
            "vdur.0.interfaces.0.mac-address": None,
        }
        expected_vnfr_update = {
            "35c034cc-8c5b-48c4-bfa2-17a71577ef19.ip-address": ip1_addr
        }
        self.monitor.check_vdur_interface_updates(
            vdur_update,
            vdur_path,
            index,
            interface_info,
            old_interface2,
            vnfr_update,
            vnfr_id,
        )
        self.assertEqual(vnfr_update, expected_vnfr_update)
        self.assertEqual(vdur_update, expected_vdur_update)
        mock_get_current_ip_address.assert_called_once_with(interface_info)

    @patch("osm_ng_ro.monitor.MonitorVms._get_current_ip_address")
    def test_check_vdur_interface_updates_without_ip_address(
        self, mock_get_current_ip_address
    ):
        vdur_update, vnfr_update = {}, {}
        index = 0
        interface_info = {"fixed_ips": [], "mac_address": mac1_addr}
        mock_get_current_ip_address.return_value = None
        expected_vdur_update = {
            "vdur.0.interfaces.0.mac-address": mac1_addr,
        }
        expected_vnfr_update = {}
        self.monitor.check_vdur_interface_updates(
            vdur_update,
            vdur_path,
            index,
            interface_info,
            old_interface2,
            vnfr_update,
            vnfr_id,
        )
        self.assertEqual(vnfr_update, expected_vnfr_update)
        self.assertEqual(vdur_update, expected_vdur_update)
        mock_get_current_ip_address.assert_called_once_with(interface_info)

    @patch("osm_ng_ro.monitor.MonitorVms._get_current_ip_address")
    def test_check_vdur_interface_updates_wrong_interface_info_format(
        self, mock_get_current_ip_address
    ):
        vdur_update, vnfr_update = {}, {}
        index = 0
        interface_info = {"fixed_ips": ip1_addr, "mac_address": mac1_addr}
        mock_get_current_ip_address.side_effect = TypeError(
            "str is not list like object."
        )
        old_interface = {}
        with self.assertRaises(TypeError) as err:
            self.monitor.check_vdur_interface_updates(
                vdur_update,
                vdur_path,
                index,
                interface_info,
                old_interface,
                vnfr_update,
                vnfr_id,
            )
        self.assertEqual(str(err.exception), "str is not list like object.")
        self.assertEqual(vnfr_update, {})
        self.assertEqual(vdur_update, {})
        mock_get_current_ip_address.assert_called_once_with(interface_info)

    def test_get_current_ip_address(self):
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac1_addr,
        }
        result = self.monitor._get_current_ip_address(interface_info)
        self.assertEqual(result, ip1_addr)

    def test_get_current_ip_address_no_ip(self):
        interface_info = {"fixed_ips": [{}], "mac_address": mac1_addr}
        result = self.monitor._get_current_ip_address(interface_info)
        self.assertEqual(result, None)

    def test_backup_vdu_interfaces_without_vim_message(self):
        vdur_vim_info_update = {
            "interfaces": {"mac_address": mac1_addr},
        }
        expected_vdur_vim_info_update = {
            "interfaces": {"mac_address": mac1_addr},
            "interfaces_backup": {"mac_address": mac1_addr},
        }
        self.monitor.backup_vdu_interfaces(vdur_vim_info_update)
        self.assertDictEqual(expected_vdur_vim_info_update, vdur_vim_info_update)

    def test_backup_vdu_interfaces_with_vim_message(self):
        vdur_vim_info_update = {
            "interfaces": {"mac_address": mac1_addr},
            "vim_message": "Deleted Externally",
        }
        expected_vdur_vim_info_update = {
            "interfaces": {"mac_address": mac1_addr},
            "vim_message": "Deleted Externally",
        }
        self.monitor.backup_vdu_interfaces(vdur_vim_info_update)
        self.assertDictEqual(expected_vdur_vim_info_update, vdur_vim_info_update)

    def test_backup_vdu_interfaces_with_empty_interfaces(self):
        vdur_vim_info_update = {
            "interfaces": {},
        }
        expected_vdur_vim_info_update = {
            "interfaces": {},
        }
        self.monitor.backup_vdu_interfaces(vdur_vim_info_update)
        self.assertDictEqual(expected_vdur_vim_info_update, vdur_vim_info_update)

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_update_vdur_vim_info_interfaces(self, mock_serialize):
        index = 1
        vdur_vim_info_update = {
            "interfaces": [{}, {"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        all_server_info = deepcopy(server_other_info)
        host_data = {"OS-EXT-SRV-ATTR:host": "nova"}
        mock_serialize.return_value = serialized_interface_info
        all_server_info.update(host_data)
        server7 = create_server(vm1_id, "server7", info=all_server_info)
        expected_vdur_vim_info_update = {
            "interfaces": [
                {},
                {
                    "mac_address": mac2_addr,
                    "compute_node": "nova",
                    "vim_info": serialized_interface_info,
                    "vim_net_id": net1_id,
                    "ip_address": ip1_addr,
                },
            ]
        }
        self.monitor.update_vdur_vim_info_interfaces(
            vdur_vim_info_update, index, interface_info2, server7
        )
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info_update)
        mock_serialize.assert_called_once_with(interface_info2)

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_update_vdur_vim_info_interfaces_serialize_raises(self, mock_serialize):
        index = 1
        vdur_vim_info_update = {
            "interfaces": [{}, {"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        all_server_info = deepcopy(server_other_info)
        host_data = {"OS-EXT-SRV-ATTR:host": "nova"}
        mock_serialize.side_effect = yaml.YAMLError("Cannot represent an object.")
        all_server_info.update(host_data)
        server7 = create_server(vm1_id, "server7", info=all_server_info)
        expected_vdur_vim_info = deepcopy(vdur_vim_info_update)
        with self.assertRaises(yaml.YAMLError) as err:
            self.monitor.update_vdur_vim_info_interfaces(
                vdur_vim_info_update, index, interface_info2, server7
            )
        self.assertEqual(str(err.exception), "Cannot represent an object.")
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info)
        mock_serialize.assert_called_once_with(interface_info2)

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_update_vdur_vim_info_interfaces_empty_interface_info(self, mock_serialize):
        index = 1
        vdur_vim_info_update = {
            "interfaces": [{}, {"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        interface_info = {}
        all_server_info = deepcopy(server_other_info)
        host_data = {"OS-EXT-SRV-ATTR:host": "nova"}
        all_server_info.update(host_data)
        server7 = create_server(vm1_id, "server7", info=all_server_info)
        expected_vdur_vim_info = deepcopy(vdur_vim_info_update)
        with self.assertRaises(KeyError) as err:
            self.monitor.update_vdur_vim_info_interfaces(
                vdur_vim_info_update, index, interface_info, server7
            )
        self.assertEqual(str(err.exception.args[0]), "mac_address")
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info)
        mock_serialize.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.serialize")
    def test_update_vdur_vim_info_interfaces_invalid_vdur_vim_info(
        self, mock_serialize
    ):
        index = 1
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}, {}]
        }
        expected_vdur_vim_info = deepcopy(vdur_vim_info_update)
        with self.assertRaises(MonitorVmsException) as err:
            self.monitor.update_vdur_vim_info_interfaces(
                vdur_vim_info_update, index, interface_info2, server7
            )
        self.assertEqual(
            str(err.exception.args[0]), "Existing interfaces info could not found."
        )
        self.assertDictEqual(vdur_vim_info_update, expected_vdur_vim_info)
        mock_serialize.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.update_vdur_vim_info_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vlan_pci_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vdur_interface_updates")
    def test_prepare_interface_updates(
        self,
        mock_check_vdur_interface_updates,
        mock_check_vlan_pci_updates,
        mock_update_vdur_vim_info_interfaces,
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac2_addr,
            "network_id": net1_id,
        }
        old_interface = {
            "mgmt_vdu_interface": True,
            "mgmt_vnf_interface": True,
        }
        index = 0
        vnfr_update, vdur_update = {}, {}
        self.monitor.prepare_interface_updates(
            vdur_vim_info_update,
            index,
            interface_info,
            server7,
            vdur_path,
            vnfr_update,
            old_interface2,
            vdur_update,
            vnfr_id,
        )
        mock_update_vdur_vim_info_interfaces.assert_called_once_with(
            vdur_vim_info_update, index, interface_info, server7
        )
        mock_check_vlan_pci_updates.assert_called_once_with(
            interface_info, index, vdur_vim_info_update
        )
        mock_check_vdur_interface_updates.assert_called_once_with(
            vdur_update,
            vdur_path,
            index,
            interface_info,
            old_interface,
            vnfr_update,
            vnfr_id,
        )

    @patch("osm_ng_ro.monitor.MonitorVms.update_vdur_vim_info_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vlan_pci_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vdur_interface_updates")
    def test_prepare_interface_updates_update_vdur_vim_info_interfaces_raises(
        self,
        mock_check_vdur_interface_updates,
        mock_check_vlan_pci_updates,
        mock_update_vdur_vim_info_interfaces,
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        index = 0
        vnfr_update, vdur_update = {}, {}
        mock_update_vdur_vim_info_interfaces.side_effect = MonitorVmsException(
            "Existing interfaces info could not found."
        )
        with self.assertRaises(MonitorVmsException) as err:
            self.monitor.prepare_interface_updates(
                vdur_vim_info_update,
                index,
                interface_info2,
                server7,
                vdur_path,
                vnfr_update,
                old_interface2,
                vdur_update,
                vnfr_id,
            )
        self.assertEqual(
            str(err.exception.args[0]), "Existing interfaces info could not found."
        )
        mock_update_vdur_vim_info_interfaces.assert_called_once_with(
            vdur_vim_info_update, index, interface_info2, server7
        )
        check_if_assert_not_called(
            [mock_check_vlan_pci_updates, mock_check_vdur_interface_updates]
        )

    @patch("osm_ng_ro.monitor.MonitorVms.update_vdur_vim_info_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vlan_pci_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vdur_interface_updates")
    def test_prepare_interface_updates_check_vlan_pci_updates_raises(
        self,
        mock_check_vdur_interface_updates,
        mock_check_vlan_pci_updates,
        mock_update_vdur_vim_info_interfaces,
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        index = 0
        vnfr_update, vdur_update = {}, {}
        mock_check_vlan_pci_updates.side_effect = KeyError("vlan is not found.")
        with self.assertRaises(KeyError) as err:
            self.monitor.prepare_interface_updates(
                vdur_vim_info_update,
                index,
                interface_info2,
                server7,
                vdur_path,
                vnfr_update,
                old_interface2,
                vdur_update,
                vnfr_id,
            )
        self.assertEqual(str(err.exception.args[0]), "vlan is not found.")
        mock_update_vdur_vim_info_interfaces.assert_called_once_with(
            vdur_vim_info_update, index, interface_info2, server7
        )
        mock_check_vlan_pci_updates.assert_called_once_with(
            interface_info2, index, vdur_vim_info_update
        )
        mock_check_vdur_interface_updates.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms.get_interface_info")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_interface_updates")
    def test_check_vm_interface_updates(
        self, mock_prepare_interface_updates, mock_get_interface_info
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        index = 0
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac2_addr,
            "network_id": net1_id,
            "status": "ACTIVE",
        }
        vnfr_update, vdur_update = {}, {}
        ports = {"ports": [port1, port2]}
        existing_vim_info = sample_vim_info
        mock_get_interface_info.return_value = interface_info
        self.monitor.check_vm_interface_updates(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            vdur_update,
            vdur_path,
            vnfr_update,
            vnfr_id,
        )
        mock_get_interface_info.assert_called_once_with(ports, old_interface, server7)
        mock_prepare_interface_updates.assert_called_once_with(
            vdur_vim_info_update,
            index,
            interface_info,
            server7,
            vdur_path,
            vnfr_update,
            old_interface,
            vdur_update,
            vnfr_id,
        )
        self.assertNotIn("vim_message", vdur_vim_info_update)

    @patch("osm_ng_ro.monitor.MonitorVms.get_interface_info")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_interface_updates")
    def test_check_vm_interface_updates_interface_new_status_is_nok(
        self, mock_prepare_interface_updates, mock_get_interface_info
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac2_addr,
            "network_id": net1_id,
            "status": "DOWN",
        }
        vnfr_update, vdur_update = {}, {}
        ports = {"ports": [port1, port2]}
        existing_vim_info = sample_vim_info
        mock_get_interface_info.return_value = interface_info
        self.monitor.check_vm_interface_updates(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            vdur_update,
            vdur_path,
            vnfr_update,
            vnfr_id,
        )
        mock_get_interface_info.assert_called_once_with(ports, old_interface, server7)
        mock_prepare_interface_updates.assert_not_called()
        self.assertEqual(
            vdur_vim_info_update["vim_message"],
            "Interface 4d081f50-e13a-4306-a67e-1edb28d76013 status: DOWN",
        )

    @patch("osm_ng_ro.monitor.MonitorVms.get_interface_info")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_interface_updates")
    def test_check_vm_interface_updates_no_new_interface_info(
        self, mock_prepare_interface_updates, mock_get_interface_info
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        vnfr_update, vdur_update = {}, {}
        ports = {"ports": [port1, port2]}
        existing_vim_info = sample_vim_info
        mock_get_interface_info.return_value = None
        self.monitor.check_vm_interface_updates(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            vdur_update,
            vdur_path,
            vnfr_update,
            vnfr_id,
        )
        mock_get_interface_info.assert_called_once_with(ports, old_interface, server7)
        mock_prepare_interface_updates.assert_not_called()
        self.assertEqual(
            vdur_vim_info_update["vim_message"],
            "Interface 4d081f50-e13a-4306-a67e-1edb28d76013 deleted externally.",
        )

    @patch("osm_ng_ro.monitor.MonitorVms.get_interface_info")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_interface_updates")
    def test_check_vm_interface_updates_no_existing_interface(
        self, mock_prepare_interface_updates, mock_get_interface_info
    ):
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        interface_info = {
            "fixed_ips": [{"ip_address": ip1_addr}],
            "mac_address": mac2_addr,
            "network_id": net1_id,
            "status": "ACTIVE",
        }
        vnfr_update, vdur_update = {}, {}
        ports = {"ports": [port1, port2]}
        updated_sample_vim_info = deepcopy(sample_vim_info)
        updated_sample_vim_info["interfaces"] = []
        existing_vim_info = updated_sample_vim_info
        mock_get_interface_info.return_value = interface_info
        self.monitor.check_vm_interface_updates(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            vdur_update,
            vdur_path,
            vnfr_update,
            vnfr_id,
        )
        check_if_assert_not_called(
            [mock_get_interface_info, mock_prepare_interface_updates]
        )
        self.assertNotIn("vim_message", vdur_vim_info_update)

    def test_update_in_database(self):
        all_updates = [{"some-key": "some-value"}, {"other-key": "other-value"}]
        self.monitor.update_in_database(all_updates, vnfr_id)
        self.assertEqual(self.monitor.db.set_list.call_count, 2)
        _call_mock_set_list = self.monitor.db.set_list.call_args_list
        self.assertEqual(
            _call_mock_set_list[0][0],
            ("vnfrs",),
        )
        self.assertEqual(
            _call_mock_set_list[0][1],
            (
                {
                    "q_filter": {"_id": vnfr_id},
                    "update_dict": {"some-key": "some-value"},
                }
            ),
        )
        self.assertEqual(
            _call_mock_set_list[1][0],
            ("vnfrs",),
        )
        self.assertEqual(
            _call_mock_set_list[1][1],
            (
                {
                    "q_filter": {"_id": vnfr_id},
                    "update_dict": {"other-key": "other-value"},
                }
            ),
        )

    def test_update_in_database_set_list_raises(self):
        all_updates = [{"some-key": "some-value"}, {"other-key": "other-value"}]
        self.monitor.db.set_list.side_effect = DbException("Connection failed.")
        with self.assertRaises(MonitorDbException) as err:
            self.monitor.update_in_database(all_updates, vnfr_id)
        self.assertEqual(
            str(err.exception.args[0]),
            "Error while updating differences in VNFR database exception Connection failed.",
        )
        self.assertEqual(self.monitor.db.set_list.call_count, 1)
        _call_mock_set_list = self.monitor.db.set_list.call_args_list
        self.assertEqual(
            _call_mock_set_list[0][0],
            ("vnfrs",),
        )
        self.assertEqual(
            _call_mock_set_list[0][1],
            (
                {
                    "q_filter": {"_id": vnfr_id},
                    "update_dict": {"some-key": "some-value"},
                }
            ),
        )

    def test_update_in_database_empty_all_updates(self):
        all_updates = []
        self.monitor.update_in_database(all_updates, vnfr_id)
        self.monitor.db.set_list.assert_not_called()

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_status_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_interface_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_vdur_updates_no_change_in_vdur(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_check_vm_interface_updates,
        mock_check_vm_status_updates,
        mock_get_vm_data_from_db,
    ):
        existing_vim_info = sample_vim_info
        vdur_vim_info_update = deepcopy(existing_vim_info)
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        ports = {"ports": [port1, port2]}
        self.monitor.report_vdur_updates(server7, sample_vm, ports)
        check_if_assert_not_called(
            [mock_update_in_database, mock_backup_vdu_interfaces]
        )
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_check_vm_status_updates.assert_called_once_with(
            vdur_vim_info_update, {}, server7, vdur_path
        )
        mock_check_vm_interface_updates.assert_called_once_with(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            {},
            vdur_path,
            {},
            vnfr_id,
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_status_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_interface_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_vdur_updates_vdur_changed(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_check_vm_interface_updates,
        mock_check_vm_status_updates,
        mock_get_vm_data_from_db,
    ):
        existing_vim_info = sample_vim_info
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        all_updates = [{}, {vim_info_path: vdur_vim_info_update}, {}]
        ports = {"ports": [port1, port2]}
        self.monitor.report_vdur_updates(server7, sample_vm, ports)
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_check_vm_status_updates.assert_called_once_with(
            vdur_vim_info_update, {}, server7, vdur_path
        )
        mock_check_vm_interface_updates.assert_called_once_with(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            {},
            vdur_path,
            {},
            vnfr_id,
        )
        mock_backup_vdu_interfaces.assert_called_once_with(vdur_vim_info_update)
        mock_update_in_database.assert_called_once_with(all_updates, vnfr_id)

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_status_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_interface_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_vdur_updates_check_vm_status_updates_raises(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_check_vm_interface_updates,
        mock_check_vm_status_updates,
        mock_get_vm_data_from_db,
    ):
        existing_vim_info = sample_vim_info
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        ports = {"ports": [port1, port2]}
        mock_check_vm_status_updates.side_effect = yaml.YAMLError(
            "Cannot represent an object."
        )
        with self.assertRaises(yaml.YAMLError) as err:
            self.monitor.report_vdur_updates(server7, sample_vm, ports)
        self.assertEqual(str(err.exception), "Cannot represent an object.")
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_check_vm_status_updates.assert_called_once_with(
            vdur_vim_info_update, {}, server7, vdur_path
        )
        check_if_assert_not_called(
            [
                mock_check_vm_interface_updates,
                mock_backup_vdu_interfaces,
                mock_update_in_database,
            ]
        )

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_status_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_interface_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_vdur_updates_database_update_raises(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_check_vm_interface_updates,
        mock_check_vm_status_updates,
        mock_get_vm_data_from_db,
    ):
        existing_vim_info = sample_vim_info
        vdur_vim_info_update = {
            "interfaces": [{"mac_address": mac1_addr, "compute_node": "host1"}]
        }
        mock_get_vm_data_from_db.return_value = (
            vdur_path,
            vdur_vim_info_update,
            None,
            existing_vim_info,
            vnfr_id,
            vim_info_path,
        )
        all_updates = [{}, {vim_info_path: vdur_vim_info_update}, {}]
        ports = {"ports": [port1, port2]}
        mock_update_in_database.side_effect = MonitorDbException(
            f"Error while updating differences in VNFR {vnfr_id}."
        )
        with self.assertRaises(MonitorDbException) as err:
            self.monitor.report_vdur_updates(server7, sample_vm, ports)
        self.assertEqual(
            str(err.exception), f"Error while updating differences in VNFR {vnfr_id}."
        )
        mock_get_vm_data_from_db.assert_called_with(sample_vm)
        self.assertEqual(mock_get_vm_data_from_db.call_count, 1)
        mock_check_vm_status_updates.assert_called_once_with(
            vdur_vim_info_update, {}, server7, vdur_path
        )
        mock_check_vm_interface_updates.assert_called_once_with(
            server7,
            existing_vim_info,
            ports,
            vdur_vim_info_update,
            {},
            vdur_path,
            {},
            vnfr_id,
        )
        mock_backup_vdu_interfaces.assert_called_once_with(vdur_vim_info_update)
        mock_update_in_database.assert_called_once_with(all_updates, vnfr_id)

    @patch("osm_ng_ro.monitor.MonitorVms._get_vm_data_from_db")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_status_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.check_vm_interface_updates")
    @patch("osm_ng_ro.monitor.MonitorVms.backup_vdu_interfaces")
    @patch("osm_ng_ro.monitor.MonitorVms.update_in_database")
    def test_report_vdur_updates_no_vm_data(
        self,
        mock_update_in_database,
        mock_backup_vdu_interfaces,
        mock_check_vm_interface_updates,
        mock_check_vm_status_updates,
        mock_get_vm_data_from_db,
    ):
        mock_get_vm_data_from_db.return_value = None
        ports = {"ports": [port1, port2]}
        self.monitor.report_vdur_updates(server7, sample_vm, ports)
        check_if_assert_not_called(
            [
                mock_update_in_database,
                mock_backup_vdu_interfaces,
                mock_check_vm_interface_updates,
                mock_check_vm_status_updates,
            ]
        )
        mock_get_vm_data_from_db.assert_called_once_with(sample_vm)

    @patch("osm_ng_ro.monitor.MonitorVms.find_ro_tasks_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_vims_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vnfrs")
    def test_run_no_db_vims(
        self,
        mock_update_vnfrs,
        mock_prepare_vims_to_monitor,
        mock_find_ro_tasks_to_monitor,
    ):
        self.monitor.db_vims = None
        self.monitor.run()
        check_if_assert_not_called(
            [
                mock_prepare_vims_to_monitor,
                mock_find_ro_tasks_to_monitor,
                mock_update_vnfrs,
            ]
        )

    @patch("osm_ng_ro.monitor.MonitorVms.find_ro_tasks_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_vims_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vnfrs")
    def test_run_refresh_disabled(
        self,
        mock_update_vnfrs,
        mock_prepare_vims_to_monitor,
        mock_find_ro_tasks_to_monitor,
    ):
        self.monitor.db_vims = vims
        self.monitor.refresh_config.active = -1
        self.monitor.run()
        check_if_assert_not_called(
            [
                mock_prepare_vims_to_monitor,
                mock_find_ro_tasks_to_monitor,
                mock_update_vnfrs,
            ]
        )

    @patch("osm_ng_ro.monitor.MonitorVms.find_ro_tasks_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.prepare_vims_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vnfrs")
    def test_run_no_proper_ro_task(
        self,
        mock_update_vnfrs,
        mock_prepare_vims_to_monitor,
        mock_find_ro_tasks_to_monitor,
    ):
        self.monitor.db_vims = vims
        self.monitor.refresh_config.active = 60
        mock_find_ro_tasks_to_monitor.return_value = []
        self.monitor.run()
        check_if_assert_not_called([mock_prepare_vims_to_monitor, mock_update_vnfrs])
        mock_find_ro_tasks_to_monitor.assert_called_once()

    @patch("osm_ng_ro.monitor.MonitorVms.find_ro_tasks_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vnfrs")
    def test_run_with_proper_ro_task(
        self, mock_update_vnfrs, mock_find_ro_tasks_to_monitor
    ):
        self.monitor.db_vims = vims
        all_servers = [server1, server2]
        vim1_vms = [
            VmToMonitor(
                vm_id=vm1_id,
                target_record=target_record,
            )
        ]
        vim2_vms = [
            VmToMonitor(
                vm_id=vm2_id,
                target_record=target_record2,
            )
        ]
        all_ports = {"ports": [port1, port2]}
        mock_vim_connector = MagicMock()
        mock_vim_connector.get_monitoring_data.return_value = all_servers, all_ports
        self.monitor.my_vims = {
            vim1_id: mock_vim_connector,
            vim2_id: mock_vim_connector,
            vim3_id: mock_vim_connector,
        }
        self.monitor.refresh_config.active = 60
        mock_find_ro_tasks_to_monitor.return_value = [ro_task1, ro_task2]
        self.monitor.run()
        mock_find_ro_tasks_to_monitor.assert_called_once()
        _call_mock_update_vnfrs = mock_update_vnfrs.call_args_list
        self.assertEqual(mock_update_vnfrs.call_count, 2)
        self.assertEqual(
            _call_mock_update_vnfrs[0][0],
            (all_servers, all_ports, vim1_vms),
        )
        self.assertEqual(
            _call_mock_update_vnfrs[1][0],
            (all_servers, all_ports, vim2_vms),
        )
        self.assertEqual(mock_vim_connector.get_monitoring_data.call_count, 2)

    @patch("osm_ng_ro.monitor.MonitorVms.find_ro_tasks_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vnfrs")
    def test_run_update_vnfrs_raises(
        self, mock_update_vnfrs, mock_find_ro_tasks_to_monitor
    ):
        self.monitor.db_vims = vims
        all_servers = [server1, server2]
        vim1_vms = [
            VmToMonitor(
                vm_id=vm1_id,
                target_record=target_record,
            )
        ]
        all_ports = {"ports": [port1, port2]}
        mock_vim_connector = MagicMock()
        mock_vim_connector.get_monitoring_data.return_value = all_servers, all_ports
        self.monitor.my_vims = {
            vim1_id: mock_vim_connector,
            vim2_id: mock_vim_connector,
            vim3_id: mock_vim_connector,
        }
        self.monitor.refresh_config.active = 60
        mock_find_ro_tasks_to_monitor.return_value = [ro_task1, ro_task2]
        mock_update_vnfrs.side_effect = DbException("DB is not active state.")
        with self.assertRaises(MonitorVmsException) as err:
            self.monitor.run()
        self.assertEqual(
            str(err.exception),
            "Exception while monitoring Openstack VMs: database exception DB is not active state.",
        )
        mock_find_ro_tasks_to_monitor.assert_called_once()
        _call_mock_update_vnfrs = mock_update_vnfrs.call_args_list
        self.assertEqual(mock_update_vnfrs.call_count, 1)
        self.assertEqual(
            _call_mock_update_vnfrs[0][0],
            (all_servers, all_ports, vim1_vms),
        )
        self.assertEqual(mock_vim_connector.get_monitoring_data.call_count, 1)

    @patch("osm_ng_ro.monitor.MonitorVms.prepare_vims_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.find_ro_tasks_to_monitor")
    @patch("osm_ng_ro.monitor.MonitorVms.update_vnfrs")
    def test_run_prepare_vims_to_monitor_raises(
        self,
        mock_update_vnfrs,
        mock_find_ro_tasks_to_monitor,
        mock_prepare_vims_to_monitor,
    ):
        self.monitor.db_vims = vims
        mock_vim_connector = MagicMock()
        self.monitor.my_vims = {
            vim1_id: mock_vim_connector,
            vim2_id: mock_vim_connector,
            vim3_id: mock_vim_connector,
        }
        self.monitor.refresh_config.active = 60
        mock_find_ro_tasks_to_monitor.return_value = [ro_task1, ro_task2]
        mock_prepare_vims_to_monitor.side_effect = KeyError("vim_id")
        with self.assertRaises(MonitorVmsException) as err:
            self.monitor.run()
        self.assertEqual(
            str(err.exception), "Exception while monitoring Openstack VMs: 'vim_id'"
        )
        mock_find_ro_tasks_to_monitor.assert_called_once()
        check_if_assert_not_called(
            [mock_update_vnfrs, mock_vim_connector.get_monitoring_data]
        )

    @patch("osm_ng_ro.monitor.monitoring_task")
    @patch("osm_ng_ro.monitor.threading.Timer")
    @patch("osm_ng_ro.monitor.MonitorVms")
    def test_start_monitoring(
        self, mock_monitor_vms, mock_threading_timer, mock_monitoring_task
    ):
        mock_monitor_vms.return_value.refresh_config.active = 20
        mock_threading_timer.return_value = mock_monitoring_task
        start_monitoring(config)
        mock_threading_timer.assert_called_once_with(
            20, start_monitoring, args=(config,)
        )
        mock_threading_timer.return_value = CopyingMock(threading.Timer)
        self.assertEqual(mock_threading_timer.call_count, 1)
        mock_monitor_vms.return_value.run.assert_called_once()
        mock_monitor_vms.assert_called_once_with(config)
        mock_monitoring_task.start.assert_called_once()

    @patch("osm_ng_ro.monitor.monitoring_task")
    @patch("osm_ng_ro.monitor.threading.Timer")
    @patch("osm_ng_ro.monitor.MonitorVms")
    def test_start_monitoring_empty_config(
        self, mock_monitor_vms, mock_threading_timer, mock_monitoring_task
    ):
        with self.assertRaises(MonitorVmsException) as err:
            start_monitoring(config={})
        self.assertEqual(
            str(err.exception),
            "Wrong configuration format is provided.",
        )
        check_if_assert_not_called(
            [mock_threading_timer, mock_monitor_vms, mock_monitoring_task]
        )

    @patch("osm_ng_ro.monitor.monitoring_task")
    @patch("osm_ng_ro.monitor.threading.Timer")
    @patch("osm_ng_ro.monitor.MonitorVms")
    def test_start_monitoring_monitor_vms_raises(
        self, mock_monitor_vms, mock_threading_timer, mock_monitoring_task
    ):
        mock_monitor_vms.side_effect = MonitorDbException("Can not connect to DB.")
        with self.assertRaises(MonitorDbException) as err:
            start_monitoring(config)
        self.assertEqual(str(err.exception), "Can not connect to DB.")
        mock_monitor_vms.assert_called_once_with(config)
        check_if_assert_not_called([mock_threading_timer, mock_monitoring_task])

    @patch("osm_ng_ro.monitor.monitoring_task")
    @patch("osm_ng_ro.monitor.threading.Timer")
    @patch("osm_ng_ro.monitor.MonitorVms")
    def test_start_monitoring_timer_thread_raises(
        self, mock_monitor_vms, mock_threading_timer, mock_monitoring_task
    ):
        mock_threading_timer.side_effect = RuntimeError(
            "cannot release un-acquired lock"
        )
        mock_monitor_vms.return_value.refresh_config.active = 2
        with self.assertRaises(RuntimeError) as err:
            start_monitoring(config)
        self.assertEqual(str(err.exception), "cannot release un-acquired lock")
        mock_monitor_vms.assert_called_once_with(config)
        mock_monitor_vms.return_value.run.assert_called_once()
        mock_threading_timer.assert_called_once_with(
            2, start_monitoring, args=(config,)
        )
        mock_monitoring_task.start.assert_not_called()

    @patch("osm_ng_ro.monitor.monitoring_task")
    def test_stop_monitoring(self, mock_monitoring_task):
        mock_monitoring_task.return_value = CopyingMock(threading.Timer)
        stop_monitoring()
        self.assertIsNotNone(mock_monitoring_task)
        mock_monitoring_task.cancel.assert_called_once()

    @patch("osm_ng_ro.monitor.monitoring_task")
    def test_stop_monitoring_no_task(self, mock_monitoring_task):
        mock_monitoring_task = CopyingMock(threading.Timer, return_value=None)
        stop_monitoring()
        mock_monitoring_task.cancel.assert_not_called()


if __name__ == "__main__":
    unittest.main()
