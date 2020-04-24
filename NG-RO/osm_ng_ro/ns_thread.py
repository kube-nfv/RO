# -*- coding: utf-8 -*-

##
# Copyright 2020 Telefonica Investigacion y Desarrollo, S.A.U.
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
##

""""
This is thread that interacts with a VIM. It processes TASKs sequentially against a single VIM.
The tasks are stored at database in table ro_tasks
A single ro_task refers to a VIM element (flavor, image, network, ...).
A ro_task can contain several 'tasks', each one with a target, where to store the results
"""

import threading
import time
import queue
import logging
from pkg_resources import iter_entry_points
# from osm_common import dbmongo, dbmemory, fslocal, fsmongo, msglocal, msgkafka, version as common_version
from osm_common.dbbase import DbException
# from osm_common.fsbase import FsException
# from osm_common.msgbase import MsgException
from osm_ro_plugin.vim_dummy import VimDummyConnector
from osm_ro_plugin import vimconn
from copy import deepcopy
from unittest.mock import Mock

__author__ = "Alfonso Tierno"
__date__ = "$28-Sep-2017 12:07:15$"


def deep_get(target_dict, *args, **kwargs):
    """
    Get a value from target_dict entering in the nested keys. If keys does not exist, it returns None
    Example target_dict={a: {b: 5}}; key_list=[a,b] returns 5; both key_list=[a,b,c] and key_list=[f,h] return None
    :param target_dict: dictionary to be read
    :param args: list of keys to read from  target_dict
    :param kwargs: only can contain default=value to return if key is not present in the nested dictionary
    :return: The wanted value if exist, None or default otherwise
    """
    for key in args:
        if not isinstance(target_dict, dict) or key not in target_dict:
            return kwargs.get("default")
        target_dict = target_dict[key]
    return target_dict


class NsWorkerException(Exception):
    pass


class FailingConnector:
    def __init__(self, error_msg):
        self.error_msg = error_msg
        for method in dir(vimconn.VimConnector):
            if method[0] != "_":
                setattr(self, method, Mock(side_effect=vimconn.VimConnException(error_msg)))


class NsWorkerExceptionNotFound(NsWorkerException):
    pass


class NsWorker(threading.Thread):
    REFRESH_BUILD = 5  # 5 seconds
    REFRESH_ACTIVE = 60  # 1 minute
    REFRESH_ERROR = 600
    REFRESH_IMAGE = 3600 * 10
    REFRESH_DELETE = 3600 * 10
    QUEUE_SIZE = 2000
    # TODO delete assigment_lock = Lock()
    terminate = False
    # TODO delete assignment = {}
    MAX_TIME_LOCKED = 3600

    def __init__(self, worker, config, plugins, db):
        """Init a thread.
        Arguments:
            'id' number of thead
            'name' name of thread
            'host','user':  host ip or name to manage and user
            'db', 'db_lock': database class and lock to use it in exclusion
        """
        threading.Thread.__init__(self)
        self.config = config
        self.plugins = plugins
        self.plugin_name = "unknown"
        self.logger = logging.getLogger('ro.worker{}'.format("worker"))
        self.worker_id = worker
        self.task_queue = queue.Queue(self.QUEUE_SIZE)
        self.my_vims = {}   # targetvim: vimplugin class
        self.db_vims = {}   # targetvim: vim information from database
        self.vim_targets = []   # targetvim list
        self.my_id = config["process_id"] + ":" + str(worker)
        self.db = db
        self.item2create = {
            "net": self.new_net,
            "vdu": self.new_vm,
            "image": self.new_image,
            "flavor": self.new_flavor,
        }
        self.item2refresh = {
            "net": self.refresh_net,
            "vdu": self.refresh_vm,
            "image": self.refresh_ok,
            "flavor": self.refresh_ok,
        }
        self.item2delete = {
            "net": self.del_net,
            "vdu": self.del_vm,
            "image": self.delete_ok,
            "flavor": self.del_flavor,
        }
        self.item2action = {
            "vdu": self.exec_vm,
        }
        self.time_last_task_processed = None

    def insert_task(self, task):
        try:
            self.task_queue.put(task, False)
            return None
        except queue.Full:
            raise NsWorkerException("timeout inserting a task")

    def terminate(self):
        self.insert_task("exit")

    def del_task(self, task):
        with self.task_lock:
            if task["status"] == "SCHEDULED":
                task["status"] = "SUPERSEDED"
                return True
            else:  # task["status"] == "processing"
                self.task_lock.release()
                return False

    def _load_plugin(self, name, type="vim"):
        # type can be vim or sdn
        if "rovim_dummy" not in self.plugins:
            self.plugins["rovim_dummy"] = VimDummyConnector
        if name in self.plugins:
            return self.plugins[name]
        try:
            for v in iter_entry_points('osm_ro{}.plugins'.format(type), name):
                self.plugins[name] = v.load()
        except Exception as e:
            self.logger.critical("Cannot load osm_{}: {}".format(name, e))
            if name:
                self.plugins[name] = FailingConnector("Cannot load osm_{}: {}".format(name, e))
        if name and name not in self.plugins:
            error_text = "Cannot load a module for {t} type '{n}'. The plugin 'osm_{n}' has not been" \
                         " registered".format(t=type, n=name)
            self.logger.critical(error_text)
            self.plugins[name] = FailingConnector(error_text)

        return self.plugins[name]

    def _load_vim(self, vim_account_id):
        target_id = "vim:" + vim_account_id
        plugin_name = ""
        vim = None
        try:
            step = "Getting vim={} from db".format(vim_account_id)
            vim = self.db.get_one("vim_accounts", {"_id": vim_account_id})

            # if deep_get(vim, "config", "sdn-controller"):
            #     step = "Getting sdn-controller-id='{}' from db".format(vim["config"]["sdn-controller"])
            #     db_sdn = self.db.get_one("sdns", {"_id": vim["config"]["sdn-controller"]})

            step = "Decrypt password"
            schema_version = vim.get("schema_version")
            self.db.encrypt_decrypt_fields(vim, "decrypt", fields=('password', 'secret'),
                                           schema_version=schema_version, salt=vim_account_id)

            step = "Load plugin 'rovim_{}'".format(vim.get("vim_type"))
            plugin_name = "rovim_" + vim["vim_type"]
            vim_module_conn = self._load_plugin(plugin_name)
            self.my_vims[target_id] = vim_module_conn(
                uuid=vim['_id'], name=vim['name'],
                tenant_id=vim.get('vim_tenant_id'), tenant_name=vim.get('vim_tenant_name'),
                url=vim['vim_url'], url_admin=None,
                user=vim['vim_user'], passwd=vim['vim_password'],
                config=vim.get('config'), persistent_info={}
            )
            self.vim_targets.append(target_id)
            self.db_vims[target_id] = vim
            self.error_status = None
            self.logger.info("Vim Connector loaded for vim_account={}, plugin={}".format(
                vim_account_id, plugin_name))
        except Exception as e:
            self.logger.error("Cannot load vimconnector for vim_account={} plugin={}: {} {}".format(
                vim_account_id, plugin_name, step, e))
            self.db_vims[target_id] = vim or {}
            self.my_vims[target_id] = FailingConnector(str(e))
            self.error_status = "Error loading vimconnector: {}".format(e)

    def _get_db_task(self):
        """
        Read actions from database and reload them at memory. Fill self.refresh_list, pending_list, vim_actions
        :return: None
        """
        now = time.time()
        if not self.time_last_task_processed:
            self.time_last_task_processed = now
        try:
            while True:
                locked = self.db.set_one(
                    "ro_tasks",
                    q_filter={"target_id": self.vim_targets,
                              "tasks.status": ['SCHEDULED', 'BUILD', 'DONE', 'FAILED'],
                              "locked_at.lt": now - self.MAX_TIME_LOCKED,
                              "to_check_at.lt": self.time_last_task_processed},
                    update_dict={"locked_by": self.my_id, "locked_at": now},
                    fail_on_empty=False)
                if locked:
                    # read and return
                    ro_task = self.db.get_one(
                        "ro_tasks",
                        q_filter={"target_id": self.vim_targets,
                                  "tasks.status": ['SCHEDULED', 'BUILD', 'DONE', 'FAILED'],
                                  "locked_at": now})
                    return ro_task
                if self.time_last_task_processed == now:
                    self.time_last_task_processed = None
                    return None
                else:
                    self.time_last_task_processed = now
                    # self.time_last_task_processed = min(self.time_last_task_processed + 1000, now)

        except DbException as e:
            self.logger.error("Database exception at _get_db_task: {}".format(e))
        except Exception as e:
            self.logger.critical("Unexpected exception at _get_db_task: {}".format(e), exc_info=True)
        return None

    def _delete_task(self, ro_task, task_index, task_depends, db_update):
        """
        Determine if this task need to be done or superseded
        :return: None
        """
        my_task = ro_task["tasks"][task_index]
        task_id = my_task["task_id"]
        needed_delete = ro_task["vim_info"]["created"] or ro_task["vim_info"].get("created_items", False)
        if my_task["status"] == "FAILED":
            return None, None  # TODO need to be retry??
        try:
            for index, task in enumerate(ro_task["tasks"]):
                if index == task_index:
                    continue  # own task
                if my_task["target_record"] == task["target_record"] and task["action"] == "CREATE":
                    # set to finished
                    db_update["tasks.{}.status".format(index)] = task["status"] = "FINISHED"
                elif task["action"] == "CREATE" and task["status"] not in ("FINISHED", "SUPERSEDED"):
                    needed_delete = False
            if needed_delete:
                return self.item2delete[my_task["item"]](ro_task, task_index)
            else:
                return "SUPERSEDED", None
        except Exception as e:
            if not isinstance(e, NsWorkerException):
                self.logger.critical("Unexpected exception at _delete_task task={}: {}".format(task_id, e),
                                     exc_info=True)
            return "FAILED", {"vim_status": "VIM_ERROR", "vim_details": str(e)}

    def _create_task(self, ro_task, task_index, task_depends, db_update):
        """
        Determine if this task need to be created
        :return: None
        """
        my_task = ro_task["tasks"][task_index]
        task_id = my_task["task_id"]
        task_status = None
        if my_task["status"] == "FAILED":
            return None, None  # TODO need to be retry??
        elif my_task["status"] == "SCHEDULED":
            # check if already created by another task
            for index, task in enumerate(ro_task["tasks"]):
                if index == task_index:
                    continue  # own task
                if task["action"] == "CREATE" and task["status"] not in ("SCHEDULED", "FINISHED", "SUPERSEDED"):
                    return task["status"], "COPY_VIM_INFO"

            try:
                task_status, ro_vim_item_update = self.item2create[my_task["item"]](ro_task, task_index, task_depends)
                # TODO update other CREATE tasks
            except Exception as e:
                if not isinstance(e, NsWorkerException):
                    self.logger.error("Error executing task={}: {}".format(task_id, e), exc_info=True)
                task_status = "FAILED"
                ro_vim_item_update = {"vim_status": "VIM_ERROR", "vim_details": str(e)}
                # TODO update    ro_vim_item_update
            return task_status, ro_vim_item_update
        else:
            return None, None

    def _get_dependency(self, task_id, ro_task=None, target_id=None):
        if task_id.startswith("nsrs:") or task_id.startswith("vnfrs:"):
            ro_task_dependency = self.db.get_one(
                "ro_tasks",
                q_filter={"target_id": target_id,
                          "tasks.target_record_id": task_id
                          },
                fail_on_empty=False)
            if ro_task_dependency:
                for task_index, task in enumerate(ro_task_dependency["tasks"]):
                    if task["target_record_id"] == task_id:
                        return ro_task_dependency, task_index

        else:
            if ro_task:
                for task_index, task in enumerate(ro_task["tasks"]):
                    if task["task_id"] == task_id:
                        return ro_task, task_index
            ro_task_dependency = self.db.get_one(
                "ro_tasks",
                q_filter={"tasks.ANYINDEX.task_id": task_id,
                          "tasks.ANYINDEX.target_record.ne": None
                          },
                fail_on_empty=False)
            if ro_task_dependency:
                for task_index, task in ro_task_dependency["tasks"]:
                    if task["task_id"] == task_id:
                        return ro_task_dependency, task_index
        raise NsWorkerException("Cannot get depending task {}".format(task_id))

    def _proccess_pending_tasks(self, ro_task):
        ro_task_id = ro_task["_id"]
        now = time.time()
        next_check_at = now + (24*60*60)   # one day
        db_ro_task_update = {}

        def _update_refresh(new_status):
            # compute next_refresh
            nonlocal task
            nonlocal next_check_at
            nonlocal db_ro_task_update
            nonlocal ro_task

            next_refresh = time.time()
            if task["item"] in ("image", "flavor"):
                next_refresh += self.REFRESH_IMAGE
            elif new_status == "BUILD":
                next_refresh += self.REFRESH_BUILD
            elif new_status == "DONE":
                next_refresh += self.REFRESH_ACTIVE
            else:
                next_refresh += self.REFRESH_ERROR
            next_check_at = min(next_check_at, next_refresh)
            db_ro_task_update["vim_info.refresh_at"] = next_refresh
            ro_task["vim_info"]["refresh_at"] = next_refresh

        try:
            # 0 get task_status_create
            task_status_create = None
            task_create = next((t for t in ro_task["tasks"] if t["action"] == "CREATE" and
                                t["status"] in ("BUILD", "DONE")), None)
            if task_create:
                task_status_create = task_create["status"]
            # 1. look for SCHEDULED or if CREATE also DONE,BUILD
            for task_action in ("DELETE", "CREATE", "EXEC"):
                db_vim_update = None
                for task_index, task in enumerate(ro_task["tasks"]):
                    target_update = None
                    if (task_action in ("DELETE", "EXEC") and task["status"] != "SCHEDULED") or\
                            task["action"] != task_action or \
                            (task_action == "CREATE" and task["status"] in ("FINISHED", "SUPERSEDED")):
                        continue
                    task_path = "tasks.{}.status".format(task_index)
                    try:
                        if task["status"] == "SCHEDULED":
                            task_depends = {}
                            # check if tasks that this depends on have been completed
                            dependency_not_completed = False
                            for dependency_task_id in (task.get("depends_on") or ()):
                                dependency_ro_task, dependency_task_index = \
                                    self._get_dependency(dependency_task_id, target_id=ro_task["target_id"])
                                dependency_task = dependency_ro_task["tasks"][dependency_task_index]
                                if dependency_task["status"] == "SCHEDULED":
                                    dependency_not_completed = True
                                    next_check_at = min(next_check_at, dependency_ro_task["to_check_at"])
                                    break
                                elif dependency_task["status"] == "FAILED":
                                    error_text = "Cannot {} {} because depends on failed {} {} id={}): {}".format(
                                        task["action"], task["item"], dependency_task["action"],
                                        dependency_task["item"], dependency_task_id,
                                        dependency_ro_task["vim_info"].get("vim_details"))
                                    self.logger.error("task={} {}".format(task["task_id"], error_text))
                                    raise NsWorkerException(error_text)

                                task_depends[dependency_task_id] = dependency_ro_task["vim_info"]["vim_id"]
                                task_depends["TASK-{}".format(dependency_task_id)] = \
                                    dependency_ro_task["vim_info"]["vim_id"]
                            if dependency_not_completed:
                                # TODO set at vim_info.vim_details that it is waiting
                                continue

                        if task["action"] == "DELETE":
                            new_status, db_vim_info_update = self._delete_task(ro_task, task_index,
                                                                               task_depends, db_ro_task_update)
                            new_status = "FINISHED" if new_status == "DONE" else new_status
                            # ^with FINISHED instead of DONE it will not be refreshing
                            if new_status in ("FINISHED", "SUPERSEDED"):
                                target_update = "DELETE"
                        elif task["action"] == "EXEC":
                            self.item2action[task["item"]](ro_task, task_index, task_depends, db_ro_task_update)
                            new_status = "FINISHED" if new_status == "DONE" else new_status
                            # ^with FINISHED instead of DONE it will not be refreshing
                            if new_status in ("FINISHED", "SUPERSEDED"):
                                target_update = "DELETE"
                        elif task["action"] == "CREATE":
                            if task["status"] == "SCHEDULED":
                                if task_status_create:
                                    new_status = task_status_create
                                    target_update = "COPY_VIM_INFO"
                                else:
                                    new_status, db_vim_info_update = \
                                        self.item2create[task["item"]](ro_task, task_index, task_depends)
                                    # self._create_task(ro_task, task_index, task_depends, db_ro_task_update)
                                    _update_refresh(new_status)
                            else:
                                if ro_task["vim_info"]["refresh_at"] and now > ro_task["vim_info"]["refresh_at"]:
                                    new_status, db_vim_info_update = self.item2refresh[task["item"]](ro_task)
                                    _update_refresh(new_status)
                    except Exception as e:
                        new_status = "FAILED"
                        db_vim_info_update = {"vim_status": "VIM_ERROR", "vim_details": str(e)}
                        if not isinstance(e, (NsWorkerException, vimconn.VimConnException)):
                            self.logger.error("Unexpected exception at _delete_task task={}: {}".
                                              format(task["task_id"], e), exc_info=True)

                    try:
                        if db_vim_info_update:
                            db_vim_update = db_vim_info_update.copy()
                            db_ro_task_update.update({"vim_info." + k: v for k, v in db_vim_info_update.items()})
                            ro_task["vim_info"].update(db_vim_info_update)

                        if new_status:
                            if task_action == "CREATE":
                                task_status_create = new_status
                            db_ro_task_update[task_path] = new_status
                        if target_update or db_vim_update:

                            if target_update == "DELETE":
                                self._update_target(task, None)
                            elif target_update == "COPY_VIM_INFO":
                                self._update_target(task, ro_task["vim_info"])
                            else:
                                self._update_target(task, db_vim_update)

                    except Exception as e:
                        self.logger.error("Unexpected exception at _update_target task={}: {}".
                                          format(task["task_id"], e), exc_info=True)

            # modify own task. Try filtering by to_next_check. For race condition if to_check_at has been modified,
            # outside this task (by ro_nbi) do not update it
            db_ro_task_update["locked_by"] = None
            # locked_at converted to int only for debugging. When has not decimals it means it has been unlocked
            db_ro_task_update["locked_at"] = int(now - self.MAX_TIME_LOCKED)
            db_ro_task_update["to_check_at"] = next_check_at
            if not self.db.set_one("ro_tasks",
                                   update_dict=db_ro_task_update,
                                   q_filter={"_id": ro_task["_id"], "to_check_at": ro_task["to_check_at"]},
                                   fail_on_empty=False):
                del db_ro_task_update["to_check_at"]
                self.db.set_one("ro_tasks",
                                q_filter={"_id": ro_task["_id"]},
                                update_dict=db_ro_task_update,
                                fail_on_empty=True)
        except DbException as e:
            self.logger.error("ro_task={} Error updating database {}".format(ro_task_id, e))
        except Exception as e:
            self.logger.error("Error executing ro_task={}: {}".format(ro_task_id, e), exc_info=True)

    def _update_target(self, task, ro_vim_item_update):
        try:
            table, _id, path = task["target_record"].split(":")
            if ro_vim_item_update:
                update_dict = {path + "." + k: v for k, v in ro_vim_item_update.items() if k in
                               ('vim_id', 'vim_details', 'vim_name', 'vim_status', 'interfaces')}
                if ro_vim_item_update.get("interfaces"):
                    path_vdu = path[:path.rfind(".")]
                    path_vdu = path_vdu[:path_vdu.rfind(".")]
                    path_interfaces = path_vdu + ".interfaces"
                    for i, iface in enumerate(ro_vim_item_update.get("interfaces")):
                        if iface:
                            update_dict.update({path_interfaces + ".{}.".format(i) + k: v for k, v in iface.items() if
                                                k in ('ip_address', 'mac_address', 'vlan', 'compute_node', 'pci')})
                            if iface.get("mgmt_vnf_interface") and iface.get("ip_address"):
                                update_dict["ip-address"] = iface.get("ip_address").split(";")[0]
                            if iface.get("mgmt_vdu_interface") and iface.get("ip_address"):
                                update_dict[path_vdu + ".ip-address"] = iface.get("ip_address").split(";")[0]

                self.db.set_one(table, q_filter={"_id": _id}, update_dict=update_dict)
            else:
                self.db.set_one(table, q_filter={"_id": _id}, update_dict=None,
                                unset={path: None})
        except DbException as e:
            self.logger.error("Cannot update database '{}': '{}'".format(task["target_record"], e))

    def new_image(self, ro_task, task_index, task_depends):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        created = False
        created_items = {}
        target_vim = self.my_vims[ro_task["target_id"]]
        try:
            # FIND
            if task.get("find_params"):
                vim_images = target_vim.get_image_list(**task["find_params"])
                if not vim_images:
                    raise NsWorkerExceptionNotFound("Image not found with this criteria: '{}'".format(
                        task["find_params"]))
                elif len(vim_images) > 1:
                    raise NsWorkerException(
                        "More than one network found with this criteria: '{}'".format(task["find_params"]))
                else:
                    vim_image_id = vim_images[0]["id"]

            ro_vim_item_update = {"vim_id": vim_image_id,
                                  "vim_status": "DONE",
                                  "created": created,
                                  "created_items": created_items,
                                  "vim_details": None}
            self.logger.debug(
                "task={} {} new-image={} created={}".format(task_id, ro_task["target_id"], vim_image_id, created))
            return "DONE", ro_vim_item_update
        except (NsWorkerException, vimconn.VimConnException) as e:
            self.logger.error("task={} {} new-image: {}".format(task_id, ro_task["target_id"], e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "created": created,
                                  "vim_details": str(e)}
            return "FAILED", ro_vim_item_update

    def del_flavor(self, ro_task, task_index):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        flavor_vim_id = ro_task["vim_info"]["vim_id"]
        ro_vim_item_update_ok = {"vim_status": "DELETED",
                                 "created": False,
                                 "vim_details": "DELETED",
                                 "vim_id": None}
        try:
            if flavor_vim_id:
                target_vim = self.my_vims[ro_task["target_id"]]
                target_vim.delete_flavor(flavor_vim_id)

        except vimconn.VimConnNotFoundException:
            ro_vim_item_update_ok["vim_details"] = "already deleted"

        except vimconn.VimConnException as e:
            self.logger.error("ro_task={} vim={} del-flavor={}: {}".format(
                ro_task["_id"], ro_task["target_id"], flavor_vim_id, e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "vim_details": "Error while deleting: {}".format(e)}
            return "FAILED", ro_vim_item_update

        self.logger.debug("task={} {} del-flavor={} {}".format(
            task_id, ro_task["target_id"], flavor_vim_id, ro_vim_item_update_ok.get("vim_details", "")))
        return "DONE", ro_vim_item_update_ok

    def refresh_ok(self, ro_task):
        """skip calling VIM to get image status. Assumes ok"""
        if ro_task["vim_info"]["vim_status"] == "VIM_ERROR":
            return "FAILED", {}
        return "DONE", {}

    def delete_ok(self, ro_task):
        """skip calling VIM to delete image status. Assumes ok"""
        return "DONE", {}

    def new_flavor(self, ro_task, task_index, task_depends):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        created = False
        created_items = {}
        target_vim = self.my_vims[ro_task["target_id"]]
        try:
            # FIND
            vim_flavor_id = None
            if task.get("find_params"):
                try:
                    flavor_data = task["find_params"]["flavor_data"]
                    vim_flavor_id = target_vim.get_flavor_id_from_data(flavor_data)
                except vimconn.VimConnNotFoundException:
                    pass

            if not vim_flavor_id and task.get("params"):
                # CREATE
                flavor_data = task["params"]["flavor_data"]
                vim_flavor_id = target_vim.new_flavor(flavor_data)
                created = True

            ro_vim_item_update = {"vim_id": vim_flavor_id,
                                  "vim_status": "DONE",
                                  "created": created,
                                  "created_items": created_items,
                                  "vim_details": None}
            self.logger.debug(
                "task={} {} new-flavor={} created={}".format(task_id, ro_task["target_id"], vim_flavor_id, created))
            return "DONE", ro_vim_item_update
        except (vimconn.VimConnException, NsWorkerException) as e:
            self.logger.error("task={} vim={} new-flavor: {}".format(task_id, ro_task["target_id"], e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "created": created,
                                  "vim_details": str(e)}
            return "FAILED", ro_vim_item_update

    def new_net(self, ro_task, task_index, task_depends):
        vim_net_id = None
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        created = False
        created_items = {}
        target_vim = self.my_vims[ro_task["target_id"]]
        try:
            # FIND
            if task.get("find_params"):
                # if management, get configuration of VIM
                if task["find_params"].get("filter_dict"):
                    vim_filter = task["find_params"]["filter_dict"]
                elif task["find_params"].get("mgmt"):   # mamagement network
                    if deep_get(self.db_vims[ro_task["target_id"]], "config", "management_network_id"):
                        vim_filter = {"id": self.db_vims[ro_task["target_id"]]["config"]["management_network_id"]}
                    elif deep_get(self.db_vims[ro_task["target_id"]], "config", "management_network_name"):
                        vim_filter = {"name": self.db_vims[ro_task["target_id"]]["config"]["management_network_name"]}
                    else:
                        vim_filter = {"name": task["find_params"]["name"]}
                else:
                    raise NsWorkerExceptionNotFound("Invalid find_params for new_net {}".format(task["find_params"]))

                vim_nets = target_vim.get_network_list(vim_filter)
                if not vim_nets and not task.get("params"):
                    raise NsWorkerExceptionNotFound("Network not found with this criteria: '{}'".format(
                        task.get("find_params")))
                elif len(vim_nets) > 1:
                    raise NsWorkerException(
                        "More than one network found with this criteria: '{}'".format(task["find_params"]))
                if vim_nets:
                    vim_net_id = vim_nets[0]["id"]
            else:
                # CREATE
                params = task["params"]
                vim_net_id, created_items = target_vim.new_network(**params)
                created = True

            ro_vim_item_update = {"vim_id": vim_net_id,
                                  "vim_status": "BUILD",
                                  "created": created,
                                  "created_items": created_items,
                                  "vim_details": None}
            self.logger.debug(
                "task={} {} new-net={} created={}".format(task_id, ro_task["target_id"], vim_net_id, created))
            return "BUILD", ro_vim_item_update
        except (vimconn.VimConnException, NsWorkerException) as e:
            self.logger.error("task={} vim={} new-net: {}".format(task_id, ro_task["target_id"], e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "created": created,
                                  "vim_details": str(e)}
            return "FAILED", ro_vim_item_update

    def refresh_net(self, ro_task):
        """Call VIM to get network status"""
        ro_task_id = ro_task["_id"]
        target_vim = self.my_vims[ro_task["target_id"]]

        vim_id = ro_task["vim_info"]["vim_id"]
        net_to_refresh_list = [vim_id]
        try:
            vim_dict = target_vim.refresh_nets_status(net_to_refresh_list)
            vim_info = vim_dict[vim_id]
            if vim_info["status"] == "ACTIVE":
                task_status = "DONE"
            elif vim_info["status"] == "BUILD":
                task_status = "BUILD"
            else:
                task_status = "FAILED"
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("ro_task={} vim={} get-net={}: {}".format(ro_task_id, ro_task["target_id"], vim_id, e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}
            task_status = "FAILED"

        ro_vim_item_update = {}
        if ro_task["vim_info"]["vim_status"] != vim_info["status"]:
            ro_vim_item_update["vim_status"] = vim_info["status"]
        if ro_task["vim_info"]["vim_name"] != vim_info.get("name"):
            ro_vim_item_update["vim_name"] = vim_info.get("name")
        if vim_info["status"] in ("ERROR", "VIM_ERROR"):
            if ro_task["vim_info"]["vim_details"] != vim_info["error_msg"]:
                ro_vim_item_update["vim_details"] = vim_info["error_msg"]
        elif vim_info["status"] == "DELETED":
            ro_vim_item_update["vim_id"] = None
            ro_vim_item_update["vim_details"] = "Deleted externally"
        else:
            if ro_task["vim_info"]["vim_details"] != vim_info["vim_info"]:
                ro_vim_item_update["vim_details"] = vim_info["vim_info"]
        if ro_vim_item_update:
            self.logger.debug("ro_task={} {} get-net={}: status={} {}".format(
                ro_task_id, ro_task["target_id"], vim_id, ro_vim_item_update.get("vim_status"),
                ro_vim_item_update.get("vim_details") if ro_vim_item_update.get("vim_status") != "ACTIVE" else ''))
        return task_status, ro_vim_item_update

    def del_net(self, ro_task, task_index):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        net_vim_id = ro_task["vim_info"]["vim_id"]
        ro_vim_item_update_ok = {"vim_status": "DELETED",
                                 "created": False,
                                 "vim_details": "DELETED",
                                 "vim_id": None}
        try:
            if net_vim_id or ro_task["vim_info"]["created_items"]:
                target_vim = self.my_vims[ro_task["target_id"]]
                target_vim.delete_network(net_vim_id, ro_task["vim_info"]["created_items"])

        except vimconn.VimConnNotFoundException:
            ro_vim_item_update_ok["vim_details"] = "already deleted"

        except vimconn.VimConnException as e:
            self.logger.error("ro_task={} vim={} del-net={}: {}".format(ro_task["_id"], ro_task["target_id"],
                                                                        net_vim_id, e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "vim_details": "Error while deleting: {}".format(e)}
            return "FAILED", ro_vim_item_update

        self.logger.debug("task={} {} del-net={} {}".format(task_id, ro_task["target_id"], net_vim_id,
                                                            ro_vim_item_update_ok.get("vim_details", "")))
        return "DONE", ro_vim_item_update_ok

    def new_vm(self, ro_task, task_index, task_depends):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        created = False
        created_items = {}
        target_vim = self.my_vims[ro_task["target_id"]]
        try:
            created = True
            params = task["params"]
            params_copy = deepcopy(params)
            net_list = params_copy["net_list"]
            for net in net_list:
                if "net_id" in net and net["net_id"].startswith("TASK-"):  # change task_id into network_id
                    network_id = task_depends[net["net_id"]]
                    if not network_id:
                        raise NsWorkerException("Cannot create VM because depends on a network not created or found "
                                                "for {}".format(net["net_id"]))
                    net["net_id"] = network_id
            if params_copy["image_id"].startswith("TASK-"):
                params_copy["image_id"] = task_depends[params_copy["image_id"]]
            if params_copy["flavor_id"].startswith("TASK-"):
                params_copy["flavor_id"] = task_depends[params_copy["flavor_id"]]

            vim_vm_id, created_items = target_vim.new_vminstance(**params_copy)
            interfaces = [iface["vim_id"] for iface in params_copy["net_list"]]

            ro_vim_item_update = {"vim_id": vim_vm_id,
                                  "vim_status": "BUILD",
                                  "created": created,
                                  "created_items": created_items,
                                  "vim_details": None,
                                  "interfaces_vim_ids": interfaces,
                                  "interfaces": [],
                                  }
            self.logger.debug(
                "task={} {} new-vm={} created={}".format(task_id, ro_task["target_id"], vim_vm_id, created))
            return "BUILD", ro_vim_item_update
        except (vimconn.VimConnException, NsWorkerException) as e:
            self.logger.error("task={} vim={} new-vm: {}".format(task_id, ro_task["target_id"], e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "created": created,
                                  "vim_details": str(e)}
            return "FAILED", ro_vim_item_update

    def del_vm(self, ro_task, task_index):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        vm_vim_id = ro_task["vim_info"]["vim_id"]
        ro_vim_item_update_ok = {"vim_status": "DELETED",
                                 "created": False,
                                 "vim_details": "DELETED",
                                 "vim_id": None}
        try:
            if vm_vim_id or ro_task["vim_info"]["created_items"]:
                target_vim = self.my_vims[ro_task["target_id"]]
                target_vim.delete_vminstance(vm_vim_id, ro_task["vim_info"]["created_items"])

        except vimconn.VimConnNotFoundException:
            ro_vim_item_update_ok["vim_details"] = "already deleted"

        except vimconn.VimConnException as e:
            self.logger.error("ro_task={} vim={} del-vm={}: {}".format(ro_task["_id"], ro_task["target_id"],
                                                                       vm_vim_id, e))
            ro_vim_item_update = {"vim_status": "VIM_ERROR",
                                  "vim_details": "Error while deleting: {}".format(e)}
            return "FAILED", ro_vim_item_update

        self.logger.debug("task={} {} del-vm={} {}".format(task_id, ro_task["target_id"], vm_vim_id,
                                                           ro_vim_item_update_ok.get("vim_details", "")))
        return "DONE", ro_vim_item_update_ok

    def refresh_vm(self, ro_task):
        """Call VIM to get vm status"""
        ro_task_id = ro_task["_id"]
        target_vim = self.my_vims[ro_task["target_id"]]

        vim_id = ro_task["vim_info"]["vim_id"]
        if not vim_id:
            return None, None
        vm_to_refresh_list = [vim_id]
        try:
            vim_dict = target_vim.refresh_vms_status(vm_to_refresh_list)
            vim_info = vim_dict[vim_id]
            if vim_info["status"] == "ACTIVE":
                task_status = "DONE"
            elif vim_info["status"] == "BUILD":
                task_status = "BUILD"
            else:
                task_status = "FAILED"
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("ro_task={} vim={} get-vm={}: {}".format(ro_task_id, ro_task["target_id"], vim_id, e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}
            task_status = "FAILED"

        ro_vim_item_update = {}
        # TODO check and update interfaces
        vim_interfaces = []
        for vim_iface_id in ro_task["vim_info"]["interfaces_vim_ids"]:
            iface = next((iface for iface in vim_info["interfaces"] if vim_iface_id == iface["vim_interface_id"]), None)
            # if iface:
            #     iface.pop("vim_info", None)
            vim_interfaces.append(iface)

        task = ro_task["tasks"][0]  # TODO look for a task CREATE and active
        if task.get("mgmt_vnf_interface") is not None:
            vim_interfaces[task["mgmt_vnf_interface"]]["mgmt_vnf_interface"] = True
        mgmt_vdu_iface = task.get("mgmt_vdu_interface", task.get("mgmt_vnf_interface", 0))
        vim_interfaces[mgmt_vdu_iface]["mgmt_vdu_interface"] = True

        if ro_task["vim_info"]["interfaces"] != vim_interfaces:
            ro_vim_item_update["interfaces"] = vim_interfaces
        if ro_task["vim_info"]["vim_status"] != vim_info["status"]:
            ro_vim_item_update["vim_status"] = vim_info["status"]
        if ro_task["vim_info"]["vim_name"] != vim_info.get("name"):
            ro_vim_item_update["vim_name"] = vim_info.get("name")
        if vim_info["status"] in ("ERROR", "VIM_ERROR"):
            if ro_task["vim_info"]["vim_details"] != vim_info["error_msg"]:
                ro_vim_item_update["vim_details"] = vim_info["error_msg"]
        elif vim_info["status"] == "DELETED":
            ro_vim_item_update["vim_id"] = None
            ro_vim_item_update["vim_details"] = "Deleted externally"
        else:
            if ro_task["vim_info"]["vim_details"] != vim_info["vim_info"]:
                ro_vim_item_update["vim_details"] = vim_info["vim_info"]
        if ro_vim_item_update:
            self.logger.debug("ro_task={} {} get-vm={}: status={} {}".format(
                ro_task_id, ro_task["target_id"], vim_id, ro_vim_item_update.get("vim_status"),
                ro_vim_item_update.get("vim_details") if ro_vim_item_update.get("vim_status") != "ACTIVE" else ''))
        return task_status, ro_vim_item_update

    def exec_vm(self, ro_task, task_index, task_depends):
        task = ro_task["tasks"][task_index]
        task_id = task["task_id"]
        target_vim = self.my_vims[ro_task["target_id"]]
        try:
            params = task["params"]
            params_copy = deepcopy(params)
            params_copy["use_pri_key"] = self.db.decrypt(params_copy.pop("private_key"),
                                                         params_copy.pop("schema_version"), params_copy.pop("salt"))

            target_vim.inject_user_key(**params_copy)
            self.logger.debug(
                "task={} {} action-vm=inject_key".format(task_id, ro_task["target_id"]))
            return "DONE", params_copy["key"]
        except (vimconn.VimConnException, NsWorkerException) as e:
            self.logger.error("task={} vim={} new-vm: {}".format(task_id, ro_task["target_id"], e))
            ro_vim_item_update = {"vim_details": str(e)}
            return "FAILED", ro_vim_item_update

    def run(self):
        # load database
        self.logger.debug("Starting")
        while True:
            try:
                task = self.task_queue.get(block=False if self.my_vims else True)
                if task[0] == "terminate":
                    break
                if task[0] == "load_vim":
                    self._load_vim(task[1])
                continue
            except queue.Empty:
                pass

            try:
                busy = False
                ro_task = self._get_db_task()
                if ro_task:
                    self._proccess_pending_tasks(ro_task)
                    busy = True
                if not busy:
                    time.sleep(5)
            except Exception as e:
                self.logger.critical("Unexpected exception at run: " + str(e), exc_info=True)

        self.logger.debug("Finishing")
