# -*- coding: utf-8 -*-

##
# Copyright 2015 Telefonica Investigacion y Desarrollo, S.A.U.
# This file is part of openvim
# All Rights Reserved.
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

""""
This is thread that interacts with a VIM. It processes TASKs sequentially against a single VIM.
The tasks are stored at database in table vim_wim_actions
Several vim_wim_actions can refer to the same element at VIM (flavor, network, ...). This is somethng to avoid if RO
is migrated to a non-relational database as mongo db. Each vim_wim_actions reference a different instance_Xxxxx
In this case "related" colunm contains the same value, to know they refer to the same vim. In case of deletion, it
there is related tasks using this element, it is not deleted, The vim_info needed to delete is transfered to other task

The task content is (M: stored at memory, D: stored at database):
    MD  instance_action_id:  reference a global action over an instance-scenario: database instance_actions
    MD  task_index:     index number of the task. This together with the previous forms a unique key identifier
    MD  datacenter_vim_id:  should contain the uuid of the VIM managed by this thread
    MD  vim_id:     id of the vm,net,etc at VIM
    MD  item:       database table name, can be instance_vms, instance_nets, TODO: datacenter_flavors, datacenter_images
    MD  item_id:    uuid of the referenced entry in the previous table
    MD  action:     CREATE, DELETE, FIND
    MD  status:     SCHEDULED: action need to be done
                    BUILD: not used
                    DONE: Done and it must be polled to VIM periodically to see status. ONLY for action=CREATE or FIND
                    FAILED: It cannot be created/found/deleted
                    FINISHED: similar to DONE, but no refresh is needed anymore. Task is maintained at database but
                        it is never processed by any thread
                    SUPERSEDED: similar to FINSISHED, but nothing has been done to completed the task.
    MD  extra:      text with yaml format at database, dict at memory with:
            params:     list with the params to be sent to the VIM for CREATE or FIND. For DELETE the vim_id is taken
                        from other related tasks
            find:       (only for CREATE tasks) if present it should FIND before creating and use if existing. Contains
                        the FIND params
            depends_on: list with the 'task_index'es of tasks that must be completed before. e.g. a vm creation depends
                        on a net creation
                        can contain an int (single index on the same instance-action) or str (compete action ID)
            sdn_net_id: used for net.
            interfaces: used for VMs. Each key is the uuid of the instance_interfaces entry at database
                iface_id: uuid of intance_interfaces
                sdn_port_id:
                sdn_net_id:
                vim_info
            created_items: dictionary with extra elements created that need to be deleted. e.g. ports, volumes,...
            created:    False if the VIM element is not created by other actions, and it should not be deleted
            vim_status: VIM status of the element. Stored also at database in the instance_XXX
            vim_info:   Detailed information of a vm/net from the VIM. Stored at database in the instance_XXX but not at
                        vim_wim_actions
    M   depends:    dict with task_index(from depends_on) to dependency task
    M   params:     same as extra[params]
    MD  error_msg:  descriptive text upon an error.Stored also at database instance_XXX
    MD  created_at: task creation time. The task of creation must be the oldest
    MD  modified_at: next time task need to be processed. For example, for a refresh, it contain next time refresh must
                     be done
    MD related:     All the tasks over the same VIM element have same "related". Note that other VIMs can contain the
                    same value of related, but this thread only process those task of one VIM.  Also related can be the
                    same among several NS os isntance-scenarios
    MD worker:      Used to lock in case of several thread workers.

"""

import threading
import time
import queue
import logging
from osm_ro_plugin import vimconn
from osm_ro_plugin.sdnconn import SdnConnectorError
import yaml
from osm_ro.db_base import db_base_Exception
from http import HTTPStatus
from copy import deepcopy

__author__ = "Alfonso Tierno, Pablo Montes"
__date__ = "$28-Sep-2017 12:07:15$"


def is_task_id(task_id):
    return task_id.startswith("TASK-")


class VimThreadException(Exception):
    pass


class VimThreadExceptionNotFound(VimThreadException):
    pass


class vim_thread(threading.Thread):
    REFRESH_BUILD = 5  # 5 seconds
    REFRESH_ACTIVE = 60  # 1 minute
    REFRESH_ERROR = 600
    REFRESH_DELETE = 3600 * 10

    def __init__(self, task_lock, plugins, name=None, wim_account_id=None, datacenter_tenant_id=None, db=None):
        """Init a thread.
        Arguments:
            'id' number of thead
            'name' name of thread
            'host','user':  host ip or name to manage and user
            'db', 'db_lock': database class and lock to use it in exclusion
        """
        threading.Thread.__init__(self)
        self.plugins = plugins
        self.plugin_name = "unknown"
        self.vim = None
        self.sdnconnector = None
        self.sdnconn_config = None
        self.error_status = None
        self.wim_account_id = wim_account_id
        self.datacenter_tenant_id = datacenter_tenant_id
        self.port_mappings = None
        if self.wim_account_id:
            self.target_k = "wim_account_id"
            self.target_v = self.wim_account_id
        else:
            self.target_k = "datacenter_vim_id"
            self.target_v = self.datacenter_tenant_id
        if not name:
            self.name = wim_account_id or str(datacenter_tenant_id)
        else:
            self.name = name
        self.vim_persistent_info = {}
        self.my_id = self.name[:64]

        self.logger = logging.getLogger('openmano.{}.{}'.format("vim" if self.datacenter_tenant_id else "sdn",
                                                                self.name))
        self.db = db

        self.task_lock = task_lock
        self.task_queue = queue.Queue(2000)

    def _proccess_sdn_exception(self, exc):
        if isinstance(exc, SdnConnectorError):
            raise
        else:
            self.logger.error("plugin={} throws a non SdnConnectorError exception {}".format(self.plugin_name, exc),
                              exc_info=True)
            raise SdnConnectorError(str(exc), http_code=HTTPStatus.INTERNAL_SERVER_ERROR.value) from exc

    def _proccess_vim_exception(self, exc):
        if isinstance(exc, vimconn.VimConnException):
            raise
        else:
            self.logger.error("plugin={} throws a non vimconnException exception {}".format(self.plugin_name, exc),
                              exc_info=True)
            raise vimconn.VimConnException(str(exc), http_code=HTTPStatus.INTERNAL_SERVER_ERROR.value) from exc

    def get_vim_sdn_connector(self):
        if self.datacenter_tenant_id:
            try:
                from_ = "datacenter_tenants as dt join datacenters as d on dt.datacenter_id=d.uuid"
                select_ = ('type', 'd.config as config', 'd.uuid as datacenter_id', 'vim_url', 'vim_url_admin',
                           'd.name as datacenter_name', 'dt.uuid as datacenter_tenant_id',
                           'dt.vim_tenant_name as vim_tenant_name', 'dt.vim_tenant_id as vim_tenant_id',
                           'user', 'passwd', 'dt.config as dt_config')
                where_ = {"dt.uuid": self.datacenter_tenant_id}
                vims = self.db.get_rows(FROM=from_, SELECT=select_, WHERE=where_)
                vim = vims[0]
                vim_config = {}
                if vim["config"]:
                    vim_config.update(yaml.load(vim["config"], Loader=yaml.Loader))
                if vim["dt_config"]:
                    vim_config.update(yaml.load(vim["dt_config"], Loader=yaml.Loader))
                vim_config['datacenter_tenant_id'] = vim.get('datacenter_tenant_id')
                vim_config['datacenter_id'] = vim.get('datacenter_id')

                # get port_mapping
                # vim_port_mappings = self.ovim.get_of_port_mappings(
                #     db_filter={"datacenter_id": vim_config['datacenter_id']})
                # vim_config["wim_external_ports"] = [x for x in vim_port_mappings
                #                                     if x["service_mapping_info"].get("wim")]
                self.plugin_name = "rovim_" + vim["type"]
                self.vim = self.plugins[self.plugin_name](
                    uuid=vim['datacenter_id'], name=vim['datacenter_name'],
                    tenant_id=vim['vim_tenant_id'], tenant_name=vim['vim_tenant_name'],
                    url=vim['vim_url'], url_admin=vim['vim_url_admin'],
                    user=vim['user'], passwd=vim['passwd'],
                    config=vim_config, persistent_info=self.vim_persistent_info
                )
                self.error_status = None
                self.logger.info("Vim Connector loaded for vim_account={}, plugin={}".format(
                    self.datacenter_tenant_id, self.plugin_name))
            except Exception as e:
                self.logger.error("Cannot load vimconnector for vim_account={} plugin={}: {}".format(
                    self.datacenter_tenant_id, self.plugin_name, e))
                self.vim = None
                self.error_status = "Error loading vimconnector: {}".format(e)
        else:
            try:
                wim_account = self.db.get_rows(FROM="wim_accounts", WHERE={"uuid": self.wim_account_id})[0]
                wim = self.db.get_rows(FROM="wims", WHERE={"uuid": wim_account["wim_id"]})[0]
                if wim["config"]:
                    self.sdnconn_config = yaml.load(wim["config"], Loader=yaml.Loader)
                else:
                    self.sdnconn_config = {}
                if wim_account["config"]:
                    self.sdnconn_config.update(yaml.load(wim_account["config"], Loader=yaml.Loader))
                self.port_mappings = self.db.get_rows(FROM="wim_port_mappings", WHERE={"wim_id": wim_account["wim_id"]})
                if self.port_mappings:
                    self.sdnconn_config["service_endpoint_mapping"] = self.port_mappings
                self.plugin_name = "rosdn_" + wim["type"]
                self.sdnconnector = self.plugins[self.plugin_name](
                    wim, wim_account, config=self.sdnconn_config)
                self.error_status = None
                self.logger.info("Sdn Connector loaded for wim_account={}, plugin={}".format(
                    self.wim_account_id, self.plugin_name))
            except Exception as e:
                self.logger.error("Cannot load sdn connector for wim_account={}, plugin={}: {}".format(
                    self.wim_account_id, self.plugin_name, e), exc_info=True)
                self.sdnconnector = None
                self.error_status = self._format_vim_error_msg("Error loading sdn connector: {}".format(e))

    def _get_db_task(self):
        """
        Read actions from database and reload them at memory. Fill self.refresh_list, pending_list, vim_actions
        :return: None
        """
        now = time.time()
        try:
            database_limit = 20
            task_related = None
            while True:
                # get 20 (database_limit) entries each time
                vim_actions = self.db.get_rows(FROM="vim_wim_actions",
                                               WHERE={self.target_k: self.target_v,
                                                      "status": ['SCHEDULED', 'BUILD', 'DONE'],
                                                      "worker": [None, self.my_id], "modified_at<=": now
                                                      },
                                               ORDER_BY=("modified_at", "created_at",),
                                               LIMIT=database_limit)
                if not vim_actions:
                    return None, None
                # if vim_actions[0]["modified_at"] > now:
                #     return int(vim_actions[0] - now)
                for task in vim_actions:
                    # block related task
                    if task_related == task["related"]:
                        continue  # ignore if a locking has already tried for these task set
                    task_related = task["related"]
                    # lock ...
                    self.db.update_rows("vim_wim_actions", UPDATE={"worker": self.my_id}, modified_time=0,
                                        WHERE={self.target_k: self.target_v,
                                               "status": ['SCHEDULED', 'BUILD', 'DONE', 'FAILED'],
                                               "worker": [None, self.my_id],
                                               "related": task_related,
                                               "item": task["item"],
                                               })
                    # ... and read all related and check if locked
                    related_tasks = self.db.get_rows(FROM="vim_wim_actions",
                                                     WHERE={self.target_k: self.target_v,
                                                            "status": ['SCHEDULED', 'BUILD', 'DONE', 'FAILED'],
                                                            "related": task_related,
                                                            "item": task["item"],
                                                            },
                                                     ORDER_BY=("created_at",))
                    # check that all related tasks have been locked. If not release and try again. It can happen
                    # for race conditions if a new related task has been inserted by nfvo in the process
                    some_tasks_locked = False
                    some_tasks_not_locked = False
                    creation_task = None
                    for relate_task in related_tasks:
                        if relate_task["worker"] != self.my_id:
                            some_tasks_not_locked = True
                        else:
                            some_tasks_locked = True
                        if not creation_task and relate_task["action"] in ("CREATE", "FIND"):
                            creation_task = relate_task
                    if some_tasks_not_locked:
                        if some_tasks_locked:  # unlock
                            self.db.update_rows("vim_wim_actions", UPDATE={"worker": None}, modified_time=0,
                                                WHERE={self.target_k: self.target_v,
                                                       "worker": self.my_id,
                                                       "related": task_related,
                                                       "item": task["item"],
                                                       })
                        continue

                    task["params"] = None
                    if task["extra"]:
                        extra = yaml.load(task["extra"], Loader=yaml.Loader)
                    else:
                        extra = {}
                    task["extra"] = extra
                    if extra.get("depends_on"):
                        task["depends"] = {}
                    if extra.get("params"):
                        task["params"] = deepcopy(extra["params"])
                    return task, related_tasks
        except Exception as e:
            self.logger.critical("Unexpected exception at _get_db_task: " + str(e), exc_info=True)
            return None, None

    def _delete_task(self, task):
        """
        Determine if this task need to be done or superseded
        :return: None
        """

        def copy_extra_created(copy_to, copy_from):
            copy_to["created"] = copy_from["created"]
            if copy_from.get("sdn_net_id"):
                copy_to["sdn_net_id"] = copy_from["sdn_net_id"]
            if copy_from.get("interfaces"):
                copy_to["interfaces"] = copy_from["interfaces"]
            if copy_from.get("sdn-ports"):
                copy_to["sdn-ports"] = copy_from["sdn-ports"]
            if copy_from.get("created_items"):
                if not copy_to.get("created_items"):
                    copy_to["created_items"] = {}
                copy_to["created_items"].update(copy_from["created_items"])

        task_create = None
        dependency_task = None
        deletion_needed = task["extra"].get("created", False)
        if task["status"] == "FAILED":
            return   # TODO need to be retry??
        try:
            # get all related tasks. task of creation must be the first in the list of related_task,
            # unless the deletion fails and it is pendingit fails
            # TODO this should be removed, passing related_tasks
            related_tasks = self.db.get_rows(FROM="vim_wim_actions",
                                             WHERE={self.target_k: self.target_v,
                                                    "status": ['SCHEDULED', 'BUILD', 'DONE', 'FAILED'],
                                                    "action": ["FIND", "CREATE"],
                                                    "related": task["related"],
                                                    },
                                             ORDER_BY=("created_at",),
                                             )
            for related_task in related_tasks:
                if related_task["item"] == task["item"] and related_task["item_id"] == task["item_id"]:
                    task_create = related_task
                    # TASK_CREATE
                    if related_task["extra"]:
                        extra_created = yaml.load(related_task["extra"], Loader=yaml.Loader)
                        if extra_created.get("created"):
                            deletion_needed = True
                        related_task["extra"] = extra_created
                elif not dependency_task:
                    dependency_task = related_task
                if task_create and dependency_task:
                    break

            # mark task_create as FINISHED
            if task_create:
                self.db.update_rows("vim_wim_actions", UPDATE={"status": "FINISHED"},
                                    WHERE={self.target_k: self.target_v,
                                           "instance_action_id": task_create["instance_action_id"],
                                           "task_index": task_create["task_index"]
                                           })
            if not deletion_needed:
                return False
            elif dependency_task:
                # move create information  from task_create to relate_task
                extra_new_created = yaml.load(dependency_task["extra"], Loader=yaml.Loader) or {}
                extra_new_created["created"] = extra_created["created"]
                copy_extra_created(copy_to=extra_new_created, copy_from=extra_created)

                self.db.update_rows("vim_wim_actions",
                                    UPDATE={"extra": yaml.safe_dump(extra_new_created, default_flow_style=True,
                                                                    width=256),
                                            "vim_id": task_create.get("vim_id")},
                                    WHERE={self.target_k: self.target_v,
                                           "instance_action_id": dependency_task["instance_action_id"],
                                           "task_index": dependency_task["task_index"]
                                           })
                return False
            elif task_create:
                task["vim_id"] = task_create["vim_id"]
                copy_extra_created(copy_to=task["extra"], copy_from=task_create["extra"])
                # Ensure this task extra information is stored at database
                self.db.update_rows("vim_wim_actions",
                                    UPDATE={"extra":  yaml.safe_dump(task["extra"], default_flow_style=True,
                                                                     width=256)},
                                    WHERE={self.target_k: self.target_v,
                                           "instance_action_id": task["instance_action_id"],
                                           "task_index": task["task_index"],
                                           })
                return True
            return deletion_needed

        except Exception as e:
            self.logger.critical("Unexpected exception at _delete_task: " + str(e), exc_info=True)

    def _refres_vm(self, task):
        """Call VIM to get VMs status"""
        database_update = None

        vim_id = task["vim_id"]
        vm_to_refresh_list = [vim_id]
        try:
            vim_dict = self.vim.refresh_vms_status(vm_to_refresh_list)
            vim_info = vim_dict[vim_id]
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("task=several get-VM: vimconnException when trying to refresh vms " + str(e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}

        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        self.logger.debug("task={} get-VM: vim_vm_id={} result={}".format(task_id, task["vim_id"], vim_info))

        # check and update interfaces
        task_warning_msg = ""
        for interface in vim_info.get("interfaces", ()):
            vim_interface_id = interface["vim_interface_id"]
            if vim_interface_id not in task["extra"]["interfaces"]:
                self.logger.critical("task={} get-VM: Interface not found {} on task info {}".format(
                    task_id, vim_interface_id, task["extra"]["interfaces"]), exc_info=True)
                continue
            task_interface = task["extra"]["interfaces"][vim_interface_id]
            task_vim_interface = task_interface.get("vim_info")
            if task_vim_interface != interface:
                # delete old port
                # if task_interface.get("sdn_port_id"):
                #     try:
                #         self.ovim.delete_port(task_interface["sdn_port_id"], idempotent=True)
                #         task_interface["sdn_port_id"] = None
                #     except ovimException as e:
                #         error_text = "ovimException deleting external_port={}: {}".format(
                #             task_interface["sdn_port_id"], e)
                #         self.logger.error("task={} get-VM: {}".format(task_id, error_text), exc_info=True)
                #         task_warning_msg += error_text
                #         # TODO Set error_msg at instance_nets instead of instance VMs

                # Create SDN port
                # sdn_net_id = task_interface.get("sdn_net_id")
                # if sdn_net_id and interface.get("compute_node") and interface.get("pci"):
                #     sdn_port_name = sdn_net_id + "." + task["vim_id"]
                #     sdn_port_name = sdn_port_name[:63]
                #     try:
                #         sdn_port_id = self.ovim.new_external_port(
                #             {"compute_node": interface["compute_node"],
                #                 "pci": interface["pci"],
                #                 "vlan": interface.get("vlan"),
                #                 "net_id": sdn_net_id,
                #                 "region": self.vim["config"]["datacenter_id"],
                #                 "name": sdn_port_name,
                #                 "mac": interface.get("mac_address")})
                #         task_interface["sdn_port_id"] = sdn_port_id
                #     except (ovimException, Exception) as e:
                #         error_text = "ovimException creating new_external_port compute_node={} pci={} vlan={} {}".\
                #             format(interface["compute_node"], interface["pci"], interface.get("vlan"), e)
                #         self.logger.error("task={} get-VM: {}".format(task_id, error_text), exc_info=True)
                #         task_warning_msg += error_text
                #         # TODO Set error_msg at instance_nets instead of instance VMs

                self.db.update_rows('instance_interfaces',
                                    UPDATE={"mac_address": interface.get("mac_address"),
                                            "ip_address": interface.get("ip_address"),
                                            "vim_interface_id": interface.get("vim_interface_id"),
                                            "vim_info": interface.get("vim_info"),
                                            "sdn_port_id": task_interface.get("sdn_port_id"),
                                            "compute_node": interface.get("compute_node"),
                                            "pci": interface.get("pci"),
                                            "vlan": interface.get("vlan")},
                                    WHERE={'uuid': task_interface["iface_id"]})
                task_interface["vim_info"] = interface
                # if sdn_net_id and interface.get("compute_node") and interface.get("pci"):
                # # TODO Send message to task SDN to update

        # check and update task and instance_vms database
        vim_info_error_msg = None
        if vim_info.get("error_msg"):
            vim_info_error_msg = self._format_vim_error_msg(vim_info["error_msg"] + task_warning_msg)
        elif task_warning_msg:
            vim_info_error_msg = self._format_vim_error_msg(task_warning_msg)
        task_vim_info = task["extra"].get("vim_info")
        task_error_msg = task.get("error_msg")
        task_vim_status = task["extra"].get("vim_status")
        if task_vim_status != vim_info["status"] or task_error_msg != vim_info_error_msg or \
                (vim_info.get("vim_info") and task_vim_info != vim_info["vim_info"]):
            database_update = {"status": vim_info["status"], "error_msg": vim_info_error_msg}
            if vim_info.get("vim_info"):
                database_update["vim_info"] = vim_info["vim_info"]

            task["extra"]["vim_status"] = vim_info["status"]
            task["error_msg"] = vim_info_error_msg
            if vim_info.get("vim_info"):
                task["extra"]["vim_info"] = vim_info["vim_info"]

        return database_update

    def _refres_net(self, task):
        """Call VIM to get network status"""
        database_update = None

        vim_id = task["vim_id"]
        net_to_refresh_list = [vim_id]
        try:
            vim_dict = self.vim.refresh_nets_status(net_to_refresh_list)
            vim_info = vim_dict[vim_id]
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("task=several get-net: vimconnException when trying to refresh nets " + str(e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}

        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        self.logger.debug("task={} get-net: vim_net_id={} result={}".format(task_id, task["vim_id"], vim_info))

        task_vim_info = task["extra"].get("vim_info")
        task_vim_status = task["extra"].get("vim_status")
        task_error_msg = task.get("error_msg")
        # task_sdn_net_id = task["extra"].get("sdn_net_id")

        vim_info_status = vim_info["status"]
        vim_info_error_msg = vim_info.get("error_msg")
        # get ovim status
        # if task_sdn_net_id:
        #     try:
        #         sdn_net = self.ovim.show_network(task_sdn_net_id)
        #     except (ovimException, Exception) as e:
        #         text_error = "ovimException getting network snd_net_id={}: {}".format(task_sdn_net_id, e)
        #         self.logger.error("task={} get-net: {}".format(task_id, text_error), exc_info=True)
        #         sdn_net = {"status": "ERROR", "last_error": text_error}
        #     if sdn_net["status"] == "ERROR":
        #         if not vim_info_error_msg:
        #             vim_info_error_msg = str(sdn_net.get("last_error"))
        #         else:
        #             vim_info_error_msg = "VIM_ERROR: {} && SDN_ERROR: {}".format(
        #                 self._format_vim_error_msg(vim_info_error_msg, 1024 // 2 - 14),
        #                 self._format_vim_error_msg(sdn_net["last_error"], 1024 // 2 - 14))
        #         vim_info_status = "ERROR"
        #     elif sdn_net["status"] == "BUILD":
        #         if vim_info_status == "ACTIVE":
        #             vim_info_status = "BUILD"

        # update database
        if vim_info_error_msg:
            vim_info_error_msg = self._format_vim_error_msg(vim_info_error_msg)
        if task_vim_status != vim_info_status or task_error_msg != vim_info_error_msg or \
                (vim_info.get("vim_info") and task_vim_info != vim_info["vim_info"]):
            task["extra"]["vim_status"] = vim_info_status
            task["error_msg"] = vim_info_error_msg
            if vim_info.get("vim_info"):
                task["extra"]["vim_info"] = vim_info["vim_info"]
            database_update = {"status": vim_info_status, "error_msg": vim_info_error_msg}
            if vim_info.get("vim_info"):
                database_update["vim_info"] = vim_info["vim_info"]
        return database_update

    def _proccess_pending_tasks(self, task, related_tasks):
        old_task_status = task["status"]
        create_or_find = False   # if as result of processing this task something is created or found
        next_refresh = 0
        task_id = task["instance_action_id"] + "." + str(task["task_index"])

        try:
            if task["status"] == "SCHEDULED":
                # check if tasks that this depends on have been completed
                dependency_not_completed = False
                dependency_modified_at = 0
                for task_index in task["extra"].get("depends_on", ()):
                    task_dependency = self._look_for_task(task["instance_action_id"], task_index)
                    if not task_dependency:
                        raise VimThreadException(
                            "Cannot get depending net task trying to get depending task {}.{}".format(
                                task["instance_action_id"], task_index))
                    # task["depends"]["TASK-" + str(task_index)] = task_dependency #it references another object,so
                    # database must be look again
                    if task_dependency["status"] == "SCHEDULED":
                        dependency_not_completed = True
                        dependency_modified_at = task_dependency["modified_at"]
                        break
                    elif task_dependency["status"] == "FAILED":
                        raise VimThreadException(
                            "Cannot {} {}, (task {}.{}) because depends on failed {}.{}, (task{}.{}): {}".format(
                                task["action"], task["item"],
                                task["instance_action_id"], task["task_index"],
                                task_dependency["instance_action_id"], task_dependency["task_index"],
                                task_dependency["action"], task_dependency["item"], task_dependency.get("error_msg")))

                    task["depends"]["TASK-"+str(task_index)] = task_dependency
                    task["depends"]["TASK-{}.{}".format(task["instance_action_id"], task_index)] = task_dependency
                if dependency_not_completed:
                    # Move this task to the time dependency is going to be modified plus 10 seconds.
                    self.db.update_rows("vim_wim_actions", modified_time=dependency_modified_at + 10,
                                        UPDATE={"worker": None},
                                        WHERE={self.target_k: self.target_v, "worker": self.my_id,
                                               "related": task["related"],
                                               })
                    # task["extra"]["tries"] = task["extra"].get("tries", 0) + 1
                    # if task["extra"]["tries"] > 3:
                    #     raise VimThreadException(
                    #         "Cannot {} {}, (task {}.{}) because timeout waiting to complete {} {}, "
                    #         "(task {}.{})".format(task["action"], task["item"],
                    #                               task["instance_action_id"], task["task_index"],
                    #                               task_dependency["instance_action_id"], task_dependency["task_index"]
                    #                               task_dependency["action"], task_dependency["item"]))
                    return

            database_update = None
            if task["action"] == "DELETE":
                deleted_needed = self._delete_task(task)
                if not deleted_needed:
                    task["status"] = "SUPERSEDED"  # with FINISHED instead of DONE it will not be refreshing
                    task["error_msg"] = None

            if task["status"] == "SUPERSEDED":
                # not needed to do anything but update database with the new status
                database_update = None
            elif not self.vim and not self.sdnconnector:
                task["status"] = "FAILED"
                task["error_msg"] = self.error_status
                database_update = {"status": "VIM_ERROR" if self.datacenter_tenant_id else "WIM_ERROR",
                                   "error_msg": task["error_msg"]}
            elif task["item_id"] != related_tasks[0]["item_id"] and task["action"] in ("FIND", "CREATE"):
                # Do nothing, just copy values from one to another and update database
                task["status"] = related_tasks[0]["status"]
                task["error_msg"] = related_tasks[0]["error_msg"]
                task["vim_id"] = related_tasks[0]["vim_id"]
                extra = yaml.load(related_tasks[0]["extra"], Loader=yaml.Loader)
                task["extra"]["vim_status"] = extra.get("vim_status")
                next_refresh = related_tasks[0]["modified_at"] + 0.001
                database_update = {"status": task["extra"].get("vim_status", "VIM_ERROR"),
                                   "error_msg": task["error_msg"]}
                if task["item"] == 'instance_vms':
                    database_update["vim_vm_id"] = task["vim_id"]
                elif task["item"] == 'instance_nets':
                    database_update["vim_net_id"] = task["vim_id"]
            elif task["item"] == 'instance_vms':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self._refres_vm(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_vm(task)
                elif task["action"] == "DELETE":
                    self.del_vm(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            elif task["item"] == 'instance_nets':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self._refres_net(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_net(task)
                elif task["action"] == "DELETE":
                    self.del_net(task)
                elif task["action"] == "FIND":
                    database_update = self.get_net(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            elif task["item"] == 'instance_wim_nets':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self.new_or_update_sdn_net(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_or_update_sdn_net(task)
                elif task["action"] == "DELETE":
                    self.del_sdn_net(task)
                elif task["action"] == "FIND":
                    database_update = self.get_sdn_net(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            elif task["item"] == 'instance_sfis':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self._refres_sfis(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_sfi(task)
                elif task["action"] == "DELETE":
                    self.del_sfi(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            elif task["item"] == 'instance_sfs':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self._refres_sfs(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_sf(task)
                elif task["action"] == "DELETE":
                    self.del_sf(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            elif task["item"] == 'instance_classifications':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self._refres_classifications(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_classification(task)
                elif task["action"] == "DELETE":
                    self.del_classification(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            elif task["item"] == 'instance_sfps':
                if task["status"] in ('BUILD', 'DONE') and task["action"] in ("FIND", "CREATE"):
                    database_update = self._refres_sfps(task)
                    create_or_find = True
                elif task["action"] == "CREATE":
                    create_or_find = True
                    database_update = self.new_sfp(task)
                elif task["action"] == "DELETE":
                    self.del_sfp(task)
                else:
                    raise vimconn.VimConnException(self.name + "unknown task action {}".format(task["action"]))
            else:
                raise vimconn.VimConnException(self.name + "unknown task item {}".format(task["item"]))
                # TODO
        except Exception as e:
            if not isinstance(e, VimThreadException):
                self.logger.error("Error executing task={}: {}".format(task_id, e), exc_info=True)
            task["error_msg"] = str(e)
            task["status"] = "FAILED"
            database_update = {"status": "VIM_ERROR" if task["item"] != "instance_wim_nets" else "WIM_ERROR",
                               "error_msg": task["error_msg"]}
            # if task["item"] == 'instance_vms':
            #     database_update["vim_vm_id"] = None
            # elif task["item"] == 'instance_nets':
            #     database_update["vim_net_id"] = None

        self.logger.debug("task={} item={} action={} result={}:'{}' params={}".format(
            task_id, task["item"], task["action"], task["status"],
            task["vim_id"] if task["status"] == "DONE" else task.get("error_msg"), task["params"]))
        try:
            if not next_refresh:
                if task["status"] == "DONE":
                    next_refresh = time.time()
                    if task["extra"].get("vim_status") == "BUILD":
                        next_refresh += self.REFRESH_BUILD
                    elif task["extra"].get("vim_status") in ("ERROR", "VIM_ERROR", "WIM_ERROR"):
                        next_refresh += self.REFRESH_ERROR
                    elif task["extra"].get("vim_status") == "DELETED":
                        next_refresh += self.REFRESH_DELETE
                    else:
                        next_refresh += self.REFRESH_ACTIVE
                elif task["status"] == "FAILED":
                    next_refresh = time.time() + self.REFRESH_DELETE

            if create_or_find:
                # modify all related task with action FIND/CREATED non SCHEDULED
                self.db.update_rows(
                    table="vim_wim_actions", modified_time=next_refresh + 0.001,
                    UPDATE={"status": task["status"], "vim_id": task.get("vim_id"),
                            "error_msg": task["error_msg"],
                            },

                    WHERE={self.target_k: self.target_v,
                           "worker": self.my_id,
                           "action": ["FIND", "CREATE"],
                           "related": task["related"],
                           "status<>": "SCHEDULED",
                           })
            # modify own task
            self.db.update_rows(
                table="vim_wim_actions", modified_time=next_refresh,
                UPDATE={"status": task["status"], "vim_id": task.get("vim_id"),
                        "error_msg": task["error_msg"],
                        "extra": yaml.safe_dump(task["extra"], default_flow_style=True, width=256)},
                WHERE={"instance_action_id": task["instance_action_id"], "task_index": task["task_index"]})
            # Unlock tasks
            self.db.update_rows(
                table="vim_wim_actions", modified_time=0,
                UPDATE={"worker": None},
                WHERE={self.target_k: self.target_v,
                       "worker": self.my_id,
                       "related": task["related"],
                       })

            # Update table instance_actions
            if old_task_status == "SCHEDULED" and task["status"] != old_task_status:
                self.db.update_rows(
                    table="instance_actions",
                    UPDATE={("number_failed" if task["status"] == "FAILED" else "number_done"): {"INCREMENT": 1}},
                    WHERE={"uuid": task["instance_action_id"]})
            if database_update:
                where_filter = {"related": task["related"]}
                if task["item"] == "instance_nets" and task["datacenter_vim_id"]:
                    where_filter["datacenter_tenant_id"] = task["datacenter_vim_id"]
                self.db.update_rows(table=task["item"],
                                    UPDATE=database_update,
                                    WHERE=where_filter)
        except db_base_Exception as e:
            self.logger.error("task={} Error updating database {}".format(task_id, e), exc_info=True)

    def insert_task(self, task):
        try:
            self.task_queue.put(task, False)
            return None
        except queue.Full:
            raise vimconn.VimConnException(self.name + ": timeout inserting a task")

    def del_task(self, task):
        with self.task_lock:
            if task["status"] == "SCHEDULED":
                task["status"] = "SUPERSEDED"
                return True
            else:  # task["status"] == "processing"
                self.task_lock.release()
                return False

    def run(self):
        self.logger.debug("Starting")
        while True:
            self.get_vim_sdn_connector()
            self.logger.debug("Vimconnector loaded")
            reload_thread = False

            while True:
                try:
                    while not self.task_queue.empty():
                        task = self.task_queue.get()
                        if isinstance(task, list):
                            pass
                        elif isinstance(task, str):
                            if task == 'exit':
                                return 0
                            elif task == 'reload':
                                reload_thread = True
                                break
                        self.task_queue.task_done()
                    if reload_thread:
                        break

                    task, related_tasks = self._get_db_task()
                    if task:
                        self._proccess_pending_tasks(task, related_tasks)
                    else:
                        time.sleep(5)

                except Exception as e:
                    self.logger.critical("Unexpected exception at run: " + str(e), exc_info=True)

        self.logger.debug("Finishing")

    def _look_for_task(self, instance_action_id, task_id):
        """
        Look for a concrete task at vim_actions database table
        :param instance_action_id: The instance_action_id
        :param task_id: Can have several formats:
            <task index>: integer
            TASK-<task index> :backward compatibility,
            [TASK-]<instance_action_id>.<task index>: this instance_action_id overrides the one in the parameter
        :return: Task dictionary or None if not found
        """
        if isinstance(task_id, int):
            task_index = task_id
        else:
            if task_id.startswith("TASK-"):
                task_id = task_id[5:]
            ins_action_id, _, task_index = task_id.rpartition(".")
            if ins_action_id:
                instance_action_id = ins_action_id

        tasks = self.db.get_rows(FROM="vim_wim_actions", WHERE={"instance_action_id": instance_action_id,
                                                                "task_index": task_index})
        if not tasks:
            return None
        task = tasks[0]
        task["params"] = None
        task["depends"] = {}
        if task["extra"]:
            extra = yaml.load(task["extra"], Loader=yaml.Loader)
            task["extra"] = extra
            task["params"] = extra.get("params")
        else:
            task["extra"] = {}
        return task

    @staticmethod
    def _format_vim_error_msg(error_text, max_length=1024):
        if error_text and len(error_text) >= max_length:
            return error_text[:max_length // 2 - 3] + " ... " + error_text[-max_length // 2 + 3:]
        return error_text

    def new_vm(self, task):
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        try:
            params = task["params"]
            depends = task.get("depends")
            net_list = params[5]
            for net in net_list:
                if "net_id" in net and is_task_id(net["net_id"]):  # change task_id into network_id
                    network_id = task["depends"][net["net_id"]].get("vim_id")
                    if not network_id:
                        raise VimThreadException(
                            "Cannot create VM because depends on a network not created or found: " +
                            str(depends[net["net_id"]]["error_msg"]))
                    net["net_id"] = network_id
            params_copy = deepcopy(params)
            vim_vm_id, created_items = self.vim.new_vminstance(*params_copy)

            # fill task_interfaces. Look for snd_net_id at database for each interface
            task_interfaces = {}
            for iface in params_copy[5]:
                task_interfaces[iface["vim_id"]] = {"iface_id": iface["uuid"]}
                result = self.db.get_rows(
                    SELECT=('sdn_net_id', 'interface_id'),
                    FROM='instance_nets as ine join instance_interfaces as ii on ii.instance_net_id=ine.uuid',
                    WHERE={'ii.uuid': iface["uuid"]})
                if result:
                    task_interfaces[iface["vim_id"]]["sdn_net_id"] = result[0]['sdn_net_id']
                    task_interfaces[iface["vim_id"]]["interface_id"] = result[0]['interface_id']
                else:
                    self.logger.critical("task={} new-VM: instance_nets uuid={} not found at DB".format(task_id,
                                                                                                        iface["uuid"]),
                                         exc_info=True)

            task["vim_info"] = {}
            task["extra"]["interfaces"] = task_interfaces
            task["extra"]["created"] = True
            task["extra"]["created_items"] = created_items
            task["extra"]["vim_status"] = "BUILD"
            task["error_msg"] = None
            task["status"] = "DONE"
            task["vim_id"] = vim_vm_id
            instance_element_update = {"status": "BUILD", "vim_vm_id": vim_vm_id, "error_msg": None}
            return instance_element_update

        except (vimconn.VimConnException, VimThreadException) as e:
            self.logger.error("task={} new-VM: {}".format(task_id, e))
            error_text = self._format_vim_error_msg(str(e))
            task["error_msg"] = error_text
            task["status"] = "FAILED"
            task["vim_id"] = None
            instance_element_update = {"status": "VIM_ERROR", "vim_vm_id": None, "error_msg": error_text}
            return instance_element_update

    def del_vm(self, task):
        # task_id = task["instance_action_id"] + "." + str(task["task_index"])
        vm_vim_id = task["vim_id"]
        # interfaces = task["extra"].get("interfaces", ())
        try:
            # for iface in interfaces.values():
            #     if iface.get("sdn_port_id"):
            #         try:
            #             self.ovim.delete_port(iface["sdn_port_id"], idempotent=True)
            #         except ovimException as e:
            #             self.logger.error("task={} del-VM: ovimException when deleting external_port={}: {} ".format(
            #                 task_id, iface["sdn_port_id"], e), exc_info=True)
            #             # TODO Set error_msg at instance_nets

            self.vim.delete_vminstance(vm_vim_id, task["extra"].get("created_items"))
            task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
            task["error_msg"] = None
            return None

        except vimconn.VimConnException as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if isinstance(e, vimconn.VimConnNotFoundException):
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                return None
            task["status"] = "FAILED"
            return None

    def _get_net_internal(self, task, filter_param):
        """
        Common code for get_net and new_net. It looks for a network on VIM with the filter_params
        :param task: task for this find or find-or-create action
        :param filter_param: parameters to send to the vimconnector
        :return: a dict with the content to update the instance_nets database table. Raises an exception on error, or
            when network is not found or found more than one
        """
        vim_nets = self.vim.get_network_list(filter_param)
        if not vim_nets:
            raise VimThreadExceptionNotFound("Network not found with this criteria: '{}'".format(filter_param))
        elif len(vim_nets) > 1:
            raise VimThreadException("More than one network found with this criteria: '{}'".format(filter_param))
        vim_net_id = vim_nets[0]["id"]

        # Discover if this network is managed by a sdn controller
        sdn_net_id = None
        result = self.db.get_rows(SELECT=('sdn_net_id',), FROM='instance_nets',
                                  WHERE={'vim_net_id': vim_net_id, 'datacenter_tenant_id': self.datacenter_tenant_id},
                                  ORDER="instance_scenario_id")
        if result:
            sdn_net_id = result[0]['sdn_net_id']

        task["status"] = "DONE"
        task["extra"]["vim_info"] = {}
        task["extra"]["created"] = False
        task["extra"]["vim_status"] = "BUILD"
        task["extra"]["sdn_net_id"] = sdn_net_id
        task["error_msg"] = None
        task["vim_id"] = vim_net_id
        instance_element_update = {"vim_net_id": vim_net_id, "created": False, "status": "BUILD",
                                   "error_msg": None, "sdn_net_id": sdn_net_id}
        return instance_element_update

    def get_net(self, task):
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        try:
            params = task["params"]
            filter_param = params[0]
            instance_element_update = self._get_net_internal(task, filter_param)
            return instance_element_update

        except (vimconn.VimConnException, VimThreadException) as e:
            self.logger.error("task={} get-net: {}".format(task_id, e))
            task["status"] = "FAILED"
            task["vim_id"] = None
            task["error_msg"] = self._format_vim_error_msg(str(e))
            instance_element_update = {"vim_net_id": None, "status": "VIM_ERROR",
                                       "error_msg": task["error_msg"]}
            return instance_element_update

    def new_net(self, task):
        vim_net_id = None
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        action_text = ""
        try:
            # FIND
            if task["extra"].get("find"):
                action_text = "finding"
                filter_param = task["extra"]["find"][0]
                try:
                    instance_element_update = self._get_net_internal(task, filter_param)
                    return instance_element_update
                except VimThreadExceptionNotFound:
                    pass
            # CREATE
            params = task["params"]
            action_text = "creating VIM"

            vim_net_id, created_items = self.vim.new_network(*params[0:5])

            # net_name = params[0]
            # net_type = params[1]
            # wim_account_name = None
            # if len(params) >= 6:
            #     wim_account_name = params[5]

            # TODO fix at nfvo adding external port
            # if wim_account_name and self.vim.config["wim_external_ports"]:
            #     # add external port to connect WIM. Try with compute node __WIM:wim_name and __WIM
            #     action_text = "attaching external port to ovim network"
            #     sdn_port_name = "external_port"
            #     sdn_port_data = {
            #         "compute_node": "__WIM:" + wim_account_name[0:58],
            #         "pci": None,
            #         "vlan": network["vlan"],
            #         "net_id": sdn_net_id,
            #         "region": self.vim["config"]["datacenter_id"],
            #         "name": sdn_port_name,
            #     }
            #     try:
            #         sdn_external_port_id = self.ovim.new_external_port(sdn_port_data)
            #     except ovimException:
            #         sdn_port_data["compute_node"] = "__WIM"
            #         sdn_external_port_id = self.ovim.new_external_port(sdn_port_data)
            #     self.logger.debug("Added sdn_external_port {} to sdn_network {}".format(sdn_external_port_id,
            #                                                                             sdn_net_id))
            task["status"] = "DONE"
            task["extra"]["vim_info"] = {}
            # task["extra"]["sdn_net_id"] = sdn_net_id
            task["extra"]["vim_status"] = "BUILD"
            task["extra"]["created"] = True
            task["extra"]["created_items"] = created_items
            task["error_msg"] = None
            task["vim_id"] = vim_net_id
            instance_element_update = {"vim_net_id": vim_net_id, "status": "BUILD",
                                       "created": True, "error_msg": None}
            return instance_element_update
        except vimconn.VimConnException as e:
            self.logger.error("task={} new-net: Error {}: {}".format(task_id, action_text, e))
            task["status"] = "FAILED"
            task["vim_id"] = vim_net_id
            task["error_msg"] = self._format_vim_error_msg(str(e))
            # task["extra"]["sdn_net_id"] = sdn_net_id
            instance_element_update = {"vim_net_id": vim_net_id, "status": "VIM_ERROR",
                                       "error_msg": task["error_msg"]}
            return instance_element_update

    def del_net(self, task):
        net_vim_id = task["vim_id"]
        # sdn_net_id = task["extra"].get("sdn_net_id")
        try:
            if net_vim_id:
                self.vim.delete_network(net_vim_id, task["extra"].get("created_items"))
            # if sdn_net_id:
            #     # Delete any attached port to this sdn network. There can be ports associated to this network in case
            #     # it was manually done using 'openmano vim-net-sdn-attach'
            #     port_list = self.ovim.get_ports(columns={'uuid'},
            #                                     filter={'name': 'external_port', 'net_id': sdn_net_id})
            #     for port in port_list:
            #         self.ovim.delete_port(port['uuid'], idempotent=True)
            #     self.ovim.delete_network(sdn_net_id, idempotent=True)
            task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
            task["error_msg"] = None
            return None
        except vimconn.VimConnException as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if isinstance(e, vimconn.VimConnNotFoundException):
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                return None
        task["status"] = "FAILED"
        return None

    def new_or_update_sdn_net(self, task):
        wimconn_net_id = task["vim_id"]
        created_items = task["extra"].get("created_items")
        connected_ports = task["extra"].get("connected_ports", [])
        new_connected_ports = []
        last_update = task["extra"].get("last_update", 0)
        sdn_status = task["extra"].get("vim_status", "BUILD")
        sdn_info = None

        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        error_list = []
        try:
            # FIND
            if task["extra"].get("find"):
                wimconn_id = task["extra"]["find"][0]
                try:
                    instance_element_update = self.sdnconnector.get_connectivity_service_status(wimconn_id)
                    wimconn_net_id = wimconn_id
                    instance_element_update = {"wim_internal_id": wimconn_net_id, "created": False, "status": "BUILD",
                                               "error_msg": None, }
                    return instance_element_update
                except Exception as e:
                    if isinstance(e, SdnConnectorError) and e.http_error == HTTPStatus.NOT_FOUND.value:
                        pass
                    else:
                        self._proccess_sdn_exception(e)

            params = task["params"]
            # CREATE
            # look for ports
            sdn_ports = []
            pending_ports = 0
            vlan_used = None

            ports = self.db.get_rows(FROM='instance_interfaces', WHERE={'instance_wim_net_id': task["item_id"]})
            sdn_need_update = False
            for port in ports:
                vlan_used = port.get("vlan") or vlan_used
                # TODO. Do not connect if already done
                if port.get("compute_node") and port.get("pci"):
                    for pmap in self.port_mappings:
                        if pmap.get("device_id") == port["compute_node"] and \
                                pmap.get("device_interface_id") == port["pci"]:
                            break
                    else:
                        if self.sdnconn_config.get("mapping_not_needed"):
                            pmap = {
                                "service_endpoint_id": "{}:{}".format(port["compute_node"], port["pci"]),
                                "service_endpoint_encapsulation_info": {
                                    "vlan": port["vlan"],
                                    "mac": port["mac_address"],
                                    "device_id": port["compute_node"],
                                    "device_interface_id": port["pci"]
                                }
                            }
                        else:
                            pmap = None
                            error_list.append("Port mapping not found for compute_node={} pci={}".format(
                                port["compute_node"], port["pci"]))

                    if pmap:
                        if port["modified_at"] > last_update:
                            sdn_need_update = True
                        new_connected_ports.append(port["uuid"])
                        sdn_ports.append({
                            "service_endpoint_id": pmap["service_endpoint_id"],
                            "service_endpoint_encapsulation_type": "dot1q" if port["model"] == "SR-IOV" else None,
                            "service_endpoint_encapsulation_info": {
                                "vlan": port["vlan"],
                                "mac": port["mac_address"],
                                "device_id": pmap.get("device_id"),
                                "device_interface_id": pmap.get("device_interface_id"),
                                "switch_dpid": pmap.get("switch_dpid"),
                                "switch_port": pmap.get("switch_port"),
                                "service_mapping_info": pmap.get("service_mapping_info"),
                            }
                        })

                else:
                    pending_ports += 1
            if pending_ports:
                error_list.append("Waiting for getting interfaces location from VIM. Obtained '{}' of {}"
                                  .format(len(ports)-pending_ports, len(ports)))

            # connect external ports
            for index, external_port in enumerate(task["extra"].get("sdn-ports") or ()):
                external_port_id = external_port.get("service_endpoint_id") or str(index)
                sdn_ports.append({
                    "service_endpoint_id": external_port_id,
                    "service_endpoint_encapsulation_type": external_port.get("service_endpoint_encapsulation_type",
                                                                             "dot1q"),
                    "service_endpoint_encapsulation_info": {
                        "vlan": external_port.get("vlan") or vlan_used,
                        "mac": external_port.get("mac_address"),
                        "device_id": external_port.get("device_id"),
                        "device_interface_id": external_port.get("device_interface_id"),
                        "switch_dpid": external_port.get("switch_dpid") or external_port.get("switch_id"),
                        "switch_port": external_port.get("switch_port"),
                        "service_mapping_info": external_port.get("service_mapping_info"),
                    }})
                new_connected_ports.append(external_port_id)

            # if there are more ports to connect or they have been modified, call create/update
            try:
                if set(connected_ports) != set(new_connected_ports) or sdn_need_update:
                    last_update = time.time()
                    if not wimconn_net_id:
                        if len(sdn_ports) < 2:
                            if not pending_ports:
                                sdn_status = "ACTIVE"
                        else:
                            if params[0] == "data":
                                net_type = "ELAN"
                            elif params[0] == "ptp":
                                net_type = "ELINE"
                            else:
                                net_type = "L3"
                            wimconn_net_id, created_items = self.sdnconnector.create_connectivity_service(
                                net_type, sdn_ports)
                    else:
                        created_items = self.sdnconnector.edit_connectivity_service(
                            wimconn_net_id, conn_info=created_items, connection_points=sdn_ports)
                    connected_ports = new_connected_ports
                elif wimconn_net_id:
                    wim_status_dict = self.sdnconnector.get_connectivity_service_status(wimconn_net_id,
                                                                                        conn_info=created_items)
                    sdn_status = wim_status_dict["sdn_status"]
                    if wim_status_dict.get("error_msg"):
                        error_list.append(wim_status_dict.get("error_msg"))
                    if wim_status_dict.get("sdn_info"):
                        sdn_info = str(wim_status_dict.get("sdn_info"))
            except Exception as e:
                self._proccess_sdn_exception(e)

            task["status"] = "DONE"
            task["extra"]["vim_info"] = {}
            # task["extra"]["sdn_net_id"] = sdn_net_id
            task["extra"]["vim_status"] = sdn_status
            task["extra"]["created"] = True
            task["extra"]["created_items"] = created_items
            task["extra"]["connected_ports"] = connected_ports
            task["extra"]["last_update"] = last_update
            task["error_msg"] = self._format_vim_error_msg(" ; ".join(error_list))
            task["vim_id"] = wimconn_net_id
            instance_element_update = {"wim_internal_id": wimconn_net_id, "status": sdn_status,
                                       "created": True, "error_msg": task["error_msg"] or None}
        except (vimconn.VimConnException, SdnConnectorError) as e:
            self.logger.error("task={} new-sdn-net: Error: {}".format(task_id, e))
            task["status"] = "FAILED"
            task["vim_id"] = wimconn_net_id
            task["error_msg"] = self._format_vim_error_msg(str(e))
            # task["extra"]["sdn_net_id"] = sdn_net_id
            instance_element_update = {"wim_internal_id": wimconn_net_id, "status": "WIM_ERROR",
                                       "error_msg": task["error_msg"]}

        if sdn_info:
            instance_element_update["wim_info"] = sdn_info
        return instance_element_update

    def del_sdn_net(self, task):
        wimconn_net_id = task["vim_id"]
        try:
            try:
                if wimconn_net_id:
                    self.sdnconnector.delete_connectivity_service(wimconn_net_id, task["extra"].get("created_items"))
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                task["error_msg"] = None
                return None
            except Exception as e:
                self._proccess_sdn_exception(e)
        except SdnConnectorError as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if e.http_code == HTTPStatus.NOT_FOUND.value:
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                task["error_msg"] = None
                return None
        task["status"] = "FAILED"
        return None

    # Service Function Instances
    def new_sfi(self, task):
        vim_sfi_id = None
        try:
            # Waits for interfaces to be ready (avoids failure)
            time.sleep(1)
            dep_id = "TASK-" + str(task["extra"]["depends_on"][0])
            task_id = task["instance_action_id"] + "." + str(task["task_index"])
            error_text = ""
            interfaces = task["depends"][dep_id]["extra"].get("interfaces")

            ingress_interface_id = task.get("extra").get("params").get("ingress_interface_id")
            egress_interface_id = task.get("extra").get("params").get("egress_interface_id")
            ingress_vim_interface_id = None
            egress_vim_interface_id = None
            for vim_interface, interface_data in interfaces.items():
                if interface_data.get("interface_id") == ingress_interface_id:
                    ingress_vim_interface_id = vim_interface
                    break
            if ingress_interface_id != egress_interface_id:
                for vim_interface, interface_data in interfaces.items():
                    if interface_data.get("interface_id") == egress_interface_id:
                        egress_vim_interface_id = vim_interface
                        break
            else:
                egress_vim_interface_id = ingress_vim_interface_id
            if not ingress_vim_interface_id or not egress_vim_interface_id:
                error_text = "Error creating Service Function Instance, Ingress: {}, Egress: {}".format(
                    ingress_vim_interface_id, egress_vim_interface_id)
                self.logger.error(error_text)
                task["error_msg"] = error_text
                task["status"] = "FAILED"
                task["vim_id"] = None
                return None
            # At the moment, every port associated with the VM will be used both as ingress and egress ports.
            # Bear in mind that different VIM connectors might support SFI differently. In the case of OpenStack,
            # only the first ingress and first egress ports will be used to create the SFI (Port Pair).
            ingress_port_id_list = [ingress_vim_interface_id]
            egress_port_id_list = [egress_vim_interface_id]
            name = "sfi-{}".format(task["item_id"][:8])
            # By default no form of IETF SFC Encapsulation will be used
            vim_sfi_id = self.vim.new_sfi(name, ingress_port_id_list, egress_port_id_list, sfc_encap=False)

            task["extra"]["created"] = True
            task["extra"]["vim_status"] = "ACTIVE"
            task["error_msg"] = None
            task["status"] = "DONE"
            task["vim_id"] = vim_sfi_id
            instance_element_update = {"status": "ACTIVE", "vim_sfi_id": vim_sfi_id, "error_msg": None}
            return instance_element_update

        except (vimconn.VimConnException, VimThreadException) as e:
            self.logger.error("Error creating Service Function Instance, task=%s: %s", task_id, str(e))
            error_text = self._format_vim_error_msg(str(e))
            task["error_msg"] = error_text
            task["status"] = "FAILED"
            task["vim_id"] = None
            instance_element_update = {"status": "VIM_ERROR", "vim_sfi_id": None, "error_msg": error_text}
            return instance_element_update

    def del_sfi(self, task):
        sfi_vim_id = task["vim_id"]
        try:
            self.vim.delete_sfi(sfi_vim_id)
            task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
            task["error_msg"] = None
            return None

        except vimconn.VimConnException as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if isinstance(e, vimconn.VimConnNotFoundException):
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                return None
            task["status"] = "FAILED"
            return None

    def new_sf(self, task):
        vim_sf_id = None
        try:
            task_id = task["instance_action_id"] + "." + str(task["task_index"])
            error_text = ""
            depending_tasks = ["TASK-" + str(dep_id) for dep_id in task["extra"]["depends_on"]]
            # sfis = next(iter(task.get("depends").values())).get("extra").get("params")[5]
            sfis = [task.get("depends").get(dep_task) for dep_task in depending_tasks]
            sfi_id_list = []
            for sfi in sfis:
                sfi_id_list.append(sfi.get("vim_id"))
            name = "sf-{}".format(task["item_id"][:8])
            # By default no form of IETF SFC Encapsulation will be used
            vim_sf_id = self.vim.new_sf(name, sfi_id_list, sfc_encap=False)

            task["extra"]["created"] = True
            task["extra"]["vim_status"] = "ACTIVE"
            task["error_msg"] = None
            task["status"] = "DONE"
            task["vim_id"] = vim_sf_id
            instance_element_update = {"status": "ACTIVE", "vim_sf_id": vim_sf_id, "error_msg": None}
            return instance_element_update

        except (vimconn.VimConnException, VimThreadException) as e:
            self.logger.error("Error creating Service Function, task=%s: %s", task_id, str(e))
            error_text = self._format_vim_error_msg(str(e))
            task["error_msg"] = error_text
            task["status"] = "FAILED"
            task["vim_id"] = None
            instance_element_update = {"status": "VIM_ERROR", "vim_sf_id": None, "error_msg": error_text}
            return instance_element_update

    def del_sf(self, task):
        sf_vim_id = task["vim_id"]
        try:
            self.vim.delete_sf(sf_vim_id)
            task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
            task["error_msg"] = None
            return None

        except vimconn.VimConnException as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if isinstance(e, vimconn.VimConnNotFoundException):
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                return None
            task["status"] = "FAILED"
            return None

    def new_classification(self, task):
        vim_classification_id = None
        try:
            params = task["params"]
            task_id = task["instance_action_id"] + "." + str(task["task_index"])
            dep_id = "TASK-" + str(task["extra"]["depends_on"][0])
            error_text = ""
            interfaces = task.get("depends").get(dep_id).get("extra").get("interfaces")
            # Bear in mind that different VIM connectors might support Classifications differently.
            # In the case of OpenStack, only the first VNF attached to the classifier will be used
            # to create the Classification(s) (the "logical source port" of the "Flow Classifier").
            # Since the VNFFG classifier match lacks the ethertype, classification defaults to
            # using the IPv4 flow classifier.
            logical_source_port_vim_id = None
            logical_source_port_id = params.get("logical_source_port")
            for vim_interface, interface_data in interfaces.items():
                if interface_data.get("interface_id") == logical_source_port_id:
                    logical_source_port_vim_id = vim_interface
                    break
            if not logical_source_port_vim_id:
                error_text = "Error creating Flow Classifier, Logical Source Port id {}".format(
                    logical_source_port_id)
                self.logger.error(error_text)
                task["error_msg"] = error_text
                task["status"] = "FAILED"
                task["vim_id"] = None
                return None

            name = "c-{}".format(task["item_id"][:8])
            # if not CIDR is given for the IP addresses, add /32:
            ip_proto = int(params.get("ip_proto"))
            source_ip = params.get("source_ip")
            destination_ip = params.get("destination_ip")
            source_port = params.get("source_port")
            destination_port = params.get("destination_port")
            definition = {"logical_source_port": logical_source_port_vim_id}
            if ip_proto:
                if ip_proto == 1:
                    ip_proto = 'icmp'
                elif ip_proto == 6:
                    ip_proto = 'tcp'
                elif ip_proto == 17:
                    ip_proto = 'udp'
                definition["protocol"] = ip_proto
            if source_ip:
                if '/' not in source_ip:
                    source_ip += '/32'
                definition["source_ip_prefix"] = source_ip
            if source_port:
                definition["source_port_range_min"] = source_port
                definition["source_port_range_max"] = source_port
            if destination_port:
                definition["destination_port_range_min"] = destination_port
                definition["destination_port_range_max"] = destination_port
            if destination_ip:
                if '/' not in destination_ip:
                    destination_ip += '/32'
                definition["destination_ip_prefix"] = destination_ip

            vim_classification_id = self.vim.new_classification(
                name, 'legacy_flow_classifier', definition)

            task["extra"]["created"] = True
            task["extra"]["vim_status"] = "ACTIVE"
            task["error_msg"] = None
            task["status"] = "DONE"
            task["vim_id"] = vim_classification_id
            instance_element_update = {"status": "ACTIVE", "vim_classification_id": vim_classification_id,
                                       "error_msg": None}
            return instance_element_update

        except (vimconn.VimConnException, VimThreadException) as e:
            self.logger.error("Error creating Classification, task=%s: %s", task_id, str(e))
            error_text = self._format_vim_error_msg(str(e))
            task["error_msg"] = error_text
            task["status"] = "FAILED"
            task["vim_id"] = None
            instance_element_update = {"status": "VIM_ERROR", "vim_classification_id": None, "error_msg": error_text}
            return instance_element_update

    def del_classification(self, task):
        classification_vim_id = task["vim_id"]
        try:
            self.vim.delete_classification(classification_vim_id)
            task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
            task["error_msg"] = None
            return None

        except vimconn.VimConnException as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if isinstance(e, vimconn.VimConnNotFoundException):
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                return None
            task["status"] = "FAILED"
            return None

    def new_sfp(self, task):
        vim_sfp_id = None
        try:
            task_id = task["instance_action_id"] + "." + str(task["task_index"])
            depending_tasks = [task.get("depends").get("TASK-" + str(tsk_id)) for tsk_id in
                               task.get("extra").get("depends_on")]
            error_text = ""
            sf_id_list = []
            classification_id_list = []
            for dep in depending_tasks:
                vim_id = dep.get("vim_id")
                resource = dep.get("item")
                if resource == "instance_sfs":
                    sf_id_list.append(vim_id)
                elif resource == "instance_classifications":
                    classification_id_list.append(vim_id)

            name = "sfp-{}".format(task["item_id"][:8])
            # By default no form of IETF SFC Encapsulation will be used
            vim_sfp_id = self.vim.new_sfp(name, classification_id_list, sf_id_list, sfc_encap=False)

            task["extra"]["created"] = True
            task["extra"]["vim_status"] = "ACTIVE"
            task["error_msg"] = None
            task["status"] = "DONE"
            task["vim_id"] = vim_sfp_id
            instance_element_update = {"status": "ACTIVE", "vim_sfp_id": vim_sfp_id, "error_msg": None}
            return instance_element_update

        except (vimconn.VimConnException, VimThreadException) as e:
            self.logger.error("Error creating Service Function, task=%s: %s", task_id, str(e))
            error_text = self._format_vim_error_msg(str(e))
            task["error_msg"] = error_text
            task["status"] = "FAILED"
            task["vim_id"] = None
            instance_element_update = {"status": "VIM_ERROR", "vim_sfp_id": None, "error_msg": error_text}
            return instance_element_update

    def del_sfp(self, task):
        sfp_vim_id = task["vim_id"]
        try:
            self.vim.delete_sfp(sfp_vim_id)
            task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
            task["error_msg"] = None
            return None

        except vimconn.VimConnException as e:
            task["error_msg"] = self._format_vim_error_msg(str(e))
            if isinstance(e, vimconn.VimConnNotFoundException):
                # If not found mark as Done and fill error_msg
                task["status"] = "FINISHED"  # with FINISHED instead of DONE it will not be refreshing
                return None
            task["status"] = "FAILED"
            return None

    def _refres_sfps(self, task):
        """Call VIM to get SFPs status"""
        database_update = None

        vim_id = task["vim_id"]
        sfp_to_refresh_list = [vim_id]
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        try:
            vim_dict = self.vim.refresh_sfps_status(sfp_to_refresh_list)
            vim_info = vim_dict[vim_id]
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("task={} get-sfp: vimconnException when trying to refresh sfps {}".format(task_id, e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}

        self.logger.debug("task={} get-sfp: vim_sfp_id={} result={}".format(task_id, task["vim_id"], vim_info))
        #TODO: Revise this part
        vim_info_error_msg = None
        if vim_info.get("error_msg"):
            vim_info_error_msg = self._format_vim_error_msg(vim_info["error_msg"])
        task_vim_info = task["extra"].get("vim_info")
        task_error_msg = task.get("error_msg")
        task_vim_status = task["extra"].get("vim_status")
        if task_vim_status != vim_info["status"] or task_error_msg != vim_info_error_msg or \
                (vim_info.get("vim_info") and task_vim_info != vim_info["vim_info"]):
            database_update = {"status": vim_info["status"], "error_msg": vim_info_error_msg}
            if vim_info.get("vim_info"):
                database_update["vim_info"] = vim_info["vim_info"]

            task["extra"]["vim_status"] = vim_info["status"]
            task["error_msg"] = vim_info_error_msg
            if vim_info.get("vim_info"):
                task["extra"]["vim_info"] = vim_info["vim_info"]

        return database_update

    def _refres_sfis(self, task):
        """Call VIM to get sfis status"""
        database_update = None

        vim_id = task["vim_id"]
        sfi_to_refresh_list = [vim_id]
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        try:
            vim_dict = self.vim.refresh_sfis_status(sfi_to_refresh_list)
            vim_info = vim_dict[vim_id]
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("task={} get-sfi: vimconnException when trying to refresh sfis {}".format(task_id, e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}

        self.logger.debug("task={} get-sfi: vim_sfi_id={} result={}".format(task_id, task["vim_id"], vim_info))
        #TODO: Revise this part
        vim_info_error_msg = None
        if vim_info.get("error_msg"):
            vim_info_error_msg = self._format_vim_error_msg(vim_info["error_msg"])
        task_vim_info = task["extra"].get("vim_info")
        task_error_msg = task.get("error_msg")
        task_vim_status = task["extra"].get("vim_status")
        if task_vim_status != vim_info["status"] or task_error_msg != vim_info_error_msg or \
                (vim_info.get("vim_info") and task_vim_info != vim_info["vim_info"]):
            database_update = {"status": vim_info["status"], "error_msg": vim_info_error_msg}
            if vim_info.get("vim_info"):
                database_update["vim_info"] = vim_info["vim_info"]

            task["extra"]["vim_status"] = vim_info["status"]
            task["error_msg"] = vim_info_error_msg
            if vim_info.get("vim_info"):
                task["extra"]["vim_info"] = vim_info["vim_info"]

        return database_update

    def _refres_sfs(self, task):
        """Call VIM to get sfs status"""
        database_update = None

        vim_id = task["vim_id"]
        sf_to_refresh_list = [vim_id]
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        try:
            vim_dict = self.vim.refresh_sfs_status(sf_to_refresh_list)
            vim_info = vim_dict[vim_id]
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("task={} get-sf: vimconnException when trying to refresh sfs {}".format(task_id, e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}

        self.logger.debug("task={} get-sf: vim_sf_id={} result={}".format(task_id, task["vim_id"], vim_info))
        #TODO: Revise this part
        vim_info_error_msg = None
        if vim_info.get("error_msg"):
            vim_info_error_msg = self._format_vim_error_msg(vim_info["error_msg"])
        task_vim_info = task["extra"].get("vim_info")
        task_error_msg = task.get("error_msg")
        task_vim_status = task["extra"].get("vim_status")
        if task_vim_status != vim_info["status"] or task_error_msg != vim_info_error_msg or \
                (vim_info.get("vim_info") and task_vim_info != vim_info["vim_info"]):
            database_update = {"status": vim_info["status"], "error_msg": vim_info_error_msg}
            if vim_info.get("vim_info"):
                database_update["vim_info"] = vim_info["vim_info"]

            task["extra"]["vim_status"] = vim_info["status"]
            task["error_msg"] = vim_info_error_msg
            if vim_info.get("vim_info"):
                task["extra"]["vim_info"] = vim_info["vim_info"]

        return database_update

    def _refres_classifications(self, task):
        """Call VIM to get classifications status"""
        database_update = None

        vim_id = task["vim_id"]
        classification_to_refresh_list = [vim_id]
        task_id = task["instance_action_id"] + "." + str(task["task_index"])
        try:
            vim_dict = self.vim.refresh_classifications_status(classification_to_refresh_list)
            vim_info = vim_dict[vim_id]
        except vimconn.VimConnException as e:
            # Mark all tasks at VIM_ERROR status
            self.logger.error("task={} get-classification: vimconnException when trying to refresh classifications {}"
                .format(task_id, e))
            vim_info = {"status": "VIM_ERROR", "error_msg": str(e)}

        self.logger.debug("task={} get-classification: vim_classification_id={} result={}".format(task_id,
            task["vim_id"], vim_info))
        #TODO: Revise this part
        vim_info_error_msg = None
        if vim_info.get("error_msg"):
            vim_info_error_msg = self._format_vim_error_msg(vim_info["error_msg"])
        task_vim_info = task["extra"].get("vim_info")
        task_error_msg = task.get("error_msg")
        task_vim_status = task["extra"].get("vim_status")
        if task_vim_status != vim_info["status"] or task_error_msg != vim_info_error_msg or \
                (vim_info.get("vim_info") and task_vim_info != vim_info["vim_info"]):
            database_update = {"status": vim_info["status"], "error_msg": vim_info_error_msg}
            if vim_info.get("vim_info"):
                database_update["vim_info"] = vim_info["vim_info"]

            task["extra"]["vim_status"] = vim_info["status"]
            task["error_msg"] = vim_info_error_msg
            if vim_info.get("vim_info"):
                task["extra"]["vim_info"] = vim_info["vim_info"]

        return database_update
