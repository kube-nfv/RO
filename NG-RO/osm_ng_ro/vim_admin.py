# -*- coding: utf-8 -*-

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

"""
This module implements a thread that reads from kafka bus reading VIM messages.
It is based on asyncio.
It is in charge of load tasks assigned to VIMs that nobody is in chage of it
"""

import asyncio
from http import HTTPStatus
import logging
import threading
from time import time

from osm_common import dbmemory, dbmongo, msgkafka, msglocal
from osm_common.dbbase import DbException
from osm_common.msgbase import MsgException

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class VimAdminException(Exception):
    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST):
        self.http_code = http_code
        Exception.__init__(self, message)


class LockRenew:

    renew_list = []
    # ^ static method, common for all RO. Time ordered list of dictionaries with information of locks that needs to
    # be renewed. The time order is achieved as it is appended at the end

    def __init__(self, config, logger):
        """
        Constructor of class
        :param config: configuration parameters of database and messaging
        """
        self.config = config
        self.logger = logger
        self.to_terminate = False
        self.loop = None
        self.db = None
        self.task_locked_time = config["global"]["task_locked_time"]
        self.task_relock_time = config["global"]["task_relock_time"]
        self.task_max_locked_time = config["global"]["task_max_locked_time"]

    def start(self, db, loop):
        self.db = db
        self.loop = loop

    @staticmethod
    def add_lock_object(database_table, database_object, thread_object):
        """
        Insert a task to renew the locking
        :param database_table: database collection where to maintain the lock
        :param database_object: database object. '_id' and 'locked_at' are mandatory keys
        :param thread_object: Thread object that has locked to check if it is alive
        :return: a locked_object needed for calling remove_lock_object. It will contain uptodya database 'locked_at'
        """
        lock_object = {
            "table": database_table,
            "_id": database_object["_id"],
            "initial_lock_time": database_object["locked_at"],
            "locked_at": database_object["locked_at"],
            "thread": thread_object,
            "unlocked": False,  # True when it is not needed any more
        }
        LockRenew.renew_list.append(lock_object)

        return lock_object

    @staticmethod
    def remove_lock_object(lock_object):
        lock_object["unlocked"] = True

    async def renew_locks(self):
        while not self.to_terminate:
            if not self.renew_list:
                await asyncio.sleep(
                    self.task_locked_time - self.task_relock_time, loop=self.loop
                )
                continue

            lock_object = self.renew_list[0]

            if (
                lock_object["unlocked"]
                or not lock_object["thread"]
                or not lock_object["thread"].is_alive()
            ):
                # task has been finished or locker thread is dead, not needed to re-locked.
                self.renew_list.pop(0)
                continue

            locked_at = lock_object["locked_at"]
            now = time()
            time_to_relock = (
                locked_at + self.task_locked_time - self.task_relock_time - now
            )

            if time_to_relock < 1:
                if lock_object["initial_lock_time"] + self.task_max_locked_time < now:
                    self.renew_list.pop(0)
                    # re-lock
                    new_locked_at = locked_at + self.task_locked_time

                    try:
                        if self.db.set_one(
                            lock_object["table"],
                            update_dict={
                                "locked_at": new_locked_at,
                                "modified_at": now,
                            },
                            q_filter={
                                "_id": lock_object["_id"],
                                "locked_at": locked_at,
                            },
                            fail_on_empty=False,
                        ):
                            self.logger.debug(
                                "Renew lock for {}.{}".format(
                                    lock_object["table"], lock_object["_id"]
                                )
                            )
                            lock_object["locked_at"] = new_locked_at
                            self.renew_list.append(lock_object)
                        else:
                            self.logger.info(
                                "Cannot renew lock for {}.{}".format(
                                    lock_object["table"], lock_object["_id"]
                                )
                            )
                    except Exception as e:
                        self.logger.error(
                            "Exception when trying to renew lock for {}.{}: {}".format(
                                lock_object["table"], lock_object["_id"], e
                            )
                        )
            else:
                # wait until it is time to re-lock it
                await asyncio.sleep(time_to_relock, loop=self.loop)

    def stop(self):
        # unlock all locked items
        now = time()

        for lock_object in self.renew_list:
            locked_at = lock_object["locked_at"]

            if not lock_object["unlocked"] or locked_at + self.task_locked_time >= now:
                self.db.set_one(
                    lock_object["table"],
                    update_dict={"locked_at": 0},
                    q_filter={"_id": lock_object["_id"], "locked_at": locked_at},
                    fail_on_empty=False,
                )


class VimAdminThread(threading.Thread):
    MAX_TIME_UNATTENDED = 600  # 10min
    TIME_CHECK_UNUSED_VIM = 3600 * 2  # 2h
    kafka_topics = ("vim_account", "wim_account", "sdn")

    def __init__(self, config, engine):
        """
        Constructor of class
        :param config: configuration parameters of database and messaging
        :param engine: an instance of Engine class, used for deleting instances
        """
        threading.Thread.__init__(self)
        self.to_terminate = False
        self.config = config
        self.db = None
        self.msg = None
        self.engine = engine
        self.loop = None
        self.last_rotask_time = 0
        self.next_check_unused_vim = time() + self.TIME_CHECK_UNUSED_VIM
        self.logger = logging.getLogger("ro.vimadmin")
        # asyncio task for receiving vim actions from kafka bus
        self.aiomain_task_kafka = None
        # asyncio task for watching ro_tasks not processed by nobody
        self.aiomain_task_vim = None
        self.aiomain_task_renew_lock = None
        # ^asyncio task for maintain an ro_task locked when VIM plugin takes too much time processing an order
        self.lock_renew = LockRenew(config, self.logger)
        self.task_locked_time = config["global"]["task_locked_time"]

    async def vim_watcher(self):
        """Reads database periodically looking for tasks not processed by nobody because of a reboot
        in order to load this vim"""
        # firstly read VIMS not processed
        for target_database in ("vim_accounts", "wim_accounts", "sdns"):
            unattended_targets = self.db.get_list(
                target_database,
                q_filter={"_admin.operations.operationState": "PROCESSING"},
            )

            for target in unattended_targets:
                target_id = "{}:{}".format(target_database[:3], target["_id"])
                self.logger.info("ordered to check {}".format(target_id))
                self.engine.check_vim(target_id)

        while not self.to_terminate:
            now = time()
            processed_vims = []

            if not self.last_rotask_time:
                self.last_rotask_time = 0

            ro_tasks = self.db.get_list(
                "ro_tasks",
                q_filter={
                    "target_id.ncont": self.engine.get_assigned_vims(),
                    "tasks.status": ["SCHEDULED", "BUILD", "DONE", "FAILED"],
                    "locked_at.lt": now - self.task_locked_time,
                    "to_check_at.gt": self.last_rotask_time,
                    "to_check_at.lte": now - self.MAX_TIME_UNATTENDED,
                },
            )
            self.last_rotask_time = now - self.MAX_TIME_UNATTENDED

            for ro_task in ro_tasks:
                # if already checked ignore
                if ro_task["target_id"] in processed_vims:
                    continue

                processed_vims.append(ro_task["target_id"])

                # if already assigned ignore
                if ro_task["target_id"] in self.engine.get_assigned_vims():
                    continue

                # if there is some task locked on this VIM, there is an RO working on it, so ignore
                if self.db.get_list(
                    "ro_tasks",
                    q_filter={
                        "target_id": ro_task["target_id"],
                        "tasks.status": ["SCHEDULED", "BUILD", "DONE", "FAILED"],
                        "locked_at.gt": now - self.task_locked_time,
                    },
                ):
                    continue

                # unattended, assign vim
                self.engine.assign_vim(ro_task["target_id"])
                self.logger.debug(
                    "ordered to load {}. Inactivity detected".format(
                        ro_task["target_id"]
                    )
                )

            # every 2 hours check if there are vims without any ro_task and unload it
            if now > self.next_check_unused_vim:
                self.next_check_unused_vim = now + self.TIME_CHECK_UNUSED_VIM
                self.engine.unload_unused_vims()

            await asyncio.sleep(self.MAX_TIME_UNATTENDED, loop=self.loop)

    async def aiomain(self):
        kafka_working = True
        while not self.to_terminate:
            try:
                if not self.aiomain_task_kafka:
                    # await self.msg.aiowrite("admin", "echo", "dummy message", loop=self.loop)
                    for kafka_topic in self.kafka_topics:
                        await self.msg.aiowrite(
                            kafka_topic, "echo", "dummy message", loop=self.loop
                        )
                    kafka_working = True
                    self.logger.debug("Starting vim_account subscription task")
                    self.aiomain_task_kafka = asyncio.ensure_future(
                        self.msg.aioread(
                            self.kafka_topics,
                            loop=self.loop,
                            group_id=False,
                            aiocallback=self._msg_callback,
                        ),
                        loop=self.loop,
                    )

                if not self.aiomain_task_vim:
                    self.aiomain_task_vim = asyncio.ensure_future(
                        self.vim_watcher(), loop=self.loop
                    )

                if not self.aiomain_task_renew_lock:
                    self.aiomain_task_renew_lock = asyncio.ensure_future(
                        self.lock_renew.renew_locks(), loop=self.loop
                    )

                done, _ = await asyncio.wait(
                    [
                        self.aiomain_task_kafka,
                        self.aiomain_task_vim,
                        self.aiomain_task_renew_lock,
                    ],
                    timeout=None,
                    loop=self.loop,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                try:
                    if self.aiomain_task_kafka in done:
                        exc = self.aiomain_task_kafka.exception()
                        self.logger.error(
                            "kafka subscription task exception: {}".format(exc)
                        )
                        self.aiomain_task_kafka = None

                    if self.aiomain_task_vim in done:
                        exc = self.aiomain_task_vim.exception()
                        self.logger.error(
                            "vim_account watcher task exception: {}".format(exc)
                        )
                        self.aiomain_task_vim = None

                    if self.aiomain_task_renew_lock in done:
                        exc = self.aiomain_task_renew_lock.exception()
                        self.logger.error("renew_locks task exception: {}".format(exc))
                        self.aiomain_task_renew_lock = None
                except asyncio.CancelledError:
                    self.logger.exception("asyncio.CancelledError occured.")

            except Exception as e:
                if self.to_terminate:
                    return

                if kafka_working:
                    # logging only first time
                    self.logger.critical(
                        "Error accessing kafka '{}'. Retrying ...".format(e)
                    )
                    kafka_working = False

            await asyncio.sleep(10, loop=self.loop)

    def run(self):
        """
        Start of the thread
        :return: None
        """
        self.loop = asyncio.new_event_loop()
        try:
            if not self.db:
                if self.config["database"]["driver"] == "mongo":
                    self.db = dbmongo.DbMongo()
                    self.db.db_connect(self.config["database"])
                elif self.config["database"]["driver"] == "memory":
                    self.db = dbmemory.DbMemory()
                    self.db.db_connect(self.config["database"])
                else:
                    raise VimAdminException(
                        "Invalid configuration param '{}' at '[database]':'driver'".format(
                            self.config["database"]["driver"]
                        )
                    )

            self.lock_renew.start(self.db, self.loop)

            if not self.msg:
                config_msg = self.config["message"].copy()
                config_msg["loop"] = self.loop

                if config_msg["driver"] == "local":
                    self.msg = msglocal.MsgLocal()
                    self.msg.connect(config_msg)
                elif config_msg["driver"] == "kafka":
                    self.msg = msgkafka.MsgKafka()
                    self.msg.connect(config_msg)
                else:
                    raise VimAdminException(
                        "Invalid configuration param '{}' at '[message]':'driver'".format(
                            config_msg["driver"]
                        )
                    )
        except (DbException, MsgException) as e:
            raise VimAdminException(str(e), http_code=e.http_code)

        self.logger.info("Starting")
        while not self.to_terminate:
            try:
                self.loop.run_until_complete(
                    asyncio.ensure_future(self.aiomain(), loop=self.loop)
                )
            # except asyncio.CancelledError:
            #     break  # if cancelled it should end, breaking loop
            except Exception as e:
                if not self.to_terminate:
                    self.logger.exception(
                        "Exception '{}' at messaging read loop".format(e), exc_info=True
                    )

        self.logger.info("Finishing")
        self._stop()
        self.loop.close()

    async def _msg_callback(self, topic, command, params):
        """
        Callback to process a received message from kafka
        :param topic:  topic received
        :param command:  command received
        :param params: rest of parameters
        :return: None
        """
        try:
            if command == "echo":
                return

            if topic in self.kafka_topics:
                target = topic[0:3]  # vim, wim or sdn
                target_id = target + ":" + params["_id"]

                if command in ("edited", "edit"):
                    self.engine.reload_vim(target_id)
                    self.logger.debug("ordered to reload {}".format(target_id))
                elif command in ("deleted", "delete"):
                    self.engine.unload_vim(target_id)
                    self.logger.debug("ordered to unload {}".format(target_id))
                elif command in ("create", "created"):
                    self.engine.check_vim(target_id)
                    self.logger.debug("ordered to check {}".format(target_id))
        except (DbException, MsgException) as e:
            self.logger.error(
                "Error while processing topic={} command={}: {}".format(
                    topic, command, e
                )
            )
        except Exception as e:
            self.logger.exception(
                "Exception while processing topic={} command={}: {}".format(
                    topic, command, e
                ),
                exc_info=True,
            )

    def _stop(self):
        """
        Close all connections
        :return: None
        """
        try:
            if self.db:
                self.db.db_disconnect()

            if self.msg:
                self.msg.disconnect()
        except (DbException, MsgException) as e:
            raise VimAdminException(str(e), http_code=e.http_code)

    def terminate(self):
        """
        This is a threading safe method to terminate this thread. Termination is done asynchronous afterwards,
        but not immediately.
        :return: None
        """
        self.to_terminate = True
        self.lock_renew.to_terminate = True

        if self.aiomain_task_kafka:
            self.loop.call_soon_threadsafe(self.aiomain_task_kafka.cancel)

        if self.aiomain_task_vim:
            self.loop.call_soon_threadsafe(self.aiomain_task_vim.cancel)

        if self.aiomain_task_renew_lock:
            self.loop.call_soon_threadsafe(self.aiomain_task_renew_lock.cancel)

        self.lock_renew.stop()
