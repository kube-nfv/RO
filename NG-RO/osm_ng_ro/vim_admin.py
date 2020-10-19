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

import logging
import threading
import asyncio
from http import HTTPStatus

from osm_common import dbmongo, dbmemory, msglocal, msgkafka
from osm_common.dbbase import DbException
from osm_common.msgbase import MsgException
from osm_ng_ro.ns import NsException
from time import time

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class VimAdminException(Exception):

    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST):
        self.http_code = http_code
        Exception.__init__(self, message)


class VimAdminThread(threading.Thread):
    MAX_TIME_LOCKED = 3600  # 1h
    MAX_TIME_UNATTENDED = 60  # 600  # 10min
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
        self.logger = logging.getLogger("ro.vimadmin")
        self.aiomain_task_kafka = None  # asyncio task for receiving vim actions from kafka bus
        self.aiomain_task_vim = None  # asyncio task for watching ro_tasks not processed by nobody

    async def vim_watcher(self):
        """ Reads database periodically looking for tasks not processed by nobody because of a restar
        in order to load this vim"""
        while not self.to_terminate:
            now = time()
            if not self.last_rotask_time:
                self.last_rotask_time = 0
            ro_tasks = self.db.get_list("ro_tasks",
                                        q_filter={"target_id.ncont": self.engine.assignment_list,
                                                  "tasks.status": ['SCHEDULED', 'BUILD', 'DONE', 'FAILED'],
                                                  "locked_at.lt": now - self.MAX_TIME_LOCKED,
                                                  "to_check_at.gt": self.last_rotask_time,
                                                  "to_check_at.lte": now - self.MAX_TIME_UNATTENDED})
            self.last_rotask_time = now - self.MAX_TIME_UNATTENDED
            for ro_task in ro_tasks:
                if ro_task["target_id"] not in self.engine.assignment_list:
                    self.engine.assign_vim(ro_task["target_id"])
                    self.logger.debug("ordered to load {}. Inactivity detected".format(ro_task["target_id"]))

            await asyncio.sleep(300, loop=self.loop)

    async def aiomain(self):
        kafka_working = True
        while not self.to_terminate:
            try:
                if not self.aiomain_task_kafka:
                    # await self.msg.aiowrite("admin", "echo", "dummy message", loop=self.loop)
                    await self.msg.aiowrite("vim_account", "echo", "dummy message", loop=self.loop)
                    kafka_working = True
                    self.logger.debug("Starting vim_account subscription task")
                    self.aiomain_task_kafka = asyncio.ensure_future(
                        self.msg.aioread(self.kafka_topics, loop=self.loop, group_id=False,
                                         aiocallback=self._msg_callback),
                        loop=self.loop)
                if not self.aiomain_task_vim:
                    self.aiomain_task_vim = asyncio.ensure_future(
                        self.vim_watcher(),
                        loop=self.loop)
                done, _ = await asyncio.wait([self.aiomain_task_kafka, self.aiomain_task_vim],
                                             timeout=None, loop=self.loop, return_when=asyncio.FIRST_COMPLETED)
                try:
                    if self.aiomain_task_kafka in done:
                        exc = self.aiomain_task_kafka.exception()
                        self.logger.error("kafka subscription task exception: {}".format(exc))
                        self.aiomain_task_kafka = None
                    if self.aiomain_task_vim in done:
                        exc = self.aiomain_task_vim.exception()
                        self.logger.error("vim_account watcher task exception: {}".format(exc))
                        self.aiomain_task_vim = None
                except asyncio.CancelledError:
                    pass

            except Exception as e:
                if self.to_terminate:
                    return
                if kafka_working:
                    # logging only first time
                    self.logger.critical("Error accessing kafka '{}'. Retrying ...".format(e))
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
                    raise VimAdminException("Invalid configuration param '{}' at '[database]':'driver'".format(
                        self.config["database"]["driver"]))
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
                    raise VimAdminException("Invalid configuration param '{}' at '[message]':'driver'".format(
                        config_msg["driver"]))
        except (DbException, MsgException) as e:
            raise VimAdminException(str(e), http_code=e.http_code)

        self.logger.debug("Starting")
        while not self.to_terminate:
            try:
                self.loop.run_until_complete(asyncio.ensure_future(self.aiomain(), loop=self.loop))
            # except asyncio.CancelledError:
            #     break  # if cancelled it should end, breaking loop
            except Exception as e:
                if not self.to_terminate:
                    self.logger.exception("Exception '{}' at messaging read loop".format(e), exc_info=True)

        self.logger.debug("Finishing")
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
                target = topic[0:3]   # vim, wim or sdn
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

        except (NsException, DbException, MsgException) as e:
            self.logger.error("Error while processing topic={} command={}: {}".format(topic, command, e))
        except Exception as e:
            self.logger.exception("Exception while processing topic={} command={}: {}".format(topic, command, e),
                                  exc_info=True)

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
        if self.aiomain_task_kafka:
            self.loop.call_soon_threadsafe(self.aiomain_task_kafka.cancel)
        if self.aiomain_task_vim:
            self.loop.call_soon_threadsafe(self.aiomain_task_vim.cancel)
