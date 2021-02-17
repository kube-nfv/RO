# -*- coding: utf-8 -*-
##
# Copyright 2019 Atos - CoE Telco NFV Team
# All Rights Reserved.
#
# Contributors: Oscar Luis Peral, Atos
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
# contact with: <oscarluis.peral@atos.net>
#
# Neither the name of Atos nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# This work has been performed in the context of Arista Telefonica OSM PoC.
##
import time


class AristaCVPTask:
    def __init__(self, cvpClientApi):
        self.cvpClientApi = cvpClientApi

    def __get_id(self, task):
        return task.get("workOrderId")

    def __get_state(self, task):
        return task.get("workOrderUserDefinedStatus")

    def __execute_task(self, task_id):
        return self.cvpClientApi.execute_task(task_id)

    def __cancel_task(self, task_id):
        return self.cvpClientApi.cancel_task(task_id)

    def __apply_state(self, task, state):
        t_id = self.__get_id(task)
        self.cvpClientApi.add_note_to_task(t_id, "Executed by OSM")

        if state == "executed":
            return self.__execute_task(t_id)
        elif state == "cancelled":
            return self.__cancel_task(t_id)

    def __actionable(self, state):
        return state in ["Pending"]

    def __terminal(self, state):
        return state in ["Completed", "Cancelled"]

    def __state_is_different(self, task, target):
        return self.__get_state(task) != target

    def update_all_tasks(self, data):
        new_data = dict()

        for task_id in data.keys():
            res = self.cvpClientApi.get_task_by_id(task_id)
            new_data[task_id] = res

        return new_data

    def get_pending_tasks(self):
        return self.cvpClientApi.get_tasks_by_status("Pending")

    def get_pending_tasks_old(self):
        taskList = []
        tasksField = {
            "workOrderId": "workOrderId",
            "workOrderState": "workOrderState",
            "currentTaskName": "currentTaskName",
            "description": "description",
            "workOrderUserDefinedStatus": "workOrderUserDefinedStatus",
            "note": "note",
            "taskStatus": "taskStatus",
            "workOrderDetails": "workOrderDetails",
        }
        tasks = self.cvpClientApi.get_tasks_by_status("Pending")

        # Reduce task data to required fields
        for task in tasks:
            taskFacts = {}
            for field in task.keys():
                if field in tasksField:
                    taskFacts[tasksField[field]] = task[field]

            taskList.append(taskFacts)

        return taskList

    def task_action(self, tasks, wait, state):
        changed = False
        data = dict()
        warnings = list()

        at = [t for t in tasks if self.__actionable(self.__get_state(t))]
        actionable_tasks = at

        if len(actionable_tasks) == 0:
            warnings.append("No actionable tasks found on CVP")
            return changed, data, warnings

        for task in actionable_tasks:
            if self.__state_is_different(task, state):
                self.__apply_state(task, state)
                changed = True
                data[self.__get_id(task)] = task

        if wait == 0:
            return changed, data, warnings

        start = time.time()
        now = time.time()
        while (now - start) < wait:
            data = self.update_all_tasks(data)

            if all([self.__terminal(self.__get_state(t)) for t in data.values()]):
                break

            time.sleep(1)
            now = time.time()

        if wait:
            for i, task in data.items():
                if not self.__terminal(self.__get_state(task)):
                    warnings.append(
                        "Task {} has not completed in {} seconds".format(i, wait)
                    )

        return changed, data, warnings
