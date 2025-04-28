# -*- coding: utf-8 -*-
# Copyright 2025 Indra
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
"""
Utility class with helper methods to deal with vcenter
"""
import logging
from queue import Empty, Queue
import ssl
import threading
import time

from osm_ro_plugin import vimconn
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim
import requests


def get_vcenter_content(session):
    """
    Obtains the vcenter content object
    """
    return session.RetrieveContent()


def get_vcenter_obj(session, vim_type, name, folder=None):
    """
    Get the vSphere object associated with a given text name
    """
    obj = None

    content = get_vcenter_content(session)
    if not folder:
        folder = content.rootFolder

    container = content.viewManager.CreateContainerView(folder, vim_type, True)
    for c in container.view:
        if c.name == name:
            obj = c
            break
    container.Destroy()
    return obj


def get_vcenter_folder(server_instance, folder_name, base_folder=None):
    """
    Obtains the vcenter folder object with the provided folder_name
    """
    return get_vcenter_obj(server_instance, [vim.Folder], folder_name, base_folder)


def wait_for_task(task):
    """Wait for a task to complete and handle any errors."""
    if task:
        while task.info.state not in [
            vim.TaskInfo.State.success,
            vim.TaskInfo.State.error,
        ]:
            time.sleep(1)
        if task.info.state == vim.TaskInfo.State.success:
            return task.info.result
        else:
            raise task.info.error  # Raise the specific exception


def wait_for_tasks(tasks):
    """Wait until all tasks in the list are finished. If any task fails, raise an error."""
    while any(task.info.state not in ["success", "error"] for task in tasks):
        time.sleep(2)

    for task in tasks:
        if task.info.state == "error":
            raise task.info.error


class VCenterFileUploader:
    """
    Helper class to upload files to vcenter
    """

    def __init__(
        self,
        host,
        port,
        user,
        password,
        ca_cert_path,
        log_level=None,
        default_timeout=None,
    ):
        self.logger = logging.getLogger("ro.vim.vcenter.util")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.ssl_verify = False
        if ca_cert_path:
            self.ssl_verify = ca_cert_path

        self.default_timeout = default_timeout or 30

    def upload_file(
        self,
        local_file_path,
        datacenter_name,
        datastore_name,
        folder_name,
        file_name,
        timeout=None,
    ):
        """
        Upload local file to a vmware datastore into the indicated folder
        and with the indicated name
        """
        timeout = timeout or self.default_timeout
        self.logger.debug(
            "Upload file %s to datastore %s, folder %s, timeout %s",
            local_file_path,
            datastore_name,
            folder_name,
            timeout,
        )

        upload_path = f"/folder/{folder_name}/{file_name}"
        url = f"https://{self.host}:{self.port}{upload_path}?dcPath={datacenter_name}&dsName={datastore_name}"
        self.logger.debug("Upload file to url: %s", url)

        with open(local_file_path, "rb") as file:
            headers = {"Content-Type": "application/octet-stream"}
            response = requests.put(
                url,
                headers=headers,
                auth=(self.user, self.password),  # Basic authentication
                data=file,
                verify=self.ssl_verify,
                timeout=timeout,
            )

        self.logger.debug(
            "Response code: %s, text: %s", response.status_code, response.text
        )
        if response.status_code not in (200, 201):
            self.logger.error(
                "Error uploading file error_code: %s, text: %s",
                response.status_code,
                response.text,
            )
            raise vimconn.VimConnException(
                f"Error uploading file error_code: {response.status_code}, text {response.textt}"
            )
        else:
            self.logger.debug("ISO File updated successfully")


class VCenterSessionPool:
    """
    Utility class to manage sessions using a pool
    """

    def __init__(
        self,
        host,
        user,
        password,
        port=443,
        pool_size=5,
        ssl_context=None,
        log_level=None,
    ):
        self._host = host
        self._user = user
        self._password = password
        self._port = port
        self._max_pool_size = pool_size
        self._ssl_context = ssl_context
        if not self._ssl_context:
            self._ssl_context = ssl._create_unverified_context()

        self.pool = Queue(maxsize=pool_size)  # Limit the queue size
        self.lock = threading.Lock()
        self.live_sessions = 0

        self.logger = logging.getLogger("ro.vim.vcenter.util")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

    def _connect(self):
        try:
            si = SmartConnect(
                host=self._host,
                user=self._user,
                pwd=self._password,
                port=self._port,
                sslContext=self._ssl_context,
            )
            self.logger.debug("Created a new vCenter session")
            return si
        except vim.fault.InvalidLogin as e:
            raise vimconn.VimConnAuthException(
                f"Invalid login accesing vcenter: {str(e)}"
            )
        except Exception as e:
            raise vimconn.VimConnConnectionException(
                f"Invalid login accesing vcenter: {str(e)}"
            )

    def _is_session_alive(self, si):
        if si is None:
            return False
        try:
            alive = si.content.sessionManager.currentSession is not None
            return alive
        except Exception as e:
            self.logger.info(f"Session check failed: {e}, must recreate session")
            return False

    def get_session(self, timeout=5):
        try:
            si = self.pool.get_nowait()
            self.logger.debug("Reusing session from pool.")
        except Empty:
            with self.lock:
                if self.live_sessions < self._max_pool_size:
                    si = self._connect()
                    self.live_sessions += 1
                    self.logger.debug(f"Live sessions count: {self.live_sessions}")
                else:
                    self.logger.info(
                        "Pool is full. Waiting for an available session..."
                    )
                    si = self.pool.get(timeout=timeout)

        if not self._is_session_alive(si):
            self.logger.warning("Dead session detected. Replacing...")
            try:
                Disconnect(si)
            except Exception as e:
                self.logger.debug(f"Error during disconnect: {e}")
            with self.lock:
                self.live_sessions -= 1
                self.logger.debug(f"Live sessions count: {self.live_sessions}")
            return self.get_session(timeout=timeout)

        return si

    def return_session(self, si):
        if self._is_session_alive(si):
            self.logger.debug("Returning session to pool.")
            self.pool.put(si)
        else:
            self.logger.debug(
                "Session is dead on return. Dropping and decrementing count."
            )
            try:
                Disconnect(si)
            except Exception as e:
                self.logger.debug(f"Error during disconnect: {e}")
            with self.lock:
                self.live_sessions -= 1
                self.logger.info(f"Live sessions count: {self.live_sessions}")

    def close_all(self):
        self.logger.info("Closing all sessions in pool...")
        while not self.pool.empty():
            si = self.pool.get_nowait()
            try:
                Disconnect(si)
                self.logger.debug("Session disconnected.")
            except Exception as e:
                self.logger.warning(f"Error closing session: {e}")
        with self.lock:
            self.live_sessions = 0
        self.logger.info("All sessions closed. Pool is clean.")
