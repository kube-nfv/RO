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

from jsonrpclib import Server
import socket
import ssl


class AristaSwitch():
    """
    Used to run switch commands through eAPI and check command output
    """

    def __init__(self, name=None, host=None, user=None, passwd=None,
                 verify_ssl=False, unix_socket=None,
                 logger=None):

        self.host = host
        self.user = user
        self.passwd = passwd

        self.unix_socket = unix_socket
        self.local_ep = Server(unix_socket) \
            if unix_socket is not None else None

        s = "https://{user}:{passwd}@{host}/command-api"
        self.url = s.format(user=user, passwd=passwd, host=host)
        self.ep = Server(self.url)
        self.verify_ssl = verify_ssl
        if not self.verify_ssl:
            try:
                ssl._create_default_https_context = ssl.\
                                                    _create_unverified_context
            except AttributeError:
                # Old python versions do not verify certs by default
                pass

        self.log = logger

    def _multilinestr_to_list(self, multilinestr=None):
        """
        Returns a list, each item been one line of a (multi)line string
        Handy for running multiple lines commands through one API call
        """
        mylist = \
            [x.strip() for x in multilinestr.split('\n') if x.strip() != '']
        return mylist

    def run(self, cmds=None, timeout=10, local_run=False):
        """
        Runs commands through eAPI

        If local_run is True eAPI call will be done using local unix socket
        If local run is False eAPI call will be done using TCPIP
        """
        socket.setdefaulttimeout(timeout)

        r = None

        if type(cmds) is str:
            run_list = self._multilinestr_to_list(cmds)

        if type(cmds) is list:
            run_list = cmds

        if local_run:
            ep = self.local_ep
            ep_log = "local unix socket {}".format(str(self.unix_socket))
        else:
            ep = self.ep
            ep_log = "tcpip socket {}".format(str(self.host))

        self.log.debug("Calling eAPI at {} with commands {}".
                       format(ep_log, str(run_list)))

        try:
            r = ep.runCmds(1, run_list)
        except Exception as e:
            self.log.error(str(e))
            raise(e)

        return r
