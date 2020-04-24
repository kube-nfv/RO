#!/usr/bin/python3
# -*- coding: utf-8 -*-

##
# Copyright 2020 Telefonica Investigacion y Desarrollo, S.A.U.
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
##

import cherrypy
import time
import json
import yaml
import osm_ng_ro.html_out as html
import logging
import logging.handlers
import getopt
import sys

from osm_ng_ro.ns import Ns, NsException
from osm_ng_ro.validation import ValidationError
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from http import HTTPStatus
from codecs import getreader
from os import environ, path
from osm_ng_ro import version as ro_version, version_date as ro_version_date

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"

__version__ = "0.1."    # file version, not NBI version
version_date = "May 2020"

database_version = '1.2'
auth_database_version = '1.0'
ro_server = None           # instance of Server class
# vim_threads = None  # instance of VimThread class

"""
RO North Bound Interface
URL: /ro                                                       GET     POST    PUT     DELETE  PATCH
        /ns/v1/deploy                                           O
            /<nsrs_id>                                          O       O               O
                /<action_id>                                    O
                    /cancel                                             O

"""

valid_query_string = ("ADMIN", "SET_PROJECT", "FORCE", "PUBLIC")
# ^ Contains possible administrative query string words:
#     ADMIN=True(by default)|Project|Project-list:  See all elements, or elements of a project
#           (not owned by my session project).
#     PUBLIC=True(by default)|False: See/hide public elements. Set/Unset a topic to be public
#     FORCE=True(by default)|False: Force edition/deletion operations
#     SET_PROJECT=Project|Project-list: Add/Delete the topic to the projects portfolio

valid_url_methods = {
    # contains allowed URL and methods, and the role_permission name
    "admin": {
        "v1": {
            "tokens": {
                "METHODS": ("POST",),
                "ROLE_PERMISSION": "tokens:",
                "<ID>": {
                    "METHODS": ("DELETE",),
                    "ROLE_PERMISSION": "tokens:id:"
                }
            },
        }
    },
    "ns": {
        "v1": {
            "deploy": {
                "METHODS": ("GET",),
                "ROLE_PERMISSION": "deploy:",
                "<ID>": {
                    "METHODS": ("GET", "POST", "DELETE"),
                    "ROLE_PERMISSION": "deploy:id:",
                    "<ID>": {
                        "METHODS": ("GET",),
                        "ROLE_PERMISSION": "deploy:id:id:",
                        "cancel": {
                            "METHODS": ("POST",),
                            "ROLE_PERMISSION": "deploy:id:id:cancel",
                        }
                    }
                }
            },
        }
    },
}


class RoException(Exception):

    def __init__(self, message, http_code=HTTPStatus.METHOD_NOT_ALLOWED):
        Exception.__init__(self, message)
        self.http_code = http_code


class AuthException(RoException):
    pass


class Authenticator:
    
    def __init__(self, valid_url_methods, valid_query_string):
        self.valid_url_methods = valid_url_methods
        self.valid_query_string = valid_query_string

    def authorize(self, *args, **kwargs):
        return {"token": "ok", "id": "ok"}
    
    def new_token(self, token_info, indata, remote):
        return {"token": "ok",
                "id": "ok",
                "remote": remote}

    def del_token(self, token_id):
        pass

    def start(self, engine_config):
        pass


class Server(object):
    instance = 0
    # to decode bytes to str
    reader = getreader("utf-8")

    def __init__(self):
        self.instance += 1
        self.authenticator = Authenticator(valid_url_methods, valid_query_string)
        self.ns = Ns()
        self.map_operation = {
            "token:post": self.new_token,
            "token:id:delete": self.del_token,
            "deploy:get": self.ns.get_deploy,
            "deploy:id:get": self.ns.get_actions,
            "deploy:id:post": self.ns.deploy,
            "deploy:id:delete": self.ns.delete,
            "deploy:id:id:get": self.ns.status,
            "deploy:id:id:cancel:post": self.ns.cancel,
        }

    def _format_in(self, kwargs):
        try:
            indata = None
            if cherrypy.request.body.length:
                error_text = "Invalid input format "

                if "Content-Type" in cherrypy.request.headers:
                    if "application/json" in cherrypy.request.headers["Content-Type"]:
                        error_text = "Invalid json format "
                        indata = json.load(self.reader(cherrypy.request.body))
                        cherrypy.request.headers.pop("Content-File-MD5", None)
                    elif "application/yaml" in cherrypy.request.headers["Content-Type"]:
                        error_text = "Invalid yaml format "
                        indata = yaml.load(cherrypy.request.body, Loader=yaml.SafeLoader)
                        cherrypy.request.headers.pop("Content-File-MD5", None)
                    elif "application/binary" in cherrypy.request.headers["Content-Type"] or \
                         "application/gzip" in cherrypy.request.headers["Content-Type"] or \
                         "application/zip" in cherrypy.request.headers["Content-Type"] or \
                         "text/plain" in cherrypy.request.headers["Content-Type"]:
                        indata = cherrypy.request.body  # .read()
                    elif "multipart/form-data" in cherrypy.request.headers["Content-Type"]:
                        if "descriptor_file" in kwargs:
                            filecontent = kwargs.pop("descriptor_file")
                            if not filecontent.file:
                                raise RoException("empty file or content", HTTPStatus.BAD_REQUEST)
                            indata = filecontent.file  # .read()
                            if filecontent.content_type.value:
                                cherrypy.request.headers["Content-Type"] = filecontent.content_type.value
                    else:
                        # raise cherrypy.HTTPError(HTTPStatus.Not_Acceptable,
                        #                          "Only 'Content-Type' of type 'application/json' or
                        # 'application/yaml' for input format are available")
                        error_text = "Invalid yaml format "
                        indata = yaml.load(cherrypy.request.body, Loader=yaml.SafeLoader)
                        cherrypy.request.headers.pop("Content-File-MD5", None)
                else:
                    error_text = "Invalid yaml format "
                    indata = yaml.load(cherrypy.request.body, Loader=yaml.SafeLoader)
                    cherrypy.request.headers.pop("Content-File-MD5", None)
            if not indata:
                indata = {}

            format_yaml = False
            if cherrypy.request.headers.get("Query-String-Format") == "yaml":
                format_yaml = True

            for k, v in kwargs.items():
                if isinstance(v, str):
                    if v == "":
                        kwargs[k] = None
                    elif format_yaml:
                        try:
                            kwargs[k] = yaml.load(v, Loader=yaml.SafeLoader)
                        except Exception:
                            pass
                    elif k.endswith(".gt") or k.endswith(".lt") or k.endswith(".gte") or k.endswith(".lte"):
                        try:
                            kwargs[k] = int(v)
                        except Exception:
                            try:
                                kwargs[k] = float(v)
                            except Exception:
                                pass
                    elif v.find(",") > 0:
                        kwargs[k] = v.split(",")
                elif isinstance(v, (list, tuple)):
                    for index in range(0, len(v)):
                        if v[index] == "":
                            v[index] = None
                        elif format_yaml:
                            try:
                                v[index] = yaml.load(v[index], Loader=yaml.SafeLoader)
                            except Exception:
                                pass

            return indata
        except (ValueError, yaml.YAMLError) as exc:
            raise RoException(error_text + str(exc), HTTPStatus.BAD_REQUEST)
        except KeyError as exc:
            raise RoException("Query string error: " + str(exc), HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            raise RoException(error_text + str(exc), HTTPStatus.BAD_REQUEST)

    @staticmethod
    def _format_out(data, token_info=None, _format=None):
        """
        return string of dictionary data according to requested json, yaml, xml. By default json
        :param data: response to be sent. Can be a dict, text or file
        :param token_info: Contains among other username and project
        :param _format: The format to be set as Content-Type if data is a file
        :return: None
        """
        accept = cherrypy.request.headers.get("Accept")
        if data is None:
            if accept and "text/html" in accept:
                return html.format(data, cherrypy.request, cherrypy.response, token_info)
            # cherrypy.response.status = HTTPStatus.NO_CONTENT.value
            return
        elif hasattr(data, "read"):  # file object
            if _format:
                cherrypy.response.headers["Content-Type"] = _format
            elif "b" in data.mode:  # binariy asssumig zip
                cherrypy.response.headers["Content-Type"] = 'application/zip'
            else:
                cherrypy.response.headers["Content-Type"] = 'text/plain'
            # TODO check that cherrypy close file. If not implement pending things to close  per thread next
            return data
        if accept:
            if "application/json" in accept:
                cherrypy.response.headers["Content-Type"] = 'application/json; charset=utf-8'
                a = json.dumps(data, indent=4) + "\n"
                return a.encode("utf8")
            elif "text/html" in accept:
                return html.format(data, cherrypy.request, cherrypy.response, token_info)

            elif "application/yaml" in accept or "*/*" in accept or "text/plain" in accept:
                pass
            # if there is not any valid accept, raise an error. But if response is already an error, format in yaml
            elif cherrypy.response.status >= 400:
                raise cherrypy.HTTPError(HTTPStatus.NOT_ACCEPTABLE.value,
                                         "Only 'Accept' of type 'application/json' or 'application/yaml' "
                                         "for output format are available")
        cherrypy.response.headers["Content-Type"] = 'application/yaml'
        return yaml.safe_dump(data, explicit_start=True, indent=4, default_flow_style=False, tags=False,
                              encoding='utf-8', allow_unicode=True)  # , canonical=True, default_style='"'

    @cherrypy.expose
    def index(self, *args, **kwargs):
        token_info = None
        try:
            if cherrypy.request.method == "GET":
                token_info = self.authenticator.authorize()
                outdata = token_info   # Home page
            else:
                raise cherrypy.HTTPError(HTTPStatus.METHOD_NOT_ALLOWED.value,
                                         "Method {} not allowed for tokens".format(cherrypy.request.method))

            return self._format_out(outdata, token_info)

        except (NsException, AuthException) as e:
            # cherrypy.log("index Exception {}".format(e))
            cherrypy.response.status = e.http_code.value
            return self._format_out("Welcome to OSM!", token_info)

    @cherrypy.expose
    def version(self, *args, **kwargs):
        # TODO consider to remove and provide version using the static version file
        try:
            if cherrypy.request.method != "GET":
                raise RoException("Only method GET is allowed", HTTPStatus.METHOD_NOT_ALLOWED)
            elif args or kwargs:
                raise RoException("Invalid URL or query string for version", HTTPStatus.METHOD_NOT_ALLOWED)
            # TODO include version of other modules, pick up from some kafka admin message
            osm_ng_ro_version = {"version": ro_version, "date": ro_version_date}
            return self._format_out(osm_ng_ro_version)
        except RoException as e:
            cherrypy.response.status = e.http_code.value
            problem_details = {
                "code": e.http_code.name,
                "status": e.http_code.value,
                "detail": str(e),
            }
            return self._format_out(problem_details, None)

    def new_token(self, engine_session, indata, *args, **kwargs):
        token_info = None

        try:
            token_info = self.authenticator.authorize()
        except Exception:
            token_info = None
        if kwargs:
            indata.update(kwargs)
        # This is needed to log the user when authentication fails
        cherrypy.request.login = "{}".format(indata.get("username", "-"))
        token_info = self.authenticator.new_token(token_info, indata, cherrypy.request.remote)
        cherrypy.session['Authorization'] = token_info["id"]
        self._set_location_header("admin", "v1", "tokens", token_info["id"])
        # for logging

        # cherrypy.response.cookie["Authorization"] = outdata["id"]
        # cherrypy.response.cookie["Authorization"]['expires'] = 3600
        return token_info, token_info["id"], True

    def del_token(self, engine_session, indata, version, _id, *args, **kwargs):
        token_id = _id
        if not token_id and "id" in kwargs:
            token_id = kwargs["id"]
        elif not token_id:
            token_info = self.authenticator.authorize()
            # for logging
            token_id = token_info["id"]
        self.authenticator.del_token(token_id)
        token_info = None
        cherrypy.session['Authorization'] = "logout"
        # cherrypy.response.cookie["Authorization"] = token_id
        # cherrypy.response.cookie["Authorization"]['expires'] = 0
        return None, None, True
    
    @cherrypy.expose
    def test(self, *args, **kwargs):
        if not cherrypy.config.get("server.enable_test") or (isinstance(cherrypy.config["server.enable_test"], str) and
                                                             cherrypy.config["server.enable_test"].lower() == "false"):
            cherrypy.response.status = HTTPStatus.METHOD_NOT_ALLOWED.value
            return "test URL is disabled"
        thread_info = None
        if args and args[0] == "help":
            return "<html><pre>\ninit\nfile/<name>  download file\ndb-clear/table\nfs-clear[/folder]\nlogin\nlogin2\n"\
                   "sleep/<time>\nmessage/topic\n</pre></html>"

        elif args and args[0] == "init":
            try:
                # self.ns.load_dbase(cherrypy.request.app.config)
                self.ns.create_admin()
                return "Done. User 'admin', password 'admin' created"
            except Exception:
                cherrypy.response.status = HTTPStatus.FORBIDDEN.value
                return self._format_out("Database already initialized")
        elif args and args[0] == "file":
            return cherrypy.lib.static.serve_file(cherrypy.tree.apps['/ro'].config["storage"]["path"] + "/" + args[1],
                                                  "text/plain", "attachment")
        elif args and args[0] == "file2":
            f_path = cherrypy.tree.apps['/ro'].config["storage"]["path"] + "/" + args[1]
            f = open(f_path, "r")
            cherrypy.response.headers["Content-type"] = "text/plain"
            return f

        elif len(args) == 2 and args[0] == "db-clear":
            deleted_info = self.ns.db.del_list(args[1], kwargs)
            return "{} {} deleted\n".format(deleted_info["deleted"], args[1])
        elif len(args) and args[0] == "fs-clear":
            if len(args) >= 2:
                folders = (args[1],)
            else:
                folders = self.ns.fs.dir_ls(".")
            for folder in folders:
                self.ns.fs.file_delete(folder)
            return ",".join(folders) + " folders deleted\n"
        elif args and args[0] == "login":
            if not cherrypy.request.headers.get("Authorization"):
                cherrypy.response.headers["WWW-Authenticate"] = 'Basic realm="Access to OSM site", charset="UTF-8"'
                cherrypy.response.status = HTTPStatus.UNAUTHORIZED.value
        elif args and args[0] == "login2":
            if not cherrypy.request.headers.get("Authorization"):
                cherrypy.response.headers["WWW-Authenticate"] = 'Bearer realm="Access to OSM site"'
                cherrypy.response.status = HTTPStatus.UNAUTHORIZED.value
        elif args and args[0] == "sleep":
            sleep_time = 5
            try:
                sleep_time = int(args[1])
            except Exception:
                cherrypy.response.status = HTTPStatus.FORBIDDEN.value
                return self._format_out("Database already initialized")
            thread_info = cherrypy.thread_data
            print(thread_info)
            time.sleep(sleep_time)
            # thread_info
        elif len(args) >= 2 and args[0] == "message":
            main_topic = args[1]
            return_text = "<html><pre>{} ->\n".format(main_topic)
            try:
                if cherrypy.request.method == 'POST':
                    to_send = yaml.load(cherrypy.request.body, Loader=yaml.SafeLoader)
                    for k, v in to_send.items():
                        self.ns.msg.write(main_topic, k, v)
                        return_text += "  {}: {}\n".format(k, v)
                elif cherrypy.request.method == 'GET':
                    for k, v in kwargs.items():
                        self.ns.msg.write(main_topic, k, yaml.load(v, Loader=yaml.SafeLoader))
                        return_text += "  {}: {}\n".format(k, yaml.load(v, Loader=yaml.SafeLoader))
            except Exception as e:
                return_text += "Error: " + str(e)
            return_text += "</pre></html>\n"
            return return_text

        return_text = (
            "<html><pre>\nheaders:\n  args: {}\n".format(args) +
            "  kwargs: {}\n".format(kwargs) +
            "  headers: {}\n".format(cherrypy.request.headers) +
            "  path_info: {}\n".format(cherrypy.request.path_info) +
            "  query_string: {}\n".format(cherrypy.request.query_string) +
            "  session: {}\n".format(cherrypy.session) +
            "  cookie: {}\n".format(cherrypy.request.cookie) +
            "  method: {}\n".format(cherrypy.request.method) +
            "  session: {}\n".format(cherrypy.session.get('fieldname')) +
            "  body:\n")
        return_text += "    length: {}\n".format(cherrypy.request.body.length)
        if cherrypy.request.body.length:
            return_text += "    content: {}\n".format(
                str(cherrypy.request.body.read(int(cherrypy.request.headers.get('Content-Length', 0)))))
        if thread_info:
            return_text += "thread: {}\n".format(thread_info)
        return_text += "</pre></html>"
        return return_text

    @staticmethod
    def _check_valid_url_method(method, *args):
        if len(args) < 3:
            raise RoException("URL must contain at least 'main_topic/version/topic'", HTTPStatus.METHOD_NOT_ALLOWED)

        reference = valid_url_methods
        for arg in args:
            if arg is None:
                break
            if not isinstance(reference, dict):
                raise RoException("URL contains unexpected extra items '{}'".format(arg),
                                  HTTPStatus.METHOD_NOT_ALLOWED)

            if arg in reference:
                reference = reference[arg]
            elif "<ID>" in reference:
                reference = reference["<ID>"]
            elif "*" in reference:
                # reference = reference["*"]
                break
            else:
                raise RoException("Unexpected URL item {}".format(arg), HTTPStatus.METHOD_NOT_ALLOWED)
        if "TODO" in reference and method in reference["TODO"]:
            raise RoException("Method {} not supported yet for this URL".format(method), HTTPStatus.NOT_IMPLEMENTED)
        elif "METHODS" not in reference or method not in reference["METHODS"]:
            raise RoException("Method {} not supported for this URL".format(method), HTTPStatus.METHOD_NOT_ALLOWED)
        return reference["ROLE_PERMISSION"] + method.lower()

    @staticmethod
    def _set_location_header(main_topic, version, topic, id):
        """
        Insert response header Location with the URL of created item base on URL params
        :param main_topic:
        :param version:
        :param topic:
        :param id:
        :return: None
        """
        # Use cherrypy.request.base for absoluted path and make use of request.header HOST just in case behind aNAT
        cherrypy.response.headers["Location"] = "/ro/{}/{}/{}/{}".format(main_topic, version, topic, id)
        return

    @cherrypy.expose
    def default(self, main_topic=None, version=None, topic=None, _id=None, _id2=None, *args, **kwargs):
        token_info = None
        outdata = None
        _format = None
        method = "DONE"
        rollback = []
        engine_session = None
        try:
            if not main_topic or not version or not topic:
                raise RoException("URL must contain at least 'main_topic/version/topic'",
                                  HTTPStatus.METHOD_NOT_ALLOWED)
            if main_topic not in ("admin", "ns",):
                raise RoException("URL main_topic '{}' not supported".format(main_topic),
                                  HTTPStatus.METHOD_NOT_ALLOWED)
            if version != 'v1':
                raise RoException("URL version '{}' not supported".format(version), HTTPStatus.METHOD_NOT_ALLOWED)

            if kwargs and "METHOD" in kwargs and kwargs["METHOD"] in ("PUT", "POST", "DELETE", "GET", "PATCH"):
                method = kwargs.pop("METHOD")
            else:
                method = cherrypy.request.method

            role_permission = self._check_valid_url_method(method, main_topic, version, topic, _id, _id2, *args,
                                                           **kwargs)
            # skip token validation if requesting a token
            indata = self._format_in(kwargs)
            if main_topic != "admin" or topic != "tokens":
                token_info = self.authenticator.authorize(role_permission, _id)
            outdata, created_id, done = self.map_operation[role_permission](
                engine_session, indata, version, _id, _id2, *args, *kwargs)
            if created_id:
                self._set_location_header(main_topic, version, topic, _id)
            cherrypy.response.status = HTTPStatus.ACCEPTED.value if not done else HTTPStatus.OK.value if \
                outdata is not None else HTTPStatus.NO_CONTENT.value
            return self._format_out(outdata, token_info, _format)
        except Exception as e:
            if isinstance(e, (RoException, NsException, DbException, FsException, MsgException, AuthException,
                              ValidationError)):
                http_code_value = cherrypy.response.status = e.http_code.value
                http_code_name = e.http_code.name
                cherrypy.log("Exception {}".format(e))
            else:
                http_code_value = cherrypy.response.status = HTTPStatus.BAD_REQUEST.value  # INTERNAL_SERVER_ERROR
                cherrypy.log("CRITICAL: Exception {}".format(e), traceback=True)
                http_code_name = HTTPStatus.BAD_REQUEST.name
            if hasattr(outdata, "close"):  # is an open file
                outdata.close()
            error_text = str(e)
            rollback.reverse()
            for rollback_item in rollback:
                try:
                    if rollback_item.get("operation") == "set":
                        self.ns.db.set_one(rollback_item["topic"], {"_id": rollback_item["_id"]},
                                           rollback_item["content"], fail_on_empty=False)
                    else:
                        self.ns.db.del_one(rollback_item["topic"], {"_id": rollback_item["_id"]},
                                           fail_on_empty=False)
                except Exception as e2:
                    rollback_error_text = "Rollback Exception {}: {}".format(rollback_item, e2)
                    cherrypy.log(rollback_error_text)
                    error_text += ". " + rollback_error_text
            # if isinstance(e, MsgException):
            #     error_text = "{} has been '{}' but other modules cannot be informed because an error on bus".format(
            #         engine_topic[:-1], method, error_text)
            problem_details = {
                "code": http_code_name,
                "status": http_code_value,
                "detail": error_text,
            }
            return self._format_out(problem_details, token_info)
            # raise cherrypy.HTTPError(e.http_code.value, str(e))
        finally:
            if token_info:
                if method in ("PUT", "PATCH", "POST") and isinstance(outdata, dict):
                    for logging_id in ("id", "op_id", "nsilcmop_id", "nslcmop_id"):
                        if outdata.get(logging_id):
                            cherrypy.request.login += ";{}={}".format(logging_id, outdata[logging_id][:36])


def _start_service():
    """
    Callback function called when cherrypy.engine starts
    Override configuration with env variables
    Set database, storage, message configuration
    Init database with admin/admin user password
    """
    global ro_server
    # global vim_threads
    cherrypy.log.error("Starting osm_ng_ro")
    # update general cherrypy configuration
    update_dict = {}

    engine_config = cherrypy.tree.apps['/ro'].config
    for k, v in environ.items():
        if not k.startswith("OSMRO_"):
            continue
        k1, _, k2 = k[6:].lower().partition("_")
        if not k2:
            continue
        try:
            if k1 in ("server", "test", "auth", "log"):
                # update [global] configuration
                update_dict[k1 + '.' + k2] = yaml.safe_load(v)
            elif k1 == "static":
                # update [/static] configuration
                engine_config["/static"]["tools.staticdir." + k2] = yaml.safe_load(v)
            elif k1 == "tools":
                # update [/] configuration
                engine_config["/"]["tools." + k2.replace('_', '.')] = yaml.safe_load(v)
            elif k1 in ("message", "database", "storage", "authentication"):
                # update [message], [database], ... configuration
                if k2 in ("port", "db_port"):
                    engine_config[k1][k2] = int(v)
                else:
                    engine_config[k1][k2] = v

        except Exception as e:
            raise RoException("Cannot load env '{}': {}".format(k, e))

    if update_dict:
        cherrypy.config.update(update_dict)
        engine_config["global"].update(update_dict)

    # logging cherrypy
    log_format_simple = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(message)s"
    log_formatter_simple = logging.Formatter(log_format_simple, datefmt='%Y-%m-%dT%H:%M:%S')
    logger_server = logging.getLogger("cherrypy.error")
    logger_access = logging.getLogger("cherrypy.access")
    logger_cherry = logging.getLogger("cherrypy")
    logger_nbi = logging.getLogger("ro")

    if "log.file" in engine_config["global"]:
        file_handler = logging.handlers.RotatingFileHandler(engine_config["global"]["log.file"],
                                                            maxBytes=100e6, backupCount=9, delay=0)
        file_handler.setFormatter(log_formatter_simple)
        logger_cherry.addHandler(file_handler)
        logger_nbi.addHandler(file_handler)
    # log always to standard output
    for format_, logger in {"ro.server %(filename)s:%(lineno)s": logger_server,
                            "ro.access %(filename)s:%(lineno)s": logger_access,
                            "%(name)s %(filename)s:%(lineno)s": logger_nbi
                            }.items():
        log_format_cherry = "%(asctime)s %(levelname)s {} %(message)s".format(format_)
        log_formatter_cherry = logging.Formatter(log_format_cherry, datefmt='%Y-%m-%dT%H:%M:%S')
        str_handler = logging.StreamHandler()
        str_handler.setFormatter(log_formatter_cherry)
        logger.addHandler(str_handler)

    if engine_config["global"].get("log.level"):
        logger_cherry.setLevel(engine_config["global"]["log.level"])
        logger_nbi.setLevel(engine_config["global"]["log.level"])

    # logging other modules
    for k1, logname in {"message": "ro.msg", "database": "ro.db", "storage": "ro.fs"}.items():
        engine_config[k1]["logger_name"] = logname
        logger_module = logging.getLogger(logname)
        if "logfile" in engine_config[k1]:
            file_handler = logging.handlers.RotatingFileHandler(engine_config[k1]["logfile"],
                                                                maxBytes=100e6, backupCount=9, delay=0)
            file_handler.setFormatter(log_formatter_simple)
            logger_module.addHandler(file_handler)
        if "loglevel" in engine_config[k1]:
            logger_module.setLevel(engine_config[k1]["loglevel"])
    # TODO add more entries, e.g.: storage

    engine_config["assignment"] = {}
    # ^ each VIM, SDNc will be assigned one worker id. Ns class will add items and VimThread will auto-assign
    cherrypy.tree.apps['/ro'].root.ns.start(engine_config)
    cherrypy.tree.apps['/ro'].root.authenticator.start(engine_config)
    cherrypy.tree.apps['/ro'].root.ns.init_db(target_version=database_version)

    # # start subscriptions thread:
    # vim_threads = []
    # for thread_id in range(engine_config["global"]["server.ns_threads"]):
    #     vim_thread = VimThread(thread_id, config=engine_config, engine=ro_server.ns)
    #     vim_thread.start()
    #     vim_threads.append(vim_thread)
    # # Do not capture except SubscriptionException

    backend = engine_config["authentication"]["backend"]
    cherrypy.log.error("Starting OSM NBI Version '{} {}' with '{}' authentication backend"
                       .format(ro_version, ro_version_date, backend))


def _stop_service():
    """
    Callback function called when cherrypy.engine stops
    TODO: Ending database connections.
    """
    # global vim_threads
    # if vim_threads:
    #     for vim_thread in vim_threads:
    #         vim_thread.terminate()
    # vim_threads = None
    cherrypy.tree.apps['/ro'].root.ns.stop()
    cherrypy.log.error("Stopping osm_ng_ro")


def ro_main(config_file):
    global ro_server
    ro_server = Server()
    cherrypy.engine.subscribe('start', _start_service)
    cherrypy.engine.subscribe('stop', _stop_service)
    cherrypy.quickstart(ro_server, '/ro', config_file)


def usage():
    print("""Usage: {} [options]
        -c|--config [configuration_file]: loads the configuration file (default: ./ro.cfg)
        -h|--help: shows this help
        """.format(sys.argv[0]))
    # --log-socket-host HOST: send logs to this host")
    # --log-socket-port PORT: send logs using this port (default: 9022)")


if __name__ == '__main__':
    try:
        # load parameters and configuration
        opts, args = getopt.getopt(sys.argv[1:], "hvc:", ["config=", "help"])
        # TODO add  "log-socket-host=", "log-socket-port=", "log-file="
        config_file = None
        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o in ("-c", "--config"):
                config_file = a
            else:
                assert False, "Unhandled option"
        if config_file:
            if not path.isfile(config_file):
                print("configuration file '{}' that not exist".format(config_file), file=sys.stderr)
                exit(1)
        else:
            for config_file in (path.dirname(__file__) + "/ro.cfg", "./ro.cfg", "/etc/osm/ro.cfg"):
                if path.isfile(config_file):
                    break
            else:
                print("No configuration file 'ro.cfg' found neither at local folder nor at /etc/osm/", file=sys.stderr)
                exit(1)
        ro_main(config_file)
    except getopt.GetoptError as e:
        print(str(e), file=sys.stderr)
        # usage()
        exit(1)
