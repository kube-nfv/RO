# -*- coding: utf-8 -*-

##
# Copyright 2020 Telefonica Investigacion y Desarrollo, S.A.U.
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

# import yaml
import logging
from traceback import format_exc as traceback_format_exc
from osm_ng_ro.ns_thread import NsWorker, NsWorkerException, deep_get
from osm_ng_ro.validation import validate_input, deploy_schema
from osm_common import (
    dbmongo,
    dbmemory,
    fslocal,
    fsmongo,
    msglocal,
    msgkafka,
    version as common_version,
)
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from http import HTTPStatus
from uuid import uuid4
from threading import Lock
from random import choice as random_choice
from time import time
from jinja2 import (
    Environment,
    TemplateError,
    TemplateNotFound,
    StrictUndefined,
    UndefinedError,
)
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"
min_common_version = "0.1.16"


class NsException(Exception):
    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST):
        self.http_code = http_code
        super(Exception, self).__init__(message)


def get_process_id():
    """
    Obtain a unique ID for this process. If running from inside docker, it will get docker ID. If not it
    will provide a random one
    :return: Obtained ID
    """
    # Try getting docker id. If fails, get pid
    try:
        with open("/proc/self/cgroup", "r") as f:
            text_id_ = f.readline()
            _, _, text_id = text_id_.rpartition("/")
            text_id = text_id.replace("\n", "")[:12]

            if text_id:
                return text_id
    except Exception:
        pass

    # Return a random id
    return "".join(random_choice("0123456789abcdef") for _ in range(12))


def versiontuple(v):
    """utility for compare dot separate versions. Fills with zeros to proper number comparison"""
    filled = []

    for point in v.split("."):
        filled.append(point.zfill(8))

    return tuple(filled)


class Ns(object):
    def __init__(self):
        self.db = None
        self.fs = None
        self.msg = None
        self.config = None
        # self.operations = None
        self.logger = None
        # ^ Getting logger inside method self.start because parent logger (ro) is not available yet.
        # If done now it will not be linked to parent not getting its handler and level
        self.map_topic = {}
        self.write_lock = None
        self.vims_assigned = {}
        self.next_worker = 0
        self.plugins = {}
        self.workers = []

    def init_db(self, target_version):
        pass

    def start(self, config):
        """
        Connect to database, filesystem storage, and messaging
        :param config: two level dictionary with configuration. Top level should contain 'database', 'storage',
        :param config: Configuration of db, storage, etc
        :return: None
        """
        self.config = config
        self.config["process_id"] = get_process_id()  # used for HA identity
        self.logger = logging.getLogger("ro.ns")

        # check right version of common
        if versiontuple(common_version) < versiontuple(min_common_version):
            raise NsException(
                "Not compatible osm/common version '{}'. Needed '{}' or higher".format(
                    common_version, min_common_version
                )
            )

        try:
            if not self.db:
                if config["database"]["driver"] == "mongo":
                    self.db = dbmongo.DbMongo()
                    self.db.db_connect(config["database"])
                elif config["database"]["driver"] == "memory":
                    self.db = dbmemory.DbMemory()
                    self.db.db_connect(config["database"])
                else:
                    raise NsException(
                        "Invalid configuration param '{}' at '[database]':'driver'".format(
                            config["database"]["driver"]
                        )
                    )

            if not self.fs:
                if config["storage"]["driver"] == "local":
                    self.fs = fslocal.FsLocal()
                    self.fs.fs_connect(config["storage"])
                elif config["storage"]["driver"] == "mongo":
                    self.fs = fsmongo.FsMongo()
                    self.fs.fs_connect(config["storage"])
                elif config["storage"]["driver"] is None:
                    pass
                else:
                    raise NsException(
                        "Invalid configuration param '{}' at '[storage]':'driver'".format(
                            config["storage"]["driver"]
                        )
                    )

            if not self.msg:
                if config["message"]["driver"] == "local":
                    self.msg = msglocal.MsgLocal()
                    self.msg.connect(config["message"])
                elif config["message"]["driver"] == "kafka":
                    self.msg = msgkafka.MsgKafka()
                    self.msg.connect(config["message"])
                else:
                    raise NsException(
                        "Invalid configuration param '{}' at '[message]':'driver'".format(
                            config["message"]["driver"]
                        )
                    )

            # TODO load workers to deal with exising database tasks

            self.write_lock = Lock()
        except (DbException, FsException, MsgException) as e:
            raise NsException(str(e), http_code=e.http_code)

    def get_assigned_vims(self):
        return list(self.vims_assigned.keys())

    def stop(self):
        try:
            if self.db:
                self.db.db_disconnect()

            if self.fs:
                self.fs.fs_disconnect()

            if self.msg:
                self.msg.disconnect()

            self.write_lock = None
        except (DbException, FsException, MsgException) as e:
            raise NsException(str(e), http_code=e.http_code)

        for worker in self.workers:
            worker.insert_task(("terminate",))

    def _create_worker(self):
        """
        Look for a worker thread in idle status. If not found it creates one unless the number of threads reach the
        limit of 'server.ns_threads' configuration. If reached, it just assigns one existing thread
        return the index of the assigned worker thread. Worker threads are storead at self.workers
        """
        # Look for a thread in idle status
        worker_id = next(
            (
                i
                for i in range(len(self.workers))
                if self.workers[i] and self.workers[i].idle
            ),
            None,
        )

        if worker_id is not None:
            # unset idle status to avoid race conditions
            self.workers[worker_id].idle = False
        else:
            worker_id = len(self.workers)

            if worker_id < self.config["global"]["server.ns_threads"]:
                # create a new worker
                self.workers.append(
                    NsWorker(worker_id, self.config, self.plugins, self.db)
                )
                self.workers[worker_id].start()
            else:
                # reached maximum number of threads, assign VIM to an existing one
                worker_id = self.next_worker
                self.next_worker = (self.next_worker + 1) % self.config["global"][
                    "server.ns_threads"
                ]

        return worker_id

    def assign_vim(self, target_id):
        with self.write_lock:
            return self._assign_vim(target_id)

    def _assign_vim(self, target_id):
        if target_id not in self.vims_assigned:
            worker_id = self.vims_assigned[target_id] = self._create_worker()
            self.workers[worker_id].insert_task(("load_vim", target_id))

    def reload_vim(self, target_id):
        # send reload_vim to the thread working with this VIM and inform all that a VIM has been changed,
        # this is because database VIM information is cached for threads working with SDN
        with self.write_lock:
            for worker in self.workers:
                if worker and not worker.idle:
                    worker.insert_task(("reload_vim", target_id))

    def unload_vim(self, target_id):
        with self.write_lock:
            return self._unload_vim(target_id)

    def _unload_vim(self, target_id):
        if target_id in self.vims_assigned:
            worker_id = self.vims_assigned[target_id]
            self.workers[worker_id].insert_task(("unload_vim", target_id))
            del self.vims_assigned[target_id]

    def check_vim(self, target_id):
        with self.write_lock:
            if target_id in self.vims_assigned:
                worker_id = self.vims_assigned[target_id]
            else:
                worker_id = self._create_worker()

        worker = self.workers[worker_id]
        worker.insert_task(("check_vim", target_id))

    def unload_unused_vims(self):
        with self.write_lock:
            vims_to_unload = []

            for target_id in self.vims_assigned:
                if not self.db.get_one(
                    "ro_tasks",
                    q_filter={
                        "target_id": target_id,
                        "tasks.status": ["SCHEDULED", "BUILD", "DONE", "FAILED"],
                    },
                    fail_on_empty=False,
                ):
                    vims_to_unload.append(target_id)

            for target_id in vims_to_unload:
                self._unload_vim(target_id)

    def _get_cloud_init(self, where):
        """
        Not used as cloud init content is provided in the http body. This method reads cloud init from a file
        :param where: can be 'vnfr_id:file:file_name' or 'vnfr_id:vdu:vdu_idex'
        :return:
        """
        vnfd_id, _, other = where.partition(":")
        _type, _, name = other.partition(":")
        vnfd = self.db.get_one("vnfds", {"_id": vnfd_id})

        if _type == "file":
            base_folder = vnfd["_admin"]["storage"]
            cloud_init_file = "{}/{}/cloud_init/{}".format(
                base_folder["folder"], base_folder["pkg-dir"], name
            )

            if not self.fs:
                raise NsException(
                    "Cannot read file '{}'. Filesystem not loaded, change configuration at storage.driver".format(
                        cloud_init_file
                    )
                )

            with self.fs.file_open(cloud_init_file, "r") as ci_file:
                cloud_init_content = ci_file.read()
        elif _type == "vdu":
            cloud_init_content = vnfd["vdu"][int(name)]["cloud-init"]
        else:
            raise NsException("Mismatch descriptor for cloud init: {}".format(where))

        return cloud_init_content

    def _parse_jinja2(self, cloud_init_content, params, context):
        try:
            env = Environment(undefined=StrictUndefined)
            template = env.from_string(cloud_init_content)

            return template.render(params or {})
        except UndefinedError as e:
            raise NsException(
                "Variable '{}' defined at vnfd='{}' must be provided in the instantiation parameters"
                "inside the 'additionalParamsForVnf' block".format(e, context)
            )
        except (TemplateError, TemplateNotFound) as e:
            raise NsException(
                "Error parsing Jinja2 to cloud-init content at vnfd='{}': {}".format(
                    context, e
                )
            )

    def _create_db_ro_nsrs(self, nsr_id, now):
        try:
            key = rsa.generate_private_key(
                backend=crypto_default_backend(), public_exponent=65537, key_size=2048
            )
            private_key = key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption(),
            )
            public_key = key.public_key().public_bytes(
                crypto_serialization.Encoding.OpenSSH,
                crypto_serialization.PublicFormat.OpenSSH,
            )
            private_key = private_key.decode("utf8")
            # Change first line because Paramiko needs a explicit start with 'BEGIN RSA PRIVATE KEY'
            i = private_key.find("\n")
            private_key = "-----BEGIN RSA PRIVATE KEY-----" + private_key[i:]
            public_key = public_key.decode("utf8")
        except Exception as e:
            raise NsException("Cannot create ssh-keys: {}".format(e))

        schema_version = "1.1"
        private_key_encrypted = self.db.encrypt(
            private_key, schema_version=schema_version, salt=nsr_id
        )
        db_content = {
            "_id": nsr_id,
            "_admin": {
                "created": now,
                "modified": now,
                "schema_version": schema_version,
            },
            "public_key": public_key,
            "private_key": private_key_encrypted,
            "actions": [],
        }
        self.db.create("ro_nsrs", db_content)

        return db_content

    def deploy(self, session, indata, version, nsr_id, *args, **kwargs):
        self.logger.debug("ns.deploy nsr_id={} indata={}".format(nsr_id, indata))
        validate_input(indata, deploy_schema)
        action_id = indata.get("action_id", str(uuid4()))
        task_index = 0
        # get current deployment
        db_nsr_update = {}  # update operation on nsrs
        db_vnfrs_update = {}
        db_vnfrs = {}  # vnf's info indexed by _id
        nb_ro_tasks = 0  # for logging
        vdu2cloud_init = indata.get("cloud_init_content") or {}
        step = ""
        logging_text = "Task deploy nsr_id={} action_id={} ".format(nsr_id, action_id)
        self.logger.debug(logging_text + "Enter")

        try:
            step = "Getting ns and vnfr record from db"
            db_nsr = self.db.get_one("nsrs", {"_id": nsr_id})
            db_new_tasks = []
            tasks_by_target_record_id = {}
            # read from db: vnf's of this ns
            step = "Getting vnfrs from db"
            db_vnfrs_list = self.db.get_list("vnfrs", {"nsr-id-ref": nsr_id})

            if not db_vnfrs_list:
                raise NsException("Cannot obtain associated VNF for ns")

            for vnfr in db_vnfrs_list:
                db_vnfrs[vnfr["_id"]] = vnfr
                db_vnfrs_update[vnfr["_id"]] = {}

            now = time()
            db_ro_nsr = self.db.get_one("ro_nsrs", {"_id": nsr_id}, fail_on_empty=False)

            if not db_ro_nsr:
                db_ro_nsr = self._create_db_ro_nsrs(nsr_id, now)

            ro_nsr_public_key = db_ro_nsr["public_key"]

            # check that action_id is not in the list of actions. Suffixed with :index
            if action_id in db_ro_nsr["actions"]:
                index = 1

                while True:
                    new_action_id = "{}:{}".format(action_id, index)

                    if new_action_id not in db_ro_nsr["actions"]:
                        action_id = new_action_id
                        self.logger.debug(
                            logging_text
                            + "Changing action_id in use to {}".format(action_id)
                        )
                        break

                    index += 1

            def _create_task(
                target_id,
                item,
                action,
                target_record,
                target_record_id,
                extra_dict=None,
            ):
                nonlocal task_index
                nonlocal action_id
                nonlocal nsr_id

                task = {
                    "target_id": target_id,  # it will be removed before pushing at database
                    "action_id": action_id,
                    "nsr_id": nsr_id,
                    "task_id": "{}:{}".format(action_id, task_index),
                    "status": "SCHEDULED",
                    "action": action,
                    "item": item,
                    "target_record": target_record,
                    "target_record_id": target_record_id,
                }

                if extra_dict:
                    task.update(extra_dict)  # params, find_params, depends_on

                task_index += 1

                return task

            def _create_ro_task(target_id, task):
                nonlocal action_id
                nonlocal task_index
                nonlocal now

                _id = task["task_id"]
                db_ro_task = {
                    "_id": _id,
                    "locked_by": None,
                    "locked_at": 0.0,
                    "target_id": target_id,
                    "vim_info": {
                        "created": False,
                        "created_items": None,
                        "vim_id": None,
                        "vim_name": None,
                        "vim_status": None,
                        "vim_details": None,
                        "refresh_at": None,
                    },
                    "modified_at": now,
                    "created_at": now,
                    "to_check_at": now,
                    "tasks": [task],
                }

                return db_ro_task

            def _process_image_params(target_image, vim_info, target_record_id):
                find_params = {}

                if target_image.get("image"):
                    find_params["filter_dict"] = {"name": target_image.get("image")}

                if target_image.get("vim_image_id"):
                    find_params["filter_dict"] = {
                        "id": target_image.get("vim_image_id")
                    }

                if target_image.get("image_checksum"):
                    find_params["filter_dict"] = {
                        "checksum": target_image.get("image_checksum")
                    }

                return {"find_params": find_params}

            def _process_flavor_params(target_flavor, vim_info, target_record_id):
                def _get_resource_allocation_params(quota_descriptor):
                    """
                    read the quota_descriptor from vnfd and fetch the resource allocation properties from the
                     descriptor object
                    :param quota_descriptor: cpu/mem/vif/disk-io quota descriptor
                    :return: quota params for limit, reserve, shares from the descriptor object
                    """
                    quota = {}

                    if quota_descriptor.get("limit"):
                        quota["limit"] = int(quota_descriptor["limit"])

                    if quota_descriptor.get("reserve"):
                        quota["reserve"] = int(quota_descriptor["reserve"])

                    if quota_descriptor.get("shares"):
                        quota["shares"] = int(quota_descriptor["shares"])

                    return quota

                flavor_data = {
                    "disk": int(target_flavor["storage-gb"]),
                    "ram": int(target_flavor["memory-mb"]),
                    "vcpus": int(target_flavor["vcpu-count"]),
                }
                numa = {}
                extended = {}

                if target_flavor.get("guest-epa"):
                    extended = {}
                    epa_vcpu_set = False

                    if target_flavor["guest-epa"].get("numa-node-policy"):
                        numa_node_policy = target_flavor["guest-epa"].get(
                            "numa-node-policy"
                        )

                        if numa_node_policy.get("node"):
                            numa_node = numa_node_policy["node"][0]

                            if numa_node.get("num-cores"):
                                numa["cores"] = numa_node["num-cores"]
                                epa_vcpu_set = True

                            if numa_node.get("paired-threads"):
                                if numa_node["paired-threads"].get(
                                    "num-paired-threads"
                                ):
                                    numa["paired-threads"] = int(
                                        numa_node["paired-threads"][
                                            "num-paired-threads"
                                        ]
                                    )
                                    epa_vcpu_set = True

                                if len(
                                    numa_node["paired-threads"].get("paired-thread-ids")
                                ):
                                    numa["paired-threads-id"] = []

                                    for pair in numa_node["paired-threads"][
                                        "paired-thread-ids"
                                    ]:
                                        numa["paired-threads-id"].append(
                                            (
                                                str(pair["thread-a"]),
                                                str(pair["thread-b"]),
                                            )
                                        )

                            if numa_node.get("num-threads"):
                                numa["threads"] = int(numa_node["num-threads"])
                                epa_vcpu_set = True

                            if numa_node.get("memory-mb"):
                                numa["memory"] = max(
                                    int(numa_node["memory-mb"] / 1024), 1
                                )

                    if target_flavor["guest-epa"].get("mempage-size"):
                        extended["mempage-size"] = target_flavor["guest-epa"].get(
                            "mempage-size"
                        )

                    if (
                        target_flavor["guest-epa"].get("cpu-pinning-policy")
                        and not epa_vcpu_set
                    ):
                        if (
                            target_flavor["guest-epa"]["cpu-pinning-policy"]
                            == "DEDICATED"
                        ):
                            if (
                                target_flavor["guest-epa"].get(
                                    "cpu-thread-pinning-policy"
                                )
                                and target_flavor["guest-epa"][
                                    "cpu-thread-pinning-policy"
                                ]
                                != "PREFER"
                            ):
                                numa["cores"] = max(flavor_data["vcpus"], 1)
                            else:
                                numa["threads"] = max(flavor_data["vcpus"], 1)

                            epa_vcpu_set = True

                    if target_flavor["guest-epa"].get("cpu-quota") and not epa_vcpu_set:
                        cpuquota = _get_resource_allocation_params(
                            target_flavor["guest-epa"].get("cpu-quota")
                        )

                        if cpuquota:
                            extended["cpu-quota"] = cpuquota

                    if target_flavor["guest-epa"].get("mem-quota"):
                        vduquota = _get_resource_allocation_params(
                            target_flavor["guest-epa"].get("mem-quota")
                        )

                        if vduquota:
                            extended["mem-quota"] = vduquota

                    if target_flavor["guest-epa"].get("disk-io-quota"):
                        diskioquota = _get_resource_allocation_params(
                            target_flavor["guest-epa"].get("disk-io-quota")
                        )

                        if diskioquota:
                            extended["disk-io-quota"] = diskioquota

                    if target_flavor["guest-epa"].get("vif-quota"):
                        vifquota = _get_resource_allocation_params(
                            target_flavor["guest-epa"].get("vif-quota")
                        )

                        if vifquota:
                            extended["vif-quota"] = vifquota

                if numa:
                    extended["numas"] = [numa]

                if extended:
                    flavor_data["extended"] = extended

                extra_dict = {"find_params": {"flavor_data": flavor_data}}
                flavor_data_name = flavor_data.copy()
                flavor_data_name["name"] = target_flavor["name"]
                extra_dict["params"] = {"flavor_data": flavor_data_name}

                return extra_dict

            def _ip_profile_2_ro(ip_profile):
                if not ip_profile:
                    return None

                ro_ip_profile = {
                    "ip_version": "IPv4"
                    if "v4" in ip_profile.get("ip-version", "ipv4")
                    else "IPv6",
                    "subnet_address": ip_profile.get("subnet-address"),
                    "gateway_address": ip_profile.get("gateway-address"),
                    "dhcp_enabled": ip_profile.get("dhcp-params", {}).get(
                        "enabled", False
                    ),
                    "dhcp_start_address": ip_profile.get("dhcp-params", {}).get(
                        "start-address", None
                    ),
                    "dhcp_count": ip_profile.get("dhcp-params", {}).get("count", None),
                }

                if ip_profile.get("dns-server"):
                    ro_ip_profile["dns_address"] = ";".join(
                        [v["address"] for v in ip_profile["dns-server"]]
                    )

                if ip_profile.get("security-group"):
                    ro_ip_profile["security_group"] = ip_profile["security-group"]

                return ro_ip_profile

            def _process_net_params(target_vld, vim_info, target_record_id):
                nonlocal indata
                extra_dict = {}

                if vim_info.get("sdn"):
                    # vnf_preffix = "vnfrs:{}".format(vnfr_id)
                    # ns_preffix = "nsrs:{}".format(nsr_id)
                    # remove the ending ".sdn
                    vld_target_record_id, _, _ = target_record_id.rpartition(".")
                    extra_dict["params"] = {
                        k: vim_info[k]
                        for k in ("sdn-ports", "target_vim", "vlds", "type")
                        if vim_info.get(k)
                    }

                    # TODO needed to add target_id in the dependency.
                    if vim_info.get("target_vim"):
                        extra_dict["depends_on"] = [
                            vim_info.get("target_vim") + " " + vld_target_record_id
                        ]

                    return extra_dict

                if vim_info.get("vim_network_name"):
                    extra_dict["find_params"] = {
                        "filter_dict": {"name": vim_info.get("vim_network_name")}
                    }
                elif vim_info.get("vim_network_id"):
                    extra_dict["find_params"] = {
                        "filter_dict": {"id": vim_info.get("vim_network_id")}
                    }
                elif target_vld.get("mgmt-network"):
                    extra_dict["find_params"] = {"mgmt": True, "name": target_vld["id"]}
                else:
                    # create
                    extra_dict["params"] = {
                        "net_name": "{}-{}".format(
                            indata["name"][:16],
                            target_vld.get("name", target_vld["id"])[:16],
                        ),
                        "ip_profile": _ip_profile_2_ro(vim_info.get("ip_profile")),
                        "provider_network_profile": vim_info.get("provider_network"),
                    }

                    if not target_vld.get("underlay"):
                        extra_dict["params"]["net_type"] = "bridge"
                    else:
                        extra_dict["params"]["net_type"] = (
                            "ptp" if target_vld.get("type") == "ELINE" else "data"
                        )

                return extra_dict

            def _process_vdu_params(target_vdu, vim_info, target_record_id):
                nonlocal vnfr_id
                nonlocal nsr_id
                nonlocal indata
                nonlocal vnfr
                nonlocal vdu2cloud_init
                nonlocal tasks_by_target_record_id

                vnf_preffix = "vnfrs:{}".format(vnfr_id)
                ns_preffix = "nsrs:{}".format(nsr_id)
                image_text = ns_preffix + ":image." + target_vdu["ns-image-id"]
                flavor_text = ns_preffix + ":flavor." + target_vdu["ns-flavor-id"]
                extra_dict = {"depends_on": [image_text, flavor_text]}
                net_list = []

                for iface_index, interface in enumerate(target_vdu["interfaces"]):
                    if interface.get("ns-vld-id"):
                        net_text = ns_preffix + ":vld." + interface["ns-vld-id"]
                    elif interface.get("vnf-vld-id"):
                        net_text = vnf_preffix + ":vld." + interface["vnf-vld-id"]
                    else:
                        self.logger.error(
                            "Interface {} from vdu {} not connected to any vld".format(
                                iface_index, target_vdu["vdu-name"]
                            )
                        )

                        continue  # interface not connected to any vld

                    extra_dict["depends_on"].append(net_text)

                    if "port-security-enabled" in interface:
                        interface["port_security"] = interface.pop(
                            "port-security-enabled"
                        )

                    if "port-security-disable-strategy" in interface:
                        interface["port_security_disable_strategy"] = interface.pop(
                            "port-security-disable-strategy"
                        )

                    net_item = {
                        x: v
                        for x, v in interface.items()
                        if x
                        in (
                            "name",
                            "vpci",
                            "port_security",
                            "port_security_disable_strategy",
                            "floating_ip",
                        )
                    }
                    net_item["net_id"] = "TASK-" + net_text
                    net_item["type"] = "virtual"

                    # TODO mac_address: used for  SR-IOV ifaces #TODO for other types
                    # TODO floating_ip: True/False (or it can be None)
                    if interface.get("type") in ("SR-IOV", "PCI-PASSTHROUGH"):
                        # mark the net create task as type data
                        if deep_get(
                            tasks_by_target_record_id, net_text, "params", "net_type"
                        ):
                            tasks_by_target_record_id[net_text]["params"][
                                "net_type"
                            ] = "data"

                        net_item["use"] = "data"
                        net_item["model"] = interface["type"]
                        net_item["type"] = interface["type"]
                    elif (
                        interface.get("type") == "OM-MGMT"
                        or interface.get("mgmt-interface")
                        or interface.get("mgmt-vnf")
                    ):
                        net_item["use"] = "mgmt"
                    else:
                        # if interface.get("type") in ("VIRTIO", "E1000", "PARAVIRT"):
                        net_item["use"] = "bridge"
                        net_item["model"] = interface.get("type")

                    if interface.get("ip-address"):
                        net_item["ip_address"] = interface["ip-address"]

                    if interface.get("mac-address"):
                        net_item["mac_address"] = interface["mac-address"]

                    net_list.append(net_item)

                    if interface.get("mgmt-vnf"):
                        extra_dict["mgmt_vnf_interface"] = iface_index
                    elif interface.get("mgmt-interface"):
                        extra_dict["mgmt_vdu_interface"] = iface_index

                # cloud config
                cloud_config = {}

                if target_vdu.get("cloud-init"):
                    if target_vdu["cloud-init"] not in vdu2cloud_init:
                        vdu2cloud_init[target_vdu["cloud-init"]] = self._get_cloud_init(
                            target_vdu["cloud-init"]
                        )

                    cloud_content_ = vdu2cloud_init[target_vdu["cloud-init"]]
                    cloud_config["user-data"] = self._parse_jinja2(
                        cloud_content_,
                        target_vdu.get("additionalParams"),
                        target_vdu["cloud-init"],
                    )

                if target_vdu.get("boot-data-drive"):
                    cloud_config["boot-data-drive"] = target_vdu.get("boot-data-drive")

                ssh_keys = []

                if target_vdu.get("ssh-keys"):
                    ssh_keys += target_vdu.get("ssh-keys")

                if target_vdu.get("ssh-access-required"):
                    ssh_keys.append(ro_nsr_public_key)

                if ssh_keys:
                    cloud_config["key-pairs"] = ssh_keys

                disk_list = None
                if target_vdu.get("virtual-storages"):
                    disk_list = [
                        {"size": disk["size-of-storage"]}
                        for disk in target_vdu["virtual-storages"]
                        if disk.get("type-of-storage")
                        == "persistent-storage:persistent-storage"
                    ]

                extra_dict["params"] = {
                    "name": "{}-{}-{}-{}".format(
                        indata["name"][:16],
                        vnfr["member-vnf-index-ref"][:16],
                        target_vdu["vdu-name"][:32],
                        target_vdu.get("count-index") or 0,
                    ),
                    "description": target_vdu["vdu-name"],
                    "start": True,
                    "image_id": "TASK-" + image_text,
                    "flavor_id": "TASK-" + flavor_text,
                    "net_list": net_list,
                    "cloud_config": cloud_config or None,
                    "disk_list": disk_list,
                    "availability_zone_index": None,  # TODO
                    "availability_zone_list": None,  # TODO
                }

                return extra_dict

            def _process_items(
                target_list,
                existing_list,
                db_record,
                db_update,
                db_path,
                item,
                process_params,
            ):
                nonlocal db_new_tasks
                nonlocal tasks_by_target_record_id
                nonlocal task_index

                # ensure all the target_list elements has an "id". If not assign the index as id
                for target_index, tl in enumerate(target_list):
                    if tl and not tl.get("id"):
                        tl["id"] = str(target_index)

                # step 1 items (networks,vdus,...) to be deleted/updated
                for item_index, existing_item in enumerate(existing_list):
                    target_item = next(
                        (t for t in target_list if t["id"] == existing_item["id"]), None
                    )

                    for target_vim, existing_viminfo in existing_item.get(
                        "vim_info", {}
                    ).items():
                        if existing_viminfo is None:
                            continue

                        if target_item:
                            target_viminfo = target_item.get("vim_info", {}).get(
                                target_vim
                            )
                        else:
                            target_viminfo = None

                        if target_viminfo is None:
                            # must be deleted
                            self._assign_vim(target_vim)
                            target_record_id = "{}.{}".format(
                                db_record, existing_item["id"]
                            )
                            item_ = item

                            if target_vim.startswith("sdn"):
                                # item must be sdn-net instead of net if target_vim is a sdn
                                item_ = "sdn_net"
                                target_record_id += ".sdn"

                            task = _create_task(
                                target_vim,
                                item_,
                                "DELETE",
                                target_record="{}.{}.vim_info.{}".format(
                                    db_record, item_index, target_vim
                                ),
                                target_record_id=target_record_id,
                            )
                            tasks_by_target_record_id[target_record_id] = task
                            db_new_tasks.append(task)
                            # TODO delete
                    # TODO check one by one the vims to be created/deleted

                # step 2 items (networks,vdus,...) to be created
                for target_item in target_list:
                    item_index = -1

                    for item_index, existing_item in enumerate(existing_list):
                        if existing_item["id"] == target_item["id"]:
                            break
                    else:
                        item_index += 1
                        db_update[db_path + ".{}".format(item_index)] = target_item
                        existing_list.append(target_item)
                        existing_item = None

                    for target_vim, target_viminfo in target_item.get(
                        "vim_info", {}
                    ).items():
                        existing_viminfo = None

                        if existing_item:
                            existing_viminfo = existing_item.get("vim_info", {}).get(
                                target_vim
                            )

                        # TODO check if different. Delete and create???
                        # TODO delete if not exist
                        if existing_viminfo is not None:
                            continue

                        target_record_id = "{}.{}".format(db_record, target_item["id"])
                        item_ = item

                        if target_vim.startswith("sdn"):
                            # item must be sdn-net instead of net if target_vim is a sdn
                            item_ = "sdn_net"
                            target_record_id += ".sdn"

                        extra_dict = process_params(
                            target_item, target_viminfo, target_record_id
                        )
                        self._assign_vim(target_vim)
                        task = _create_task(
                            target_vim,
                            item_,
                            "CREATE",
                            target_record="{}.{}.vim_info.{}".format(
                                db_record, item_index, target_vim
                            ),
                            target_record_id=target_record_id,
                            extra_dict=extra_dict,
                        )
                        tasks_by_target_record_id[target_record_id] = task
                        db_new_tasks.append(task)

                        if target_item.get("common_id"):
                            task["common_id"] = target_item["common_id"]

                        db_update[db_path + ".{}".format(item_index)] = target_item

            def _process_action(indata):
                nonlocal db_new_tasks
                nonlocal task_index
                nonlocal db_vnfrs
                nonlocal db_ro_nsr

                if indata["action"]["action"] == "inject_ssh_key":
                    key = indata["action"].get("key")
                    user = indata["action"].get("user")
                    password = indata["action"].get("password")

                    for vnf in indata.get("vnf", ()):
                        if vnf["_id"] not in db_vnfrs:
                            raise NsException("Invalid vnf={}".format(vnf["_id"]))

                        db_vnfr = db_vnfrs[vnf["_id"]]

                        for target_vdu in vnf.get("vdur", ()):
                            vdu_index, vdur = next(
                                (
                                    i_v
                                    for i_v in enumerate(db_vnfr["vdur"])
                                    if i_v[1]["id"] == target_vdu["id"]
                                ),
                                (None, None),
                            )

                            if not vdur:
                                raise NsException(
                                    "Invalid vdu vnf={}.{}".format(
                                        vnf["_id"], target_vdu["id"]
                                    )
                                )

                            target_vim, vim_info = next(
                                k_v for k_v in vdur["vim_info"].items()
                            )
                            self._assign_vim(target_vim)
                            target_record = "vnfrs:{}:vdur.{}.ssh_keys".format(
                                vnf["_id"], vdu_index
                            )
                            extra_dict = {
                                "depends_on": [
                                    "vnfrs:{}:vdur.{}".format(vnf["_id"], vdur["id"])
                                ],
                                "params": {
                                    "ip_address": vdur.get("ip-address"),
                                    "user": user,
                                    "key": key,
                                    "password": password,
                                    "private_key": db_ro_nsr["private_key"],
                                    "salt": db_ro_nsr["_id"],
                                    "schema_version": db_ro_nsr["_admin"][
                                        "schema_version"
                                    ],
                                },
                            }
                            task = _create_task(
                                target_vim,
                                "vdu",
                                "EXEC",
                                target_record=target_record,
                                target_record_id=None,
                                extra_dict=extra_dict,
                            )
                            db_new_tasks.append(task)

            with self.write_lock:
                if indata.get("action"):
                    _process_action(indata)
                else:
                    # compute network differences
                    # NS.vld
                    step = "process NS VLDs"
                    _process_items(
                        target_list=indata["ns"]["vld"] or [],
                        existing_list=db_nsr.get("vld") or [],
                        db_record="nsrs:{}:vld".format(nsr_id),
                        db_update=db_nsr_update,
                        db_path="vld",
                        item="net",
                        process_params=_process_net_params,
                    )

                    step = "process NS images"
                    _process_items(
                        target_list=indata.get("image") or [],
                        existing_list=db_nsr.get("image") or [],
                        db_record="nsrs:{}:image".format(nsr_id),
                        db_update=db_nsr_update,
                        db_path="image",
                        item="image",
                        process_params=_process_image_params,
                    )

                    step = "process NS flavors"
                    _process_items(
                        target_list=indata.get("flavor") or [],
                        existing_list=db_nsr.get("flavor") or [],
                        db_record="nsrs:{}:flavor".format(nsr_id),
                        db_update=db_nsr_update,
                        db_path="flavor",
                        item="flavor",
                        process_params=_process_flavor_params,
                    )

                    # VNF.vld
                    for vnfr_id, vnfr in db_vnfrs.items():
                        # vnfr_id need to be set as global variable for among others nested method _process_vdu_params
                        step = "process VNF={} VLDs".format(vnfr_id)
                        target_vnf = next(
                            (
                                vnf
                                for vnf in indata.get("vnf", ())
                                if vnf["_id"] == vnfr_id
                            ),
                            None,
                        )
                        target_list = target_vnf.get("vld") if target_vnf else None
                        _process_items(
                            target_list=target_list or [],
                            existing_list=vnfr.get("vld") or [],
                            db_record="vnfrs:{}:vld".format(vnfr_id),
                            db_update=db_vnfrs_update[vnfr["_id"]],
                            db_path="vld",
                            item="net",
                            process_params=_process_net_params,
                        )

                        target_list = target_vnf.get("vdur") if target_vnf else None
                        step = "process VNF={} VDUs".format(vnfr_id)
                        _process_items(
                            target_list=target_list or [],
                            existing_list=vnfr.get("vdur") or [],
                            db_record="vnfrs:{}:vdur".format(vnfr_id),
                            db_update=db_vnfrs_update[vnfr["_id"]],
                            db_path="vdur",
                            item="vdu",
                            process_params=_process_vdu_params,
                        )

                for db_task in db_new_tasks:
                    step = "Updating database, Appending tasks to ro_tasks"
                    target_id = db_task.pop("target_id")
                    common_id = db_task.get("common_id")

                    if common_id:
                        if self.db.set_one(
                            "ro_tasks",
                            q_filter={
                                "target_id": target_id,
                                "tasks.common_id": common_id,
                            },
                            update_dict={"to_check_at": now, "modified_at": now},
                            push={"tasks": db_task},
                            fail_on_empty=False,
                        ):
                            continue

                    if not self.db.set_one(
                        "ro_tasks",
                        q_filter={
                            "target_id": target_id,
                            "tasks.target_record": db_task["target_record"],
                        },
                        update_dict={"to_check_at": now, "modified_at": now},
                        push={"tasks": db_task},
                        fail_on_empty=False,
                    ):
                        # Create a ro_task
                        step = "Updating database, Creating ro_tasks"
                        db_ro_task = _create_ro_task(target_id, db_task)
                        nb_ro_tasks += 1
                        self.db.create("ro_tasks", db_ro_task)

                step = "Updating database, nsrs"
                if db_nsr_update:
                    self.db.set_one("nsrs", {"_id": nsr_id}, db_nsr_update)

                for vnfr_id, db_vnfr_update in db_vnfrs_update.items():
                    if db_vnfr_update:
                        step = "Updating database, vnfrs={}".format(vnfr_id)
                        self.db.set_one("vnfrs", {"_id": vnfr_id}, db_vnfr_update)

            self.logger.debug(
                logging_text
                + "Exit. Created {} ro_tasks; {} tasks".format(
                    nb_ro_tasks, len(db_new_tasks)
                )
            )

            return (
                {"status": "ok", "nsr_id": nsr_id, "action_id": action_id},
                action_id,
                True,
            )
        except Exception as e:
            if isinstance(e, (DbException, NsException)):
                self.logger.error(
                    logging_text + "Exit Exception while '{}': {}".format(step, e)
                )
            else:
                e = traceback_format_exc()
                self.logger.critical(
                    logging_text + "Exit Exception while '{}': {}".format(step, e),
                    exc_info=True,
                )

            raise NsException(e)

    def delete(self, session, indata, version, nsr_id, *args, **kwargs):
        self.logger.debug("ns.delete version={} nsr_id={}".format(version, nsr_id))
        # self.db.del_list({"_id": ro_task["_id"], "tasks.nsr_id.ne": nsr_id})

        with self.write_lock:
            try:
                NsWorker.delete_db_tasks(self.db, nsr_id, None)
            except NsWorkerException as e:
                raise NsException(e)

        return None, None, True

    def status(self, session, indata, version, nsr_id, action_id, *args, **kwargs):
        # self.logger.debug("ns.status version={} nsr_id={}, action_id={} indata={}"
        #                   .format(version, nsr_id, action_id, indata))
        task_list = []
        done = 0
        total = 0
        ro_tasks = self.db.get_list("ro_tasks", {"tasks.action_id": action_id})
        global_status = "DONE"
        details = []

        for ro_task in ro_tasks:
            for task in ro_task["tasks"]:
                if task and task["action_id"] == action_id:
                    task_list.append(task)
                    total += 1

                    if task["status"] == "FAILED":
                        global_status = "FAILED"
                        error_text = "Error at {} {}: {}".format(
                            task["action"].lower(),
                            task["item"],
                            ro_task["vim_info"].get("vim_details") or "unknown",
                        )
                        details.append(error_text)
                    elif task["status"] in ("SCHEDULED", "BUILD"):
                        if global_status != "FAILED":
                            global_status = "BUILD"
                    else:
                        done += 1

        return_data = {
            "status": global_status,
            "details": ". ".join(details)
            if details
            else "progress {}/{}".format(done, total),
            "nsr_id": nsr_id,
            "action_id": action_id,
            "tasks": task_list,
        }

        return return_data, None, True

    def cancel(self, session, indata, version, nsr_id, action_id, *args, **kwargs):
        print(
            "ns.cancel session={} indata={} version={} nsr_id={}, action_id={}".format(
                session, indata, version, nsr_id, action_id
            )
        )

        return None, None, True

    def get_deploy(self, session, indata, version, nsr_id, action_id, *args, **kwargs):
        nsrs = self.db.get_list("nsrs", {})
        return_data = []

        for ns in nsrs:
            return_data.append({"_id": ns["_id"], "name": ns["name"]})

        return return_data, None, True

    def get_actions(self, session, indata, version, nsr_id, action_id, *args, **kwargs):
        ro_tasks = self.db.get_list("ro_tasks", {"tasks.nsr_id": nsr_id})
        return_data = []

        for ro_task in ro_tasks:
            for task in ro_task["tasks"]:
                if task["action_id"] not in return_data:
                    return_data.append(task["action_id"])

        return return_data, None, True
