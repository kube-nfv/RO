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

from http import HTTPStatus
import logging
from random import choice as random_choice
from threading import Lock
from time import time
from traceback import format_exc as traceback_format_exc
from typing import Any, Dict, Tuple, Type
from uuid import uuid4

from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jinja2 import (
    Environment,
    StrictUndefined,
    TemplateError,
    TemplateNotFound,
    UndefinedError,
)
from osm_common import (
    dbmemory,
    dbmongo,
    fslocal,
    fsmongo,
    msgkafka,
    msglocal,
    version as common_version,
)
from osm_common.dbbase import DbBase, DbException
from osm_common.fsbase import FsBase, FsException
from osm_common.msgbase import MsgException
from osm_ng_ro.ns_thread import deep_get, NsWorker, NsWorkerException
from osm_ng_ro.validation import deploy_schema, validate_input
import yaml

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
        self.process_params_function_map = {
            "net": Ns._process_net_params,
            "image": Ns._process_image_params,
            "flavor": Ns._process_flavor_params,
            "vdu": Ns._process_vdu_params,
            "affinity-or-anti-affinity-group": Ns._process_affinity_group_params,
        }
        self.db_path_map = {
            "net": "vld",
            "image": "image",
            "flavor": "flavor",
            "vdu": "vdur",
            "affinity-or-anti-affinity-group": "affinity-or-anti-affinity-group",
        }

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

    @staticmethod
    def _get_cloud_init(
        db: Type[DbBase],
        fs: Type[FsBase],
        location: str,
    ) -> str:
        """This method reads cloud init from a file.

        Note: Not used as cloud init content is provided in the http body.

        Args:
            db (Type[DbBase]): [description]
            fs (Type[FsBase]): [description]
            location (str): can be 'vnfr_id:file:file_name' or 'vnfr_id:vdu:vdu_idex'

        Raises:
            NsException: [description]
            NsException: [description]

        Returns:
            str: [description]
        """
        vnfd_id, _, other = location.partition(":")
        _type, _, name = other.partition(":")
        vnfd = db.get_one("vnfds", {"_id": vnfd_id})

        if _type == "file":
            base_folder = vnfd["_admin"]["storage"]
            cloud_init_file = "{}/{}/cloud_init/{}".format(
                base_folder["folder"], base_folder["pkg-dir"], name
            )

            if not fs:
                raise NsException(
                    "Cannot read file '{}'. Filesystem not loaded, change configuration at storage.driver".format(
                        cloud_init_file
                    )
                )

            with fs.file_open(cloud_init_file, "r") as ci_file:
                cloud_init_content = ci_file.read()
        elif _type == "vdu":
            cloud_init_content = vnfd["vdu"][int(name)]["cloud-init"]
        else:
            raise NsException("Mismatch descriptor for cloud init: {}".format(location))

        return cloud_init_content

    @staticmethod
    def _parse_jinja2(
        cloud_init_content: str,
        params: Dict[str, Any],
        context: str,
    ) -> str:
        """Function that processes the cloud init to replace Jinja2 encoded parameters.

        Args:
            cloud_init_content (str): [description]
            params (Dict[str, Any]): [description]
            context (str): [description]

        Raises:
            NsException: [description]
            NsException: [description]

        Returns:
            str: [description]
        """
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

    @staticmethod
    def _create_task(
        deployment_info: Dict[str, Any],
        target_id: str,
        item: str,
        action: str,
        target_record: str,
        target_record_id: str,
        extra_dict: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Function to create task dict from deployment information.

        Args:
            deployment_info (Dict[str, Any]): [description]
            target_id (str): [description]
            item (str): [description]
            action (str): [description]
            target_record (str): [description]
            target_record_id (str): [description]
            extra_dict (Dict[str, Any], optional): [description]. Defaults to None.

        Returns:
            Dict[str, Any]: [description]
        """
        task = {
            "target_id": target_id,  # it will be removed before pushing at database
            "action_id": deployment_info.get("action_id"),
            "nsr_id": deployment_info.get("nsr_id"),
            "task_id": f"{deployment_info.get('action_id')}:{deployment_info.get('task_index')}",
            "status": "SCHEDULED",
            "action": action,
            "item": item,
            "target_record": target_record,
            "target_record_id": target_record_id,
        }

        if extra_dict:
            task.update(extra_dict)  # params, find_params, depends_on

        deployment_info["task_index"] = deployment_info.get("task_index", 0) + 1

        return task

    @staticmethod
    def _create_ro_task(
        target_id: str,
        task: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Function to create an RO task from task information.

        Args:
            target_id (str): [description]
            task (Dict[str, Any]): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        now = time()

        _id = task.get("task_id")
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
                "vim_message": None,
                "refresh_at": None,
            },
            "modified_at": now,
            "created_at": now,
            "to_check_at": now,
            "tasks": [task],
        }

        return db_ro_task

    @staticmethod
    def _process_image_params(
        target_image: Dict[str, Any],
        indata: Dict[str, Any],
        vim_info: Dict[str, Any],
        target_record_id: str,
        **kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Function to process VDU image parameters.

        Args:
            target_image (Dict[str, Any]): [description]
            indata (Dict[str, Any]): [description]
            vim_info (Dict[str, Any]): [description]
            target_record_id (str): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        find_params = {}

        if target_image.get("image"):
            find_params["filter_dict"] = {"name": target_image.get("image")}

        if target_image.get("vim_image_id"):
            find_params["filter_dict"] = {"id": target_image.get("vim_image_id")}

        if target_image.get("image_checksum"):
            find_params["filter_dict"] = {
                "checksum": target_image.get("image_checksum")
            }

        return {"find_params": find_params}

    @staticmethod
    def _get_resource_allocation_params(
        quota_descriptor: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Read the quota_descriptor from vnfd and fetch the resource allocation properties from the
        descriptor object.

        Args:
            quota_descriptor (Dict[str, Any]): cpu/mem/vif/disk-io quota descriptor

        Returns:
            Dict[str, Any]: quota params for limit, reserve, shares from the descriptor object
        """
        quota = {}

        if quota_descriptor.get("limit"):
            quota["limit"] = int(quota_descriptor["limit"])

        if quota_descriptor.get("reserve"):
            quota["reserve"] = int(quota_descriptor["reserve"])

        if quota_descriptor.get("shares"):
            quota["shares"] = int(quota_descriptor["shares"])

        return quota

    @staticmethod
    def _process_guest_epa_quota_params(
        guest_epa_quota: Dict[str, Any],
        epa_vcpu_set: bool,
    ) -> Dict[str, Any]:
        """Function to extract the guest epa quota parameters.

        Args:
            guest_epa_quota (Dict[str, Any]): [description]
            epa_vcpu_set (bool): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        result = {}

        if guest_epa_quota.get("cpu-quota") and not epa_vcpu_set:
            cpuquota = Ns._get_resource_allocation_params(
                guest_epa_quota.get("cpu-quota")
            )

            if cpuquota:
                result["cpu-quota"] = cpuquota

        if guest_epa_quota.get("mem-quota"):
            vduquota = Ns._get_resource_allocation_params(
                guest_epa_quota.get("mem-quota")
            )

            if vduquota:
                result["mem-quota"] = vduquota

        if guest_epa_quota.get("disk-io-quota"):
            diskioquota = Ns._get_resource_allocation_params(
                guest_epa_quota.get("disk-io-quota")
            )

            if diskioquota:
                result["disk-io-quota"] = diskioquota

        if guest_epa_quota.get("vif-quota"):
            vifquota = Ns._get_resource_allocation_params(
                guest_epa_quota.get("vif-quota")
            )

            if vifquota:
                result["vif-quota"] = vifquota

        return result

    @staticmethod
    def _process_guest_epa_numa_params(
        guest_epa_quota: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], bool]:
        """[summary]

        Args:
            guest_epa_quota (Dict[str, Any]): [description]

        Returns:
            Tuple[Dict[str, Any], bool]: [description]
        """
        numa = {}
        epa_vcpu_set = False

        if guest_epa_quota.get("numa-node-policy"):
            numa_node_policy = guest_epa_quota.get("numa-node-policy")

            if numa_node_policy.get("node"):
                numa_node = numa_node_policy["node"][0]

                if numa_node.get("num-cores"):
                    numa["cores"] = numa_node["num-cores"]
                    epa_vcpu_set = True

                paired_threads = numa_node.get("paired-threads", {})
                if paired_threads.get("num-paired-threads"):
                    numa["paired-threads"] = int(
                        numa_node["paired-threads"]["num-paired-threads"]
                    )
                    epa_vcpu_set = True

                if paired_threads.get("paired-thread-ids"):
                    numa["paired-threads-id"] = []

                    for pair in paired_threads["paired-thread-ids"]:
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
                    numa["memory"] = max(int(int(numa_node["memory-mb"]) / 1024), 1)

        return numa, epa_vcpu_set

    @staticmethod
    def _process_guest_epa_cpu_pinning_params(
        guest_epa_quota: Dict[str, Any],
        vcpu_count: int,
        epa_vcpu_set: bool,
    ) -> Tuple[Dict[str, Any], bool]:
        """[summary]

        Args:
            guest_epa_quota (Dict[str, Any]): [description]
            vcpu_count (int): [description]
            epa_vcpu_set (bool): [description]

        Returns:
            Tuple[Dict[str, Any], bool]: [description]
        """
        numa = {}
        local_epa_vcpu_set = epa_vcpu_set

        if (
            guest_epa_quota.get("cpu-pinning-policy") == "DEDICATED"
            and not epa_vcpu_set
        ):
            numa[
                "cores"
                if guest_epa_quota.get("cpu-thread-pinning-policy") != "PREFER"
                else "threads"
            ] = max(vcpu_count, 1)
            local_epa_vcpu_set = True

        return numa, local_epa_vcpu_set

    @staticmethod
    def _process_epa_params(
        target_flavor: Dict[str, Any],
    ) -> Dict[str, Any]:
        """[summary]

        Args:
            target_flavor (Dict[str, Any]): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        extended = {}
        numa = {}

        if target_flavor.get("guest-epa"):
            guest_epa = target_flavor["guest-epa"]

            numa, epa_vcpu_set = Ns._process_guest_epa_numa_params(
                guest_epa_quota=guest_epa
            )

            if guest_epa.get("mempage-size"):
                extended["mempage-size"] = guest_epa.get("mempage-size")

            tmp_numa, epa_vcpu_set = Ns._process_guest_epa_cpu_pinning_params(
                guest_epa_quota=guest_epa,
                vcpu_count=int(target_flavor.get("vcpu-count", 1)),
                epa_vcpu_set=epa_vcpu_set,
            )
            numa.update(tmp_numa)

            extended.update(
                Ns._process_guest_epa_quota_params(
                    guest_epa_quota=guest_epa,
                    epa_vcpu_set=epa_vcpu_set,
                )
            )

        if numa:
            extended["numas"] = [numa]

        return extended

    @staticmethod
    def _process_flavor_params(
        target_flavor: Dict[str, Any],
        indata: Dict[str, Any],
        vim_info: Dict[str, Any],
        target_record_id: str,
        **kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """[summary]

        Args:
            target_flavor (Dict[str, Any]): [description]
            indata (Dict[str, Any]): [description]
            vim_info (Dict[str, Any]): [description]
            target_record_id (str): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        flavor_data = {
            "disk": int(target_flavor["storage-gb"]),
            "ram": int(target_flavor["memory-mb"]),
            "vcpus": int(target_flavor["vcpu-count"]),
        }

        target_vdur = {}
        for vnf in indata.get("vnf", []):
            for vdur in vnf.get("vdur", []):
                if vdur.get("ns-flavor-id") == target_flavor["id"]:
                    target_vdur = vdur

        for storage in target_vdur.get("virtual-storages", []):
            if (
                storage.get("type-of-storage")
                == "etsi-nfv-descriptors:ephemeral-storage"
            ):
                flavor_data["ephemeral"] = int(storage.get("size-of-storage", 0))
            elif storage.get("type-of-storage") == "etsi-nfv-descriptors:swap-storage":
                flavor_data["swap"] = int(storage.get("size-of-storage", 0))

        extended = Ns._process_epa_params(target_flavor)
        if extended:
            flavor_data["extended"] = extended

        extra_dict = {"find_params": {"flavor_data": flavor_data}}
        flavor_data_name = flavor_data.copy()
        flavor_data_name["name"] = target_flavor["name"]
        extra_dict["params"] = {"flavor_data": flavor_data_name}

        return extra_dict

    @staticmethod
    def _ip_profile_to_ro(
        ip_profile: Dict[str, Any],
    ) -> Dict[str, Any]:
        """[summary]

        Args:
            ip_profile (Dict[str, Any]): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        if not ip_profile:
            return None

        ro_ip_profile = {
            "ip_version": "IPv4"
            if "v4" in ip_profile.get("ip-version", "ipv4")
            else "IPv6",
            "subnet_address": ip_profile.get("subnet-address"),
            "gateway_address": ip_profile.get("gateway-address"),
            "dhcp_enabled": ip_profile.get("dhcp-params", {}).get("enabled", False),
            "dhcp_start_address": ip_profile.get("dhcp-params", {}).get(
                "start-address", None
            ),
            "dhcp_count": ip_profile.get("dhcp-params", {}).get("count", None),
        }

        if ip_profile.get("dns-server"):
            ro_ip_profile["dns_address"] = ";".join(
                [v["address"] for v in ip_profile["dns-server"] if v.get("address")]
            )

        if ip_profile.get("security-group"):
            ro_ip_profile["security_group"] = ip_profile["security-group"]

        return ro_ip_profile

    @staticmethod
    def _process_net_params(
        target_vld: Dict[str, Any],
        indata: Dict[str, Any],
        vim_info: Dict[str, Any],
        target_record_id: str,
        **kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Function to process network parameters.

        Args:
            target_vld (Dict[str, Any]): [description]
            indata (Dict[str, Any]): [description]
            vim_info (Dict[str, Any]): [description]
            target_record_id (str): [description]

        Returns:
            Dict[str, Any]: [description]
        """
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
                    f"{vim_info.get('target_vim')} {vld_target_record_id}"
                ]

            return extra_dict

        if vim_info.get("vim_network_name"):
            extra_dict["find_params"] = {
                "filter_dict": {
                    "name": vim_info.get("vim_network_name"),
                },
            }
        elif vim_info.get("vim_network_id"):
            extra_dict["find_params"] = {
                "filter_dict": {
                    "id": vim_info.get("vim_network_id"),
                },
            }
        elif target_vld.get("mgmt-network"):
            extra_dict["find_params"] = {
                "mgmt": True,
                "name": target_vld["id"],
            }
        else:
            # create
            extra_dict["params"] = {
                "net_name": (
                    f"{indata.get('name')[:16]}-{target_vld.get('name', target_vld.get('id'))[:16]}"
                ),
                "ip_profile": Ns._ip_profile_to_ro(vim_info.get("ip_profile")),
                "provider_network_profile": vim_info.get("provider_network"),
            }

            if not target_vld.get("underlay"):
                extra_dict["params"]["net_type"] = "bridge"
            else:
                extra_dict["params"]["net_type"] = (
                    "ptp" if target_vld.get("type") == "ELINE" else "data"
                )

        return extra_dict

    @staticmethod
    def _process_vdu_params(
        target_vdu: Dict[str, Any],
        indata: Dict[str, Any],
        vim_info: Dict[str, Any],
        target_record_id: str,
        **kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Function to process VDU parameters.

        Args:
            target_vdu (Dict[str, Any]): [description]
            indata (Dict[str, Any]): [description]
            vim_info (Dict[str, Any]): [description]
            target_record_id (str): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        vnfr_id = kwargs.get("vnfr_id")
        nsr_id = kwargs.get("nsr_id")
        vnfr = kwargs.get("vnfr")
        vdu2cloud_init = kwargs.get("vdu2cloud_init")
        tasks_by_target_record_id = kwargs.get("tasks_by_target_record_id")
        logger = kwargs.get("logger")
        db = kwargs.get("db")
        fs = kwargs.get("fs")
        ro_nsr_public_key = kwargs.get("ro_nsr_public_key")

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
                logger.error(
                    "Interface {} from vdu {} not connected to any vld".format(
                        iface_index, target_vdu["vdu-name"]
                    )
                )

                continue  # interface not connected to any vld

            extra_dict["depends_on"].append(net_text)

            if "port-security-enabled" in interface:
                interface["port_security"] = interface.pop("port-security-enabled")

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
                    tasks_by_target_record_id,
                    net_text,
                    "extra_dict",
                    "params",
                    "net_type",
                ):
                    tasks_by_target_record_id[net_text]["extra_dict"]["params"][
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
                vdu2cloud_init[target_vdu["cloud-init"]] = Ns._get_cloud_init(
                    db=db,
                    fs=fs,
                    location=target_vdu["cloud-init"],
                )

            cloud_content_ = vdu2cloud_init[target_vdu["cloud-init"]]
            cloud_config["user-data"] = Ns._parse_jinja2(
                cloud_init_content=cloud_content_,
                params=target_vdu.get("additionalParams"),
                context=target_vdu["cloud-init"],
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

        persistent_root_disk = {}
        disk_list = []
        vnfd_id = vnfr["vnfd-id"]
        vnfd = db.get_one("vnfds", {"_id": vnfd_id})
        for vdu in vnfd.get("vdu", ()):
            if vdu["name"] == target_vdu["vdu-name"]:
                for vsd in vnfd.get("virtual-storage-desc", ()):
                    if vsd.get("id") == vdu.get("virtual-storage-desc", [[]])[0]:
                        root_disk = vsd
                        if root_disk.get(
                            "type-of-storage"
                        ) == "persistent-storage:persistent-storage" and root_disk.get(
                            "size-of-storage"
                        ):
                            persistent_root_disk[vsd["id"]] = {
                                "image_id": vdu.get("sw-image-desc"),
                                "size": root_disk["size-of-storage"],
                            }
                            disk_list.append(persistent_root_disk[vsd["id"]])

        if target_vdu.get("virtual-storages"):
            for disk in target_vdu["virtual-storages"]:
                if (
                    disk.get("type-of-storage")
                    == "persistent-storage:persistent-storage"
                    and disk["id"] not in persistent_root_disk.keys()
                ):
                    disk_list.append({"size": disk["size-of-storage"]})

        affinity_group_list = []

        if target_vdu.get("affinity-or-anti-affinity-group-id"):
            affinity_group = {}
            for affinity_group_id in target_vdu["affinity-or-anti-affinity-group-id"]:
                affinity_group_text = (
                    ns_preffix + ":affinity-or-anti-affinity-group." + affinity_group_id
                )

                extra_dict["depends_on"].append(affinity_group_text)
                affinity_group["affinity_group_id"] = "TASK-" + affinity_group_text
                affinity_group_list.append(affinity_group)

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
            "affinity_group_list": affinity_group_list,
            "net_list": net_list,
            "cloud_config": cloud_config or None,
            "disk_list": disk_list,
            "availability_zone_index": None,  # TODO
            "availability_zone_list": None,  # TODO
        }

        return extra_dict

    @staticmethod
    def _process_affinity_group_params(
        target_affinity_group: Dict[str, Any],
        indata: Dict[str, Any],
        vim_info: Dict[str, Any],
        target_record_id: str,
        **kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Get affinity or anti-affinity group parameters.

        Args:
            target_affinity_group (Dict[str, Any]): [description]
            indata (Dict[str, Any]): [description]
            vim_info (Dict[str, Any]): [description]
            target_record_id (str): [description]

        Returns:
            Dict[str, Any]: [description]
        """

        extra_dict = {}
        affinity_group_data = {
            "name": target_affinity_group["name"],
            "type": target_affinity_group["type"],
            "scope": target_affinity_group["scope"],
        }

        if target_affinity_group.get("vim-affinity-group-id"):
            affinity_group_data["vim-affinity-group-id"] = target_affinity_group[
                "vim-affinity-group-id"
            ]

        extra_dict["params"] = {
            "affinity_group_data": affinity_group_data,
        }

        return extra_dict

    @staticmethod
    def _process_recreate_vdu_params(
        existing_vdu: Dict[str, Any],
        db_nsr: Dict[str, Any],
        vim_info: Dict[str, Any],
        target_record_id: str,
        target_id: str,
        **kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Function to process VDU parameters to recreate.

        Args:
            existing_vdu (Dict[str, Any]): [description]
            db_nsr (Dict[str, Any]): [description]
            vim_info (Dict[str, Any]): [description]
            target_record_id (str): [description]
            target_id (str): [description]

        Returns:
            Dict[str, Any]: [description]
        """
        vnfr = kwargs.get("vnfr")
        vdu2cloud_init = kwargs.get("vdu2cloud_init")
        # logger = kwargs.get("logger")
        db = kwargs.get("db")
        fs = kwargs.get("fs")
        ro_nsr_public_key = kwargs.get("ro_nsr_public_key")

        extra_dict = {}
        net_list = []

        vim_details = {}
        vim_details_text = existing_vdu["vim_info"][target_id].get("vim_details", None)
        if vim_details_text:
            vim_details = yaml.safe_load(f"{vim_details_text}")

        for iface_index, interface in enumerate(existing_vdu["interfaces"]):

            if "port-security-enabled" in interface:
                interface["port_security"] = interface.pop("port-security-enabled")

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
            existing_ifaces = existing_vdu["vim_info"][target_id].get("interfaces", [])
            net_id = next(
                (
                    i["vim_net_id"]
                    for i in existing_ifaces
                    if i["ip_address"] == interface["ip-address"]
                ),
                None,
            )

            net_item["net_id"] = net_id
            net_item["type"] = "virtual"

            # TODO mac_address: used for  SR-IOV ifaces #TODO for other types
            # TODO floating_ip: True/False (or it can be None)
            if interface.get("type") in ("SR-IOV", "PCI-PASSTHROUGH"):
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

        if existing_vdu.get("cloud-init"):
            if existing_vdu["cloud-init"] not in vdu2cloud_init:
                vdu2cloud_init[existing_vdu["cloud-init"]] = Ns._get_cloud_init(
                    db=db,
                    fs=fs,
                    location=existing_vdu["cloud-init"],
                )

            cloud_content_ = vdu2cloud_init[existing_vdu["cloud-init"]]
            cloud_config["user-data"] = Ns._parse_jinja2(
                cloud_init_content=cloud_content_,
                params=existing_vdu.get("additionalParams"),
                context=existing_vdu["cloud-init"],
            )

        if existing_vdu.get("boot-data-drive"):
            cloud_config["boot-data-drive"] = existing_vdu.get("boot-data-drive")

        ssh_keys = []

        if existing_vdu.get("ssh-keys"):
            ssh_keys += existing_vdu.get("ssh-keys")

        if existing_vdu.get("ssh-access-required"):
            ssh_keys.append(ro_nsr_public_key)

        if ssh_keys:
            cloud_config["key-pairs"] = ssh_keys

        disk_list = []
        for vol_id in vim_details.get("os-extended-volumes:volumes_attached", []):
            disk_list.append({"vim_id": vol_id["id"]})

        affinity_group_list = []

        if existing_vdu.get("affinity-or-anti-affinity-group-id"):
            affinity_group = {}
            for affinity_group_id in existing_vdu["affinity-or-anti-affinity-group-id"]:
                for group in db_nsr.get("affinity-or-anti-affinity-group"):
                    if (
                        group["id"] == affinity_group_id
                        and group["vim_info"][target_id].get("vim_id", None) is not None
                    ):
                        affinity_group["affinity_group_id"] = group["vim_info"][
                            target_id
                        ].get("vim_id", None)
                        affinity_group_list.append(affinity_group)

        extra_dict["params"] = {
            "name": "{}-{}-{}-{}".format(
                db_nsr["name"][:16],
                vnfr["member-vnf-index-ref"][:16],
                existing_vdu["vdu-name"][:32],
                existing_vdu.get("count-index") or 0,
            ),
            "description": existing_vdu["vdu-name"],
            "start": True,
            "image_id": vim_details["image"]["id"],
            "flavor_id": vim_details["flavor"]["id"],
            "affinity_group_list": affinity_group_list,
            "net_list": net_list,
            "cloud_config": cloud_config or None,
            "disk_list": disk_list,
            "availability_zone_index": None,  # TODO
            "availability_zone_list": None,  # TODO
        }

        return extra_dict

    def calculate_diff_items(
        self,
        indata,
        db_nsr,
        db_ro_nsr,
        db_nsr_update,
        item,
        tasks_by_target_record_id,
        action_id,
        nsr_id,
        task_index,
        vnfr_id=None,
        vnfr=None,
    ):
        """Function that returns the incremental changes (creation, deletion)
        related to a specific item `item` to be done. This function should be
        called for NS instantiation, NS termination, NS update to add a new VNF
        or a new VLD, remove a VNF or VLD, etc.
        Item can be `net`, `flavor`, `image` or `vdu`.
        It takes a list of target items from indata (which came from the REST API)
        and compares with the existing items from db_ro_nsr, identifying the
        incremental changes to be done. During the comparison, it calls the method
        `process_params` (which was passed as parameter, and is particular for each
        `item`)

        Args:
            indata (Dict[str, Any]): deployment info
            db_nsr: NSR record from DB
            db_ro_nsr (Dict[str, Any]): record from "ro_nsrs"
            db_nsr_update (Dict[str, Any]): NSR info to update in DB
            item (str): element to process (net, vdu...)
            tasks_by_target_record_id (Dict[str, Any]):
                [<target_record_id>, <task>]
            action_id (str): action id
            nsr_id (str): NSR id
            task_index (number): task index to add to task name
            vnfr_id (str): VNFR id
            vnfr (Dict[str, Any]): VNFR info

        Returns:
            List: list with the incremental changes (deletes, creates) for each item
            number: current task index
        """

        diff_items = []
        db_path = ""
        db_record = ""
        target_list = []
        existing_list = []
        process_params = None
        vdu2cloud_init = indata.get("cloud_init_content") or {}
        ro_nsr_public_key = db_ro_nsr["public_key"]

        # According to the type of item, the path, the target_list,
        # the existing_list and the method to process params are set
        db_path = self.db_path_map[item]
        process_params = self.process_params_function_map[item]
        if item in ("net", "vdu"):
            # This case is specific for the NS VLD (not applied to VDU)
            if vnfr is None:
                db_record = "nsrs:{}:{}".format(nsr_id, db_path)
                target_list = indata.get("ns", []).get(db_path, [])
                existing_list = db_nsr.get(db_path, [])
            # This case is common for VNF VLDs and VNF VDUs
            else:
                db_record = "vnfrs:{}:{}".format(vnfr_id, db_path)
                target_vnf = next(
                    (vnf for vnf in indata.get("vnf", ()) if vnf["_id"] == vnfr_id),
                    None,
                )
                target_list = target_vnf.get(db_path, []) if target_vnf else []
                existing_list = vnfr.get(db_path, [])
        elif item in ("image", "flavor", "affinity-or-anti-affinity-group"):
            db_record = "nsrs:{}:{}".format(nsr_id, db_path)
            target_list = indata.get(item, [])
            existing_list = db_nsr.get(item, [])
        else:
            raise NsException("Item not supported: {}", item)

        # ensure all the target_list elements has an "id". If not assign the index as id
        if target_list is None:
            target_list = []
        for target_index, tl in enumerate(target_list):
            if tl and not tl.get("id"):
                tl["id"] = str(target_index)

        # step 1 items (networks,vdus,...) to be deleted/updated
        for item_index, existing_item in enumerate(existing_list):
            target_item = next(
                (t for t in target_list if t["id"] == existing_item["id"]),
                None,
            )

            for target_vim, existing_viminfo in existing_item.get(
                "vim_info", {}
            ).items():
                if existing_viminfo is None:
                    continue

                if target_item:
                    target_viminfo = target_item.get("vim_info", {}).get(target_vim)
                else:
                    target_viminfo = None

                if target_viminfo is None:
                    # must be deleted
                    self._assign_vim(target_vim)
                    target_record_id = "{}.{}".format(db_record, existing_item["id"])
                    item_ = item

                    if target_vim.startswith("sdn"):
                        # item must be sdn-net instead of net if target_vim is a sdn
                        item_ = "sdn_net"
                        target_record_id += ".sdn"

                    deployment_info = {
                        "action_id": action_id,
                        "nsr_id": nsr_id,
                        "task_index": task_index,
                    }

                    diff_items.append(
                        {
                            "deployment_info": deployment_info,
                            "target_id": target_vim,
                            "item": item_,
                            "action": "DELETE",
                            "target_record": f"{db_record}.{item_index}.vim_info.{target_vim}",
                            "target_record_id": target_record_id,
                        }
                    )
                    task_index += 1

        # step 2 items (networks,vdus,...) to be created
        for target_item in target_list:
            item_index = -1

            for item_index, existing_item in enumerate(existing_list):
                if existing_item["id"] == target_item["id"]:
                    break
            else:
                item_index += 1
                db_nsr_update[db_path + ".{}".format(item_index)] = target_item
                existing_list.append(target_item)
                existing_item = None

            for target_vim, target_viminfo in target_item.get("vim_info", {}).items():
                existing_viminfo = None

                if existing_item:
                    existing_viminfo = existing_item.get("vim_info", {}).get(target_vim)

                if existing_viminfo is not None:
                    continue

                target_record_id = "{}.{}".format(db_record, target_item["id"])
                item_ = item

                if target_vim.startswith("sdn"):
                    # item must be sdn-net instead of net if target_vim is a sdn
                    item_ = "sdn_net"
                    target_record_id += ".sdn"

                kwargs = {}
                self.logger.warning(
                    "ns.calculate_diff_items target_item={}".format(target_item)
                )
                if process_params == Ns._process_vdu_params:
                    self.logger.warning(
                        "calculate_diff_items self.fs={}".format(self.fs)
                    )
                    kwargs.update(
                        {
                            "vnfr_id": vnfr_id,
                            "nsr_id": nsr_id,
                            "vnfr": vnfr,
                            "vdu2cloud_init": vdu2cloud_init,
                            "tasks_by_target_record_id": tasks_by_target_record_id,
                            "logger": self.logger,
                            "db": self.db,
                            "fs": self.fs,
                            "ro_nsr_public_key": ro_nsr_public_key,
                        }
                    )
                    self.logger.warning("calculate_diff_items kwargs={}".format(kwargs))

                extra_dict = process_params(
                    target_item,
                    indata,
                    target_viminfo,
                    target_record_id,
                    **kwargs,
                )
                self._assign_vim(target_vim)

                deployment_info = {
                    "action_id": action_id,
                    "nsr_id": nsr_id,
                    "task_index": task_index,
                }

                new_item = {
                    "deployment_info": deployment_info,
                    "target_id": target_vim,
                    "item": item_,
                    "action": "CREATE",
                    "target_record": f"{db_record}.{item_index}.vim_info.{target_vim}",
                    "target_record_id": target_record_id,
                    "extra_dict": extra_dict,
                    "common_id": target_item.get("common_id", None),
                }
                diff_items.append(new_item)
                tasks_by_target_record_id[target_record_id] = new_item
                task_index += 1

                db_nsr_update[db_path + ".{}".format(item_index)] = target_item

        return diff_items, task_index

    def calculate_all_differences_to_deploy(
        self,
        indata,
        nsr_id,
        db_nsr,
        db_vnfrs,
        db_ro_nsr,
        db_nsr_update,
        db_vnfrs_update,
        action_id,
        tasks_by_target_record_id,
    ):
        """This method calculates the ordered list of items (`changes_list`)
        to be created and deleted.

        Args:
            indata (Dict[str, Any]): deployment info
            nsr_id (str): NSR id
            db_nsr: NSR record from DB
            db_vnfrs: VNFRS record from DB
            db_ro_nsr (Dict[str, Any]): record from "ro_nsrs"
            db_nsr_update (Dict[str, Any]): NSR info to update in DB
            db_vnfrs_update (Dict[str, Any]): VNFRS info to update in DB
            action_id (str): action id
            tasks_by_target_record_id (Dict[str, Any]):
                [<target_record_id>, <task>]

        Returns:
            List: ordered list of items to be created and deleted.
        """

        task_index = 0
        # set list with diffs:
        changes_list = []

        # NS vld, image and flavor
        for item in ["net", "image", "flavor", "affinity-or-anti-affinity-group"]:
            self.logger.debug("process NS={} {}".format(nsr_id, item))
            diff_items, task_index = self.calculate_diff_items(
                indata=indata,
                db_nsr=db_nsr,
                db_ro_nsr=db_ro_nsr,
                db_nsr_update=db_nsr_update,
                item=item,
                tasks_by_target_record_id=tasks_by_target_record_id,
                action_id=action_id,
                nsr_id=nsr_id,
                task_index=task_index,
                vnfr_id=None,
            )
            changes_list += diff_items

        # VNF vlds and vdus
        for vnfr_id, vnfr in db_vnfrs.items():
            # vnfr_id need to be set as global variable for among others nested method _process_vdu_params
            for item in ["net", "vdu"]:
                self.logger.debug("process VNF={} {}".format(vnfr_id, item))
                diff_items, task_index = self.calculate_diff_items(
                    indata=indata,
                    db_nsr=db_nsr,
                    db_ro_nsr=db_ro_nsr,
                    db_nsr_update=db_vnfrs_update[vnfr["_id"]],
                    item=item,
                    tasks_by_target_record_id=tasks_by_target_record_id,
                    action_id=action_id,
                    nsr_id=nsr_id,
                    task_index=task_index,
                    vnfr_id=vnfr_id,
                    vnfr=vnfr,
                )
                changes_list += diff_items

        return changes_list

    def define_all_tasks(
        self,
        changes_list,
        db_new_tasks,
        tasks_by_target_record_id,
    ):
        """Function to create all the task structures obtanied from
        the method calculate_all_differences_to_deploy

        Args:
            changes_list (List): ordered list of items to be created or deleted
            db_new_tasks (List): tasks list to be created
            action_id (str): action id
            tasks_by_target_record_id (Dict[str, Any]):
                [<target_record_id>, <task>]

        """

        for change in changes_list:
            task = Ns._create_task(
                deployment_info=change["deployment_info"],
                target_id=change["target_id"],
                item=change["item"],
                action=change["action"],
                target_record=change["target_record"],
                target_record_id=change["target_record_id"],
                extra_dict=change.get("extra_dict", None),
            )

            self.logger.warning("ns.define_all_tasks task={}".format(task))
            tasks_by_target_record_id[change["target_record_id"]] = task
            db_new_tasks.append(task)

            if change.get("common_id"):
                task["common_id"] = change["common_id"]

    def upload_all_tasks(
        self,
        db_new_tasks,
        now,
    ):
        """Function to save all tasks in the common DB

        Args:
            db_new_tasks (List): tasks list to be created
            now (time): current time

        """

        nb_ro_tasks = 0  # for logging

        for db_task in db_new_tasks:
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
                self.logger.debug("Updating database, Creating ro_tasks")
                db_ro_task = Ns._create_ro_task(target_id, db_task)
                nb_ro_tasks += 1
                self.db.create("ro_tasks", db_ro_task)

        self.logger.debug(
            "Created {} ro_tasks; {} tasks - db_new_tasks={}".format(
                nb_ro_tasks, len(db_new_tasks), db_new_tasks
            )
        )

    def upload_recreate_tasks(
        self,
        db_new_tasks,
        now,
    ):
        """Function to save recreate tasks in the common DB

        Args:
            db_new_tasks (List): tasks list to be created
            now (time): current time

        """

        nb_ro_tasks = 0  # for logging

        for db_task in db_new_tasks:
            target_id = db_task.pop("target_id")
            self.logger.warning("target_id={} db_task={}".format(target_id, db_task))

            action = db_task.get("action", None)

            # Create a ro_task
            self.logger.debug("Updating database, Creating ro_tasks")
            db_ro_task = Ns._create_ro_task(target_id, db_task)

            # If DELETE task: the associated created items should be removed
            # (except persistent volumes):
            if action == "DELETE":
                db_ro_task["vim_info"]["created"] = True
                db_ro_task["vim_info"]["created_items"] = db_task.get(
                    "created_items", {}
                )
                db_ro_task["vim_info"]["vim_id"] = db_task.get("vim_id", None)

            nb_ro_tasks += 1
            self.logger.warning("upload_all_tasks db_ro_task={}".format(db_ro_task))
            self.db.create("ro_tasks", db_ro_task)

        self.logger.debug(
            "Created {} ro_tasks; {} tasks - db_new_tasks={}".format(
                nb_ro_tasks, len(db_new_tasks), db_new_tasks
            )
        )

    def _prepare_created_items_for_healing(
        self,
        target_id,
        existing_vdu,
    ):
        # Only ports are considered because created volumes are persistent
        ports_list = {}
        vim_interfaces = existing_vdu["vim_info"][target_id].get("interfaces", [])
        for iface in vim_interfaces:
            ports_list["port:" + iface["vim_interface_id"]] = True

        return ports_list

    def _prepare_persistent_volumes_for_healing(
        self,
        target_id,
        existing_vdu,
    ):
        # The associated volumes of the VM shouldn't be removed
        volumes_list = []
        vim_details = {}
        vim_details_text = existing_vdu["vim_info"][target_id].get("vim_details", None)
        if vim_details_text:
            vim_details = yaml.safe_load(f"{vim_details_text}")

            for vol_id in vim_details.get("os-extended-volumes:volumes_attached", []):
                volumes_list.append(vol_id["id"])

        return volumes_list

    def prepare_changes_to_recreate(
        self,
        indata,
        nsr_id,
        db_nsr,
        db_vnfrs,
        db_ro_nsr,
        action_id,
        tasks_by_target_record_id,
    ):
        """This method will obtain an ordered list of items (`changes_list`)
        to be created and deleted to meet the recreate request.
        """

        self.logger.debug(
            "ns.prepare_changes_to_recreate nsr_id={} indata={}".format(nsr_id, indata)
        )

        task_index = 0
        # set list with diffs:
        changes_list = []
        db_path = self.db_path_map["vdu"]
        target_list = indata.get("healVnfData", {})
        vdu2cloud_init = indata.get("cloud_init_content") or {}
        ro_nsr_public_key = db_ro_nsr["public_key"]

        # Check each VNF of the target
        for target_vnf in target_list:
            # Find this VNF in the list from DB
            vnfr_id = target_vnf.get("vnfInstanceId", None)
            if vnfr_id:
                existing_vnf = db_vnfrs.get(vnfr_id)
                db_record = "vnfrs:{}:{}".format(vnfr_id, db_path)
                # vim_account_id = existing_vnf.get("vim-account-id", "")

            # Check each VDU of this VNF
            for target_vdu in target_vnf["additionalParams"].get("vdu", None):
                vdu_name = target_vdu.get("vdu-id", None)
                # For multi instance VDU count-index is mandatory
                # For single session VDU count-indes is 0
                count_index = target_vdu.get("count-index", 0)
                item_index = 0
                existing_instance = None
                for instance in existing_vnf.get("vdur", None):
                    if (
                        instance["vdu-name"] == vdu_name
                        and instance["count-index"] == count_index
                    ):
                        existing_instance = instance
                        break
                    else:
                        item_index += 1

                target_record_id = "{}.{}".format(db_record, existing_instance["id"])

                # The target VIM is the one already existing in DB to recreate
                for target_vim, target_viminfo in existing_instance.get(
                    "vim_info", {}
                ).items():
                    # step 1 vdu to be deleted
                    self._assign_vim(target_vim)
                    deployment_info = {
                        "action_id": action_id,
                        "nsr_id": nsr_id,
                        "task_index": task_index,
                    }

                    target_record = f"{db_record}.{item_index}.vim_info.{target_vim}"
                    created_items = self._prepare_created_items_for_healing(
                        target_vim, existing_instance
                    )

                    volumes_to_hold = self._prepare_persistent_volumes_for_healing(
                        target_vim, existing_instance
                    )

                    # Specific extra params for recreate tasks:
                    extra_dict = {
                        "created_items": created_items,
                        "vim_id": existing_instance["vim-id"],
                        "volumes_to_hold": volumes_to_hold,
                    }

                    changes_list.append(
                        {
                            "deployment_info": deployment_info,
                            "target_id": target_vim,
                            "item": "vdu",
                            "action": "DELETE",
                            "target_record": target_record,
                            "target_record_id": target_record_id,
                            "extra_dict": extra_dict,
                        }
                    )
                    delete_task_id = f"{action_id}:{task_index}"
                    task_index += 1

                    # step 2 vdu to be created
                    kwargs = {}
                    kwargs.update(
                        {
                            "vnfr_id": vnfr_id,
                            "nsr_id": nsr_id,
                            "vnfr": existing_vnf,
                            "vdu2cloud_init": vdu2cloud_init,
                            "tasks_by_target_record_id": tasks_by_target_record_id,
                            "logger": self.logger,
                            "db": self.db,
                            "fs": self.fs,
                            "ro_nsr_public_key": ro_nsr_public_key,
                        }
                    )

                    extra_dict = self._process_recreate_vdu_params(
                        existing_instance,
                        db_nsr,
                        target_viminfo,
                        target_record_id,
                        target_vim,
                        **kwargs,
                    )

                    # The CREATE task depens on the DELETE task
                    extra_dict["depends_on"] = [delete_task_id]

                    deployment_info = {
                        "action_id": action_id,
                        "nsr_id": nsr_id,
                        "task_index": task_index,
                    }
                    self._assign_vim(target_vim)

                    new_item = {
                        "deployment_info": deployment_info,
                        "target_id": target_vim,
                        "item": "vdu",
                        "action": "CREATE",
                        "target_record": target_record,
                        "target_record_id": target_record_id,
                        "extra_dict": extra_dict,
                    }
                    changes_list.append(new_item)
                    tasks_by_target_record_id[target_record_id] = new_item
                    task_index += 1

        return changes_list

    def recreate(self, session, indata, version, nsr_id, *args, **kwargs):
        self.logger.debug("ns.recreate nsr_id={} indata={}".format(nsr_id, indata))
        # TODO: validate_input(indata, recreate_schema)
        action_id = indata.get("action_id", str(uuid4()))
        # get current deployment
        db_vnfrs = {}  # vnf's info indexed by _id
        step = ""
        logging_text = "Recreate nsr_id={} action_id={} indata={}".format(
            nsr_id, action_id, indata
        )
        self.logger.debug(logging_text + "Enter")

        try:
            step = "Getting ns and vnfr record from db"
            db_nsr = self.db.get_one("nsrs", {"_id": nsr_id})
            db_new_tasks = []
            tasks_by_target_record_id = {}
            # read from db: vnf's of this ns
            step = "Getting vnfrs from db"
            db_vnfrs_list = self.db.get_list("vnfrs", {"nsr-id-ref": nsr_id})
            self.logger.debug("ns.recreate: db_vnfrs_list={}".format(db_vnfrs_list))

            if not db_vnfrs_list:
                raise NsException("Cannot obtain associated VNF for ns")

            for vnfr in db_vnfrs_list:
                db_vnfrs[vnfr["_id"]] = vnfr

            now = time()
            db_ro_nsr = self.db.get_one("ro_nsrs", {"_id": nsr_id}, fail_on_empty=False)
            self.logger.debug("ns.recreate: db_ro_nsr={}".format(db_ro_nsr))

            if not db_ro_nsr:
                db_ro_nsr = self._create_db_ro_nsrs(nsr_id, now)

            with self.write_lock:
                # NS
                step = "process NS elements"
                changes_list = self.prepare_changes_to_recreate(
                    indata=indata,
                    nsr_id=nsr_id,
                    db_nsr=db_nsr,
                    db_vnfrs=db_vnfrs,
                    db_ro_nsr=db_ro_nsr,
                    action_id=action_id,
                    tasks_by_target_record_id=tasks_by_target_record_id,
                )

                self.define_all_tasks(
                    changes_list=changes_list,
                    db_new_tasks=db_new_tasks,
                    tasks_by_target_record_id=tasks_by_target_record_id,
                )

                # Delete all ro_tasks registered for the targets vdurs (target_record)
                # If task of type CREATE exist then vim will try to get info form deleted VMs.
                # So remove all task related to target record.
                ro_tasks = self.db.get_list("ro_tasks", {"tasks.nsr_id": nsr_id})
                for change in changes_list:
                    for ro_task in ro_tasks:
                        for task in ro_task["tasks"]:
                            if task["target_record"] == change["target_record"]:
                                self.db.del_one(
                                    "ro_tasks",
                                    q_filter={
                                        "_id": ro_task["_id"],
                                        "modified_at": ro_task["modified_at"],
                                    },
                                    fail_on_empty=False,
                                )

                step = "Updating database, Appending tasks to ro_tasks"
                self.upload_recreate_tasks(
                    db_new_tasks=db_new_tasks,
                    now=now,
                )

            self.logger.debug(
                logging_text + "Exit. Created {} tasks".format(len(db_new_tasks))
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

    def deploy(self, session, indata, version, nsr_id, *args, **kwargs):
        self.logger.debug("ns.deploy nsr_id={} indata={}".format(nsr_id, indata))
        validate_input(indata, deploy_schema)
        action_id = indata.get("action_id", str(uuid4()))
        task_index = 0
        # get current deployment
        db_nsr_update = {}  # update operation on nsrs
        db_vnfrs_update = {}
        db_vnfrs = {}  # vnf's info indexed by _id
        step = ""
        logging_text = "Task deploy nsr_id={} action_id={} ".format(nsr_id, action_id)
        self.logger.debug(logging_text + "Enter")

        try:
            step = "Getting ns and vnfr record from db"
            db_nsr = self.db.get_one("nsrs", {"_id": nsr_id})
            self.logger.debug("ns.deploy: db_nsr={}".format(db_nsr))
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
            self.logger.debug("ns.deploy db_vnfrs={}".format(db_vnfrs))

            now = time()
            db_ro_nsr = self.db.get_one("ro_nsrs", {"_id": nsr_id}, fail_on_empty=False)

            if not db_ro_nsr:
                db_ro_nsr = self._create_db_ro_nsrs(nsr_id, now)

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

            def _process_action(indata):
                nonlocal db_new_tasks
                nonlocal action_id
                nonlocal nsr_id
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

                            deployment_info = {
                                "action_id": action_id,
                                "nsr_id": nsr_id,
                                "task_index": task_index,
                            }

                            task = Ns._create_task(
                                deployment_info=deployment_info,
                                target_id=target_vim,
                                item="vdu",
                                action="EXEC",
                                target_record=target_record,
                                target_record_id=None,
                                extra_dict=extra_dict,
                            )

                            task_index = deployment_info.get("task_index")

                            db_new_tasks.append(task)

            with self.write_lock:
                if indata.get("action"):
                    _process_action(indata)
                else:
                    # compute network differences
                    # NS
                    step = "process NS elements"
                    changes_list = self.calculate_all_differences_to_deploy(
                        indata=indata,
                        nsr_id=nsr_id,
                        db_nsr=db_nsr,
                        db_vnfrs=db_vnfrs,
                        db_ro_nsr=db_ro_nsr,
                        db_nsr_update=db_nsr_update,
                        db_vnfrs_update=db_vnfrs_update,
                        action_id=action_id,
                        tasks_by_target_record_id=tasks_by_target_record_id,
                    )
                    self.define_all_tasks(
                        changes_list=changes_list,
                        db_new_tasks=db_new_tasks,
                        tasks_by_target_record_id=tasks_by_target_record_id,
                    )

                step = "Updating database, Appending tasks to ro_tasks"
                self.upload_all_tasks(
                    db_new_tasks=db_new_tasks,
                    now=now,
                )

                step = "Updating database, nsrs"
                if db_nsr_update:
                    self.db.set_one("nsrs", {"_id": nsr_id}, db_nsr_update)

                for vnfr_id, db_vnfr_update in db_vnfrs_update.items():
                    if db_vnfr_update:
                        step = "Updating database, vnfrs={}".format(vnfr_id)
                        self.db.set_one("vnfrs", {"_id": vnfr_id}, db_vnfr_update)

            self.logger.debug(
                logging_text + "Exit. Created {} tasks".format(len(db_new_tasks))
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
        self.logger.debug(
            "ns.status version={} nsr_id={}, action_id={} indata={}".format(
                version, nsr_id, action_id, indata
            )
        )
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
                            ro_task["vim_info"].get("vim_message") or "unknown",
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

    def recreate_status(
        self, session, indata, version, nsr_id, action_id, *args, **kwargs
    ):
        return self.status(session, indata, version, nsr_id, action_id, *args, **kwargs)

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

    def migrate_task(
        self, vdu, vnf, vdu_index, action_id, nsr_id, task_index, extra_dict
    ):
        target_vim, vim_info = next(k_v for k_v in vdu["vim_info"].items())
        self._assign_vim(target_vim)
        target_record = "vnfrs:{}:vdur.{}".format(vnf["_id"], vdu_index)
        target_record_id = "vnfrs:{}:vdur.{}".format(vnf["_id"], vdu["id"])
        deployment_info = {
            "action_id": action_id,
            "nsr_id": nsr_id,
            "task_index": task_index,
        }

        task = Ns._create_task(
            deployment_info=deployment_info,
            target_id=target_vim,
            item="migrate",
            action="EXEC",
            target_record=target_record,
            target_record_id=target_record_id,
            extra_dict=extra_dict,
        )

        return task

    def migrate(self, session, indata, version, nsr_id, *args, **kwargs):
        task_index = 0
        extra_dict = {}
        now = time()
        action_id = indata.get("action_id", str(uuid4()))
        step = ""
        logging_text = "Task deploy nsr_id={} action_id={} ".format(nsr_id, action_id)
        self.logger.debug(logging_text + "Enter")
        try:
            vnf_instance_id = indata["vnfInstanceId"]
            step = "Getting vnfrs from db"
            db_vnfr = self.db.get_one("vnfrs", {"_id": vnf_instance_id})
            vdu = indata.get("vdu")
            migrateToHost = indata.get("migrateToHost")
            db_new_tasks = []

            with self.write_lock:
                if vdu is not None:
                    vdu_id = indata["vdu"]["vduId"]
                    vdu_count_index = indata["vdu"].get("vduCountIndex", 0)
                    for vdu_index, vdu in enumerate(db_vnfr["vdur"]):
                        if (
                            vdu["vdu-id-ref"] == vdu_id
                            and vdu["count-index"] == vdu_count_index
                        ):
                            extra_dict["params"] = {
                                "vim_vm_id": vdu["vim-id"],
                                "migrate_host": migrateToHost,
                                "vdu_vim_info": vdu["vim_info"],
                            }
                            step = "Creating migration task for vdu:{}".format(vdu)
                            task = self.migrate_task(
                                vdu,
                                db_vnfr,
                                vdu_index,
                                action_id,
                                nsr_id,
                                task_index,
                                extra_dict,
                            )
                            db_new_tasks.append(task)
                            task_index += 1
                            break
                else:

                    for vdu_index, vdu in enumerate(db_vnfr["vdur"]):
                        extra_dict["params"] = {
                            "vim_vm_id": vdu["vim-id"],
                            "migrate_host": migrateToHost,
                            "vdu_vim_info": vdu["vim_info"],
                        }
                        step = "Creating migration task for vdu:{}".format(vdu)
                        task = self.migrate_task(
                            vdu,
                            db_vnfr,
                            vdu_index,
                            action_id,
                            nsr_id,
                            task_index,
                            extra_dict,
                        )
                        db_new_tasks.append(task)
                        task_index += 1

                self.upload_all_tasks(
                    db_new_tasks=db_new_tasks,
                    now=now,
                )

            self.logger.debug(
                logging_text + "Exit. Created {} tasks".format(len(db_new_tasks))
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
