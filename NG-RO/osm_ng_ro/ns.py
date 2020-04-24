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

import logging
# import yaml
from traceback import format_exc as traceback_format_exc
from osm_ng_ro.ns_thread import NsWorker
from osm_ng_ro.validation import validate_input, deploy_schema
from osm_common import dbmongo, dbmemory, fslocal, fsmongo, msglocal, msgkafka, version as common_version
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from http import HTTPStatus
from uuid import uuid4
from threading import Lock
from random import choice as random_choice
from time import time
from jinja2 import Environment, Template, meta, TemplateError, TemplateNotFound, TemplateSyntaxError
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
        self.logger = logging.getLogger("ro.ns")
        self.map_topic = {}
        self.write_lock = None
        self.assignment = {}
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
        # check right version of common
        if versiontuple(common_version) < versiontuple(min_common_version):
            raise NsException("Not compatible osm/common version '{}'. Needed '{}' or higher".format(
                common_version, min_common_version))

        try:
            if not self.db:
                if config["database"]["driver"] == "mongo":
                    self.db = dbmongo.DbMongo()
                    self.db.db_connect(config["database"])
                elif config["database"]["driver"] == "memory":
                    self.db = dbmemory.DbMemory()
                    self.db.db_connect(config["database"])
                else:
                    raise NsException("Invalid configuration param '{}' at '[database]':'driver'".format(
                        config["database"]["driver"]))
            if not self.fs:
                if config["storage"]["driver"] == "local":
                    self.fs = fslocal.FsLocal()
                    self.fs.fs_connect(config["storage"])
                elif config["storage"]["driver"] == "mongo":
                    self.fs = fsmongo.FsMongo()
                    self.fs.fs_connect(config["storage"])
                else:
                    raise NsException("Invalid configuration param '{}' at '[storage]':'driver'".format(
                        config["storage"]["driver"]))
            if not self.msg:
                if config["message"]["driver"] == "local":
                    self.msg = msglocal.MsgLocal()
                    self.msg.connect(config["message"])
                elif config["message"]["driver"] == "kafka":
                    self.msg = msgkafka.MsgKafka()
                    self.msg.connect(config["message"])
                else:
                    raise NsException("Invalid configuration param '{}' at '[message]':'driver'".format(
                        config["message"]["driver"]))

            # TODO load workers to deal with exising database tasks

            self.write_lock = Lock()
        except (DbException, FsException, MsgException) as e:
            raise NsException(str(e), http_code=e.http_code)

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

    def _create_worker(self, vim_account_id):
        # TODO make use of the limit self.config["global"]["server.ns_threads"]
        worker_id = next((i for i in range(len(self.workers)) if not self.workers[i].is_alive()), None)
        if worker_id is None:
            worker_id = len(self.workers)
            self.workers.append(NsWorker(worker_id, self.config, self.plugins, self.db))
            self.workers[worker_id].start()
        self.workers[worker_id].insert_task(("load_vim", vim_account_id))
        return worker_id

    def _assign_vim(self, vim_account_id):
        if vim_account_id not in self.assignment:
            self.assignment[vim_account_id] = self._create_worker(vim_account_id)

    def _get_cloud_init(self, where):
        """

        :param where: can be 'vnfr_id:file:file_name' or 'vnfr_id:vdu:vdu_idex'
        :return:
        """
        vnfd_id, _, other = where.partition(":")
        _type, _, name = other.partition(":")
        vnfd = self.db.get_one("vnfds", {"_id": vnfd_id})
        if _type == "file":
            base_folder = vnfd["_admin"]["storage"]
            cloud_init_file = "{}/{}/cloud_init/{}".format(base_folder["folder"], base_folder["pkg-dir"], name)
            with self.fs.file_open(cloud_init_file, "r") as ci_file:
                cloud_init_content = ci_file.read()
        elif _type == "vdu":
            cloud_init_content = vnfd["vdu"][int(name)]["cloud-init"]
        else:
            raise NsException("Mismatch descriptor for cloud init: {}".format(where))
        return cloud_init_content

    def _parse_jinja2(self, cloud_init_content, params, context):
        try:
            env = Environment()
            ast = env.parse(cloud_init_content)
            mandatory_vars = meta.find_undeclared_variables(ast)
            if mandatory_vars:
                for var in mandatory_vars:
                    if not params or var not in params:
                        raise NsException(
                            "Variable '{}' defined at vnfd='{}' must be provided in the instantiation parameters"
                            "inside the 'additionalParamsForVnf' block".format(var, context))
            template = Template(cloud_init_content)
            return template.render(params or {})

        except (TemplateError, TemplateNotFound, TemplateSyntaxError) as e:
            raise NsException("Error parsing Jinja2 to cloud-init content at vnfd='{}': {}".format(context, e))

    def _create_db_ro_nsrs(self, nsr_id, now):
        try:
            key = rsa.generate_private_key(
                backend=crypto_default_backend(),
                public_exponent=65537,
                key_size=2048
            )
            private_key = key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption())
            public_key = key.public_key().public_bytes(
                crypto_serialization.Encoding.OpenSSH,
                crypto_serialization.PublicFormat.OpenSSH
            )
            private_key = private_key.decode('utf8')
            public_key = public_key.decode('utf8')
        except Exception as e:
            raise NsException("Cannot create ssh-keys: {}".format(e))

        schema_version = "1.1"
        private_key_encrypted = self.db.encrypt(private_key, schema_version=schema_version, salt=nsr_id)
        db_content = {
            "_id": nsr_id,
            "_admin": {
                "created": now,
                "modified": now,
                "schema_version": schema_version
            },
            "public_key": public_key,
            "private_key": private_key_encrypted,
            "actions": [],
        }
        self.db.create("ro_nsrs", db_content)
        return db_content

    def deploy(self, session, indata, version, nsr_id, *args, **kwargs):
        print("ns.deploy session={} indata={} version={} nsr_id={}".format(session, indata, version, nsr_id))
        validate_input(indata, deploy_schema)
        action_id = indata.get("action_id", str(uuid4()))
        task_index = 0
        # get current deployment
        db_nsr = None
        # db_nslcmop = None
        db_nsr_update = {}        # update operation on nsrs
        db_vnfrs_update = {}
        # db_nslcmop_update = {}        # update operation on nslcmops
        db_vnfrs = {}     # vnf's info indexed by _id
        vdu2cloud_init = {}
        step = ''
        logging_text = "Task deploy nsr_id={} action_id={} ".format(nsr_id, action_id)
        self.logger.debug(logging_text + "Enter")
        try:
            step = "Getting ns and vnfr record from db"
            # db_nslcmop = self.db.get_one("nslcmops", {"_id": nslcmop_id})
            db_nsr = self.db.get_one("nsrs", {"_id": nsr_id})
            db_ro_tasks = []
            db_new_tasks = []
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
                        self.logger.debug(logging_text + "Changing action_id in use to {}".format(action_id))
                        break
                    index += 1

            def _create_task(item, action, target_record, target_record_id, extra_dict=None):
                nonlocal task_index
                nonlocal action_id
                nonlocal nsr_id

                task = {
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
                    task.update(extra_dict)   # params, find_params, depends_on
                task_index += 1
                return task

            def _create_ro_task(vim_account_id, item, action, target_record, target_record_id, extra_dict=None):
                nonlocal action_id
                nonlocal task_index
                nonlocal now

                _id = action_id + ":" + str(task_index)
                db_ro_task = {
                    "_id": _id,
                    "locked_by": None,
                    "locked_at": 0.0,
                    "target_id": "vim:" + vim_account_id,
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
                    "tasks": [_create_task(item, action, target_record, target_record_id, extra_dict)],
                }
                return db_ro_task

            def _process_image_params(target_image, vim_info):
                find_params = {}
                if target_image.get("image"):
                    find_params["filter_dict"] = {"name": target_image.get("image")}
                if target_image.get("vim_image_id"):
                    find_params["filter_dict"] = {"id": target_image.get("vim_image_id")}
                if target_image.get("image_checksum"):
                    find_params["filter_dict"] = {"checksum": target_image.get("image_checksum")}
                return {"find_params": find_params}

            def _process_flavor_params(target_flavor, vim_info):

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
                    # "ram": max(int(target_flavor["memory-mb"]) // 1024, 1),
                    # ^ TODO manage at vim_connectors MB instead of GB
                    "ram": int(target_flavor["memory-mb"]),
                    "vcpus": target_flavor["vcpu-count"],
                }
                if target_flavor.get("guest-epa"):
                    extended = {}
                    numa = {}
                    epa_vcpu_set = False
                    if target_flavor["guest-epa"].get("numa-node-policy"):
                        numa_node_policy = target_flavor["guest-epa"].get("numa-node-policy")
                        if numa_node_policy.get("node"):
                            numa_node = numa_node_policy["node"][0]
                            if numa_node.get("num-cores"):
                                numa["cores"] = numa_node["num-cores"]
                                epa_vcpu_set = True
                            if numa_node.get("paired-threads"):
                                if numa_node["paired-threads"].get("num-paired-threads"):
                                    numa["paired-threads"] = int(numa_node["paired-threads"]["num-paired-threads"])
                                    epa_vcpu_set = True
                                if len(numa_node["paired-threads"].get("paired-thread-ids")):
                                    numa["paired-threads-id"] = []
                                    for pair in numa_node["paired-threads"]["paired-thread-ids"]:
                                        numa["paired-threads-id"].append(
                                            (str(pair["thread-a"]), str(pair["thread-b"]))
                                        )
                            if numa_node.get("num-threads"):
                                numa["threads"] = int(numa_node["num-threads"])
                                epa_vcpu_set = True
                            if numa_node.get("memory-mb"):
                                numa["memory"] = max(int(numa_node["memory-mb"] / 1024), 1)
                    if target_flavor["guest-epa"].get("mempage-size"):
                        extended["mempage-size"] = target_flavor["guest-epa"].get("mempage-size")
                    if target_flavor["guest-epa"].get("cpu-pinning-policy") and not epa_vcpu_set:
                        if target_flavor["guest-epa"]["cpu-pinning-policy"] == "DEDICATED":
                            if target_flavor["guest-epa"].get("cpu-thread-pinning-policy") and \
                                    target_flavor["guest-epa"]["cpu-thread-pinning-policy"] != "PREFER":
                                numa["cores"] = max(flavor_data["vcpus"], 1)
                            else:
                                numa["threads"] = max(flavor_data["vcpus"], 1)
                            epa_vcpu_set = True
                    if target_flavor["guest-epa"].get("cpu-quota") and not epa_vcpu_set:
                        cpuquota = _get_resource_allocation_params(target_flavor["guest-epa"].get("cpu-quota"))
                        if cpuquota:
                            extended["cpu-quota"] = cpuquota
                    if target_flavor["guest-epa"].get("mem-quota"):
                        vduquota = _get_resource_allocation_params(target_flavor["guest-epa"].get("mem-quota"))
                        if vduquota:
                            extended["mem-quota"] = vduquota
                    if target_flavor["guest-epa"].get("disk-io-quota"):
                        diskioquota = _get_resource_allocation_params(target_flavor["guest-epa"].get("disk-io-quota"))
                        if diskioquota:
                            extended["disk-io-quota"] = diskioquota
                    if target_flavor["guest-epa"].get("vif-quota"):
                        vifquota = _get_resource_allocation_params(target_flavor["guest-epa"].get("vif-quota"))
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

            def _process_net_params(target_vld, vim_info):
                nonlocal indata
                extra_dict = {}
                if vim_info.get("vim_network_name"):
                    extra_dict["find_params"] = {"filter_dict": {"name": vim_info.get("vim_network_name")}}
                elif vim_info.get("vim_network_id"):
                    extra_dict["find_params"] = {"filter_dict": {"id": vim_info.get("vim_network_id")}}
                elif target_vld.get("mgmt-network"):
                    extra_dict["find_params"] = {"mgmt": True, "name": target_vld["id"]}
                else:
                    # create
                    extra_dict["params"] = {
                        "net_name": "{}-{}".format(indata["name"][:16], target_vld.get("name", target_vld["id"])[:16]),
                        "ip_profile": vim_info.get('ip_profile'),
                        "provider_network_profile": vim_info.get('provider_network'),
                    }
                    if not target_vld.get("underlay"):
                        extra_dict["params"]["net_type"] = "bridge"
                    else:
                        extra_dict["params"]["net_type"] = "ptp" if target_vld.get("type") == "ELINE" else "data"
                return extra_dict

            def _process_vdu_params(target_vdu, vim_info):
                nonlocal vnfr_id
                nonlocal nsr_id
                nonlocal indata
                nonlocal vnfr
                nonlocal vdu2cloud_init
                vnf_preffix = "vnfrs:{}".format(vnfr_id)
                ns_preffix = "nsrs:{}".format(nsr_id)
                image_text = ns_preffix + ":image." + target_vdu["ns-image-id"]
                flavor_text = ns_preffix + ":flavor." + target_vdu["ns-flavor-id"]
                extra_dict = {"depends_on": [image_text, flavor_text]}
                net_list = []
                for iface_index, interface in enumerate(target_vdu["interfaces"]):
                    if interface.get("ns-vld-id"):
                        net_text = ns_preffix + ":vld." + interface["ns-vld-id"]
                    else:
                        net_text = vnf_preffix + ":vld." + interface["vnf-vld-id"]
                    extra_dict["depends_on"].append(net_text)
                    net_item = {
                        "name": interface["name"],
                        "net_id": "TASK-" + net_text,
                        "vpci": interface.get("vpci"),
                        "type": "virtual",
                        # TODO mac_address: used for  SR-IOV ifaces #TODO for other types
                        # TODO floating_ip: True/False (or it can be None)
                    }
                    if interface.get("type") in ("SR-IOV", "PCI-PASSTHROUGH"):
                        net_item["use"] = "data"
                        net_item["model"] = interface["type"]
                        net_item["type"] = interface["type"]
                    elif interface.get("type") == "OM-MGMT" or interface.get("mgmt-interface") or \
                            interface.get("mgmt-vnf"):
                        net_item["use"] = "mgmt"
                    else:   # if interface.get("type") in ("VIRTIO", "E1000", "PARAVIRT"):
                        net_item["use"] = "bridge"
                        net_item["model"] = interface.get("type")
                    net_list.append(net_item)
                    if interface.get("mgmt-vnf"):
                        extra_dict["mgmt_vnf_interface"] = iface_index
                    elif interface.get("mgmt-interface"):
                        extra_dict["mgmt_vdu_interface"] = iface_index

                # cloud config
                cloud_config = {}
                if target_vdu.get("cloud-init"):
                    if target_vdu["cloud-init"] not in vdu2cloud_init:
                        vdu2cloud_init[target_vdu["cloud-init"]] = self._get_cloud_init(target_vdu["cloud-init"])
                    cloud_content_ = vdu2cloud_init[target_vdu["cloud-init"]]
                    cloud_config["user-data"] = self._parse_jinja2(cloud_content_, target_vdu.get("additionalParams"),
                                                                   target_vdu["cloud-init"])
                if target_vdu.get("boot-data-drive"):
                    cloud_config["boot-data-drive"] = target_vdu.get("boot-data-drive")
                ssh_keys = []
                if target_vdu.get("ssh-keys"):
                    ssh_keys += target_vdu.get("ssh-keys")
                if target_vdu.get("ssh-access-required"):
                    ssh_keys.append(ro_nsr_public_key)
                if ssh_keys:
                    cloud_config["key-pairs"] = ssh_keys

                extra_dict["params"] = {
                    "name": "{}-{}-{}-{}".format(indata["name"][:16], vnfr["member-vnf-index-ref"][:16],
                                                 target_vdu["vdu-name"][:32], target_vdu.get("count-index") or 0),
                    "description": target_vdu["vdu-name"],
                    "start": True,
                    "image_id": "TASK-" + image_text,
                    "flavor_id": "TASK-" + flavor_text,
                    "net_list": net_list,
                    "cloud_config": cloud_config or None,
                    "disk_list": None,  # TODO
                    "availability_zone_index": None,  # TODO
                    "availability_zone_list": None,  # TODO
                }
                return extra_dict

            def _process_items(target_list, existing_list, db_record, db_update, db_path, item, process_params):
                nonlocal db_ro_tasks
                nonlocal db_new_tasks
                nonlocal task_index

                # ensure all the target_list elements has an "id". If not assign the index
                for target_index, tl in enumerate(target_list):
                    if tl and not tl.get("id"):
                        tl["id"] = str(target_index)

                # step 1 networks to be deleted/updated
                for vld_index, existing_vld in enumerate(existing_list):
                    target_vld = next((vld for vld in target_list if vld["id"] == existing_vld["id"]), None)
                    for existing_vim_index, existing_vim_info in enumerate(existing_vld.get("vim_info", ())):
                        if not existing_vim_info:
                            continue
                        if target_vld:
                            target_viminfo = next((target_viminfo for target_viminfo in target_vld.get("vim_info", ())
                                                   if existing_vim_info["vim_account_id"] == target_viminfo[
                                                       "vim_account_id"]), None)
                        else:
                            target_viminfo = None
                        if not target_viminfo:
                            # must be deleted
                            self._assign_vim(existing_vim_info["vim_account_id"])
                            db_new_tasks.append(_create_task(
                                item, "DELETE",
                                target_record="{}.{}.vim_info.{}".format(db_record, vld_index, existing_vim_index),
                                target_record_id="{}.{}".format(db_record, existing_vld["id"])))
                            # TODO delete
                    # TODO check one by one the vims to be created/deleted

                # step 2 networks to be created
                for target_vld in target_list:
                    vld_index = -1
                    for vld_index, existing_vld in enumerate(existing_list):
                        if existing_vld["id"] == target_vld["id"]:
                            break
                    else:
                        vld_index += 1
                        db_update[db_path + ".{}".format(vld_index)] = target_vld
                        existing_list.append(target_vld)
                        existing_vld = None

                    for vim_index, vim_info in enumerate(target_vld["vim_info"]):
                        existing_viminfo = None
                        if existing_vld:
                            existing_viminfo = next(
                                (existing_viminfo for existing_viminfo in existing_vld.get("vim_info", ())
                                 if vim_info["vim_account_id"] == existing_viminfo["vim_account_id"]), None)
                        # TODO check if different. Delete and create???
                        # TODO delete if not exist
                        if existing_viminfo:
                            continue

                        extra_dict = process_params(target_vld, vim_info)

                        self._assign_vim(vim_info["vim_account_id"])
                        db_ro_tasks.append(_create_ro_task(
                            vim_info["vim_account_id"], item, "CREATE",
                            target_record="{}.{}.vim_info.{}".format(db_record, vld_index, vim_index),
                            target_record_id="{}.{}".format(db_record, target_vld["id"]),
                            extra_dict=extra_dict))

                        db_update[db_path + ".{}".format(vld_index)] = target_vld

            def _process_action(indata):
                nonlocal db_ro_tasks
                nonlocal db_new_tasks
                nonlocal task_index
                nonlocal db_vnfrs
                nonlocal db_ro_nsr

                if indata["action"] == "inject_ssh_key":
                    key = indata.get("key")
                    user = indata.get("user")
                    password = indata.get("password")
                    for vnf in indata.get("vnf", ()):
                        if vnf.get("_id") not in db_vnfrs:
                            raise NsException("Invalid vnf={}".format(vnf["_id"]))
                        db_vnfr = db_vnfrs[vnf["_id"]]
                        for target_vdu in vnf.get("vdur", ()):
                            vdu_index, vdur = next((i_v for i_v in enumerate(db_vnfr["vdur"]) if
                                                    i_v[1]["id"] == target_vdu["id"]), (None, None))
                            if not vdur:
                                raise NsException("Invalid vdu vnf={}.{}".format(vnf["_id"], target_vdu["id"]))
                            vim_info = vdur["vim_info"][0]
                            self._assign_vim(vim_info["vim_account_id"])
                            target_record = "vnfrs:{}:vdur.{}.ssh_keys".format(vnf["_id"], vdu_index)
                            extra_dict = {
                                "depends_on": ["vnfrs:{}:vdur.{}".format(vnf["_id"], vdur["id"])],
                                "params": {
                                    "ip_address": vdur.gt("ip_address"),
                                    "user": user,
                                    "key": key,
                                    "password": password,
                                    "private_key": db_ro_nsr["private_key"],
                                    "salt": db_ro_nsr["_id"],
                                    "schema_version": db_ro_nsr["_admin"]["schema_version"]
                                }
                            }
                            db_ro_tasks.append(_create_ro_task(vim_info["vim_account_id"], "vdu", "EXEC",
                                                               target_record=target_record,
                                                               target_record_id=None,
                                                               extra_dict=extra_dict))

            with self.write_lock:
                if indata.get("action"):
                    _process_action(indata)
                else:
                    # compute network differences
                    # NS.vld
                    step = "process NS VLDs"
                    _process_items(target_list=indata["ns"]["vld"] or [], existing_list=db_nsr.get("vld") or [],
                                   db_record="nsrs:{}:vld".format(nsr_id), db_update=db_nsr_update,
                                   db_path="vld", item="net", process_params=_process_net_params)

                    step = "process NS images"
                    _process_items(target_list=indata["image"] or [], existing_list=db_nsr.get("image") or [],
                                   db_record="nsrs:{}:image".format(nsr_id),
                                   db_update=db_nsr_update, db_path="image", item="image",
                                   process_params=_process_image_params)

                    step = "process NS flavors"
                    _process_items(target_list=indata["flavor"] or [], existing_list=db_nsr.get("flavor") or [],
                                   db_record="nsrs:{}:flavor".format(nsr_id),
                                   db_update=db_nsr_update, db_path="flavor", item="flavor",
                                   process_params=_process_flavor_params)

                    # VNF.vld
                    for vnfr_id, vnfr in db_vnfrs.items():
                        # vnfr_id need to be set as global variable for among others nested method _process_vdu_params
                        step = "process VNF={} VLDs".format(vnfr_id)
                        target_vnf = next((vnf for vnf in indata.get("vnf", ()) if vnf["_id"] == vnfr_id), None)
                        target_list = target_vnf.get("vld") if target_vnf else None
                        _process_items(target_list=target_list or [], existing_list=vnfr.get("vld") or [],
                                       db_record="vnfrs:{}:vld".format(vnfr_id), db_update=db_vnfrs_update[vnfr["_id"]],
                                       db_path="vld", item="net", process_params=_process_net_params)

                        target_list = target_vnf.get("vdur") if target_vnf else None
                        step = "process VNF={} VDUs".format(vnfr_id)
                        _process_items(target_list=target_list or [], existing_list=vnfr.get("vdur") or [],
                                       db_record="vnfrs:{}:vdur".format(vnfr_id),
                                       db_update=db_vnfrs_update[vnfr["_id"]], db_path="vdur", item="vdu",
                                       process_params=_process_vdu_params)

                step = "Updating database, Creating ro_tasks"
                if db_ro_tasks:
                    self.db.create_list("ro_tasks", db_ro_tasks)
                step = "Updating database, Appending tasks to ro_tasks"
                for task in db_new_tasks:
                    if not self.db.set_one("ro_tasks", q_filter={"tasks.target_record": task["target_record"]},
                                           update_dict={"to_check_at": now, "modified_at": now},
                                           push={"tasks": task}, fail_on_empty=False):
                        self.logger.error(logging_text + "Cannot find task for target_record={}".
                                          format(task["target_record"]))
                    # TODO something else appart from logging?
                step = "Updating database, nsrs"
                if db_nsr_update:
                    self.db.set_one("nsrs", {"_id": nsr_id}, db_nsr_update)
                for vnfr_id, db_vnfr_update in db_vnfrs_update.items():
                    if db_vnfr_update:
                        step = "Updating database, vnfrs={}".format(vnfr_id)
                        self.db.set_one("vnfrs", {"_id": vnfr_id}, db_vnfr_update)

            self.logger.debug(logging_text + "Exit")
            return {"status": "ok", "nsr_id": nsr_id, "action_id": action_id}, action_id, True

        except Exception as e:
            if isinstance(e, (DbException, NsException)):
                self.logger.error(logging_text + "Exit Exception while '{}': {}".format(step, e))
            else:
                e = traceback_format_exc()
                self.logger.critical(logging_text + "Exit Exception while '{}': {}".format(step, e), exc_info=True)
            raise NsException(e)

    def delete(self, session, indata, version, nsr_id, *args, **kwargs):
        print("ns.delete session={} indata={} version={} nsr_id={}".format(session, indata, version, nsr_id))
        # TODO del when ALL "tasks.nsr_id" are None of nsr_id
        # self.db.del_list({"_id": ro_task["_id"], "tasks.nsr_id.ne": nsr_id})
        retries = 5
        for retry in range(retries):
            with self.write_lock:
                ro_tasks = self.db.get_list("ro_tasks", {"tasks.nsr_id": nsr_id})
                if not ro_tasks:
                    break
                now = time()
                conflict = False
                for ro_task in ro_tasks:
                    db_update = {}
                    to_delete = True
                    for index, task in enumerate(ro_task["tasks"]):
                        if not task:
                            pass
                        elif task["nsr_id"] == nsr_id:
                            db_update["tasks.{}".format(index)] = None
                        else:
                            to_delete = False  # used by other nsr, cannot be deleted
                    # delete or update if nobody has changed ro_task meanwhile. Used modified_at for known if changed
                    if to_delete:
                        if not self.db.del_one("ro_tasks",
                                               q_filter={"_id": ro_task["_id"], "modified_at": ro_task["modified_at"]},
                                               fail_on_empty=False):
                            conflict = True
                    elif db_update:
                        db_update["modified_at"] = now
                        if not self.db.set_one("ro_tasks",
                                               q_filter={"_id": ro_task["_id"], "modified_at": ro_task["modified_at"]},
                                               update_dict=db_update,
                                               fail_on_empty=False):
                            conflict = True
                if not conflict:
                    break
        else:
            raise NsException("Exceeded {} retries".format(retries))

        return None, None, True

    def status(self, session, indata, version, nsr_id, action_id, *args, **kwargs):
        print("ns.status session={} indata={} version={} nsr_id={}, action_id={}".format(session, indata, version,
                                                                                         nsr_id, action_id))
        task_list = []
        done = 0
        total = 0
        ro_tasks = self.db.get_list("ro_tasks", {"tasks.action_id": action_id})
        global_status = "DONE"
        details = []
        for ro_task in ro_tasks:
            for task in ro_task["tasks"]:
                if task["action_id"] == action_id:
                    task_list.append(task)
                    total += 1
                    if task["status"] == "FAILED":
                        global_status = "FAILED"
                        details.append(ro_task.get("vim_details", ''))
                    elif task["status"] in ("SCHEDULED", "BUILD"):
                        if global_status != "FAILED":
                            global_status = "BUILD"
                    else:
                        done += 1
        return_data = {
            "status": global_status,
            "details": ". ".join(details) if details else "progress {}/{}".format(done, total),
            "nsr_id": nsr_id,
            "action_id": action_id,
            "tasks": task_list
        }
        return return_data, None, True

    def cancel(self, session, indata, version, nsr_id, action_id, *args, **kwargs):
        print("ns.cancel session={} indata={} version={} nsr_id={}, action_id={}".format(session, indata, version,
                                                                                         nsr_id, action_id))
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
