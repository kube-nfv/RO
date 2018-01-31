#!/usr/bin/python3
# -*- coding: utf-8 -*-


import argparse
import glob
from juju_api import JujuApi
import mimetypes
import os
import os.path
import re
import shutil
import tarfile

import asyncio
import aiohttp
import yaml
import ROclient
import time
import dbmemory
import logging

from copy import deepcopy
from uuid import uuid4

#streamformat = "%(asctime)s %(name)s %(levelname)s: %(message)s"
streamformat = "%(name)s %(levelname)s: %(message)s"
logging.basicConfig(format=streamformat, level=logging.DEBUG)
logger = logging.getLogger('lcm')

ro_account = {
    "url": "http://10.105.129.121:9090/openmano",
    "tenant": "osm",
}

vca_account = {
    "ip": "10.105.129.40",
    "port": 17070,
    "user": "admin",
    "secret": "NzdjM2M4ODA5NjlhNzRkZGJhMzc2NjNk",
}

# These functions are written to use the JujuApi class from juju_api.py, a
# drop-in copy of the one used in OSM today. This will make it easier to extend
# functionality in the LCM as it's added to the Juju API


def GetJujuApi(loop):
    # Quiet logging from the websocket library. If you want to see
    # everything sent over the wire, set this to DEBUG.
    logging.basicConfig(level=logging.DEBUG)

    ws_logger = logging.getLogger('websockets.protocol')
    ws_logger.setLevel(logging.INFO)

    api = JujuApi(server=vca_account['ip'],
                  port=vca_account['port'],
                  user=vca_account['user'],
                  secret=vca_account['secret'],
                  loop=loop,
                  log=ws_logger,
                  model_name='default'
                  )
    return api


def get_vnf_unique_name(nsr_name, vnfr_name, member_vnf_index):
    """Get the unique VNF name.
    Charm names accepts only a to z and non-consecutive - characters."""
    name = "{}-{}-{}".format(nsr_name, vnfr_name, member_vnf_index)
    new_name = ''
    for c in name:
        if c.isdigit():
            c = chr(97 + int(c))
        elif not c.isalpha():
            c = "-"
        new_name += c
    return re.sub('\-+', '-', new_name.lower())


async def DeployApplication(loop, application_name, charm_path, config):
    """
    Deploy a charm.

    Deploy a VNF configuration charm from a local directory.
    :param object loop: The event loop
    :param str application_name: The unique name of this application.
    :param str charm_path: The path to the charm.

    :Example:

    DeployApplication(loop, ".cache/ping_vnf/charm/pingpong", "ping_vnf")
    """

    api = GetJujuApi(loop)

    await api.login()
    if api.authenticated:
        charm = os.path.basename(charm_path)

        await api.deploy_application(charm,
                                     name=application_name,
                                     path=charm_path,
                                     )
        await api.apply_config(config, application_name)

        # Wait for the application to fully deploy. This will block until the
        # agent is in an idle state, and the charm's workload is either
        # 'active' or 'unknown', meaning it's ready but the author did not
        # explicitly set a workload state.
        # print("Waiting for application '{}' to deploy...".format(charm))
        while (True):
            # Deploy the charm and wait, periodically checking its status
            await api.wait_for_application(charm, 30)

            error = await api.is_application_error(charm)
            if error:
                print("This application is in an error state.")
                break

            blocked = await api.is_application_blocked(charm)
            if blocked:
                print("This application is blocked.")
                break

            # An extra check to see if the charm is ready
            up = await api.is_application_up(charm)
            # print("Application is {}".format("up" if up else "down"))

        print("Application {} is deployed".format(args.application))
    await api.logout()


async def RemoveApplication(loop, application_name):
    """
    Remove an application from the Juju Controller

    Removed the named application and it's charm from the Juju controller.

    :param object loop: The event loop.
    :param str application_name: The unique name of the application.

    :Example:

    RemoveApplication(loop, "ping_vnf")
    RemoveApplication(loop, "pong_vnf")
    """
    api = GetJujuApi(loop)

    await api.login()
    if api.authenticated:
        print("Removing application {}".format(application_name))
        await api.remove_application(application_name)
    await api.logout()

# conains created tasks/futures to be able to cancel
lcm_tasks = {}

headers_req = {'Accept': 'application/yaml', 'content-type': 'application/yaml'}
ns_status = ("CREATION-SCHEDULED", "DEPLOYING", "CONFIGURING", "DELETION-SCHEDULED", "UN-CONFIGURING", "UNDEPLOYING")

# TODO replace with database calls
db = dbmemory.dbmemory()


class RO_Exception(Exception):
    pass


async def CreateNS(loop, nsr_id):
    logger.debug("CreateNS task nsr_id={} Enter".format(nsr_id))
    nsr_lcm = {
        "id": nsr_id,
        "RO": {"vnfd_id": {}, "nsd_id": None, "nsr_id": None, "nsr_status": "SCHEDULED"},
        "nsr_ip": {},
        "VCA": {"TODO"},
        "status": "BUILD",
        "status_detailed": "",
    }

    deloyment_timeout = 120
    try:
        ns_request = db.get_one("ns_request", {"id": nsr_id})
        nsd = db.get_one("nsd", {"id": ns_request["nsd_id"]})
        RO = ROclient.ROClient(loop, endpoint_url=ro_account["url"], tenant=ro_account["tenant"],
                               datacenter=ns_request["vim"])
        nsr_lcm["status_detailed"] = "Creating vnfd at RO"
        # ns_request["constituent-vnfr-ref"] = []

        db.create("nsr_lcm", nsr_lcm)

        # get vnfds, instantiate at RO
        logger.debug("CreateNS task nsr_id={} RO VNFD".format(nsr_id))
        for c_vnf in nsd["constituent-vnfd"]:
            vnfd_id = c_vnf["vnfd-id-ref"]
            vnfd = db.get_one("vnfd", {"id": vnfd_id})
            vnfd.pop("_admin", None)
            vnfd.pop("_id", None)
            # vnfr = deepcopy(vnfd)
            # vnfr["member-vnf-index"] = c_vnf["member-vnf-index"]
            # vnfr["nsr-id"] = nsr_id
            # vnfr["id"] = uuid4()
            # vnfr["vnf-id"] = vnfd["id"]
            # ns_request["constituent-vnfr-ref"],append(vnfd_id)

            # TODO change id for RO in case it is present
            try:
                desc = await RO.create("vnfd", descriptor=vnfd)
                nsr_lcm["RO"]["vnfd_id"][vnfd_id] = desc["uuid"]
                db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)
            except ROclient.ROClientException as e:
                if e.http_code == 409:  # conflict, vnfd already present
                    print("debug", e)
                else:
                    raise

            # db_new("vnfr", vnfr)
            # db_update("ns_request", nsr_id, ns_request)

        # create nsd at RO
        logger.debug("CreateNS task nsr_id={} RO NSD".format(nsr_id))
        nsr_lcm["status_detailed"] = "Creating nsd at RO"
        nsd_id = ns_request["nsd_id"]
        nsd = db.get_one("nsd", {"id": nsd_id})
        nsd.pop("_admin", None)
        nsd.pop("_id", None)
        try:
            desc = await RO.create("nsd", descriptor=nsd)
            nsr_lcm["RO"]["nsd_id"] = desc["uuid"]
            db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)
        except ROclient.ROClientException as e:
            if e.http_code == 409:  # conflict, nsd already present
                print("debug", e)
            else:
                raise

        # Crate ns at RO
        logger.debug("CreateNS task nsr_id={} RO NS".format(nsr_id))
        nsr_lcm["status_detailed"] = "Creating ns at RO"
        desc = await RO.create("ns", name=ns_request["name"], datacenter=ns_request["vim"], scenario=nsr_lcm["RO"]["nsd_id"])
        RO_nsr_id = desc["uuid"]
        nsr_lcm["RO"]["nsr_id"] = RO_nsr_id
        nsr_lcm["RO"]["nsr_status"] = "BUILD"
        db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)

        # wait until NS is ready
        deloyment_timeout = 600
        while deloyment_timeout > 0:
            ns_status_detailed = "Waiting ns ready at RO"
            nsr_lcm["status_detailed"] = ns_status_detailed
            desc = await RO.show("ns", RO_nsr_id)
            ns_status, ns_status_info = RO.check_ns_status(desc)
            nsr_lcm["RO"]["nsr_status"] = ns_status
            if ns_status == "ERROR":
                raise ROclient.ROClientException(ns_status_info)
            elif ns_status == "BUILD":
                nsr_lcm["status_detailed"] = ns_status_detailed + "; nsr_id: '{}', {}".format(nsr_id, ns_status_info)
            elif ns_status == "ACTIVE":
                nsr_lcm["nsr_ip"] = RO.get_ns_vnf_ip(desc)
                break
            else:
                assert False, "ROclient.check_ns_status returns unknown {}".format(ns_status)

            await asyncio.sleep(5, loop=loop)
            deloyment_timeout -= 5
        if deloyment_timeout <= 0:
            raise ROclient.ROClientException("Timeot wating ns to be ready")
        nsr_lcm["status_detailed"] = "Configuring vnfr"
        db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)

        #for nsd in nsr_lcm["descriptors"]["nsd"]:

        logger.debug("CreateNS task nsr_id={} VCA look for".format(nsr_id))
        for c_vnf in nsd["constituent-vnfd"]:
            vnfd_id = c_vnf["vnfd-id-ref"]
            vnfd_index = int(c_vnf["member-vnf-index"])
            vnfd = db.get_one("vnfd", {"id": vnfd_id})
            if vnfd.get("vnf-configuration") and vnfd["vnf-configuration"].get("juju"):
                proxy_charm = vnfd["vnf-configuration"]["juju"]["charm"]
                # config_primitive = vnfd["vnf-configuration"].get("config-primitive")
                initial_config_primitive = vnfd["vnf-configuration"].get("initial-config-primitive")
                # get parameters for juju charm
                base_folder = vnfd["_admin"]["storage"]
                path = base_folder + "/charms/" + proxy_charm
                mgmt_ip = nsr_lcm['nsr_ip'][vnfd_index]

                # TODO launch VCA charm
                # task = asyncio.ensure_future(DeployCharm(loop, path, mgmt_ip, config_primitive))
                config = {}
                for primitive in initial_config_primitive:
                    if primitive['name'] == 'config':
                        for parameter in primitive['parameter']:
                            param = parameter['name']
                            if parameter['value'] == "<rw_mgmt_ip>":
                                config[param] = mgmt_ip
                            else:
                                config[param] = parameter['value']

                task = asyncio.ensure_future(
                    DeployApplication(
                        loop,
                        get_vnf_unique_name(nsd_id, vnfd_id, vnfd_index),
                        path,
                        config,
                    )
                )


        nsr_lcm["status"] = "DONE"
        db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)

        return nsr_lcm

    except (ROclient.ROClientException, Exception) as e:
        logger.debug("CreateNS nsr_id={} Exception {}".format(nsr_id, e), exc_info=True)
        nsr_lcm["status"] = "ERROR"
        nsr_lcm["status_detailed"] += ": ERROR {}".format(e)
    finally:
        logger.debug("CreateNS task nsr_id={} Exit".format(nsr_id))


async def DestroyNS(loop, nsr_id):
    logger.debug("DestroyNS task nsr_id={} Enter".format(nsr_id))
    nsr_lcm = db.get_one("nsr_lcm", {"id": nsr_id})
    ns_request = db.get_one("ns_request", {"id": nsr_id})
    nsd_id = ns_request["nsd_id"]

    nsr_lcm["status"] = "DELETING"
    nsr_lcm["status_detailed"] = "Deleting charms"
    db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)

    # TODO destroy charms
    for c_vnf in nsd["constituent-vnfd"]:
        vnfd_id = c_vnf["vnfd-id-ref"]
        vnfd_index = int(c_vnf["member-vnf-index"])
        vnfd = db.get_one("vnfd", {"id": vnfd_id})
        if vnfd.get("vnf-configuration") and vnfd["vnf-configuration"].get("juju"):
            RemoveApplication(
                get_vnf_unique_name(
                    nsd_id, vnfd_id, vnfd_index
                )
            )

    # remove from RO
    RO = ROclient.ROClient(loop, endpoint_url=ro_account["url"], tenant=ro_account["tenant"],
                           datacenter=ns_request["vim"])
    # Delete ns
    try:
        RO_nsr_id = nsr_lcm["RO"]["nsr_id"]
        if RO_nsr_id:
            nsr_lcm["status_detailed"] = "Deleting ns at RO"
            desc = await RO.delete("ns", RO_nsr_id)
            print("debug", "deleted RO ns {}".format(RO_nsr_id))
            nsr_lcm["RO"]["nsr_id"] = None
            nsr_lcm["RO"]["nsr_status"] = "DELETED"
            db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)
    except ROclient.ROClientException as e:
        if e.http_code == 404:
            nsr_lcm["RO"]["nsr_id"] = None
            nsr_lcm["RO"]["nsr_status"] = "DELETED"
            db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)
            print("warning", e)
        else:
            print("error", e)

    # Delete nsd
    try:
        RO_nsd_id = nsr_lcm["RO"]["nsd_id"]
        if RO_nsd_id:
            nsr_lcm["status_detailed"] = "Deleting nsd at RO"
            desc = await RO.delete("nsd", RO_nsd_id)
            print("debug", "deleted RO nsd {}".format(RO_nsd_id))
            nsr_lcm["RO"]["nsd_id"] = None
            db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)
    except ROclient.ROClientException as e:
        if e.http_code == 404:
            nsr_lcm["RO"]["nsd_id"] = None
            print("warning", e)
        else:
            print("error", e)

    for vnf_id, RO_vnfd_id in nsr_lcm["RO"]["vnfd_id"].items():
        try:
            if RO_vnfd_id:
                nsr_lcm["status_detailed"] = "Deleting vnfd at RO"
                desc = await RO.delete("vnfd", RO_vnfd_id)
                print("debug", "deleted RO vnfd {}".format(RO_vnfd_id))
                nsr_lcm["RO"]["vnfd_id"][vnf_id] = None
                db.replace("nsr_lcm", {"id": nsr_id}, nsr_lcm)
        except ROclient.ROClientException as e:
            if e.http_code == 404:
                nsr_lcm["RO"]["vnfd_id"][vnf_id] = None
                print("warning", e)
            else:
                print("error", e)
    logger.debug("DestroyNS task nsr_id={} Exit".format(nsr_id))


async def test(loop, param=None):
    logger.debug("Starting/Ending test task: {}".format(param))


def cancel_tasks(loop, nsr_id):
    """
    Cancel all active tasks of a concrete nsr identified for nsr_id
    :param loop: loop
    :param nsr_id:  nsr identity
    :return: None, or raises an exception if not possible
    """
    global lcm_tasks
    if not lcm_tasks.get(nsr_id):
        return
    for order_id, tasks_set in lcm_tasks[nsr_id].items():
        for task_name, task in tasks_set.items():
            result = task.cancel()
            if result:
                logger.debug("nsr_id={} order_id={} task={} cancelled".format(nsr_id, order_id, task_name))
    lcm_tasks[nsr_id] = {}


async def read_kafka(loop, bus_info):
    global lcm_tasks
    logger.debug("kafka task Enter")
    order_id = 1
    # future = asyncio.Future()
    with open(bus_info["file"]) as f:

        # ignore old orders. Read file
        command = "fake"
        while command:
            command = f.read()

        while True:
            command = f.read()
            if not command:
                await asyncio.sleep(2, loop=loop)
                continue
            order_id += 1
            command = command.strip()
            command, _, params = command.partition(" ")
            if command == "exit":
                print("Bye!")
                break
            elif command.startswith("#"):
                continue
            elif command == "echo":
                print(params)
            elif command == "test":
                asyncio.Task(test(loop, params), loop=loop)
            elif command == "break":
                print("put a break in this line of code")
            elif command == "new-ns":
                nsr_id = params.strip()
                logger.debug("Deploying NS {}".format(nsr_id))
                task = asyncio.ensure_future(CreateNS(loop, nsr_id))
                if nsr_id not in lcm_tasks:
                    lcm_tasks[nsr_id] = {}
                lcm_tasks[nsr_id][order_id] = {"CreateNS": task}
            elif command == "del-ns":
                nsr_id = params.strip()
                logger.debug("Deleting NS {}".format(nsr_id))
                cancel_tasks(loop, nsr_id)
                task = asyncio.ensure_future(DestroyNS(loop, nsr_id))
                if nsr_id not in lcm_tasks:
                    lcm_tasks[nsr_id] = {}
                lcm_tasks[nsr_id][order_id] = {"DestroyNS": task}
            elif command == "get-ns":
                nsr_id = params.strip()
                nsr_lcm = db.get_one("nsr_lcm", {"id": nsr_id})
                print("nsr_lcm", nsr_lcm)
                print("lcm_tasks", lcm_tasks.get(nsr_id))
            else:
                logger.debug("unknown command '{}'".format(command))
                print("Usage:\n  echo <>\n  new-ns <ns1|ns2>\n  del-ns <ns1|ns2>\n  get-ns <ns1|ns2>")
    logger.debug("kafka task Exit")


def lcm(kafka):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(read_kafka(loop, {"file": kafka}))
    return


def lcm2():
    loop = asyncio.get_event_loop()
    # asyncio.ensure_future(CreateNS, loop)
    try:
        content = loop.run_until_complete(CreateNS(loop, "ns1"))
        print("Done: {}".format(content))
    except ROclient.ROClientException as e:
        print("Error {}".format(e))

    time.sleep(10)

    content = loop.run_until_complete(DestroyNS(loop, "ns1"))
    print(content)

    loop.close()


def get_argparser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--vnfd',
        nargs="+",
        type=str,
        action='append',
        required=True,
    )
    parser.add_argument(
        '--nsd',
        type=str,
        required=True,
    )

    parser.add_argument(
        '--kafka',
        type=str,
        required=True,
    )

    parser.add_argument(
        '--datacenter',
        type=str,
        required=True,
        default="OST2_MRT"
    )
    args = parser.parse_args()

    # Quick hack to make this one list
    vnfds = []
    for vnfd in args.vnfd:
        vnfds += vnfd
    args.vnfd = vnfds

    return args


# def find_yaml(path):
#     """Find the first yaml file, rescursively, in the path."""
#     for filename in glob.iglob('path/**/.yaml'):
#         print(filename)
#
#
if __name__ == '__main__':

    args = get_argparser()
    print(args)

    # FOR TEST
    RO_VIM = args.datacenter

    # Unpack the NSD/VNFD packages to a persistent on-disk cache
    if os.path.exists('.cache'):
        shutil.rmtree('.cache')
    os.mkdir('.cache')

    for vnfd in args.vnfd:
        if mimetypes.guess_type(vnfd)[0] == "application/x-tar":
            with tarfile.open(vnfd) as tar:
                tar.extractall('.cache/')
                # The path is the root of our charm
                vnfd_dir = "{}/.cache/{}".format(
                    os.path.dirname(
                        os.path.realpath(__file__)
                    ),
                    tar.getnames()[0]
                )
                for entity in tar:
                    if entity.name.endswith('_vnfd.yaml'):
                        print("VNFD: {}/{}".format(".cache", entity.name))
                        with open("{}/{}".format(".cache", entity.name)) as f:
                            vnfd = yaml.load(f)
                            vnfd_clean, _ = ROclient.remove_envelop("vnfd", vnfd)
                            vnfd_clean["_admin"] = {"storage": vnfd_dir}
                            db.create("vnfd", vnfd_clean)

    if mimetypes.guess_type(args.nsd)[0] == "application/x-tar":
        with tarfile.open(args.nsd) as tar:
            tar.extractall('.cache/')

            nsd_dir = "{}/.cache/{}".format(
                os.path.dirname(
                    os.path.realpath(__file__)
                ),
                tar.getnames()[0]
            )
            for entity in tar:
                if entity.name.endswith('_nsd.yaml'):
                    with open("{}/{}".format(".cache", entity.name)) as f:
                        nsd = yaml.load(f)
                        nsd_clean, _ = ROclient.remove_envelop("nsd", nsd)
                        nsd_clean["_admin"] = {"storage": nsd_dir}
                        db.create("nsd", nsd_clean)

    ns_request = {
        "id": "ns1",
        "nsr_id": "ns1",
        "name": "pingpongOne",
        "vim": RO_VIM,
        "nsd_id": nsd_clean["id"],  # nsd_ping_pong
    }
    db.create("ns_request", ns_request)
    ns_request = {
        "id": "ns2",
        "nsr_id": "ns2",
        "name": "pingpongTwo",
        "vim": RO_VIM,
        "nsd_id": nsd_clean["id"],  # nsd_ping_pong
    }
    db.create("ns_request", ns_request)
    # lcm2()
    lcm(args.kafka)

    pass

    #FILL DATABASE
    # with open("/home/atierno/OSM/osm/devops/descriptor-packages/vnfd/ping_vnf/src/ping_vnfd.yaml") as f:
    #     vnfd = yaml.load(f)
    #     vnfd_clean, _ = ROclient.remove_envelop("vnfd", vnfd)
    #     vnfd_clean["_admin"] = {"storage": "/home/atierno/OSM/osm/devops/descriptor-packages/vnfd/ping_vnf"}
    #     db.create("vnfd", vnfd_clean)
    # with open("/home/atierno/OSM/osm/devops/descriptor-packages/vnfd/pong_vnf/src/pong_vnfd.yaml") as f:
    #     vnfd = yaml.load(f)
    #     vnfd_clean, _ = ROclient.remove_envelop("vnfd", vnfd)
    #     vnfd_clean["_admin"] = {"storage": "/home/atierno/OSM/osm/devops/descriptor-packages/vnfd/pong_vnf"}
    #     db.create("vnfd", vnfd_clean)
    # with open("/home/atierno/OSM/osm/devops/descriptor-packages/nsd/ping_pong_ns/src/ping_pong_nsd.yaml") as f:
    #     nsd = yaml.load(f)
    #     nsd_clean, _ = ROclient.remove_envelop("nsd", nsd)
    #     nsd_clean["_admin"] = {"storage": "/home/atierno/OSM/osm/devops/descriptor-packages/nsd/ping_pong_ns"}
    #     db.create("nsd", nsd_clean)
    #
    # ns_request = {
    #     "id": "ns1",
    #     "nsr_id": "ns1",
    #     "name": "pingpongOne",
    #     "vim": RO_VIM,
    #     "nsd_id": nsd_clean["id"],  # nsd_ping_pong
    # }
    # db.create("ns_request", ns_request)
    # ns_request = {
    #     "id": "ns2",
    #     "nsr_id": "ns2",
    #     "name": "pingpongTwo",
    #     "vim": RO_VIM,
    #     "nsd_id": nsd_clean["id"],  # nsd_ping_pong
    # }
    # db.create("ns_request", ns_request)
    # # lcm2()
    # lcm()
