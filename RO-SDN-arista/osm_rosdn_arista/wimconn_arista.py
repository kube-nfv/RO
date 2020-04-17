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
from osm_ro.wim.sdnconn import SdnConnectorBase, SdnConnectorError
import re
import socket
# Required by compare function
import difflib
# Library that uses Levenshtein Distance to calculate the differences
# between strings.
# from fuzzywuzzy import fuzz

import logging
import uuid
from enum import Enum
from requests import RequestException

from cvprac.cvp_client import CvpClient
from cvprac.cvp_api import CvpApi
from cvprac.cvp_client_errors import CvpLoginError,  CvpSessionLogOutError, CvpApiError
from cvprac import __version__ as cvprac_version

from osm_rosdn_arista.aristaSwitch import AristaSwitch
from osm_rosdn_arista.aristaConfigLet import AristaSDNConfigLet
from osm_rosdn_arista.aristaTask import AristaCVPTask


class SdnError(Enum):
    UNREACHABLE = 'Unable to reach the WIM.',
    VLAN_INCONSISTENT = \
        'VLAN value inconsistent between the connection points',
    VLAN_NOT_PROVIDED = 'VLAN value not provided',
    CONNECTION_POINTS_SIZE = \
        'Unexpected number of connection points: 2 expected.',
    ENCAPSULATION_TYPE = \
        'Unexpected service_endpoint_encapsulation_type. \
         Only "dotq1" is accepted.',
    BANDWIDTH = 'Unable to get the bandwidth.',
    STATUS = 'Unable to get the status for the service.',
    DELETE = 'Unable to delete service.',
    CLEAR_ALL = 'Unable to clear all the services',
    UNKNOWN_ACTION = 'Unknown action invoked.',
    BACKUP = 'Unable to get the backup parameter.',
    UNSUPPORTED_FEATURE = "Unsupported feature",
    UNAUTHORIZED = "Failed while authenticating",
    INTERNAL_ERROR = "Internal error"


class AristaSdnConnector(SdnConnectorBase):
    """Arista class for the SDN connectors

    Arguments:
        wim (dict): WIM record, as stored in the database
        wim_account (dict): WIM account record, as stored in the database
        config
    The arguments of the constructor are converted to object attributes.
    An extra property, ``service_endpoint_mapping`` is created from ``config``.

    The access to Arista CloudVision is made through the API defined in
        https://github.com/aristanetworks/cvprac
    The a connectivity service consist in creating a VLAN and associate the interfaces
    of the connection points MAC addresses to this VLAN in all the switches of the topology,
    the BDP is also configured for this VLAN.

    The Arista Cloud Vision API workflow is the following
    -- The switch configuration is defined as a set of switch configuration commands,
       what is called 'ConfigLet'
    -- The ConfigLet is associated to the device (leaf switch)
    -- Automatically a task is associated to this activity for change control, the task
       in this stage is in 'Pending' state
    -- The task will be executed so that the configuration is applied to the switch.
    -- The service information is saved in the response of the creation call
    -- All created services identification is stored in a generic ConfigLet 'OSM_metadata'
       to keep track of the managed resources by OSM in the Arista deployment.
    """
    __supported_service_types = ["ELINE (L2)", "ELINE", "ELAN"]
    __service_types_ELAN = "ELAN"
    __service_types_ELINE = "ELINE"
    __ELINE_num_connection_points = 2
    __supported_service_types = ["ELINE", "ELAN"]
    __supported_encapsulation_types = ["dot1q"]
    __WIM_LOGGER = 'openmano.sdnconn.arista'
    __SERVICE_ENDPOINT_MAPPING = 'service_endpoint_mapping'
    __ENCAPSULATION_TYPE_PARAM = "service_endpoint_encapsulation_type"
    __ENCAPSULATION_INFO_PARAM = "service_endpoint_encapsulation_info"
    __BACKUP_PARAM = "backup"
    __BANDWIDTH_PARAM = "bandwidth"
    __SERVICE_ENDPOINT_PARAM = "service_endpoint_id"
    __MAC_PARAM = "mac"
    __WAN_SERVICE_ENDPOINT_PARAM = "service_endpoint_id"
    __WAN_MAPPING_INFO_PARAM = "service_mapping_info"
    __DEVICE_ID_PARAM = "device_id"
    __DEVICE_INTERFACE_ID_PARAM = "device_interface_id"
    __SW_ID_PARAM = "switch_dpid"
    __SW_PORT_PARAM = "switch_port"
    __VLAN_PARAM = "vlan"
    __VNI_PARAM = "vni"
    __SEPARATOR = '_'
    __MANAGED_BY_OSM = '## Managed by OSM '
    __OSM_PREFIX = "osm_"
    __OSM_METADATA = "OSM_metadata"
    __METADATA_PREFIX = '!## Service'
    __EXC_TASK_EXEC_WAIT = 10
    __ROLLB_TASK_EXEC_WAIT = 10
    __API_REQUEST_TOUT = 60
    __SWITCH_TAG_NAME = 'topology_type'
    __SWITCH_TAG_VALUE = 'leaf'


    def __init__(self, wim, wim_account, config=None, logger=None):
        """

        :param wim: (dict). Contains among others 'wim_url'
        :param wim_account: (dict). Contains among others 'uuid' (internal id), 'name',
            'sdn' (True if is intended for SDN-assist or False if intended for WIM), 'user', 'password'.
        :param config: (dict or None): Particular information of plugin. These keys if present have a common meaning:
            'mapping_not_needed': (bool) False by default or if missing, indicates that mapping is not needed.
            'service_endpoint_mapping': (list) provides the internal endpoint mapping. The meaning is:
                KEY 	    	        meaning for WIM		        meaning for SDN assist
                --------                --------                    --------
                device_id		        pop_switch_dpid		        compute_id
                device_interface_id		pop_switch_port		        compute_pci_address
                service_endpoint_id	    wan_service_endpoint_id     SDN_service_endpoint_id
                service_mapping_info	wan_service_mapping_info    SDN_service_mapping_info
                    contains extra information if needed. Text in Yaml format
                switch_dpid		        wan_switch_dpid		        SDN_switch_dpid
                switch_port		        wan_switch_port		        SDN_switch_port
                datacenter_id           vim_account                 vim_account
                id: (internal, do not use)
                wim_id: (internal, do not use)
        :param logger (logging.Logger): optional logger object. If none is passed 'openmano.sdn.sdnconn' is used.
        """
        self.__regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?', re.IGNORECASE)  # optional port
        self.raiseException = True
        self.logger = logger or logging.getLogger(self.__WIM_LOGGER)
        super().__init__(wim, wim_account, config, self.logger)
        self.__wim = wim
        self.__wim_account = wim_account
        self.__config = config
        if self.is_valid_destination(self.__wim.get("wim_url")):
            self.__wim_url = self.__wim.get("wim_url")
        else:
            raise SdnConnectorError(message='Invalid wim_url value',
                                    http_code=500)
        self.__user = wim_account.get("user")
        self.__passwd = wim_account.get("password")
        self.client = None
        self.cvp_inventory = None
        self.cvp_tags = None
        self.logger.debug("Arista SDN plugin {}, cvprac version {}, user:{} and config:{}".
                          format(wim, cvprac_version, self.__user,
                                 self.delete_keys_from_dict(config, ('passwd',))))
        self.allDeviceFacts = []
        self.clC = AristaSDNConfigLet()
        self.taskC = None
        self.__load_switches()

    def __load_switches(self):
        """ Retrieves the switches to configure in the following order
        1.  from incoming configuration:
        1.1 using port mapping
              using user and password from WIM
              retrieving Lo0 and AS from switch
        1.2 from 'switches' parameter,
              if any parameter is not present
                Lo0 and AS - it will be requested to the switch
                usr and pass - from WIM configuration
        2.  Looking in the CloudVision inventory if not in configuration parameters
        2.1 using the switches with the topology_type tag set to 'leaf'
        2.2 using the switches whose parent container is 'leaf'
        2.3 using the switches whose hostname contains with 'leaf'

        All the search methods will be used
        """
        self.switches = {}
        if self.__config and self.__config.get(self.__SERVICE_ENDPOINT_MAPPING):
            for port in self.__config.get(self.__SERVICE_ENDPOINT_MAPPING):
                switch_dpid = port.get(self.__SW_ID_PARAM)
                if switch_dpid and switch_dpid not in self.switches:
                    self.switches[switch_dpid] = {'passwd': self.__passwd,
                                                  'ip': None,
                                                  'usr': self.__user,
                                                  'lo0': None,
                                                  'AS': None}

        if self.__config and self.__config.get('switches'):
            # Not directly from json, complete one by one
            config_switches = self.__config.get('switches')
            for cs, cs_content in config_switches.items():
                if cs not in self.switches:
                    self.switches[cs] = {'passwd': self.__passwd, 'ip': None, 'usr': self.__user, 'lo0': None,'AS': None}
                if cs_content:
                    self.switches[cs].update(cs_content)

        # Load the rest of the data
        if self.client is None:
            self.client = self.__connect()
        self.__load_inventory()
        if not self.switches:
            self.__get_tags(self.__SWITCH_TAG_NAME, self.__SWITCH_TAG_VALUE)
            for device in self.allDeviceFacts:
                # get the switches whose container parent is 'leaf',
                # or the topology_tag is 'leaf'
                # or the hostname contains 'leaf'
                if ((device['serialNumber'] in self.cvp_tags) or
                    (self.__SWITCH_TAG_VALUE in device['containerName'].lower()) or 
                    (self.__SWITCH_TAG_VALUE in device['hostname'].lower())):
                        if not self.switches.get(device['hostname']):
                            switch_data = {'passwd': self.__passwd,
                                           'ip': device['ipAddress'],
                                           'usr': self.__user,
                                           'lo0': None,
                                           'AS': None}
                            self.switches[device['hostname']] = switch_data
        if len(self.switches) == 0:
            self.logger.error("Unable to load Leaf switches from CVP")
            return

        # self.s_api are switch objects, one for each switch in self.switches,
        # used to make eAPI calls by using switch.py module
        self.s_api = {}
        for s in self.switches:
            if not self.switches[s].get('ip'):
                for device in self.allDeviceFacts:
                    if device['hostname'] == s:
                        self.switches[s]['ip'] = device['ipAddress']
            if self.is_valid_destination(self.switches[s].get('ip')):
                self.s_api[s] = AristaSwitch(host=self.switches[s]['ip'],
                                             user=self.switches[s]['usr'],
                                             passwd=self.switches[s]['passwd'],
                                             logger=self.logger)
            # Each switch has a different loopback address,
            # so it's a different configLet
            if not self.switches[s].get('lo0'):
                inf = self.__get_switch_interface_ip(s, 'Loopback0')
                self.switches[s]["lo0"] = inf.split('/')[0]
            if not self.switches[s].get('AS'):
                self.switches[s]["AS"] = self.__get_switch_asn(s)
        self.logger.debug("Using Arista Leaf switches: {}".format(
                self.delete_keys_from_dict(self.switches, ('passwd',))))

    def __lldp_find_neighbor(self, tlv_name=None, tlv_value=None):
        """Returns a list of dicts where a mathing LLDP neighbor has been found
           Each dict has:
             switch -> switch name
             interface -> switch interface
        """
        r = []
        lldp_info = {}

        # Get LLDP info from each switch
        for s in self.s_api:
            result = self.s_api[s].run("show lldp neighbors detail")
            lldp_info[s] = result[0]["lldpNeighbors"]
            # Look LLDP match on each interface
            # Note that eAPI returns [] for an interface with no LLDP neighbors
            # in the corresponding interface lldpNeighborInfo field
            for interface in lldp_info[s]:
                if lldp_info[s][interface]["lldpNeighborInfo"]:
                    lldp_nInf = lldp_info[s][interface]["lldpNeighborInfo"][0]
                    if tlv_name in lldp_nInf:
                        if lldp_nInf[tlv_name] == tlv_value:
                            r.append({"name": s, "interface": interface})

        return r

    def __get_switch_asn(self, switch):
        """Returns switch ASN in default VRF
        """
        bgp_info = self.s_api[switch].run("show ip bgp summary")[0]
        return(bgp_info["vrfs"]["default"]["asn"])

    def __get_switch_po(self, switch, interface=None):
        """Returns Port-Channels for a given interface
           If interface is None returns a list with all PO interfaces
           Note that if specified, interface should be exact name
           for instance: Ethernet3 and not e3 eth3 and so on
        """
        po_inf = self.s_api[switch].run("show port-channel")[0]["portChannels"]

        if interface:
            r = [x for x in po_inf if interface in po_inf[x]["activePorts"]]
        else:
            r = po_inf

        return r

    def __get_switch_interface_ip(self, switch, interface=None):
        """Returns interface primary ip
           interface should be exact name
           for instance: Ethernet3 and not ethernet 3, e3 eth3 and so on
        """
        cmd = "show ip interface {}".format(interface)
        ip_info = self.s_api[switch].run(cmd)[0]["interfaces"][interface]

        ip = ip_info["interfaceAddress"]["primaryIp"]["address"]
        mask = ip_info["interfaceAddress"]["primaryIp"]["maskLen"]

        return "{}/{}".format(ip, mask)

    def __check_service(self, service_type, connection_points,
                        check_vlan=True, check_num_cp=True, kwargs=None):
        """ Reviews the connection points elements looking for semantic errors in the incoming data
        """
        if service_type not in self.__supported_service_types:
            raise Exception("The service '{}' is not supported. Only '{}' are accepted".format(
                            service_type,
                            self.__supported_service_types))

        if check_num_cp:
            if (len(connection_points) < 2):
                raise Exception(SdnError.CONNECTION_POINTS_SIZE)
            if ((len(connection_points) != self.__ELINE_num_connection_points) and
               (service_type == self.__service_types_ELINE)):
                raise Exception(SdnError.CONNECTION_POINTS_SIZE)

        if check_vlan:
            vlan_id = ''
            for cp in connection_points:
                enc_type = cp.get(self.__ENCAPSULATION_TYPE_PARAM)
                if (enc_type and
                        enc_type not in self.__supported_encapsulation_types):
                    raise Exception(SdnError.ENCAPSULATION_TYPE)
                encap_info = cp.get(self.__ENCAPSULATION_INFO_PARAM)
                cp_vlan_id = str(encap_info.get(self.__VLAN_PARAM))
                if cp_vlan_id:
                    if not vlan_id:
                        vlan_id = cp_vlan_id
                    elif vlan_id != cp_vlan_id:
                        raise Exception(SdnError.VLAN_INCONSISTENT)
            if not vlan_id:
                raise Exception(SdnError.VLAN_NOT_PROVIDED)
            if vlan_id in self.__get_srvVLANs():
                raise Exception('VLAN {} already assigned to a connectivity service'.format(vlan_id))

        # Commented out for as long as parameter isn't implemented
        # bandwidth = kwargs.get(self.__BANDWIDTH_PARAM)
        # if not isinstance(bandwidth, int):
            # self.__exception(SdnError.BANDWIDTH, http_code=400)

        # Commented out for as long as parameter isn't implemented
        # backup = kwargs.get(self.__BACKUP_PARAM)
        # if not isinstance(backup, bool):
            # self.__exception(SdnError.BACKUP, http_code=400)

    def check_credentials(self):
        """Retrieves the CloudVision version information, as the easiest way
        for testing the access to CloudVision API
        """
        try:
            if self.client is None:
                self.client = self.__connect()
            result = self.client.api.get_cvp_info()
            self.logger.debug(result)
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except Exception as ex:
            self.client = None
            self.logger.error(str(ex))
            raise SdnConnectorError(message=SdnError.INTERNAL_ERROR,
                                    http_code=500) from ex

    def get_connectivity_service_status(self, service_uuid, conn_info=None):
        """Monitor the status of the connectivity service established
        Arguments:
            service_uuid (str): UUID of the connectivity service
            conn_info (dict or None): Information returned by the connector
                during the service creation/edition and subsequently stored in
                the database.

        Returns:
            dict: JSON/YAML-serializable dict that contains a mandatory key
                ``sdn_status`` associated with one of the following values::

                    {'sdn_status': 'ACTIVE'}
                        # The service is up and running.

                    {'sdn_status': 'INACTIVE'}
                        # The service was created, but the connector
                        # cannot determine yet if connectivity exists
                        # (ideally, the caller needs to wait and check again).

                    {'sdn_status': 'DOWN'}
                        # Connection was previously established,
                        # but an error/failure was detected.

                    {'sdn_status': 'ERROR'}
                        # An error occurred when trying to create the service/
                        # establish the connectivity.

                    {'sdn_status': 'BUILD'}
                        # Still trying to create the service, the caller
                        # needs to wait and check again.

                Additionally ``error_msg``(**str**) and ``sdn_info``(**dict**)
                keys can be used to provide additional status explanation or
                new information available for the connectivity service.
        """
        try:
            self.logger.debug("invoked get_connectivity_service_status '{}'".format(service_uuid))
            if not service_uuid:
                raise SdnConnectorError(message='No connection service UUID',
                                        http_code=500)

            self.__get_Connection()
            if conn_info is None:
                raise SdnConnectorError(message='No connection information for service UUID {}'.format(service_uuid),
                                        http_code=500)

            if 'configLetPerSwitch' in conn_info.keys():
                c_info = conn_info
            else:
                c_info = None
            cls_perSw = self.__get_serviceData(service_uuid,
                                               conn_info['service_type'],
                                               conn_info['vlan_id'],
                                               c_info)

            t_isCancelled = False
            t_isFailed = False
            t_isPending = False
            failed_switches = []
            for s in self.s_api:
                if (len(cls_perSw[s]) > 0):
                    for cl in cls_perSw[s]:
                        # Fix 1030 SDN-ARISTA Key error note when deploy a NS
                        # Added protection to check that 'note' exists and additionally
                        # verify that it is managed by OSM
                        if (not cls_perSw[s][0]['config'] or
                                not cl.get('note') or
                                self.__MANAGED_BY_OSM not in cl['note']):
                            continue
                        note = cl['note']
                        t_id = note.split(self.__SEPARATOR)[1]
                        result = self.client.api.get_task_by_id(t_id)
                        if result['workOrderUserDefinedStatus'] == 'Completed':
                            continue
                        elif result['workOrderUserDefinedStatus'] == 'Cancelled':
                            t_isCancelled = True
                        elif result['workOrderUserDefinedStatus'] == 'Failed':
                            t_isFailed = True
                        else:
                            t_isPending = True
                        failed_switches.append(s)
            if t_isCancelled:
                error_msg = 'Some works were cancelled in switches: {}'.format(str(failed_switches))
                sdn_status = 'DOWN'
            elif t_isFailed:
                error_msg = 'Some works failed in switches: {}'.format(str(failed_switches))
                sdn_status = 'ERROR'
            elif t_isPending:
                error_msg = 'Some works are still under execution in switches: {}'.format(str(failed_switches))
                sdn_status = 'BUILD'
            else:
                error_msg = ''
                sdn_status = 'ACTIVE'
            sdn_info = ''
            return {'sdn_status': sdn_status,
                    'error_msg': error_msg,
                    'sdn_info': sdn_info}
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except Exception as ex:
            self.client = None
            self.logger.error(str(ex), exc_info=True)
            raise SdnConnectorError(message=str(ex),
                                    http_code=500) from ex

    def create_connectivity_service(self, service_type, connection_points,
                                    **kwargs):
        """Stablish SDN/WAN connectivity between the endpoints
        :param service_type:
            (str): ``ELINE`` (L2), ``ELAN`` (L2), ``ETREE`` (L2), ``L3``.
        :param connection_points:  (list): each point corresponds to
            an entry point to be connected. For WIM: from the DC
            to the transport network.
            For SDN: Compute/PCI to the transport network. One
            connection point serves to identify the specific access and
            some other service parameters, such as encapsulation type.
            Each item of the list is a dict with:
                "service_endpoint_id": (str)(uuid)  Same meaning that for
                    'service_endpoint_mapping' (see __init__)
                    In case the config attribute mapping_not_needed is True,
                    this value is not relevant. In this case
                    it will contain the string "device_id:device_interface_id"
                "service_endpoint_encapsulation_type": None, "dot1q", ...
                "service_endpoint_encapsulation_info": (dict) with:
                    "vlan": ..., (int, present if encapsulation is dot1q)
                    "vni": ... (int, present if encapsulation is vxlan),
                    "peers": [(ipv4_1), (ipv4_2)] (present if
                        encapsulation is vxlan)
                    "mac": ...
                    "device_id": ..., same meaning that for
                        'service_endpoint_mapping' (see __init__)
                    "device_interface_id": same meaning that for
                        'service_endpoint_mapping' (see __init__)
                    "switch_dpid": ..., present if mapping has been found
                        for this device_id,device_interface_id
                    "switch_port": ... present if mapping has been found
                        for this device_id,device_interface_id
                    "service_mapping_info": present if mapping has
                        been found for this device_id,device_interface_id
        :param kwargs: For future versions:
            bandwidth (int): value in kilobytes
            latency (int): value in milliseconds
            Other QoS might be passed as keyword arguments.
        :return: tuple: ``(service_id, conn_info)`` containing:
            - *service_uuid* (str): UUID of the established
                    connectivity service
            - *conn_info* (dict or None): Information to be
                    stored at the database (or ``None``).
                This information will be provided to the
                    :meth:`~.edit_connectivity_service` and :obj:`~.delete`.
                **MUST** be JSON/YAML-serializable (plain data structures).
        :raises: SdnConnectorError: In case of error. Nothing should be
                                    created in this case.
            Provide the parameter http_code
        """
        try:
            self.logger.debug("invoked create_connectivity_service '{}' ports: {}".
                              format(service_type, connection_points))
            self.__get_Connection()
            self.__check_service(service_type,
                                 connection_points,
                                 check_vlan=True,
                                 kwargs=kwargs)
            service_uuid = str(uuid.uuid4())

            self.logger.info("Service with uuid {} created.".
                             format(service_uuid))
            s_uid, s_connInf = self.__processConnection(
                                        service_uuid,
                                        service_type,
                                        connection_points,
                                        kwargs)
            try:
                self.__addMetadata(s_uid, service_type, s_connInf['vlan_id'])
            except Exception as e:
                pass

            return (s_uid, s_connInf)
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except SdnConnectorError as sde:
            raise sde
        except Exception as ex:
            self.client = None
            self.logger.error(str(ex), exc_info=True)
            if self.raiseException:
                raise ex
            raise SdnConnectorError(message=str(ex),
                                    http_code=500) from ex

    def __processConnection(self,
                            service_uuid,
                            service_type,
                            connection_points,
                            kwargs):
        """
        Invoked from creation and edit methods

        Process the connection points array,
            creating a set of configuration per switch where it has to be applied
            for creating the configuration, the switches have to be queried for obtaining:
                - the loopback address
                - the BGP ASN (autonomous system number)
                - the interface name of the MAC address to add in the connectivity service
        Once the new configuration is ready, the __updateConnection method is invoked for appling the changes
        """
        try:
            cls_perSw = {}
            cls_cp = {}
            cl_bgp = {}
            for s in self.s_api:
                cls_perSw[s] = []
                cls_cp[s] = []
            vlan_processed = False
            vlan_id = ''
            i = 0
            processed_connection_points = []
            for cp in connection_points:
                i += 1
                encap_info = cp.get(self.__ENCAPSULATION_INFO_PARAM)
                if not vlan_processed:
                    vlan_id = str(encap_info.get(self.__VLAN_PARAM))
                    if not vlan_id:
                        continue
                    vni_id = encap_info.get(self.__VNI_PARAM)
                    if not vni_id:
                        vni_id = str(10000 + int(vlan_id))

                    if service_type == self.__service_types_ELAN:
                        cl_vlan = self.clC.getElan_vlan(service_uuid,
                                                        vlan_id,
                                                        vni_id)
                    else:
                        cl_vlan = self.clC.getEline_vlan(service_uuid,
                                                         vlan_id,
                                                         vni_id)
                    vlan_processed = True

                encap_type = cp.get(self.__ENCAPSULATION_TYPE_PARAM)
                switch_id = encap_info.get(self.__SW_ID_PARAM)
                if not switch_id:
                    point_mac = encap_info.get(self.__MAC_PARAM)
                    switches = self.__lldp_find_neighbor("chassisId", point_mac)
                    self.logger.debug("Found connection point for MAC {}: {}".
                                      format(point_mac, switches))
                else:
                    interface = encap_info.get(self.__SW_PORT_PARAM)
                    switches = [{'name': switch_id, 'interface': interface}]

                if len(switches) == 0:
                    raise SdnConnectorError(message="Connection point MAC address {} not found in the switches".format(point_mac),
                                            http_code=406)

                # remove those connections that are equal. This happens when several sriovs are located in the same
                # compute node interface, that is, in the same switch and interface
                switches = [x for x in switches if x not in processed_connection_points]
                if not switches:
                    continue
                processed_connection_points += switches
                for switch in switches:
                    if not switch_id:
                        port_channel = self.__get_switch_po(switch['name'],
                                                            switch['interface'])
                        if len(port_channel) > 0:
                            interface = port_channel[0]
                        else:
                            interface = switch['interface']
                    if not interface:
                        raise SdnConnectorError(message="Connection point switch port empty for switch_dpid {}".format(switch_id),
                                                http_code=406)
                    # it should be only one switch where the mac is attached
                    if encap_type == 'dot1q':
                        # SRIOV configLet for Leaf switch mac's attached to
                        if service_type == self.__service_types_ELAN:
                            cl_encap = self.clC.getElan_sriov(service_uuid, interface, vlan_id, i)
                        else:
                            cl_encap = self.clC.getEline_sriov(service_uuid, interface, vlan_id, i)
                    elif not encap_type:
                        # PT configLet for Leaf switch attached to the mac
                        if service_type == self.__service_types_ELAN:
                            cl_encap = self.clC.getElan_passthrough(service_uuid,
                                                                    interface,
                                                                    vlan_id, i)
                        else:
                            cl_encap = self.clC.getEline_passthrough(service_uuid,
                                                                     interface,
                                                                     vlan_id, i)
                    if cls_cp.get(switch['name']):
                        cls_cp[switch['name']] = str(cls_cp[switch['name']]) + cl_encap
                    else:
                        cls_cp[switch['name']] = cl_encap

            # at least 1 connection point has to be received
            if not vlan_processed:
                raise SdnConnectorError(message=SdnError.UNSUPPORTED_FEATURE,
                                        http_code=406)

            for s in self.s_api:
                # for cl in cp_configLets:
                cl_name = (self.__OSM_PREFIX +
                           s +
                           self.__SEPARATOR + service_type + str(vlan_id) +
                           self.__SEPARATOR + service_uuid)
                # apply VLAN and BGP configLet to all Leaf switches
                if service_type == self.__service_types_ELAN:
                    cl_bgp[s] = self.clC.getElan_bgp(service_uuid,
                                                     vlan_id,
                                                     vni_id,
                                                     self.switches[s]['lo0'],
                                                     self.switches[s]['AS'])
                else:
                    cl_bgp[s] = self.clC.getEline_bgp(service_uuid,
                                                      vlan_id,
                                                      vni_id,
                                                      self.switches[s]['lo0'],
                                                      self.switches[s]['AS'])

                if not cls_cp.get(s):
                    cl_config = ''
                else:
                    cl_config = str(cl_vlan) + str(cl_bgp[s]) + str(cls_cp[s])

                cls_perSw[s] = [{'name': cl_name, 'config': cl_config}]

            allLeafConfigured, allLeafModified = self.__updateConnection(cls_perSw)

            conn_info = {
                "uuid": service_uuid,
                "status": "BUILD",
                "service_type": service_type,
                "vlan_id": vlan_id,
                "connection_points": connection_points,
                "configLetPerSwitch": cls_perSw,
                'allLeafConfigured': allLeafConfigured,
                'allLeafModified': allLeafModified}

            return service_uuid, conn_info
        except Exception as ex:
            self.logger.debug("Exception processing connection {}: {}".
                              format(service_uuid, str(ex)))
            raise ex

    def __updateConnection(self, cls_perSw):
        """ Invoked in the creation and modification

        checks if the new connection points config is:
            - already in the Cloud Vision, the configLet is modified, and applied to the switch,
                executing the corresponding task
            - if it has to be removed:
                then configuration has to be removed from the switch executing the corresponding task,
                before trying to remove the configuration
            - created, the configuration set is created, associated to the switch, and the associated
                task to the configLet modification executed
        In case of any error, rollback is executed, removing the created elements, and restoring to the
        previous state.
        """
        try:
            allLeafConfigured = {}
            allLeafModified = {}

            for s in self.s_api:
                allLeafConfigured[s] = False
                allLeafModified[s] = False
            tasks = dict()
            cl_toDelete = []
            for s in self.s_api:
                toDelete_in_cvp = False
                if not (cls_perSw.get(s) and cls_perSw[s][0].get('config')):
                    # when there is no configuration, means that there is no interface
                    # in the switch to be connected, so the configLet has to be removed from CloudVision
                    # after removing the ConfigLet fron the switch if it was already there

                    # get config let name and key
                    cl = cls_perSw[s]
                    try:
                        cvp_cl = self.client.api.get_configlet_by_name(cl[0]['name'])
                        # remove configLet
                        cl_toDelete.append(cvp_cl)
                        cl[0] = cvp_cl
                        toDelete_in_cvp = True
                    except CvpApiError as error:
                        if "Entity does not exist" in error.msg:
                            continue
                        else:
                            raise error
                    # remove configLet from device
                else:
                    res = self.__configlet_modify(cls_perSw[s])
                    allLeafConfigured[s] = res[0]
                    if not allLeafConfigured[s]:
                        continue
                    cl = cls_perSw[s]
                res = self.__device_modify(
                                           device_to_update=s,
                                           new_configlets=cl,
                                           delete=toDelete_in_cvp)
                if "errorMessage" in str(res):
                    raise Exception(str(res))
                self.logger.info("Device {} modify result {}".format(s, res))
                for t_id in res[1]['tasks']:
                    if not toDelete_in_cvp:
                        tasks[t_id] = {'workOrderId': t_id}
                        note_msg = "{}{}{}{}##".format(self.__MANAGED_BY_OSM,
                                                       self.__SEPARATOR,
                                                       t_id,
                                                       self.__SEPARATOR)
                        self.client.api.add_note_to_configlet(
                                cls_perSw[s][0]['key'],
                                note_msg)
                        cls_perSw[s][0]['note'] = note_msg
                    else:
                        delete_tasks = { t_id : {'workOrderId': t_id} }
                        self.__exec_task(delete_tasks)
                # with just one configLet assigned to a device,
                # delete all if there are errors in next loops
                if not toDelete_in_cvp:
                    allLeafModified[s] = True
            if len(tasks) > 0:
                self.__exec_task(tasks, self.__EXC_TASK_EXEC_WAIT)
            if len(cl_toDelete) > 0:
                self.__configlet_modify(cl_toDelete, delete=True)

            return allLeafConfigured, allLeafModified
        except Exception as ex:
            try:
                self.__rollbackConnection(cls_perSw,
                                          allLeafConfigured,
                                          allLeafModified)
            except Exception as e:
                self.logger.error("Exception rolling back in updating  connection: {}".
                                 format(e), exc_info=True)
            raise ex

    def __rollbackConnection(self,
                             cls_perSw,
                             allLeafConfigured,
                             allLeafModified):
        """ Removes the given configLet from the devices and then remove the configLets
        """
        for s in self.s_api:
            if allLeafModified[s]:
                try:
                    res = self.__device_modify(
                        device_to_update=s,
                        new_configlets=cls_perSw[s],
                        delete=True)
                    if "errorMessage" in str(res):
                        raise Exception(str(res))
                    tasks = dict()
                    for t_id in res[1]['tasks']:
                        tasks[t_id] = {'workOrderId': t_id}
                    self.__exec_task(tasks)
                    self.logger.info("Device {} modify result {}".format(s, res))
                except Exception as e:
                    self.logger.error('Error removing configlets from device {}: {}'.format(s, e))
                    pass
        for s in self.s_api:
            if allLeafConfigured[s]:
                self.__configlet_modify(cls_perSw[s], delete=True)

    def __exec_task(self, tasks, tout=10):
        if self.taskC is None:
            self.__connect()
        data = self.taskC.update_all_tasks(tasks).values()
        self.taskC.task_action(data, tout, 'executed')

    def __device_modify(self, device_to_update, new_configlets, delete):
        """ Updates the devices (switches) adding or removing the configLet,
        the tasks Id's associated to the change are returned
        """
        self.logger.info('Enter in __device_modify delete: {}'.format(
                            delete))
        updated = []
        changed = False
        # Task Ids that have been identified during device actions
        newTasks = []

        if (len(new_configlets) == 0 or
                device_to_update is None or
                len(device_to_update) == 0):
            data = {'updated': updated, 'tasks': newTasks}
            return [changed, data]

        self.__load_inventory()

        allDeviceFacts = self.allDeviceFacts
        # Work through Devices list adding device specific information
        device = None
        for try_device in allDeviceFacts:
            # Add Device Specific Configlets
            # self.logger.debug(device)
            if try_device['hostname'] not in device_to_update:
                continue
            dev_cvp_configlets = self.client.api.get_configlets_by_device_id(
                                    try_device['systemMacAddress'])
            # self.logger.debug(dev_cvp_configlets)
            try_device['deviceSpecificConfiglets'] = []
            for cvp_configlet in dev_cvp_configlets:
                if int(cvp_configlet['containerCount']) == 0:
                    try_device['deviceSpecificConfiglets'].append(
                                {'name': cvp_configlet['name'],
                                 'key': cvp_configlet['key']})
            # self.logger.debug(device)
            device = try_device
            break

        # Check assigned configlets
        device_update = False
        add_configlets = []
        remove_configlets = []
        update_devices = []

        if delete:
            for cvp_configlet in device['deviceSpecificConfiglets']:
                for cl in new_configlets:
                    if cvp_configlet['name'] == cl['name']:
                        remove_configlets.append(cvp_configlet)
                        device_update = True
        else:
            for configlet in new_configlets:
                if configlet not in device['deviceSpecificConfiglets']:
                    add_configlets.append(configlet)
                    device_update = True
        if device_update:
            update_devices.append({'hostname': device['hostname'],
                                   'configlets': [add_configlets,
                                                  remove_configlets],
                                   'device': device})
        self.logger.info("Device to modify: {}".format(update_devices))

        up_device = update_devices[0]
        cl_toAdd = up_device['configlets'][0]
        cl_toDel = up_device['configlets'][1]
        # Update Configlets
        try:
            if delete and len(cl_toDel) > 0:
                r = self.client.api.remove_configlets_from_device(
                                                    'OSM',
                                                    up_device['device'],
                                                    cl_toDel,
                                                    create_task=True)
                dev_action = r
                self.logger.debug("remove_configlets_from_device {} {}".format(dev_action, cl_toDel))
            elif len(cl_toAdd) > 0:
                r = self.client.api.apply_configlets_to_device(
                                                    'OSM',
                                                    up_device['device'],
                                                    cl_toAdd,
                                                    create_task=True)
                dev_action = r
                self.logger.debug("apply_configlets_to_device {} {}".format(dev_action, cl_toAdd))

        except Exception as error:
            errorMessage = str(error)
            msg = "errorMessage: Device {} Configlets couldnot be updated: {}".format(
                  up_device['hostname'], errorMessage)
            raise SdnConnectorError(msg) from error
        else:
            if "errorMessage" in str(dev_action):
                m = "Device {} Configlets update fail: {}".format(
                            up_device['name'], dev_action['errorMessage'])
                raise SdnConnectorError(m)
            else:
                changed = True
                if 'taskIds' in str(dev_action):
                    # Fix 1030 SDN-ARISTA Key error note when deploy a NS
                    if not dev_action['data']['taskIds']:
                        raise SdnConnectorError("No taskIds found: Device {} Configlets couldnot be updated".format(
                                        up_device['hostname']))
                    for taskId in dev_action['data']['taskIds']:
                        updated.append({up_device['hostname']:
                            "Configlets-{}".format(
                                taskId)})
                        newTasks.append(taskId)
                else:
                    updated.append({up_device['hostname']:
                                   "Configlets-No_Specific_Tasks"})
        data = {'updated': updated, 'tasks': newTasks}
        return [changed, data]

    def __configlet_modify(self, configletsToApply, delete=False):
        ''' adds/update or delete the provided configLets
        :param configletsToApply: list of configLets to apply
        :param delete: flag to indicate if the configLets have to be deleted
                        from Cloud Vision Portal
        :return: data: dict of module actions and taskIDs
        '''
        self.logger.info('Enter in __configlet_modify delete:{}'.format(
                            delete))

        # Compare configlets against cvp_facts-configlets
        changed = False
        checked = []
        deleted = []
        updated = []
        new = []

        for cl in configletsToApply:
            found_in_cvp = False
            to_delete = False
            to_update = False
            to_create = False
            to_check = False
            try:
                cvp_cl = self.client.api.get_configlet_by_name(cl['name'])
                cl['key'] = cvp_cl['key']
                cl['note'] = cvp_cl['note']
                found_in_cvp = True
            except CvpApiError as error:
                if "Entity does not exist" in error.msg:
                    pass
                else:
                    raise error

            if delete:
                if found_in_cvp:
                    to_delete = True
                    configlet = {'name': cvp_cl['name'],
                                 'data': cvp_cl}
            else:
                if found_in_cvp:
                    cl_compare = self.__compare(cl['config'],
                                                cvp_cl['config'])
                    # compare function returns a floating point number
                    if cl_compare[0] != 100.0:
                        to_update = True
                        configlet = {'name': cl['name'],
                                     'data': cvp_cl,
                                     'config': cl['config']}
                    else:
                        to_check = True
                        configlet = {'name': cl['name'],
                                     'key': cvp_cl['key'],
                                     'data': cvp_cl,
                                     'config': cl['config']}
                else:
                    to_create = True
                    configlet = {'name': cl['name'],
                                 'config': cl['config']}
            try:
                if to_delete:
                    operation = 'delete'
                    resp = self.client.api.delete_configlet(
                                    configlet['data']['name'],
                                    configlet['data']['key'])
                elif to_update:
                    operation = 'update'
                    resp = self.client.api.update_configlet(
                                    configlet['config'],
                                    configlet['data']['key'],
                                    configlet['data']['name'],
                                    wait_task_ids=True)
                elif to_create:
                    operation = 'create'
                    resp = self.client.api.add_configlet(
                                    configlet['name'],
                                    configlet['config'])
                else:
                    operation = 'checked'
                    resp = 'checked'
            except Exception as error:
                errorMessage = str(error).split(':')[-1]
                message = "Configlet {} cannot be {}: {}".format(
                            cl['name'], operation, errorMessage)
                if to_delete:
                    deleted.append({configlet['name']: message})
                elif to_update:
                    updated.append({configlet['name']: message})
                elif to_create:
                    new.append({configlet['name']: message})
                elif to_check:
                    checked.append({configlet['name']: message})

            else:
                if "error" in str(resp).lower():
                    message = "Configlet {} cannot be deleted: {}".format(
                            cl['name'], resp['errorMessage'])
                    if to_delete:
                        deleted.append({configlet['name']: message})
                    elif to_update:
                        updated.append({configlet['name']: message})
                    elif to_create:
                        new.append({configlet['name']: message})
                    elif to_check:
                        checked.append({configlet['name']: message})
                else:
                    if to_delete:
                        changed = True
                        deleted.append({configlet['name']: "success"})
                    elif to_update:
                        changed = True
                        updated.append({configlet['name']: "success"})
                    elif to_create:
                        changed = True
                        cl['key'] = resp  # This key is used in API call deviceApplyConfigLet FGA
                        new.append({configlet['name']: "success"})
                    elif to_check:
                        changed = False
                        checked.append({configlet['name']: "success"})

        data = {'new': new, 'updated': updated, 'deleted': deleted, 'checked': checked}
        return [changed, data]

    def __get_configletsDevices(self, configlets):
        for s in self.s_api:
            configlet = configlets[s]
            # Add applied Devices
            if len(configlet) > 0:
                configlet['devices'] = []
                applied_devices = self.client.api.get_applied_devices(
                                configlet['name'])
                for device in applied_devices['data']:
                    configlet['devices'].append(device['hostName'])

    def __get_serviceData(self, service_uuid, service_type, vlan_id, conn_info=None):
        cls_perSw = {}
        for s in self.s_api:
            cls_perSw[s] = []
        if not conn_info:
            srv_cls = self.__get_serviceConfigLets(service_uuid,
                                                   service_type,
                                                   vlan_id)
            self.__get_configletsDevices(srv_cls)
            for s in self.s_api:
                cl = srv_cls[s]
                if len(cl) > 0:
                    for dev in cl['devices']:
                        cls_perSw[dev].append(cl)
        else:
            cls_perSw = conn_info['configLetPerSwitch']
        return cls_perSw

    def delete_connectivity_service(self, service_uuid, conn_info=None):
        """
        Disconnect multi-site endpoints previously connected

        :param service_uuid: The one returned by create_connectivity_service
        :param conn_info: The one returned by last call to 'create_connectivity_service' or 'edit_connectivity_service'
            if they do not return None
        :return: None
        :raises: SdnConnectorException: In case of error. The parameter http_code must be filled
        """
        try:
            self.logger.debug('invoked delete_connectivity_service {}'.
                              format(service_uuid))
            if not service_uuid:
                raise SdnConnectorError(message='No connection service UUID',
                                        http_code=500)

            self.__get_Connection()
            if conn_info is None:
                raise SdnConnectorError(message='No connection information for service UUID {}'.format(service_uuid),
                                        http_code=500)
            c_info = None
            cls_perSw = self.__get_serviceData(service_uuid,
                                               conn_info['service_type'],
                                               conn_info['vlan_id'],
                                               c_info)
            allLeafConfigured = {}
            allLeafModified = {}
            for s in self.s_api:
                allLeafConfigured[s] = True
                allLeafModified[s] = True
            found_in_cvp = False
            for s in self.s_api:
                if cls_perSw[s]:
                    found_in_cvp = True
            if found_in_cvp:
                self.__rollbackConnection(cls_perSw,
                                          allLeafConfigured,
                                          allLeafModified)
            else:
                # if the service is not defined in Cloud Vision, return a 404 - NotFound error
                raise SdnConnectorError(message='Service {} was not found in Arista Cloud Vision {}'.
                                        format(service_uuid, self.__wim_url),
                                        http_code=404)
            self.__removeMetadata(service_uuid)
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except SdnConnectorError as sde:
            raise sde
        except Exception as ex:
            self.client = None
            self.logger.error(ex)
            if self.raiseException:
                raise ex
            raise SdnConnectorError(message=SdnError.INTERNAL_ERROR,
                                    http_code=500) from ex

    def __addMetadata(self, service_uuid, service_type, vlan_id):
        """ Adds the connectivity service from 'OSM_metadata' configLet
        """
        found_in_cvp = False
        try:
            cvp_cl = self.client.api.get_configlet_by_name(self.__OSM_METADATA)
            found_in_cvp = True
        except CvpApiError as error:
            if "Entity does not exist" in error.msg:
                pass
            else:
                raise error
        try:
            new_serv = '{} {} {} {}\n'.format(self.__METADATA_PREFIX, service_type, vlan_id, service_uuid)

            if found_in_cvp:
                cl_config = cvp_cl['config'] + new_serv
            else:
                cl_config = new_serv
            cl_meta = [{'name': self.__OSM_METADATA, 'config': cl_config}]
            self.__configlet_modify(cl_meta)
        except Exception as e:
            self.logger.error('Error in setting metadata in CloudVision from OSM for service {}: {}'.
                              format(service_uuid, str(e)))
            pass

    def __removeMetadata(self, service_uuid):
        """ Removes the connectivity service from 'OSM_metadata' configLet
        """
        found_in_cvp = False
        try:
            cvp_cl = self.client.api.get_configlet_by_name(self.__OSM_METADATA)
            found_in_cvp = True
        except CvpApiError as error:
            if "Entity does not exist" in error.msg:
                pass
            else:
                raise error
        try:
            if found_in_cvp:
                if service_uuid in cvp_cl['config']:
                    cl_config = ''
                    for line in cvp_cl['config'].split('\n'):
                        if service_uuid in line:
                            continue
                        else:
                            cl_config = cl_config + line
                    cl_meta = [{'name': self.__OSM_METADATA, 'config': cl_config}]
                    self.__configlet_modify(cl_meta)
        except Exception as e:
            self.logger.error('Error in removing metadata in CloudVision from OSM for service {}: {}'.
                              format(service_uuid, str(e)))
            pass

    def edit_connectivity_service(self,
                                  service_uuid,
                                  conn_info=None,
                                  connection_points=None,
                                  **kwargs):
        """ Change an existing connectivity service.

        This method's arguments and return value follow the same convention as
        :meth:`~.create_connectivity_service`.

        :param service_uuid: UUID of the connectivity service.
        :param conn_info: (dict or None): Information previously returned
            by last call to create_connectivity_service
            or edit_connectivity_service
        :param connection_points: (list): If provided, the old list of
            connection points will be replaced.
        :param kwargs: Same meaning that create_connectivity_service
        :return: dict or None: Information to be updated and stored at
                the database.
                When ``None`` is returned, no information should be changed.
                When an empty dict is returned, the database record will
                be deleted.
                **MUST** be JSON/YAML-serializable (plain data structures).
        Raises:
            SdnConnectorError: In case of error.
        """
        try:
            self.logger.debug('invoked edit_connectivity_service for service {}. ports: {}'.format(service_uuid,
                                                                                                   connection_points))

            if not service_uuid:
                raise SdnConnectorError(message='Unable to perform operation, missing or empty uuid',
                                        http_code=500)
            if not conn_info:
                raise SdnConnectorError(message='Unable to perform operation, missing or empty connection information',
                                        http_code=500)

            if connection_points is None:
                return None

            self.__get_Connection()

            cls_currentPerSw = conn_info['configLetPerSwitch']
            service_type = conn_info['service_type']

            self.__check_service(service_type,
                                 connection_points,
                                 check_vlan=False,
                                 check_num_cp=False,
                                 kwargs=kwargs)

            s_uid, s_connInf = self.__processConnection(
                                                        service_uuid,
                                                        service_type,
                                                        connection_points,
                                                        kwargs)
            self.logger.info("Service with uuid {} configuration updated".
                             format(s_uid))
            return s_connInf
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except SdnConnectorError as sde:
            raise sde
        except Exception as ex:
            try:
                # Add previous
                # TODO check if there are pending task, and cancel them before restoring
                self.__updateConnection(cls_currentPerSw)
            except Exception as e:
                self.logger.error("Unable to restore configuration in service {} after an error in the configuration updated: {}".
                                  format(service_uuid, str(e)))
            if self.raiseException:
                raise ex
            raise SdnConnectorError(message=str(ex),
                                    http_code=500) from ex

    def clear_all_connectivity_services(self):
        """ Removes all connectivity services from Arista CloudVision with two steps:
        - retrives all the services from Arista CloudVision
        - removes each service
        """
        try:
            self.logger.debug('invoked AristaImpl ' +
                              'clear_all_connectivity_services')
            self.__get_Connection()
            s_list = self.__get_srvUUIDs()
            for serv in s_list:
                conn_info = {}
                conn_info['service_type'] = serv['type']
                conn_info['vlan_id'] = serv['vlan']

                self.delete_connectivity_service(serv['uuid'], conn_info)
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except SdnConnectorError as sde:
            raise sde
        except Exception as ex:
            self.client = None
            self.logger.error(ex)
            if self.raiseException:
                raise ex
            raise SdnConnectorError(message=SdnError.INTERNAL_ERROR,
                                    http_code=500) from ex

    def get_all_active_connectivity_services(self):
        """ Return the uuid of all the active connectivity services with two steps:
        - retrives all the services from Arista CloudVision
        - retrives the status of each server
        """
        try:
            self.logger.debug('invoked AristaImpl {}'.format(
                              'get_all_active_connectivity_services'))
            self.__get_Connection()
            s_list = self.__get_srvUUIDs()
            result = []
            for serv in s_list:
                conn_info = {}
                conn_info['service_type'] = serv['type']
                conn_info['vlan_id'] = serv['vlan']

                status = self.get_connectivity_service_status(serv['uuid'], conn_info)
                if status['sdn_status'] == 'ACTIVE':
                    result.append(serv['uuid'])
            return result
        except CvpLoginError as e:
            self.logger.info(str(e))
            self.client = None
            raise SdnConnectorError(message=SdnError.UNAUTHORIZED,
                                    http_code=401) from e
        except SdnConnectorError as sde:
            raise sde
        except Exception as ex:
            self.client = None
            self.logger.error(ex)
            if self.raiseException:
                raise ex
            raise SdnConnectorError(message=SdnError.INTERNAL_ERROR,
                                    http_code=500) from ex

    def __get_serviceConfigLets(self, service_uuid, service_type, vlan_id):
        """ Return the configLet's associated with a connectivity service,
        There should be one, as maximum, per device (switch) for a given
        connectivity service
        """
        srv_cls = {}
        for s in self.s_api:
            srv_cls[s] = []
            found_in_cvp = False
            name = (self.__OSM_PREFIX +
                    s +
                    self.__SEPARATOR + service_type + str(vlan_id) +
                    self.__SEPARATOR + service_uuid)
            try:
                cvp_cl = self.client.api.get_configlet_by_name(name)
                found_in_cvp = True
            except CvpApiError as error:
                if "Entity does not exist" in error.msg:
                    pass
                else:
                    raise error
            if found_in_cvp:
                srv_cls[s] = cvp_cl
        return srv_cls

    def __get_srvVLANs(self):
        """ Returns a list with all the VLAN id's used in the connectivity services managed
        in tha Arista CloudVision by checking the 'OSM_metadata' configLet where this
        information is stored
        """
        found_in_cvp = False
        try:
            cvp_cl = self.client.api.get_configlet_by_name(self.__OSM_METADATA)
            found_in_cvp = True
        except CvpApiError as error:
            if "Entity does not exist" in error.msg:
                pass
            else:
                raise error
        s_vlan_list = []
        if found_in_cvp:
            lines = cvp_cl['config'].split('\n')
            for line in lines:
                if self.__METADATA_PREFIX in line:
                    s_vlan = line.split(' ')[3]
                else:
                    continue
                if (s_vlan is not None and
                        len(s_vlan) > 0 and
                        s_vlan not in s_vlan_list):
                    s_vlan_list.append(s_vlan)

        return s_vlan_list

    def __get_srvUUIDs(self):
        """ Retrieves all the connectivity services, managed in tha Arista CloudVision
        by checking the 'OSM_metadata' configLet where this information is stored
        """
        found_in_cvp = False
        try:
            cvp_cl = self.client.api.get_configlet_by_name(self.__OSM_METADATA)
            found_in_cvp = True
        except CvpApiError as error:
            if "Entity does not exist" in error.msg:
                pass
            else:
                raise error
        serv_list = []
        if found_in_cvp:
            lines = cvp_cl['config'].split('\n')
            for line in lines:
                if self.__METADATA_PREFIX in line:
                    line = line.split(' ')
                    serv = {'uuid': line[4], 'type': line[2], 'vlan': line[3]}
                else:
                    continue
                if (serv is not None and
                        len(serv) > 0 and
                        serv not in serv_list):
                    serv_list.append(serv)

        return serv_list

    def __get_Connection(self):
        """ Open a connection with Arista CloudVision,
            invoking the version retrival as test
        """
        try:
            if self.client is None:
                self.client = self.__connect()
            self.client.api.get_cvp_info()
        except (CvpSessionLogOutError, RequestException) as e:
            self.logger.debug("Connection error '{}'. Reconnecting".format(e))
            self.client = self.__connect()
            self.client.api.get_cvp_info()

    def __connect(self):
        ''' Connects to CVP device using user provided credentials from initialization.
        :return: CvpClient object with connection instantiated.
        '''
        client = CvpClient()
        protocol, _, rest_url = self.__wim_url.rpartition("://")
        host, _, port = rest_url.partition(":")
        if port and port.endswith("/"):
            port = int(port[:-1])
        elif port:
            port = int(port)
        else:
            port = 443

        client.connect([host],
                       self.__user,
                       self.__passwd,
                       protocol=protocol or "https",
                       port=port,
                       connect_timeout=2)
        client.api = CvpApi(client, request_timeout=self.__API_REQUEST_TOUT)
        self.taskC = AristaCVPTask(client.api)
        return client

    def __compare(self, fromText, toText, lines=10):
        """ Compare text string in 'fromText' with 'toText' and produce
        diffRatio - a score as a float in the range [0, 1] 2.0*M / T
          T is the total number of elements in both sequences,
          M is the number of matches.
          Score - 1.0 if the sequences are identical, and
                  0.0 if they have nothing in common.
        unified diff list
          Code	Meaning
          '- '	line unique to sequence 1
          '+ '	line unique to sequence 2
          '  '	line common to both sequences
          '? '	line not present in either input sequence
        """
        fromlines = fromText.splitlines(1)
        tolines = toText.splitlines(1)
        diff = list(difflib.unified_diff(fromlines, tolines, n=lines))
        textComp = difflib.SequenceMatcher(None, fromText, toText)
        diffRatio = round(textComp.quick_ratio()*100, 2)
        return [diffRatio, diff]

    def __load_inventory(self):
        """ Get Inventory Data for All Devices (aka switches) from the Arista CloudVision
        """
        if not self.cvp_inventory:
            self.cvp_inventory = self.client.api.get_inventory()
        self.allDeviceFacts = []
        for device in self.cvp_inventory:
            self.allDeviceFacts.append(device)

    def __get_tags(self, name, value):
        if not self.cvp_tags:
            self.cvp_tags = []
            url = '/api/v1/rest/analytics/tags/labels/devices/{}/value/{}/elements'.format(name, value)
            self.logger.debug('get_tags: URL {}'.format(url))
            data = self.client.get(url, timeout=self.__API_REQUEST_TOUT)
            for dev in data['notifications']:
                for elem in dev['updates']:
                    self.cvp_tags.append(elem)
        self.logger.debug('Available devices with tag_name {} - value {}: {} '.format(name, value, self.cvp_tags))

    def is_valid_destination(self, url):
        """ Check that the provided WIM URL is correct
        """
        if re.match(self.__regex, url):
            return True
        elif self.is_valid_ipv4_address(url):
            return True
        else:
            return self.is_valid_ipv6_address(url)

    def is_valid_ipv4_address(self, address):
        """ Checks that the given IP is IPv4 valid
        """
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:  # not a valid address
            return False
        return True

    def is_valid_ipv6_address(self, address):
        """ Checks that the given IP is IPv6 valid
        """
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True

    def delete_keys_from_dict(self, dict_del, lst_keys):
        dict_copy = {k: v for k, v in dict_del.items() if k not in lst_keys}
        for k, v in dict_copy.items():
            if isinstance(v, dict):
                dict_copy[k] = self.delete_keys_from_dict(v, lst_keys)
        return dict_copy
