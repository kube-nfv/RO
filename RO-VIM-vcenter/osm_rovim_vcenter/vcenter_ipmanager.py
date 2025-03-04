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
Utility class to get and the the information about ip address
"""
import ipaddress
import logging
import os
import re
import ssl

from osm_ro_plugin import vimconn
from osm_rovim_vcenter import vcenter_util as vcutil
from osm_rovim_vcenter.nsx_client import NsxClient
from osm_rovim_vcenter.vcenter_config import VCenterConfig
from osm_rovim_vcenter.vcenter_network import VCenterNetworkUtil
from osm_rovim_vcenter.vcenter_vms import VCenterVmsUtil
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


class VCenterIpManager:
    """
    Helper class to deal with setting and recovering fixed ip addresses
    """

    def __init__(
        self,
        vc_netutil: VCenterNetworkUtil,
        nsx_url=None,
        nsx_user=None,
        nsx_password=None,
        nsx_verify_ssl=False,
        log_level=None,
        dhcp_configure_always=False,
    ):
        self.logger = logging.getLogger("ro.vim.vcenter.network")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

        self.vc_netutil = vc_netutil
        self.dhcp_configure_always = dhcp_configure_always

        self.nsx_url = nsx_url
        self.nsx_user = nsx_user
        self.nsx_password = nsx_password
        self.nsx_verify_ssl = nsx_verify_ssl

        self.nsx_client = None
        self.logger.debug(
            "Nsx url: %s, nsx_user: %s, nsx_password: %s",
            self.nsx_url,
            self.nsx_url,
            self.nsx_password,
        )
        if self.nsx_url and self.nsx_user and self.nsx_password:
            self.logger.debug("Configure nsx client")
            self.nsx_client = NsxClient(
                nsx_url,
                nsx_user,
                nsx_password,
                verify_ssl=self.nsx_verify_ssl,
                log_level=log_level,
            )

        self.logger = logging.getLogger("ro.vim.vcenter.network")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

    def get_vm_ips(self, session, vm):
        """
        Obtain using vmware tool the ips for the provided vm
        """
        self.logger.debug("Obtain vm fixed ips configuration for vm name: %s", vm.name)

        mac_ips_dict = {}

        if vm.guest.toolsRunningStatus != "guestToolsRunning":
            self.logger.warning(
                "Unable to get vm ips for vm name: '%s' as vm tools is not running",
                vm.name,
            )
        else:
            if vm.guest.net:
                for nic in vm.guest.net:
                    if nic.macAddress and nic.ipAddress:
                        mac_ips_dict[nic.macAddress] = nic.ipAddress
        return mac_ips_dict

    def set_vm_ips(self, session, vm_name, vm, net_list):
        """
        Set the vm fixed ip address using vmware tools, the subnet information (gateway, network
        mask, dns, etc...) is obtained querying the NSX
        """
        self.logger.debug(
            "Set ip address for vm name: %s, net_list: %s", vm.name, net_list
        )

        # 1 - Check data, check if need to set some fixed ip address
        # Obtain interfaces with ip_addresses to set
        nets_fixed_ip = {
            net["net_id"]: net for net in net_list if net.get("ip_address")
        }
        if nets_fixed_ip:
            # Must set some fixed ip, check nsx configuration is provided

            # Check nsx client is configured, only nsx networks are supported:
            # it is needed to obtain subnet parameters and
            # only obtaining them by nsx is supported
            if not self.nsx_client:
                raise vimconn.VimConnException(
                    "Manual ip assigment can not be done as nsx configuration is not provided"
                )
        else:
            # There are not fixed ips to set, if configure to set dhcp configuration do it
            # otherwise return
            if not self.dhcp_configure_always:
                self.logger.debug(
                    "There are not ip fixed address to configure and "
                    "dhcp_configure_always:%s",
                    self.dhcp_configure_always,
                )
                return

        # 2 - Check vmware tools are installed
        if vm.guest.toolsStatus in ["toolsNotInstalled", None]:
            raise vimconn.VimConnException(
                "VMware Tools is not installed or not detected. To assign fixed ip it is required."
            )

        # 3 - Iterate network interfaces and configure ip assignment for each interface
        custom_spec = vim.vm.customization.Specification()
        custom_spec.nicSettingMap = []

        subnet_params_dict = {}
        dns_servers = None

        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualEthernetCard):
                net = self._get_net_with_mac(net_list, device.macAddress)

                if net.get("ip_address"):
                    subnets = self._get_subnets_for_net_id(
                        session, subnet_params_dict, net.get("net_id")
                    )
                    self.logger.debug("Subnets info obtained for net_id: %s", subnets)

                    # Update ip addresses
                    fixed_ip_dict = self._prepare_fixed_ip_dics(
                        net.get("ip_address"), subnets
                    )
                    if not dns_servers:
                        dns_servers = fixed_ip_dict.get("dns_servers")
                    self.logger.debug("Fixed ip dict: %s", fixed_ip_dict)

                    self._update_nic_fixedip_address_spec(
                        custom_spec, net.get("mac_address"), fixed_ip_dict
                    )

                else:
                    self._update_nic_dhcp_spec(custom_spec, device.macAddress)

        # Update vm configuration
        self._customize_ip_address(vm_name, vm, custom_spec, dns_servers)

    @staticmethod
    def _get_net_with_mac(net_list, mac_address):
        net = None
        for net in net_list:
            if net.get("mac_address") == mac_address:
                return net
        if not net:
            raise vimconn.VimConnException(
                f"Unable to find net with previously asigned mac address: {mac_address}"
            )

    def _get_subnets_for_net_id(self, session, subnets_params_dic, net_id):
        """
        Obtains subnet network parameters
        """
        subnets = subnets_params_dic.get(net_id)

        if not subnets:
            # Obtain network using network id
            self.logger.debug("Obtain network with net_id: %s", net_id)
            network = self.vc_netutil.get_network_by_id(session, net_id)
            self.logger.debug("Network revovered: %s", network)

            # Network recovered, do not have to check types because only distributed port groups
            # are supported so far
            if network.config.backingType == "nsx":
                # Obtain subnet parameters for network
                segment_path = network.config.segmentId
                self.logger.debug(
                    "Obtain subnet parameters for nsx segment path: %s", segment_path
                )
                subnets = self.nsx_client.get_nsx_segment_dhcp_config(segment_path)
                subnets_params_dic[net_id] = subnets
            else:
                raise vimconn.VimConnException(
                    f"Network with id: {net_id} is not a backed nsx "
                    "network and assigning fixed ip address is not supported"
                )

        return subnets

    def _prepare_fixed_ip_dics(self, ip_address, subnets):
        # Improvement - check if it should be done something else of more that one subnet is
        # supported for one segment
        fixed_ip_dict = {"ip_address": ip_address}
        subnet = subnets[0]
        gateway = str(ipaddress.IPv4Interface(subnet.get("gateway_address")).ip)
        subnet_mask = str(
            ipaddress.IPv4Network(subnet.get("network"), strict=False).netmask
        )
        fixed_ip_dict["gateway"] = gateway
        fixed_ip_dict["subnet_mask"] = subnet_mask

        dns_servers = subnet.get("dhcp_config", {}).get("dns_servers", [])
        fixed_ip_dict["dns_servers"] = dns_servers
        return fixed_ip_dict

    def _update_nic_fixedip_address_spec(self, custom_spec, mac_address, fixed_ip_dics):

        # Create a Fixed IP object
        fixed_ip = vim.vm.customization.FixedIp(
            ipAddress=fixed_ip_dics.get("ip_address")
        )

        adapter_mapping = vim.vm.customization.AdapterMapping()
        adapter_mapping.adapter = vim.vm.customization.IPSettings(
            ip=fixed_ip,
            subnetMask=fixed_ip_dics.get("subnet_mask"),
            gateway=fixed_ip_dics.get("gateway"),
        )
        adapter_mapping.macAddress = mac_address
        custom_spec.nicSettingMap.append(adapter_mapping)

    def _update_nic_dhcp_spec(self, custom_spec, mac_address):
        adapter_mapping = vim.vm.customization.AdapterMapping()
        adapter_mapping.adapter = vim.vm.customization.IPSettings(
            ip=vim.vm.customization.DhcpIpGenerator()
        )
        adapter_mapping.macAddress = mac_address
        custom_spec.nicSettingMap.append(adapter_mapping)

    def _customize_ip_address(self, vm_name, vm, custom_spec, dns_servers):
        # Check the vm name
        name = self._sanitize_vm_name(vm_name)

        # Optionally configure the hostname
        identity = vim.vm.customization.LinuxPrep(
            domain="domain.local", hostName=vim.vm.customization.FixedName(name=name)
        )
        custom_spec.identity = identity

        global_ip_settings = vim.vm.customization.GlobalIPSettings()
        if dns_servers:
            global_ip_settings = vim.vm.customization.GlobalIPSettings(
                dnsServerList=dns_servers
            )
        custom_spec.globalIPSettings = global_ip_settings

        customize_task = vm.CustomizeVM_Task(spec=custom_spec)
        vcutil.wait_for_task(customize_task)
        self.logger.debug("VM spec updated")

    def _sanitize_vm_name(self, vm_name):
        corrected_vm_name = vm_name.replace("_", "-")[:63]
        if not re.match(r"^[a-zA-Z0-9-]+$", corrected_vm_name):
            raise vimconn.VimConnException(f"Invalid hostname: {corrected_vm_name}")
        return corrected_vm_name


if __name__ == "__main__":
    # Init logger
    log_format = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(funcName)s(): %(message)s"
    logging.basicConfig(
        level=logging.DEBUG,  # Set the logging level
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # Set the log message format
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[
            logging.StreamHandler(),  # Log to the console
        ],
    )
    logger = logging.getLogger("ro.vim.vmware.test_nsx")
    logger.setLevel(level=logging.DEBUG)

    test_nsx_url = os.getenv("NSX_URL")
    test_nsx_user = os.getenv("NSX_USER")
    test_nsx_password = os.getenv("NSX_PASSWORD")

    vcnet_util = VCenterNetworkUtil(log_level="DEBUG")
    vc_ipmanager = VCenterIpManager(
        vc_netutil=vcnet_util,
        nsx_url=test_nsx_url,
        nsx_user=test_nsx_user,
        nsx_password=test_nsx_password,
        log_level="DEBUG",
    )

    vcenter_cluster = os.getenv("TEST_CLUSTER_NAME")
    VCENTER_TENANT_ID = "default"
    VCENTER_TENANT_NAME = "default"
    vc_config = VCenterConfig(
        availability_zones=vcenter_cluster,
        tenant_id=VCENTER_TENANT_ID,
        tenant_name=VCENTER_TENANT_NAME,
        log_level="DEBUG",
    )

    vcenter_cert_path = os.getenv("VCENTER_CERT_PATH")
    vcenter_host = os.getenv("VCENTER_SERVER")
    vcenter_user = os.getenv("VCENTER_USER")
    vcenter_password = os.getenv("VCENTER_PASSWORD")
    ssl_context = ssl.create_default_context(cafile=vcenter_cert_path)
    test_session = SmartConnect(
        host=vcenter_host,
        user=vcenter_user,
        pwd=vcenter_password,
        port=443,
        sslContext=ssl_context,
    )
    logger.debug("Connected to vcenter")

    try:
        # Obtain a vm
        vc_vmsutil = VCenterVmsUtil(vcenter_config=vc_config, log_level="DEBUG")

        # Test set ips
        """
        #vm = vc_vmsutil.get_vm_by_uuid(session, "5035b827-e3c4-1ca4-b689-9fadb1cc78d7")
        vm = vc_vmsutil.get_vm_by_uuid(session, "5035f893-c302-08e3-8465-345165aaf921")
        logger.debug("Vm recovered")
        net_list = [
            {'name': 'eth0', 'net_id': 'vim.dvs.DistributedVirtualPortgroup:dvportgroup-44614', 
                'type': 'SRIOV', 'use': 'data'},
            {'name': 'eth1', 'net_id': 'vim.dvs.DistributedVirtualPortgroup:dvportgroup-47674', 
                'type': 'virtual', 'use': 'data', 'ip_address': '192.168.228.23'}
        ]
        vc_ipmanager.set_vm_ips(session, vm, net_list)
        """

        # Test get ips
        test_vm = vc_vmsutil.get_vm_by_uuid(
            test_session, "50359c0a-41ee-9afc-d21b-e398b8ac1d64"
        )
        mac_ips = vc_ipmanager.get_vm_ips(test_session, test_vm)
        logger.debug("Ip address for vm mac address: %s", mac_ips)
    finally:
        Disconnect(test_session)
        logger.debug("Disconnected to vcenter")
