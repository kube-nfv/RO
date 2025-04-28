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
Utility class to deal with vms in vcenter
"""
import logging
from urllib.parse import quote, unquote

from osm_ro_plugin import vimconn
from osm_rovim_vcenter import vcenter_network as vcnetwork
from osm_rovim_vcenter import vcenter_util as vcutil
from osm_rovim_vcenter.vcenter_config import VCenterConfig
from osm_rovim_vcenter.vcenter_network import VCenterNetworkUtil
from pyVmomi import vim

vmPowerState2osm = {
    "poweredOff": "INACTIVE",
    "poweredOn": "ACTIVE",
    "suspended": "PAUSED",
    "other": "OTHER",
}

# keys for flavor dict
FLAVOR_RAM_KEY = "ram"
FLAVOR_VCPUS_KEY = "vcpus"
FLAVOR_DISK_KEY = "disk"

# Maximum number of devices of an scsi controller
SCSI_CONTROLLER_MAX_DEVICES = 16


class VCenterVmsUtil:
    """
    Utility class to get information about vms
    """

    def __init__(self, vcenter_config: VCenterConfig, log_level=None):
        self.vcenter_config = vcenter_config

        self.logger = logging.getLogger("ro.vim.vcenter.vms")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

    def list_images(self, session, filter_dict=None):
        """
        Obtain images from tenant images folder
        """
        filter_dict = filter_dict or {}

        # Obtain images folder
        images_folder = self.vcenter_config.get_images_folder(session)

        # List images in folder
        image_list = []
        vm_images = self._list_vms(session, images_folder, filter_dict)
        for image in vm_images:
            image_list.append(
                {
                    "id": image.config.instanceUuid,
                    "name": image.name,
                    "moref": image._moId,
                }
            )

        return image_list

    def _list_vms(self, session, folder=None, filter_dict=None):
        """
        Lists vms in a folder, supported filter id (vcenter instanceUuid) and name
        """
        self.logger.debug("List vms for the folder: %s", folder)
        vms = []
        filter_dict = filter_dict or {}

        content = vcutil.get_vcenter_content(session)
        if not folder:
            self.logger.debug("Folder is not provided, search from root folder")
            folder = content.rootFolder

        container = content.viewManager.CreateContainerView(
            folder, [vim.VirtualMachine], True
        )
        for vm in container.view:
            if filter_dict:
                if (
                    filter_dict.get("id")
                    and str(vm.config.instanceUuid) != filter_dict["id"]
                ):
                    continue

                if filter_dict.get("name") and str(vm.name) != filter_dict["name"]:
                    continue

            vms.append(vm)

        return vms

    def get_vm_by_uuid(self, session, vm_id):
        """
        Obtains vm by its uuid
        """
        search_index = session.content.searchIndex
        vm = search_index.FindByUuid(None, vm_id, True, True)
        if vm:
            return vm
        else:
            raise vimconn.VimConnNotFoundException(f"Vm with id: {vm_id} not found")

    def get_image_by_uuid(self, session, image_id):
        """
        Obtains an image from its uuid, today just gets a vm, will leave it this way to be
        able to change it in the future if needed
        """
        return self.get_vm_by_uuid(session, image_id)

    @staticmethod
    def get_vim_vm_basic(vm):
        """
        Creates an object with the vm basic info in the vim format from the vcenter vm data
        """
        vim_vm = {
            "id": vm.config.instanceUuid,
            "name": vm.name,
            "moref": vm._moId,
            "status": vmPowerState2osm.get(vm.runtime.powerState, "other"),
        }
        return vim_vm

    def get_vm_nics_list(self, vm):
        """
        Gets the list of nics for the provided vm and its associated info (dict)
        """
        interfaces_info = []
        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualEthernetCard):
                interface = {}
                interface["vim_interface_id"] = device.key
                interface["mac_address"] = device.macAddress

                # Obtain net_id
                if isinstance(
                    device.backing,
                    vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo,
                ):

                    interface["port_id"] = device.backing.port.portKey
                    interface["vim_net_id"] = (
                        vcnetwork.DISTRIBUTED_PORTGROUP_KEY_PREFIX
                        + device.backing.port.portgroupKey
                    )
                    interface["switch_uuid"] = device.backing.port.switchUuid
                else:
                    self.logger.warning(
                        "nic device type not supported yet %s", {type(device).__name__}
                    )

                # Complete values for vim_info, info from the data
                vim_info = {}
                vim_info["key"] = device.key
                vim_info["controllerKey"] = device.controllerKey
                vim_info["wakeOnLanEnabled"] = device.wakeOnLanEnabled
                if device.deviceInfo:
                    vim_info["label"] = device.deviceInfo.label
                    vim_info["summary"] = device.deviceInfo.summary

                interfaces_info.append(interface)

        return interfaces_info

    def delete_vm(self, session, vm_id):
        """
        Deletes the vm with the indicated instanceUuid, to delete must obtain a refreshed vm
        """
        vm = self.get_vm_by_uuid(session, vm_id)

        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
            powerof_task = vm.PowerOffVM_Task()
            vcutil.wait_for_task(powerof_task)

        destroy_task = vm.Destroy_Task()
        vcutil.wait_for_task(destroy_task)
        self.logger.debug("vm id: %s deleted", vm_id)

    def get_vm_cluster(self, session, vm):
        """
        Obtains the cluster associated to a vm
        """
        host = vm.runtime.host
        cluster = host.parent
        return cluster

    def start_vm(self, vm):
        """
        Starts the provided vm
        """
        if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
            task = vm.PowerOn()
            return task
        else:
            self.logger.warning("WARN : Instance is already started")
            return None

    def stop_vm(self, vm):
        """
        Stops the provided vm
        """
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
            task = vm.PowerOff()
            return task
        else:
            self.logger.warning("WARN : Instance is not in Active state")
            return None

    def get_vm_clone_session_ticket(self, session, vm):
        """
        Obtain a clone session ticket for the indicated vm
        """
        ticket = session.content.sessionManager.AcquireCloneTicket()
        return ticket

    def unattach_volumes(self, session, vm, volumes):
        """
        Unattach the indicated volumes, volumes includes the volume_path quoted
        """
        self.logger.debug("Volumes to unattach: %s", volumes)

        volumes_to_unattach = self._get_devices_from_volume_list(vm, volumes)

        # Unattach devices
        self._unattach_devices(session, vm, volumes_to_unattach)

    def _get_devices_from_volume_list(self, vm, volumes):

        # The list of volumes is identified by the file path encoded, unencode the list
        volume_file_paths = [unquote(volume_id) for volume_id in volumes]
        self.logger.debug("Volume file paths: %s", volume_file_paths)

        # Obtain the devices to unattach
        volumes_to_unattach = []
        for volume_path in volume_file_paths:
            # Flag to check if volume is found
            found = False

            # Iterate over devices in the VM
            for device in vm.config.hardware.device:
                # Check if the device is a VirtualDisk and its backing file matches the volume path
                if (
                    isinstance(device, vim.vm.device.VirtualDisk)
                    and hasattr(device.backing, "fileName")
                    and device.backing.fileName == volume_path
                ):
                    volumes_to_unattach.append(device)
                    found = True
                    break  # Exit the inner loop as the volume is found

            # Log a warning if volume is not found
            if not found:
                self.logger.warning(
                    "Volume path '%s' not found in VM device list.", volume_path
                )

        return volumes_to_unattach

    def _unattach_devices(self, session, vm, device_list):
        """
        Unattach the indicated list of devices
        """
        if device_list:
            change_spec = vim.vm.ConfigSpec()
            change_spec.deviceChange = []

            for device in device_list:
                device_change = vim.vm.device.VirtualDeviceSpec()
                device_change.operation = (
                    vim.vm.device.VirtualDeviceSpec.Operation.remove
                )
                device_change.device = device
                change_spec.deviceChange.append(device_change)

            # Reconfigure vm
            task = vm.ReconfigVM_Task(spec=change_spec)
            vcutil.wait_for_task(task)
            self.logger.debug("Devices unattached")

        else:
            self.logger.warning("No devices to unattach provided, will do nothing")

    def reconfig_vm(self, session, vm, reconfig_spec):
        """
        Reconfigure the indicated vm with the provided reconfigure spec
        """
        if reconfig_spec:
            # Reconfigure vm
            task = vm.ReconfigVM_Task(spec=reconfig_spec)
            vcutil.wait_for_task(task)
            self.logger.debug("Vm reconfigured")

    def prepare_unattach_volumes(self, vm, volumes, unattach_spec):
        """
        Prepares an unattach spec to be able to unattach volumes to keep
        """
        self.logger.debug("Prepare unattach volumes: %s", volumes)
        unattach_device_list = self._get_devices_from_volume_list(vm, volumes)

        # Prepare unattach spec
        unattach_spec = self._prepare_unattach_spec(unattach_spec, unattach_device_list)

        return unattach_spec

    def prepare_unattach_cloudinitiso(self, vm, cloudinitiso_list, unattach_spec):
        """
        Prepares an unattach spec to be able to unattach iso
        """
        self.logger.debug("Prepare unattach cloudinitiso: %s", cloudinitiso_list)
        unattach_device_list = self._get_cdromiso_from_list(vm, cloudinitiso_list)

        # Prepare unattach spec
        unattach_spec = self._prepare_unattach_spec(unattach_spec, unattach_device_list)

        return unattach_spec

    def _prepare_unattach_spec(self, change_spec, devices_to_unattach):
        # Prepare unattach spec
        if not change_spec:
            change_spec = vim.vm.ConfigSpec()
            change_spec.deviceChange = []

        for device in devices_to_unattach:
            device_change = vim.vm.device.VirtualDeviceSpec()
            device_change.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
            device_change.device = device
            change_spec.deviceChange.append(device_change)

        return change_spec

    def _get_cdromiso_from_list(self, vm, cloudinitiso_list):

        # The list of volumes is identified by the file path encoded, unencode the list
        cloudinitiso_paths = [
            unquote(cloudinitiso) for cloudinitiso in cloudinitiso_list
        ]
        self.logger.debug("Cloud init iso: %s", cloudinitiso_paths)

        # Obtain the iso cdrom to unattach
        devices_to_unattach = []
        for cloudinitiso_file in cloudinitiso_paths:
            found = False

            # Iterate over devices in the VM
            for device in vm.config.hardware.device:
                # Check if the device is a VirtualCdRom and its backing file matches the volume path
                if (
                    isinstance(device, vim.vm.device.VirtualCdrom)
                    and hasattr(device.backing, "fileName")
                    and device.backing.fileName == cloudinitiso_file
                ):
                    devices_to_unattach.append(device)
                    found = True
                    break  # Exit the inner loop as the volume is found

            # Log a warning if volume is not found
            if not found:
                self.logger.warning(
                    "Iso path '%s' not found in VM device list.", cloudinitiso_file
                )

        return devices_to_unattach

    def delete_iso_files(self, session, iso_file_list):
        """
        Deletes the file indicated in the isp_file_list,
        The file path is quoted and must be unquoted before delete
        """
        self.logger.debug("Delete files: %s", iso_file_list)

        isofile_paths = [unquote(cloudinitiso) for cloudinitiso in iso_file_list]
        for file_path in isofile_paths:
            self.delete_datastore_file(session, file_path)

    def delete_datastore_file(self, session, file_path):
        """
        Deletes the file indicated in the file_path
        """
        try:
            # Retrieve the file manager
            self.logger.debug("Delete the file: %s", file_path)
            file_manager = session.content.fileManager

            # Get the first datacenter (assuming a single datacenter scenario)
            datacenter = session.content.rootFolder.childEntity[0]

            # Start the delete task
            task = file_manager.DeleteDatastoreFile_Task(
                name=file_path, datacenter=datacenter
            )
            vcutil.wait_for_task(task)
            self.logger.debug("File deleted")

        except vim.fault.FileNotFound:
            # File does not exist
            self.logger.warning("File %s does not exist. No action taken.", file_path)

    def _create_cluster_rule(self, session, cluster, rule_name, rule_type, vms):
        """
        Creates a cluster rule with the indicated type
        Args:
        - session: vcenter session
        - cluster: cluster where the rule will be created
        - rule_name: name of the rule to be created
        - rule_type: type of rule, possible values affinity and anti-affinity
        - vms: list of vms to be added to the rule
        """
        self.logger.debug("Going to create affinity group: %s", rule_name)

        rule_spec = vim.cluster.RuleSpec()

        rule_info = None
        if rule_type == "affinity":
            rule_info = vim.cluster.AffinityRuleSpec()
        elif rule_type == "anti-affinity":
            rule_info = vim.cluster.AntiAffinityRuleSpec()
        else:
            raise vimconn.VimConnException(f"Invalid affinity type: {rule_type}")

        rule_info.enabled = False
        rule_info.mandatory = False  # get from configuration
        rule_info.name = rule_name
        rule_info.vm = vms

        rule_spec.info = rule_info
        rule_spec.operation = "add"

        rule_config_spec = vim.cluster.ConfigSpecEx(rulesSpec=[rule_spec])

        task = cluster.ReconfigureEx(rule_config_spec, modify=True)
        vcutil.wait_for_task(task)
        self.logger.debug("Affinity group name: %s created", rule_name)

    def _get_cluster_rule_by_name(self, session, cluster, name):
        """
        Find a rule by its name.

        Args:
            session: The session object (context or connection object).
            cluster: The cluster object containing rules.
            name (str): The name of the rule to find.

        Returns:
            The rule object if found, otherwise None.
        """
        self.logger.debug("Find cluster rule with name: %s", name)
        rules = cluster.configurationEx.rule
        if not rules:
            return None

        for rule in rules:
            if rule.name == name:
                return rule

        return None

    def _add_vm_to_affinity_rule(self, session, cluster, cluster_rule, vm):
        """
        Adds a vm to an existing cluster rule
        """
        self.logger.debug("Add vm to affinity rule name: %s", cluster_rule.name)

        # Add VM to the Rule
        cluster_rule.vm.append(vm)

        # Enable the rule as rules with less that 2 vms must be disabled
        if len(cluster_rule.vm) > 1:
            cluster_rule.enabled = True

        # Reconfigure the Cluster with the Updated Rule
        spec = vim.cluster.ConfigSpecEx()
        spec.rulesSpec = [vim.cluster.RuleSpec(operation="edit", info=cluster_rule)]
        task = cluster.ReconfigureComputeResource_Task(spec=spec, modify=True)
        vcutil.wait_for_task(task)
        self.logger.debug("Affinity rule edited successfully.")

    def _delete_cluster_rule(self, session, cluster, affinity_rule):
        """
        Delete a cluster rule from a cluster
        """
        # Delete the Rule
        spec = vim.cluster.ConfigSpecEx()
        rule_spec = vim.cluster.RuleSpec(
            operation="remove", removeKey=affinity_rule.key
        )
        spec.rulesSpec = [rule_spec]

        # Step 4: Reconfigure the Cluster
        task = cluster.ReconfigureComputeResource_Task(spec=spec, modify=True)
        vcutil.wait_for_task(task)
        self.logger.debug("Affinity rule %s deleted.", affinity_rule.name)

    def add_vm_or_create_affinity_group(
        self, session, cluster, affinity_group_name, affinity_group_type, vm
    ):
        """
        Method that manages adding a vm to a cluster rule. If the cluster_rule does
        not exist it creates it, otherwise adds the machine to the cluster rule

        Args:
        - session
        - cluster
        - affinity_group_name: Name of the cluster rule to be used
        - affinity_group_type
        - vm
        """
        self.logger.debug(
            "Add vm name: %s to affinity_group_name: %s", vm.name, affinity_group_name
        )

        # Find if affinity group exists
        affinity_group = self._get_cluster_rule_by_name(
            session, cluster, affinity_group_name
        )

        if not affinity_group:

            # If affinity group does not exist create
            self._create_cluster_rule(
                session, cluster, affinity_group_name, affinity_group_type, [vm]
            )
        else:
            # Add vm to affinity group
            self._add_vm_to_affinity_rule(session, cluster, affinity_group, vm)

    def delete_vm_affinity_rule(self, session, cluster, affinity_rule_name, vm_name):
        """
        Removest the machine with the provided name from the cluster affinity rule
        with name affinity_rule_name
        """
        self.logger.debug(
            "Remove vm: %s from affinity rule name: %s", vm_name, affinity_rule_name
        )

        # Find affinity rule
        affinity_rule = self._get_cluster_rule_by_name(
            session, cluster, affinity_rule_name
        )
        if not affinity_rule:
            # warning, affinity rule not found, unable to delete, do nothing
            self.logger.warning(
                "Affinity rule with name: %s not found, unable to delete",
                affinity_rule_name,
            )

        else:
            found = False
            for vm in affinity_rule.vm:
                if vm.name == vm_name:
                    affinity_rule.vm.remove(vm)
                    found = True

            if found and len(affinity_rule.vm) > 0:
                # Reconfigure affinity rule
                spec = vim.cluster.ConfigSpecEx()
                spec.rulesSpec = [
                    vim.cluster.RuleSpec(operation="edit", info=affinity_rule)
                ]
                task = cluster.ReconfigureComputeResource_Task(spec=spec, modify=True)
                vcutil.wait_for_task(task)
                self.logger.debug(
                    "Affinity rule %s edited successfully.", affinity_rule_name
                )

            elif len(affinity_rule.vm) == 0:
                # No vms left delete affinity group
                self._delete_cluster_rule(session, cluster, affinity_rule)

    def disconnect_vms_from_dpg(self, session, net_id, vms):
        """
        Disconnects the indicated list of vms from the network with id: net_id
        """
        self.logger.debug("Disconnect vms for from net id: %s", net_id)

        # Stop vms that are started
        stopped_vms = self.stop_vm_list(session, vms)

        # Disconnect vms
        port_group_id = net_id.removeprefix(vcnetwork.DISTRIBUTED_PORTGROUP_KEY_PREFIX)
        self._disconnect_vms(session, port_group_id, vms)

        # Restart vms
        self.start_vm_list(session, stopped_vms)

    def _disconnect_vms(self, session, port_group_id, vms):
        """
        Disconnects a list of vms from a net, the vms should be already stopped before
        calling this method
        """
        task_list = []
        for vm in vms:
            task = self._disconnect_vm(session, port_group_id, vm)
            if task:
                task_list.append(task)

        if task_list:
            # wait until all tasks are completed
            vcutil.wait_for_tasks(task_list)

    def _disconnect_vm(self, session, port_group_id, vm):
        """
        Disconnect vm from port_group
        """

        self.logger.debug(
            "Disconnect vm name: %s from port_group_id: %s", vm.name, port_group_id
        )
        task = None

        # Disconnect port group
        spec = vim.vm.ConfigSpec()
        device_changes = []

        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualEthernetCard):
                if isinstance(
                    device.backing,
                    vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo,
                ):
                    if device.backing.port.portgroupKey == port_group_id:
                        nic_spec = vim.vm.device.VirtualDeviceSpec()
                        nic_spec.operation = (
                            vim.vm.device.VirtualDeviceSpec.Operation.remove
                        )  # Remove the NIC
                        nic_spec.device = device
                        device_changes.append(nic_spec)

        if device_changes:
            spec.deviceChange = device_changes
            task = vm.ReconfigVM_Task(spec=spec)

        return task

    def stop_vm_list(self, session, vms):
        """
        Stop the vms in the provided list if they are started
        """
        stopped_vms = []
        task_stop_list = []

        for vm in vms:
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                task = vm.PowerOff()
                task_stop_list.append(task)
                stopped_vms.append(vm)

        if task_stop_list:
            # wait until all tasks are completed
            vcutil.wait_for_tasks(task_stop_list)

        return stopped_vms

    def start_vm_list(self, session, vms):
        """
        Start the vms in the provided list
        """
        started_vms = []
        task_start_list = []

        for vm in vms:
            if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
                task = vm.PowerOn()
                task_start_list.append(task)
                started_vms.append(vm)

        if task_start_list:
            # wait until all tasks are completed
            vcutil.wait_for_tasks(task_start_list)

        return started_vms


class VCenterVmsOps:
    """
    Helper class to create properly configured vms or to deal with vms configuration
    """

    def __init__(
        self,
        vc_config: VCenterConfig,
        vc_vmsutil: VCenterVmsUtil,
        vc_netutil: VCenterNetworkUtil,
        session,
    ):
        self.vc_config = vc_config
        self.vc_vmsutil = vc_vmsutil
        self.vcnet_util = vc_netutil

        # Connection is provided to this object as it used just to deal with operating on vms
        self.session = session

        self.logger = self.vc_vmsutil.logger

    def prepare_vm_base_config(self, vm_name, flavor, image):
        """
        Prepares the base config spec in pyvmomi for the new vm
        """
        self.logger.debug("Prepare vmconfig spec")

        vm_config_spec = vim.vm.ConfigSpec()
        vm_config_spec.name = vm_name
        vm_config_spec.memoryMB = flavor.get(FLAVOR_RAM_KEY)
        vm_config_spec.numCPUs = flavor.get(FLAVOR_VCPUS_KEY)
        vm_config_spec.guestId = image.config.guestId

        # Get image metadata
        metadata = self._get_vm_metadata(vm_name, flavor, image)
        vm_config_spec.annotation = metadata

        device_changes = []
        vm_config_spec.deviceChange = device_changes
        return vm_config_spec

    def _get_vm_metadata(self, vm_name, flavor, image):

        metadata = []
        metadata.append(("name", vm_name))
        metadata.append(("imageid", image.config.instanceUuid))
        for prop_name, value in flavor.items():
            metadata.append((f"flavor:{prop_name}", value))
        return "".join(["%s:%s\n" % (k, v) for k, v in metadata])

    def prepare_vm_main_disk(self, flavor, image_vm, vm_config_spec, new_datastore):
        """
        Obtain main disk from image and modify its size to clone it
        """
        # review - the code i have here considers there is only one main disk,
        # ¿is it possible this is not the case?
        self.logger.debug("Prepare main disk size: %s", flavor.get(FLAVOR_DISK_KEY))
        new_disk_size_gb = flavor.get(FLAVOR_DISK_KEY)

        # Update spec
        device_changes = vm_config_spec.deviceChange
        for device in image_vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk):
                disk_spec = vim.vm.device.VirtualDeviceSpec()
                disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
                disk_spec.device = device

                # Check old capacity is not less that new one
                curr_disk_capacity_gb = disk_spec.device.capacityInKB / (1024 * 1024)
                self.logger.debug("Obtained main disk, size: %s", curr_disk_capacity_gb)
                if curr_disk_capacity_gb > new_disk_size_gb:
                    raise vimconn.VimConnException(
                        f"New disk size : {new_disk_size_gb} can not be lower that image size: "
                        f" {curr_disk_capacity_gb}"
                    )

                # Set new capacity
                disk_spec.device.capacityInKB = (
                    new_disk_size_gb * 1024 * 1024
                )  # Convert GB to KB

                # in case at some point is it seen it is needed it is also possible to specify datastore

                device_changes.append(disk_spec)

    def prepare_vm_networks(self, net_list, template_vm, vm_config_spec):
        """
        Prepare configuration to add network interfaces to the new vm
        """

        # Obtain device_changes to update configuration
        device_changes = vm_config_spec.deviceChange

        # Remove existing network interfaces in case they exist
        self._prepare_remove_existing_nics(template_vm, device_changes)

        # Add a nic for each net
        for net in net_list:
            # Skip non-connected iface
            if not net.get("net_id"):
                self.logger.debug(f"Skipping unconnected interface: {net}")
                continue

            self.logger.debug(f"Prepare nic for net: {net}")
            nic_spec = self._prepare_vm_nic(net, vm_config_spec)
            device_changes.append(nic_spec)

    def _prepare_remove_existing_nics(self, template_vm, device_changes):
        for device in template_vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualEthernetCard):
                self.logger.debug(
                    "Remove existing nic from template, label: %s",
                    device.deviceInfo.label,
                )
                nic_spec = vim.vm.device.VirtualDeviceSpec()
                nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
                nic_spec.device = device
                device_changes.append(nic_spec)

    def _prepare_vm_nic(self, net, vm_config_spec):

        mac_address = net.get("mac_address", None)

        # Get network from network id
        self.logger.debug("Prepare nic configuration net_id: %s", net.get("net_id"))
        network = self.vcnet_util.get_network_by_id(self.session, net.get("net_id"))
        self.logger.debug(f"Recovered network: {network}")
        self.logger.debug(f"Recovered network: {network.key}")
        self.logger.debug(
            f"Recovered network: {network.config.distributedVirtualSwitch.uuid}"
        )

        # Obtain an available key
        key = self.get_unused_device_key(vm_config_spec.deviceChange)

        # Prepare nic specification
        nic_spec = vim.vm.device.VirtualDeviceSpec()
        nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add

        # Create the right adapter for the type of network
        nic = None
        nic_type = net.get("type")
        if nic_type == "virtual":
            nic = vim.vm.device.VirtualVmxnet3()
        elif nic_type == "SR-IOV":
            nic = vim.vm.device.VirtualSriovEthernetCard()

            # If we have sriov interfaces must reserve all memory
            vm_config_spec.memoryReservationLockedToMax = True
        else:
            self.logger.debug("Nic type: %s not supported", nic_type)
            raise vimconn.VimConnException(f"Nic type: {nic_type} not supported")

        nic.backing = (
            vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
        )
        nic.backing.port = vim.dvs.PortConnection()
        nic.backing.port.portgroupKey = network.key
        nic.backing.port.switchUuid = network.config.distributedVirtualSwitch.uuid

        nic.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        nic.connectable.startConnected = True
        nic.connectable.allowGuestControl = True
        nic.wakeOnLanEnabled = True

        # Assign mac address if exists
        if mac_address:
            nic.addressType = "manual"
            nic.macAddress = mac_address

        # Assign key
        nic.key = key
        nic_spec.device = nic
        return nic_spec

    def prepare_vm_quotas(self, extended_flavor_quotas, vm_config_spec):
        """
        Prepares the vm quotas configuration
        """
        self.logger.debug("Prepare quotas configuration: %s", extended_flavor_quotas)

        if extended_flavor_quotas.get("cpu-quota"):
            vm_config_spec.cpuAllocation = self._prepare_resource_allocation_config(
                extended_flavor_quotas.get("cpu-quota")
            )

        if extended_flavor_quotas.get("mem-quota"):
            vm_config_spec.memoryAllocation = self._prepare_resource_allocation_config(
                extended_flavor_quotas.get("mem-quota")
            )

    def _prepare_resource_allocation_config(self, quota_config):
        self.logger.debug("Prepare resource allocation config: %s", quota_config)
        resource_allocation = vim.ResourceAllocationInfo()
        if quota_config.get("reserve"):
            resource_allocation.reservation = quota_config.get("reserve")
        if quota_config.get("limit"):
            resource_allocation.limit = quota_config.get("limit")
        if quota_config.get("shares"):
            resource_allocation.shares = vim.SharesInfo(
                level="custom", shares=quota_config.get("shares")
            )

        self.logger.debug("Resource allocation config done")
        return resource_allocation

    def attach_cdrom(self, vm, iso_filename):
        """
        Attaches the indicated iso file to the provided vm,the iso file must be already
        uploaded in vmware vcenter
        """
        self.logger.debug(
            "Attach iso to vm: '%s', iso file: '%s'", vm.name, iso_filename
        )

        # 1 - Find free IDE controller
        controller_key = self._find_free_ide_controller(vm)

        # 2 - Build iso attach specification
        device_spec = self._prepare_cdrom_spec(controller_key, iso_filename)
        config_spec = vim.vm.ConfigSpec(deviceChange=[device_spec])

        # 3 - Must set the boot order as to start from cd
        config_spec.bootOptions = vim.vm.BootOptions(
            bootOrder=[vim.vm.BootOptions.BootableCdromDevice()]
        )

        # 4 - Reconfigure the vm to attach cd-rom
        self.reconfigure_vm(vm, config_spec)

    def _find_free_ide_controller(self, vm):
        """
        Finds a free ide controller in the provided vm
        """
        for dev in vm.config.hardware.device:
            if isinstance(dev, vim.vm.device.VirtualIDEController):
                # If there are less than 2 devices attached, we can use it.
                if len(dev.device) < 2:
                    return dev.key
        return None

    def _prepare_cdrom_spec(self, controller_key, iso_filename):

        device_spec = vim.vm.device.VirtualDeviceSpec()
        device_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add

        cdrom = vim.vm.device.VirtualCdrom()
        cdrom.controllerKey = controller_key
        cdrom.key = -1

        backing = vim.vm.device.VirtualCdrom.IsoBackingInfo()
        backing.fileName = iso_filename
        # backing.datastore = datastore
        cdrom.backing = backing

        connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        connectable.allowGuestControl = True
        connectable.startConnected = True
        cdrom.connectable = connectable

        device_spec.device = cdrom
        return device_spec

    def reconfigure_vm(self, vm, new_config_spec):
        """
        Reconfigure vm with the changes indicated in new_config_spec
        """
        self.logger.debug("Reconfigure vm name: '%s'", vm.name)
        task = vm.Reconfigure(new_config_spec)
        vcutil.wait_for_task(task)
        self.logger.debug("Vm name: '%s' reconfigured", vm.name)

    def prepare_ephemeral_disk(
        self, original_vm, vm_config_spec, datastore, disk_size_gb, created_items
    ):
        """
        Prepares the specification for an ephemeral disk
        """
        self.logger.debug("Prepare ephemeral disk size: %s", disk_size_gb)

        disk_folder = vm_config_spec.name
        disk_name = f"{vm_config_spec.name}-ephemeral"
        device_spec = self._prepare_disk_spec(
            original_vm=original_vm,
            vm_config_spec=vm_config_spec,
            datastore=datastore,
            disk_folder=disk_folder,
            disk_name=disk_name,
            disk_size_gb=disk_size_gb,
        )
        if not vm_config_spec.deviceChange:
            vm_config_spec.deviceChange = []
        vm_config_spec.deviceChange.append(device_spec)

    def prepare_permanent_disk(
        self, original_vm, vm_config_spec, datastore, disk, disk_index, created_items
    ):
        """
        Creates a permanent disk, if the disk must be kept after the vm is deleted
        create the disk in another folder
        """
        self.logger.debug(
            "Prepare persisten volume disk index: %s, size: %s, name: %s",
            disk_index,
            disk.get("size"),
            disk.get("name"),
        )

        disk_folder = vm_config_spec.name
        disk_name = f'{vm_config_spec.name}-{disk.get("name")}-{disk_index}'

        device_spec = self._prepare_disk_spec(
            original_vm=original_vm,
            vm_config_spec=vm_config_spec,
            datastore=datastore,
            disk_folder=disk_folder,
            disk_name=disk_name,
            disk_size_gb=disk.get("size"),
        )

        # Will use disk path as id as if the disk is unattache it has no other id in vcenter
        disk_id = device_spec.device.backing.fileName
        self.logger.debug("Created disk id: %s", disk_id)

        # Append to device_change so that the data will be stored
        if not vm_config_spec.deviceChange:
            vm_config_spec.deviceChange = []
        vm_config_spec.deviceChange.append(device_spec)

        # Return in created items, id is url encoded to avoid problems from spaces
        volume_txt = "volume:" + quote(disk_id)
        if disk.get("keep"):
            volume_txt += ":keep"
        created_items[volume_txt] = True

    def _prepare_disk_spec(
        self,
        original_vm,
        vm_config_spec,
        datastore,
        disk_size_gb,
        disk_folder=None,
        disk_name=None,
    ):
        # Validate disk size gb is an int > 0

        # Get the full list of devices and on the full list obtain free scsi controller
        # and unit number
        devices = self._get_complete_device_list(original_vm, vm_config_spec)
        controller_key, unit_number = self._get_scsi_controller_key_unit_number(devices)
        datastore_name = datastore.info.name

        # Create a new device spec
        device_spec = vim.vm.device.VirtualDeviceSpec()
        device_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        device_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create

        # Disk backing configuration
        disk_backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_backing.diskMode = "persistent"
        disk_backing.thinProvisioned = True  # Optional: Set True for thin provisioning
        disk_backing.datastore = datastore  # Use the first datastore by default
        if disk_folder and disk_name:
            # If this folder and name are not provided vcenter sets a default filename
            disk_backing.fileName = f"[{datastore_name}] {disk_folder}/{disk_name}.vmdk"

        # Disk size in KB (1 GB = 1024 * 1024 KB)
        disk_size_kb = int(disk_size_gb) * 1024 * 1024

        disk = vim.vm.device.VirtualDisk()
        disk.capacityInKB = disk_size_kb
        disk.backing = disk_backing
        disk.controllerKey = controller_key
        disk.unitNumber = unit_number
        disk.key = self.get_unused_device_key(vm_config_spec.deviceChange)

        device_spec.device = disk
        return device_spec

    def _get_complete_device_list(self, original_vm, vm_config_spec):
        devices = []
        # Add original vm list to devices
        devices.extend(original_vm.config.hardware.device)
        # Just add also devices in new config spec, if device is add it will be in the new list
        # In case it is edit may be added twice, for delete devices i can not reuse unit yet
        changed_devices = [
            device_spec.device for device_spec in vm_config_spec.deviceChange
        ]
        devices.extend(changed_devices)
        return devices

    def _get_scsi_controller_key_unit_number(self, devices):
        """
        Obtains an available scsi controller key and unit number
        """
        scsi_keys = [dev.key for dev in devices if self._is_scsi_controller(dev)]
        allocated_slots = self._find_allocated_slots(devices, scsi_keys)
        self.logger.debug("scsi controller keys: %s", scsi_keys)
        self.logger.debug("allocated slots: %s", allocated_slots)
        result = self._find_controller_slot(
            scsi_keys, allocated_slots, SCSI_CONTROLLER_MAX_DEVICES
        )
        if not result:
            raise vimconn.VimConnException(
                "Unable to find valid controller key to add a valid disk"
            )
        else:
            self.logger.debug("Obtained controller key and unit number: %s", result)
            return result

    @staticmethod
    def _is_scsi_controller(device):
        scsi_controller_types = (
            vim.vm.device.VirtualLsiLogicController,
            vim.vm.device.VirtualLsiLogicSASController,
            vim.vm.device.VirtualBusLogicController,
            vim.vm.device.ParaVirtualSCSIController,
        )
        return isinstance(device, scsi_controller_types)

    def _find_allocated_slots(self, devices, controller_keys):
        allocated = {}
        for device in devices:
            self.logger.debug("Find allocated slots, device: %s", device)
            if (
                (device.controllerKey is not None)
                and (device.controllerKey in controller_keys)
                and (device.unitNumber is not None)
            ):
                unit_numbers = allocated.setdefault(device.controllerKey, [])
                unit_numbers.append(device.unitNumber)
        return allocated

    @staticmethod
    def _find_controller_slot(controller_keys, taken, max_unit_number):
        for controller_key in controller_keys:
            for unit_number in range(max_unit_number):
                if unit_number not in taken.get(controller_key, []):
                    return controller_key, unit_number

    @staticmethod
    def get_unused_device_key(device_specs):
        """
        Finds the next unused negative key for a list of device specs.
        keys are temporary but

        Args:
            device_specs (list): List of vim.vm.device.VirtualDeviceSpec objects.

        Returns:
            int: The next unused negative key.
        """
        # Collect all used negative keys
        device_keys = set()
        for device_spec in device_specs:
            if device_spec.operation == vim.vm.device.VirtualDeviceSpec.Operation.add:
                device_keys.add(device_spec.device.key)

        # Find the smallest unused negative key
        next_negative_key = -1
        while next_negative_key in device_keys:
            next_negative_key -= 1

        return next_negative_key
