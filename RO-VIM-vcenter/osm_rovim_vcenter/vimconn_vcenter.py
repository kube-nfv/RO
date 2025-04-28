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
New vmware vcenter plugin documentation
"""
import logging
import ssl
from urllib.parse import quote, urlparse
import uuid

from osm_ro_plugin import vimconn
from osm_rovim_vcenter import vcenter_util as vcutil
from osm_rovim_vcenter import vcenter_vms as vcvmutil
from osm_rovim_vcenter.vcenter_config import VCenterConfig
from osm_rovim_vcenter.vcenter_ipmanager import VCenterIpManager
from osm_rovim_vcenter.vcenter_network import VCenterNetworkUtil
from osm_rovim_vcenter.vcenter_util import VCenterFileUploader
from osm_rovim_vcenter.vcenter_util import VCenterSessionPool
from osm_rovim_vcenter.vcenter_vms import VCenterVmsOps
from osm_rovim_vcenter.vcenter_vms import VCenterVmsUtil
from osm_rovim_vcenter.vim_helper import CloudInitHelper
from pyVmomi import vim
import yaml


def handle_connector_exceptions(func):
    """
    Decorator function that handles and reraises exceptions
    """

    def format_exception(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            vimconnector._format_raise_exception(e)

    return format_exception


DEFAULT_OSM_TENANT_NAME = "default"


class vimconnector(vimconn.VimConnector):
    """
    RO Vcenter plugin main class
    """

    # Dict to store flavors in memory, stores flavors with key id
    _flavorlist = {}

    # Affinity groups, will use the name as id, will not allow duplicates because
    # if we have duplicates we will not be able to know if they we must create a new affinity
    # group or not
    _affinity_groups = {}

    def __init__(
        self,
        uuid=None,
        name=None,
        tenant_id=None,
        tenant_name=None,
        url=None,
        url_admin=None,
        user=None,
        passwd=None,
        log_level=None,
        config={},
        persistent_info={},
    ):
        """
        TODO - documentation
        :param uuid:
        :param name:
        :param tenant_id:
        :param tenant_name:
        :param url:
        :param url_admin:
        :param user:
        :param passwd:
        :param log_level:
        :param config:
        :param persistent_info:
        """
        vimconn.VimConnector.__init__(
            self,
            uuid,
            name,
            tenant_id,
            tenant_name,
            url,
            url_admin,
            user,
            passwd,
            log_level,
            config,
        )

        self.logger = logging.getLogger("ro.vim.vcenter")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))
            self.log_level = log_level

        self.persistent_info = persistent_info

        self.logger.info(
            "Initializing vcenter plugin, name:%s, uuid: %s, tenant_name: %s",
            name,
            uuid,
            tenant_name,
        )
        self.logger.info("Connection info, url: %s, user: %s", url, user)
        self.logger.info("Config information: %s ", config)
        self.logger.info("Persistent info: %s", persistent_info)

        # Parse the URL to extract the hostname
        parsed_url = urlparse(url)
        self.vcenter_hostname = parsed_url.hostname

        # Default port is 443
        self.vcenter_port = (
            parsed_url.port
            if parsed_url.port
            else (443 if parsed_url.scheme == "https" else 80)
        )
        self.logger.debug(
            "vcenter_hostname: %s, vcenter_port: %s",
            self.vcenter_hostname,
            self.vcenter_port,
        )

        # Prepare ssl context
        if self.config.get("insecure") and self.config.get("ca_cert"):
            raise vimconn.VimConnException(
                "options insecure and ca_cert are mutually exclusive"
            )
        elif self.config.get("insecure") is None and self.config.get("ca_cert") is None:
            raise vimconn.VimConnException(
                "either providing certificates or selecting insecure connection is required"
            )

        if self.config.get("insecure"):
            self.logger.warning("Using insecure ssl context")
            self.ssl_context = ssl._create_unverified_context()

        if self.config.get("ca_cert"):
            self.logger.debug("ca_cert path: %s", self.config.get("ca_cert"))
            self.ssl_context = ssl.create_default_context(
                cafile=self.config.get("ca_cert")
            )

        # Assign default tenant name if not provided
        # Check with null because there seems to be
        # an error on upper layer that sets null when not provided
        if not tenant_name or tenant_name == "null":
            self.tenant_name = DEFAULT_OSM_TENANT_NAME

        # Availability zone: by the moment will support just one but is is required
        # Availibity zone must correspond to a cluster or resource pool name
        self.availability_zone = self.config.get("availability_zone")
        if not self.availability_zone:
            raise vimconn.VimConnException(
                "Config parameter availability_zone is required"
            )

        # Allow to indicate distributed virtual switch, ¿could we support more than one?
        self.dvs_names = self.config.get("availability_network_zone")
        if not self.dvs_names:
            raise vimconn.VimConnException(
                "Config parameter availability_network_zone is required"
            )

        # Datasource configuration
        self.datastore = self.config.get("datastore")
        if not self.datastore:
            raise vimconn.VimConnException("Config parameter datastore is required")

        # Nsx configuration
        self.nsx_url = self.config.get("nsx_url")
        self.nsx_user = self.config.get("nsx_user")
        self.nsx_password = self.config.get("nsx_password")
        self.nsx_verify_ssl = False
        if self.config.get("nsx_ca_cert"):
            self.nsx_verify_ssl = self.config.get("nsx_ca_cert")

        self.dhcp_configure_always = self.config.get("dhcp_configure_always", False)

        # Initialize vcenter helper objects
        self.vcenter_fileuploader = VCenterFileUploader(
            self.vcenter_hostname,
            self.vcenter_port,
            self.user,
            self.passwd,
            self.config.get("ca_cert", None),
            log_level=log_level,
        )
        self.vcenter_config = VCenterConfig(
            self.availability_zone,
            tenant_id,
            self.tenant_name,
            datastore_name=self.datastore,
            distributed_switches_names=self.dvs_names,
            log_level=log_level,
        )
        self.vcnet_util = VCenterNetworkUtil(log_level=log_level)
        self.vcvms_util = VCenterVmsUtil(self.vcenter_config, log_level=log_level)
        self.cloudinit_helper = CloudInitHelper(log_level=log_level)
        self.vcenter_ipmanager = VCenterIpManager(
            vc_netutil=self.vcnet_util,
            nsx_url=self.nsx_url,
            nsx_user=self.nsx_user,
            nsx_password=self.nsx_password,
            nsx_verify_ssl=self.nsx_verify_ssl,
            dhcp_configure_always=self.dhcp_configure_always,
        )
        self.vc_session_pool = VCenterSessionPool(
            self.vcenter_hostname,
            self.user,
            self.passwd,
            self.vcenter_port,
            ssl_context=self.ssl_context,
            log_level=log_level,
        )

    def check_vim_connectivity(self):
        self.logger.debug("Check vim connectivity")
        # Load vcenter content to test connection
        session = self._get_vcenter_instance()
        try:
            vcutil.get_vcenter_content(session)
        finally:
            self._disconnect_si(session)

    def get_tenant_list(self, filter_dict={}):
        """Obtain tenants of VIM
        filter_dict dictionary that can contain the following keys:
            name: filter by tenant name
            id: filter by tenant uuid/id
            <other VIM specific>
        Returns the tenant list of dictionaries, and empty list if no tenant match all the filers:
            [{'name':'<name>, 'id':'<id>, ...}, ...]
        """
        self.logger.warning("Get tenant list is not supported in vcenter")
        raise vimconn.VimConnNotImplemented(
            "Get tenant list is not supported in vcenter"
        )

    def new_tenant(self, tenant_name, tenant_description):
        """Adds a new tenant to VIM with this name and description, this is done using admin_url if provided
        "tenant_name": string max lenght 64
        "tenant_description": string max length 256
        returns the tenant identifier or raise exception
        """
        self.logger.warning("new_tenant is not supported in vcenter")
        raise vimconn.VimConnNotImplemented("new_tenant is not supported in vcenter")

    def delete_tenant(self, tenant_id):
        """Delete a tenant from VIM
        tenant_id: returned VIM tenant_id on "new_tenant"
        Returns None on success. Raises and exception of failure. If tenant is not found raises VimConnNotFoundException
        """
        self.logger.warning("delete_tenant is not supported in vcenter")
        raise vimconn.VimConnNotImplemented("delete_tenant is not supported in vcenter")

    def get_flavor(self, flavor_id):
        """Obtain flavor details from the VIM
        Returns the flavor dict details {'id':<>, 'name':<>, other vim specific }
        Raises an exception upon error or if not found
        """
        self.logger.debug("Get flavor with id: %s", flavor_id)

        if flavor_id not in self._flavorlist:
            raise vimconn.VimConnNotFoundException("Flavor not found.")

        return self._flavorlist[flavor_id]

    def get_flavor_id_from_data(self, flavor_dict):
        """Obtain flavor id that match the flavor description
        Params:
            'flavor_dict': dictionary that contains:
                'disk': main hard disk in GB
                'ram': meomry in MB
                'vcpus': number of virtual cpus
                #TODO: complete parameters for EPA
        Returns the flavor_id or raises a VimConnNotFoundException
        """
        self.logger.debug("Get flavor from data: %s", flavor_dict)
        # As in this connector flavors are only stored in memory always return vimconnnotfound
        # exception
        raise vimconn.VimConnNotFoundException(
            "get_flavor_id_from_data not used in this plugin"
        )

    def new_flavor(self, flavor_data):
        """Adds a tenant flavor to VIM
            flavor_data contains a dictionary with information, keys:
                name: flavor name
                ram: memory (cloud type) in MBytes
                vpcus: cpus (cloud type)
                extended: EPA parameters
                  - numas: #items requested in same NUMA
                        memory: number of 1G huge pages memory
                        paired-threads|cores|threads: number of paired hyperthreads, complete cores OR individual
                            threads
                        interfaces: # passthrough(PT) or SRIOV interfaces attached to this numa
                          - name: interface name
                            dedicated: yes|no|yes:sriov;  for PT, SRIOV or only one SRIOV for the physical NIC
                            bandwidth: X Gbps; requested guarantee bandwidth
                            vpci: requested virtual PCI address
                disk: disk size
                is_public:
                 #TODO to concrete
        Returns the flavor identifier
        """
        self.logger.debug("New flavor data: %s", flavor_data)

        new_flavor = flavor_data
        ram = flavor_data.get(vcvmutil.FLAVOR_RAM_KEY, 1024)
        cpu = flavor_data.get(vcvmutil.FLAVOR_VCPUS_KEY, 1)
        disk = flavor_data.get(vcvmutil.FLAVOR_DISK_KEY, 0)

        self._validate_int(ram, "ram")
        self._validate_int(cpu, "cpu")
        self._validate_int(disk, "disk")

        # generate a new uuid put to internal dict and return it.
        flavor_id = uuid.uuid4()
        self._flavorlist[str(flavor_id)] = new_flavor
        self.logger.debug("Created flavor - %s : %s", flavor_id, new_flavor)

        return str(flavor_id)

    def delete_flavor(self, flavor_id):
        """Deletes a tenant flavor from VIM identify by its id
        Returns the used id or raise an exception
        """
        self.logger.debug("Delete flavor id: %s", flavor_id)
        if flavor_id in self._flavorlist:
            self._flavorlist.pop(flavor_id)
            return flavor_id
        else:
            self.logger.info("Flavor with id: %s not found ", flavor_id)

    def get_affinity_group(self, affinity_group_id):
        """Obtain affinity or anti affinity group details from the VIM
        Returns the flavor dict details {'id':<>, 'name':<>, other vim specific }
        Raises an exception upon error or if not found
        """
        self.logger.debug("Get affinity group with id: %s", affinity_group_id)
        if affinity_group_id not in self._affinity_groups:
            raise vimconn.VimConnNotFoundException(
                "Affinity group with id: %s not found"
            )

        return self._affinity_groups[affinity_group_id]

    def new_affinity_group(self, affinity_group_data):
        """Adds an affinity or anti affinity group to VIM
            affinity_group_data contains a dictionary with information, keys:
                name: name in VIM for the affinity or anti-affinity group
                type: affinity or anti-affinity
                scope: Only nfvi-node allowed
        Returns the affinity or anti affinity group identifier
        """
        self.logger.debug("New affinity group, data: %s", affinity_group_data)
        affinity_group = None

        affinity_group_name = affinity_group_data.get("name")
        affinity_group_type = affinity_group_data.get("type")
        affinity_group = self._affinity_groups.get(affinity_group_name)

        if affinity_group_name in self._affinity_groups:
            affinity_group = self._affinity_groups.get(affinity_group_name)
            if affinity_group_type != affinity_group.get("type"):
                self.logger.warning(
                    "There is already an affinity group with name %s "
                    "and different type: % s",
                    affinity_group_name,
                    affinity_group_type,
                )
                raise vimconn.VimConnNotFoundException(
                    f"there is already an affinity group with name: {affinity_group_name} and "
                    "different type"
                )
        else:
            affinity_group = affinity_group_data
            self._affinity_groups[affinity_group_name] = affinity_group_data

        self.logger.debug("Affinity groups: %s", self._affinity_groups)
        return affinity_group.get("name")

    def delete_affinity_group(self, affinity_group_id):
        """
        Deletes an affinity or anti affinity group from the VIM identified by its id
        Returns the used id or raise an exception
        """
        self.logger.debug("Delete affinity group with id: %s", affinity_group_id)

        if affinity_group_id in self._affinity_groups:
            self.logger.info(
                "Deleting affinity group %s",
                self._affinity_groups.get("affinity_group_id"),
            )
            del self._affinity_groups[affinity_group_id]
        else:
            self.logger.info("Affinity group with id %s not found", affinity_group_id)

        self.logger.debug("Affinity groups: %s", self._affinity_groups)
        return affinity_group_id

    def new_image(self, image_dict):
        """Adds a tenant image to VIM
        Returns the image id or raises an exception if failed
        """
        self.logger.debug("Create new image: %s", image_dict)
        raise vimconn.VimConnNotImplemented("new image is not supported in vcenter")

    def delete_image(self, image_id):
        """Deletes a tenant image from VIM
        Returns the image_id if image is deleted or raises an exception on error
        """
        self.logger.debug("Delete image: %s", image_id)
        raise vimconn.VimConnNotImplemented("delete image is not supported in vcenter")

    def get_image_id_from_path(self, path):
        """Get the image id from image path in the VIM database.
        Returns the image_id or raises a VimConnNotFoundException
        """
        self.logger.debug("Get image from path: %s", path)
        raise vimconn.VimConnNotImplemented(
            "get image from path is not supported in vcenter"
        )

    @handle_connector_exceptions
    def get_image_list(self, filter_dict=None):
        """Obtain tenant images from VIM
        Filter_dict can be:
            name: image name
            id: image uuid
            checksum: image checksum
            location: image path
        Returns the image list of dictionaries:
            [{<the fields at Filter_dict plus some VIM specific>}, ...]
            List can be empty
        """
        filter_dict = filter_dict or {}
        self.logger.debug("Get image list, filter_dict: %s", filter_dict)

        session = self._get_vcenter_instance()
        try:
            # Get images
            image_list = self.vcvms_util.list_images(session, filter_dict=filter_dict)

            self.logger.debug("Image list: %s", image_list)
            return image_list
        finally:
            self._disconnect_si(session)

    def new_vminstance(
        self,
        name: str,
        description: str,
        start: bool,
        image_id: str,
        flavor_id: str,
        affinity_group_list: list,
        net_list: list,
        cloud_config=None,
        disk_list=None,
        availability_zone_index=None,
        availability_zone_list=None,
        security_group_name=None,
    ) -> tuple:
        """Adds a VM instance to VIM.

        Args:
            name    (str):          name of VM
            description (str):      description
            start   (bool):         indicates if VM must start or boot in pause mode. Ignored
            image_id    (str)       image uuid
            flavor_id   (str)       flavor uuid
            affinity_group_list (list):     list of affinity groups, each one is a dictionary.Ignore if empty.
            net_list    (list):         list of interfaces, each one is a dictionary with:
                name:   name of network
                net_id:     network uuid to connect
                vpci:   virtual vcpi to assign, ignored because openstack lack #TODO
                model:  interface model, ignored #TODO
                mac_address:    used for  SR-IOV ifaces #TODO for other types
                use:    'data', 'bridge',  'mgmt'
                type:   'virtual', 'PCI-PASSTHROUGH'('PF'), 'SR-IOV'('VF'), 'VFnotShared'
                vim_id:     filled/added by this function
                floating_ip:    True/False (or it can be None)
                port_security:  True/False
            cloud_config    (dict): (optional) dictionary with:
                key-pairs:      (optional) list of strings with the public key to be inserted to the default user
                users:      (optional) list of users to be inserted, each item is a dict with:
                    name:   (mandatory) user name,
                    key-pairs: (optional) list of strings with the public key to be inserted to the user
                user-data:  (optional) string is a text script to be passed directly to cloud-init
                config-files:   (optional). List of files to be transferred. Each item is a dict with:
                    dest:   (mandatory) string with the destination absolute path
                    encoding:   (optional, by default text). Can be one of:
                        'b64', 'base64', 'gz', 'gz+b64', 'gz+base64', 'gzip+b64', 'gzip+base64'
                    content :    (mandatory) string with the content of the file
                    permissions:    (optional) string with file permissions, typically octal notation '0644'
                    owner:  (optional) file owner, string with the format 'owner:group'
                boot-data-drive:    boolean to indicate if user-data must be passed using a boot drive (hard disk)
            disk_list:  (optional) list with additional disks to the VM. Each item is a dict with:
                image_id:   (optional). VIM id of an existing image. If not provided an empty disk must be mounted
                size:   (mandatory) string with the size of the disk in GB
                vim_id:  (optional) should use this existing volume id
            availability_zone_index:    Index of availability_zone_list to use for this this VM. None if not AV required
            availability_zone_list:     list of availability zones given by user in the VNFD descriptor.  Ignore if
                availability_zone_index is None
                #TODO ip, security groups

        Returns:
            A tuple with the instance identifier and created_items or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_vminstance and action_vminstance. Can be used to store created ports, volumes, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.

        """
        self.logger.info(
            "new vm_instance name: %s, image_id: %s, flavor_id: %s",
            name,
            image_id,
            flavor_id,
        )
        self.logger.debug(
            "new_vinstance data, net_list: %s, disk_list: %s"
            " affinity_group_list: %s, cloud_config: %s,",
            net_list,
            disk_list,
            affinity_group_list,
            cloud_config,
        )
        net_list = net_list or []
        disk_list = disk_list or []
        affinity_group_list = affinity_group_list or []

        session = self._get_vcenter_instance()
        new_vm = None
        created_items = {}
        try:
            vc_vmops = VCenterVmsOps(
                self.vcenter_config, self.vcvms_util, self.vcnet_util, session
            )

            # Recover flavor, image template, resource pool, cluster, datastore
            # datastore info, if it is not in configuration, get the same that template
            flavor = self.get_flavor(flavor_id)
            self.logger.debug("Flavor recovered: %s", flavor)

            # Obtain image to clone
            image_vm = self.vcvms_util.get_image_by_uuid(session, image_id)
            self.logger.debug("Image recovered: %s", image_vm)

            # Obtain needed configuration
            datastore = self.vcenter_config.get_datastore(session)
            self.logger.debug("Datastore 1: %s", datastore)
            cluster, resource_pool = self.vcenter_config.get_cluster_rp_from_av_zone(
                session, availability_zone_index, availability_zone_list
            )
            vms_folder = self.vcenter_config.get_instances_folder(session)
            self.logger.debug("Cluster: %s, resource_pool: %s", cluster, resource_pool)

            # Start to prepare config data

            # Prepare affinity groups (check that they can be found)
            affinity_groups_full = self._prepare_affinity_groups(affinity_group_list)

            # Generate vm unique name
            vm_name = self._generate_vm_name(name)

            # Prepare vmconfig based on image and flavor data
            vm_config_spec = vc_vmops.prepare_vm_base_config(vm_name, flavor, image_vm)

            # Process flavor extended config
            self._process_flavor_extended_config(vc_vmops, vm_config_spec, flavor)

            # Prepare main disk
            vc_vmops.prepare_vm_main_disk(flavor, image_vm, vm_config_spec, datastore)

            # Add network interfaces configuration
            vc_vmops.prepare_vm_networks(net_list, image_vm, vm_config_spec)

            # Prepare disks configuration
            self._prepare_vm_disks(
                flavor=flavor,
                disk_list=disk_list,
                created_items=created_items,
                vm_config_spec=vm_config_spec,
                image_vm=image_vm,
                vc_vmops=vc_vmops,
            )

            # Generate cloud init iso
            iso_path, tmp_dir = self._generate_cloud_init_iso(cloud_config)

            # Clone machine
            self.logger.debug("Cloning image to create vm name %s", vm_config_spec.name)
            # self.logger.debug("Cloning image config spec %s", vm_config_spec)
            clone_spec = vim.vm.CloneSpec(
                location=vim.vm.RelocateSpec(pool=resource_pool, datastore=datastore),
                powerOn=False,  # Power on the VM after creation
                template=False,
                config=vm_config_spec,
            )
            clone_task = image_vm.Clone(
                folder=vms_folder, name=vm_config_spec.name, spec=clone_spec
            )
            self.logger.debug("Machine cloned, wait for clone task to complete")

            # Wait until clone task is completed
            new_vm = vcutil.wait_for_task(clone_task)

            # Attach cloud init to vm
            self._attach_cloud_init_iso(
                vc_vmops, new_vm, iso_path, tmp_dir, created_items
            )

            # Add the machine to affinity groups
            self._add_vm_affinity_groups(
                session, cluster, new_vm, affinity_groups_full, created_items
            )

            # Assign vim_id to net
            self._assign_vim_id_to_net(new_vm, net_list)

            # Assign fixed ip addresses if there are any
            self.vcenter_ipmanager.set_vm_ips(session, name, new_vm, net_list)

            # Start vm
            self.vcvms_util.start_vm(new_vm)

            self.logger.info(
                "Created vm, server_id:  %s, vm_name: %s, created_items: %s, "
                " net_list: %s",
                new_vm.config.instanceUuid,
                vm_name,
                created_items,
                net_list,
            )
            return new_vm.config.instanceUuid, created_items

        except Exception as e:
            if new_vm:
                try:
                    server_uuid = new_vm.config.instanceUuid

                    created_items = self.remove_keep_tag_from_persistent_volumes(
                        created_items
                    )

                    self.delete_vminstance(server_uuid, created_items)

                except Exception as e2:
                    self.logger.error(f"new_vminstance rollback fail {e2}")

            # Logs and reraises exception
            self._format_raise_exception(e)
        finally:
            self._disconnect_si(session)

    @staticmethod
    def remove_keep_tag_from_persistent_volumes(created_items: dict) -> dict:
        """Removes the keep flag from persistent volumes. So, those volumes could be removed.

        Args:
            created_items (dict):       All created items belongs to VM

        Returns:
            updated_created_items   (dict):     Dict which does not include keep flag for volumes.

        """
        return {
            key.replace(":keep", ""): value for (key, value) in created_items.items()
        }

    def _assign_vim_id_to_net(self, vm, net_list):
        """
        Obtains the vim_id and assigns it to the net, also assigns the mac_address it is is available
        """
        nics_info = self.vcvms_util.get_vm_nics_list(vm)
        for net in net_list:
            net_id = net.get("net_id")
            # Obtain the first interface with the same net_id
            for index, nic in enumerate(nics_info):
                if nic.get("vim_net_id") == net_id:
                    net["vim_id"] = nic.get("vim_interface_id")
                    if nic.get("mac_address"):
                        net["mac_address"] = nic.get("mac_address")
                    del nics_info[index]
                    break
        if nics_info:
            self.logger.warning("Unassigned elements in network: %s", nics_info)

    def _prepare_vm_disks(
        self, flavor, disk_list, created_items, vm_config_spec, image_vm, vc_vmops
    ):
        """
        Prepare all volumes for vm instance
        """
        disk_list = disk_list or []
        datastore = image_vm.datastore[
            0
        ]  # could configure to store permanent disk in anther datastore

        # Check if an ephemeral disk needs to be created
        ephemeral_disk_size_gb = flavor.get("ephemeral", 0)
        if int(ephemeral_disk_size_gb) > 0:
            # Create ephemeral disk
            vc_vmops.prepare_ephemeral_disk(
                image_vm,
                vm_config_spec,
                datastore,
                ephemeral_disk_size_gb,
                created_items,
            )

        self.logger.debug("Process disk list: %s", disk_list)
        for disk_index, disk in enumerate(disk_list, start=1):
            self.logger.debug("disk_index: %s, disk: %s", disk_index, disk)
            if "image_id" in disk:
                self.logger.warning("Volume disks with image id not supported yet")
            elif disk.get("multiattach"):
                self.logger.warning("Volume disks with image id not supported yet")
            elif disk.get("volume_id"):
                self.logger.warning("Volumes already existing not supported yet")
            else:
                # Create permanent disk
                vc_vmops.prepare_permanent_disk(
                    image_vm, vm_config_spec, datastore, disk, disk_index, created_items
                )

    def _prepare_affinity_groups(self, affinity_group_id_list):
        """
        Check affinity groups ids in the list can be found and recover the affinity groups from ids
        """
        affinity_groups = None
        if affinity_group_id_list:
            affinity_groups = []
            for item in affinity_group_id_list:
                affinity_group_id = item["affinity_group_id"]
                # Obtain the affinity group from the environment
                affinity_group = self._affinity_groups.get(affinity_group_id)
                if not affinity_group:
                    raise vimconn.VimConnNotFoundException(
                        f"Affinity group: {affinity_group_id} not found"
                    )
                else:
                    affinity_groups.append(affinity_group)
        return affinity_groups

    def _add_vm_affinity_groups(
        self, session, cluster, new_vm, affinity_group_list, created_items
    ):

        if affinity_group_list:
            self.logger.debug("Add vm to affinity group list: %s", affinity_group_list)
            for affinity_group in affinity_group_list:
                self.vcvms_util.add_vm_or_create_affinity_group(
                    session,
                    cluster,
                    affinity_group.get("name"),
                    affinity_group.get("type"),
                    new_vm,
                )
                affinity_group_txt = "affinity-group:" + affinity_group.get("name")
                created_items[affinity_group_txt] = True

    def _process_flavor_extended_config(self, vc_vmops, vm_config_spec, flavor):
        """
        Process the flavor extended configuration
        :param flavor_data, dict with flavor_data, extended configuration is in key extended
        :param vm_config_spec, dictionaty with the new vm config to be completed with extended flavor config
        """
        quotas_keys = {"cpu-quota", "mem-quota"}
        # quotas = {"cpu-quota", "mem-quota", "vif-quota", "disk-io-quota"}

        extended = flavor.get("extended")
        if extended:
            self.logger.debug("Process flavor extended data: %s", extended)

            # Process quotas
            extended_quotas = {
                key: extended[key] for key in quotas_keys & extended.keys()
            }
            if extended_quotas:
                vc_vmops.prepare_vm_quotas(extended_quotas, vm_config_spec)

    def get_vminstance(self, vm_id):
        """Returns the VM instance information from VIM"""
        self.logger.debug("Get vm_instance id: %s", vm_id)

        session = self._get_vcenter_instance()
        try:
            vm = self.vcvms_util.get_vm_by_uuid(session, vm_id)
            return vm
        finally:
            self._disconnect_si(session)

    @handle_connector_exceptions
    def delete_vminstance(self, vm_id, created_items=None, volumes_to_hold=None):
        """
        Removes a VM instance from VIM and its associated elements
        :param vm_id: VIM identifier of the VM, provided by method new_vminstance
        :param created_items: dictionary with extra items to be deleted. provided by method new_vminstance and/or method
            action_vminstance
        :return: None or the same vm_id. Raises an exception on fail
        """
        self.logger.debug(
            "Delete vm_instance: vm_id: %s, "
            "    created_items: %s,"
            "    volumes_to_hold: %s",
            vm_id,
            created_items,
            volumes_to_hold,
        )

        created_items = created_items or {}
        volumes_to_hold = volumes_to_hold or {}

        session = self._get_vcenter_instance()
        try:
            # Obtain volumes to keep
            volumes_to_keep = self._extract_volumes_to_keep(created_items)
            self.logger.debug("volumes_to_keep: %s", volumes_to_keep)

            # Obtain cloud init iso files to delete
            cloud_init_iso = self._extract_cloudinit_iso(created_items)
            self.logger.debug("cloud init iso: %s", cloud_init_iso)

            # Obtain vm
            vm = self.vcvms_util.get_vm_by_uuid(session, vm_id)

            # Shutdown vm and wait to avoid probles when volumes are unattached
            stop_task = self.vcvms_util.stop_vm(vm)
            vcutil.wait_for_task(stop_task)

            # Prepare spec to unattach volumes
            unattach_spec = None
            if volumes_to_keep:
                unattach_spec = self.vcvms_util.prepare_unattach_volumes(
                    vm, volumes_to_keep, unattach_spec
                )

            # Prepare spec to unattach iso
            if cloud_init_iso:
                unattach_spec = self.vcvms_util.prepare_unattach_cloudinitiso(
                    vm, cloud_init_iso, unattach_spec
                )

            # Unattach volumes to keep and iso
            self.vcvms_util.reconfig_vm(session, vm, unattach_spec)

            # Delete iso files
            self.vcvms_util.delete_iso_files(session, cloud_init_iso)

            # Delete vm from affinity group
            self._delete_vm_affinity_groups(session, vm, created_items)

            # Delete vm
            self.vcvms_util.delete_vm(session, vm_id)

        finally:
            self._disconnect_si(session)

    def _delete_vm_affinity_groups(self, session, vm, created_items):

        self.logger.debug("Delete vm affinity groups: %s", created_items)
        vm_name = vm.name
        cluster = self.vcvms_util.get_vm_cluster(session, vm)

        for key, value in created_items.items():
            if value is True and key.startswith("affinity-group:"):
                self.logger.debug("Delete vm affinity groups key: %s", key)
                # Remove vm from affinity group if there is just one delete affinity group
                affinity_rule_name = key.split(":")[1]
                self.vcvms_util.delete_vm_affinity_rule(
                    session, cluster, affinity_rule_name, vm_name
                )
                created_items[key] = False

    @staticmethod
    def _extract_volumes_to_keep(created_items: dict) -> dict:
        volumes_to_keep = []
        for key, value in created_items.items():
            if value is True and key.startswith("volume:") and ":keep" in key:
                # Extract the volume ID (the part between "volume:" and ":keep")
                volume_id = key.split(":")[1]
                volumes_to_keep.append(volume_id)
        return volumes_to_keep

    @staticmethod
    def _extract_cloudinit_iso(created_items: dict) -> dict:
        cloud_init_iso_list = []
        for key, value in created_items.items():
            if value is True and key.startswith("cloud-init-iso:"):
                cloud_init_id = key.split(":")[1]
                cloud_init_iso_list.append(cloud_init_id)
        return cloud_init_iso_list

    def refresh_vms_status(self, vm_list):
        """Get the status of the virtual machines and their interfaces/ports
        Params: the list of VM identifiers
        Returns a dictionary with:
            vm_id:          #VIM id of this Virtual Machine
                status:     #Mandatory. Text with one of:
                            #  DELETED (not found at vim)
                            #  VIM_ERROR (Cannot connect to VIM, VIM response error, ...)
                            #  OTHER (Vim reported other status not understood)
                            #  ERROR (VIM indicates an ERROR status)
                            #  ACTIVE, PAUSED, SUSPENDED, INACTIVE (not running),
                            #  CREATING (on building process), ERROR
                            #  ACTIVE:NoMgmtIP (Active but any of its interface has an IP address
                            #
                error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
                vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
                interfaces:
                 -  vim_info:         #Text with plain information obtained from vim (yaml.safe_dump)
                    mac_address:      #Text format XX:XX:XX:XX:XX:XX
                    vim_net_id:       #network id where this interface is connected
                    vim_interface_id: #interface/port VIM id
                    ip_address:       #null, or text with IPv4, IPv6 address
                    compute_node:     #identification of compute node where PF,VF interface is allocated
                    pci:              #PCI address of the NIC that hosts the PF,VF
                    vlan:             #physical VLAN used for VF
        """
        self.logger.debug("Refresh vm_status vm_list: %s", vm_list)
        vm_list = vm_list or []
        out_vms = {}

        session = self._get_vcenter_instance()
        try:
            for vm_id in vm_list:
                self.logger.debug("Refresh vm id: %s", vm_id)
                out_vm = {}
                try:
                    vm = self.vcvms_util.get_vm_by_uuid(session, vm_id)

                    vim_vm = self.vcvms_util.get_vim_vm_basic(vm)
                    out_vm["vim_info"] = self.serialize(vim_vm)
                    out_vm["status"] = vim_vm.get("status", "other")

                    out_vm["interfaces"] = self.vcvms_util.get_vm_nics_list(vm)

                    mac_ips_dict = self.vcenter_ipmanager.get_vm_ips(session, vm)
                    self.logger.debug(
                        "Obtained list of macs and ip addresses: %s", mac_ips_dict
                    )

                    for interface in out_vm["interfaces"]:
                        mac_address = interface.get("mac_address")
                        if mac_ips_dict.get(mac_address):
                            interface["ip_address"] = ";".join(
                                mac_ips_dict.get(mac_address)
                            )

                except vimconn.VimConnNotFoundException as e:
                    self.logger.error(
                        "Not found error recovering vm id: %s, message: %s",
                        vm_id,
                        str(e),
                    )
                    out_vm["status"] = "DELETED"
                    out_vm["error_msg"] = str(e)
                except Exception as e:
                    self.logger.error(f"Error recovering vm id: {vm_id}".format(), e)
                    out_vm["status"] = "VIM_ERROR"
                    out_vm["error_msg"] = str(e)

                out_vms[vm_id] = out_vm
        finally:
            self._disconnect_si(session)

        self.logger.debug("Refresh vm status, result: %s", out_vms)
        return out_vms

    @handle_connector_exceptions
    def action_vminstance(self, vm_id, action_dict, created_items=None):
        """
        Send and action over a VM instance. Returns created_items if the action was successfully sent to the VIM.
        created_items is a dictionary with items that
        :param vm_id: VIM identifier of the VM, provided by method new_vminstance
        :param action_dict: dictionary with the action to perform
        :param created_items: provided by method new_vminstance is a dictionary with key-values that will be passed to
            the method delete_vminstance. Can be used to store created ports, volumes, etc. Format is VimConnector
            dependent, but do not use nested dictionaries and a value of None should be the same as not present. This
            method can modify this value
        :return: None, or a console dict
        """
        self.logger.debug(
            "Action vm_instance, id: %s, action_dict: %s", vm_id, str(action_dict)
        )
        created_items = created_items or {}

        session = self._get_vcenter_instance()
        try:
            # Get vm
            vm = self.vcvms_util.get_vm_by_uuid(session, vm_id)
            self.logger.debug("vm state: %s", vm.runtime.powerState)

            if "start" in action_dict:
                self.vcvms_util.start_vm(vm)
            elif "shutoff" in action_dict or "shutdown" in action_dict:
                self.vcvms_util.stop_vm(vm)
            elif "pause" in action_dict:
                # todo - pause
                self.logger.warning("pause not implemented yet")

            elif "resume" in action_dict:
                self.logger.warning("resume not implemented yet")

            elif "forceOff" in action_dict:
                self.logger.warning("forceOff not implemented yet")

            elif "reboot" in action_dict:
                self.logger.warning("reboot action not implemented yet")

            elif "terminate" in action_dict:
                self.logger.warning("terminate action not implemented yet")

            elif "rebuild" in action_dict:
                self.logger.warning("rebuild action not implemented yet")

            else:
                raise vimconn.VimConnException(
                    f"action_vminstance: Invalid action {action_dict} or action is None."
                )

        finally:
            self._disconnect_si(session)

    @handle_connector_exceptions
    def get_vminstance_console(self, vm_id, console_type="vmrc"):
        """
        Get a console for the virtual machine
        Params:
            vm_id: uuid of the VM
            console_type, can be:
                "novnc" (by default), "xvpvnc" for VNC types,
                "rdp-html5" for RDP types, "spice-html5" for SPICE types
        Returns dict with the console parameters:
                protocol: ssh, ftp, http, https, ...
                server:   usually ip address
                port:     the http, ssh, ... port
                suffix:   extra text, e.g. the http path and query string
        """
        self.logger.debug(
            "Get vm instance console, vm_id: %s, console_type: %s", vm_id, console_type
        )
        # Check allowed consolo type
        console_types = "vmrc"
        if console_type not in console_types:
            raise vimconn.VimConnException(
                "console type '{}' not allowed".format(console_type),
                http_code=vimconn.HTTP_Bad_Request,
            )
        VMRC_URL_FORMAT = "vmrc://clone:{ticket}@{vcenter_host}/?moid={vm_moid}"

        session = self._get_vcenter_instance()
        try:
            # Get vm
            vm = self.vcvms_util.get_vm_by_uuid(session, vm_id)

            # Get session ticket
            ticket = self.vcvms_util.get_vm_clone_session_ticket(session, vm)

            # Build the URL
            console_url = VMRC_URL_FORMAT.format(
                ticket=ticket, vcenter_host=self.vcenter_hostname, vm_moid=vm._moId
            )

            console_dict = {"console_type": console_type, "url": console_url}
            self.logger.debug("Obtained console_dict: %s", console_dict)
            return console_dict
        finally:
            self._disconnect_si(session)

    @handle_connector_exceptions
    def new_network(
        self,
        net_name,
        net_type,
        ip_profile=None,
        shared=False,
        provider_network_profile=None,
    ):
        """Adds a tenant network to VIM
        Params:
            'net_name': name of the network
            'net_type': one of:
                'bridge': overlay isolated network
                'data':   underlay E-LAN network for Passthrough and SRIOV interfaces
                'ptp':    underlay E-LINE network for Passthrough and SRIOV interfaces.
            'ip_profile': is a dict containing the IP parameters of the network
                'ip_version': can be "IPv4" or "IPv6" (Currently only IPv4 is implemented)
                'subnet_address': ip_prefix_schema, that is X.X.X.X/Y
                'gateway_address': (Optional) ip_schema, that is X.X.X.X
                'dns_address': (Optional) comma separated list of ip_schema, e.g. X.X.X.X[,X,X,X,X]
                'dhcp_enabled': True or False
                'dhcp_start_address': ip_schema, first IP to grant
                'dhcp_count': number of IPs to grant.
            'shared': if this network can be seen/use by other tenants/organization
            'provider_network_profile': (optional) contains {segmentation-id: vlan, provider-network: vim_netowrk}
        Returns a tuple with the network identifier and created_items, or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_network. Can be used to store created segments, created l2gw connections, etc.
            Format is VimConnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        self.logger.debug(
            "new network, net_name: %s, net_type: %s, ip_profile: %s,"
            "    shared: %s, provider_network_profile: %s",
            net_name,
            net_type,
            ip_profile,
            shared,
            provider_network_profile,
        )
        created_items = {}

        # Generate network name with suffix
        net_unique_name = self._generate_network_name(net_name)

        # Create distributed port group
        net_id = self._create_distributed_port_group(
            net_unique_name, net_type, ip_profile, provider_network_profile
        )

        self.logger.debug("Created network id: %s, name: %s", net_id, net_unique_name)
        return net_id, created_items

    def _create_distributed_port_group(
        self, net_name, net_type, ip_profile, provider_network_profile
    ):
        self.logger.debug("Create distributed port group with name: %s", net_name)

        session = self._get_vcenter_instance()
        try:
            # Obtain dvs_names
            dvs_names = self.vcenter_config.get_dvs_names(session)
            if len(dvs_names) != 1:
                raise vimconn.VimConnException(
                    "Creation of networks is unsupported if not just one distributed switch is configured"
                )

            dvs_name = dvs_names[0]

            # Create distributed port group
            vlan = None
            if provider_network_profile:
                vlan = provider_network_profile.get("segmentation-id")
                self.logger.debug("vlan value for network: %s", vlan)

            net_id, port_group = self.vcnet_util.create_distributed_port_group(
                session, net_name, dvs_name, vlan=vlan
            )

            return net_id
        finally:
            self._disconnect_si(session)

    def get_network_list(self, filter_dict=None):
        """Obtain tenant networks of VIM
        Params:
            'filter_dict' (optional) contains entries to return only networks that matches ALL
            entries:
                name: string  => returns only networks with this name
                id:   string  => returns networks with this VIM id, this imply returns one network
                at most
                shared: boolean >= returns only networks that are (or are not) shared
                tenant_id: sting => returns only networks that belong to this tenant/project
                ,#(not used yet) admin_state_up: boolean => returns only networks that are
                (or are not) in admin state
                    active
                #(not used yet) status: 'ACTIVE','ERROR',... => filter networks that are on this
                # status
        Returns the network list of dictionaries. each dictionary contains:
            'id': (mandatory) VIM network id
            'name': (mandatory) VIM network name
            'status': (mandatory) can be 'ACTIVE', 'INACTIVE', 'DOWN', 'BUILD', 'ERROR',
            'VIM_ERROR', 'OTHER'
            'network_type': (optional) can be 'vxlan', 'vlan' or 'flat'
            'segmentation_id': (optional) in case network_type is vlan or vxlan this field contains
            the segmentation id
            'error_msg': (optional) text that explains the ERROR status
            other VIM specific fields: (optional) whenever possible using the same naming of
            filter_dict param
        List can be empty if no network map the filter_dict. Raise an exception only upon VIM
        connectivity,
            authorization, or some other unspecific error
        """
        self.logger.debug("get network list, filter_dict: %s", filter_dict)
        filter_dict = filter_dict or {}

        # Get network list: step 1: get the list of distributed port groups
        session = self._get_vcenter_instance()
        try:
            # Get the list of available distributed switches
            dvs_names = self.vcenter_config.get_dvs_names(session)

            # Get the list of distributed port groups for the distributed switches
            dport_groups = self.vcnet_util.get_port_groups_by_dvs_name(
                session, dvs_names
            )
            # self.logger.debug("Distributed port groups: %s", dport_groups)

            network_list = []  # network list object to be returned
            for port_group in dport_groups:
                if filter_dict:
                    if (
                        filter_dict.get("id")
                        and str(port_group.key) != filter_dict["id"]
                    ):
                        continue

                    if (
                        filter_dict.get("name")
                        and str(port_group.name) != filter_dict["name"]
                    ):
                        continue

                # Obtain vim networl data
                network_list.append(self.vcnet_util.get_vim_network_from_pg(port_group))

            self.logger.debug("Network list obtained: %s", network_list)
            return network_list
        finally:
            self._disconnect_si(session)

    @handle_connector_exceptions
    def get_network(self, net_id):
        """Obtain network details from the 'net_id' VIM network
        Return a dict that contains:
            'id': (mandatory) VIM network id, that is, net_id
            'name': (mandatory) VIM network name
            'status': (mandatory) can be 'ACTIVE', 'INACTIVE', 'DOWN', 'BUILD', 'ERROR',
            'VIM_ERROR', 'OTHER'
            'error_msg': (optional) text that explains the ERROR status
            other VIM specific fields: (optional) whenever possible using the same naming of
            filter_dict param
        Raises an exception upon error or when network is not found
        """
        self.logger.debug("get network id: %s", net_id)

        session = self._get_vcenter_instance()
        try:
            vim_net = self.vcnet_util.get_vim_network_by_id(session, net_id)
            return vim_net
        finally:
            self._disconnect_si(session)

    @handle_connector_exceptions
    def delete_network(self, net_id, created_items=None):
        """
        Removes a tenant network from VIM and its associated elements
        :param net_id: VIM identifier of the network, provided by method new_network
        :param created_items: dictionary with extra items to be deleted. provided by method new_network
        Returns the network identifier or raises an exception upon error or when network is not found
        """
        self.logger.debug(
            "delete network id: %s, created_items: %s", net_id, created_items
        )

        session = self._get_vcenter_instance()
        try:
            # Check the network is distributed port group
            if not self.vcnet_util.is_distributed_port_group(net_id):
                raise vimconn.VimConnNotSupportedException(
                    f"Network with id: {net_id} is not a distributed port group, deleting is not supported"
                )

            # Obtain the network
            net = self.vcnet_util.get_network_by_id(session, net_id)
            if self.vcnet_util.is_nsx_port_group(net):
                raise vimconn.VimConnNotSupportedException(
                    f"Network with id: {net_id} is a nsx backed network, deleting is not supported"
                )

            # Obtain connected vms
            connected_vms = self.vcnet_util.get_distributed_port_connected_vms(net)

            # Disconnect vms
            self.vcvms_util.disconnect_vms_from_dpg(session, net_id, connected_vms)

            # Delete the network
            self.vcnet_util.delete_distributed_port_group(net)

        finally:
            self._disconnect_si(session)

    def refresh_nets_status(self, net_list):
        """Get the status of the networks
        Params:
            'net_list': a list with the VIM network id to be get the status
        Returns a dictionary with:
            'net_id':         #VIM id of this network
                status:     #Mandatory. Text with one of:
                    #  DELETED (not found at vim)
                    #  VIM_ERROR (Cannot connect to VIM, authentication problems, VIM response error, ...)
                    #  OTHER (Vim reported other status not understood)
                    #  ERROR (VIM indicates an ERROR status)
                    #  ACTIVE, INACTIVE, DOWN (admin down),
                    #  BUILD (on building process)
                error_msg:  #Text with VIM error message, if any. Or the VIM connection ERROR
                vim_info:   #Text with plain information obtained from vim (yaml.safe_dump)
            'net_id2': ...
        """
        self.logger.debug("Refresh network list %s", net_list)
        net_list = net_list or []
        net_dict = {}

        session = self._get_vcenter_instance()
        try:
            for net_id in net_list:
                net = {}

                try:
                    vim_net = self.vcnet_util.get_vim_network_by_id(session, net_id)

                    net["vim_info"] = self.serialize(vim_net)
                    net["status"] = vim_net.get("status", "ACTIVE")
                    # vcenter does not a status flag

                except vimconn.VimConnNotFoundException as e:
                    self.logger.error("Exception getting net status: %s", str(e))
                    net["status"] = "DELETED"
                    net["error_msg"] = str(e)
                except vimconn.VimConnException as e:
                    self.logger.error("Exception getting net status: %s", str(e))
                    net["status"] = "VIM_ERROR"
                    net["error_msg"] = str(e)
                net_dict[net_id] = net

        finally:
            self._disconnect_si(session)

        self.logger.debug("Refresh net status, result: %s", net_dict)
        return net_dict

    def serialize(self, value):
        """Serialization of python basic types.

        In the case value is not serializable a message will be logged and a
        simple representation of the data that cannot be converted back to
        python is returned.
        """
        if isinstance(value, str):
            return value

        try:
            return yaml.dump(value, default_flow_style=True, width=256)
        except yaml.representer.RepresenterError:
            self.logger.debug(
                "The following entity cannot be serialized in YAML:\n\n%s\n\n",
                str(value),
                exc_info=True,
            )

            return str(value)

    def _generate_cloud_init_iso(self, cloud_config):
        iso_path = None
        tmp_dir = None

        if cloud_config:
            self.logger.debug("Cloud config provided, generate ISO file")
            _, userdata = self._create_user_data(cloud_config)
            iso_path, tmp_dir = self.cloudinit_helper.generate_cloud_init_iso(userdata)

        return iso_path, tmp_dir

    def _attach_cloud_init_iso(
        self, vc_vmops, new_vm, iso_path, tmp_dir, created_items
    ):
        """
        Attachs a previously generated cloud init iso file to a vm
        """

        if iso_path:
            # Obtain vm folder name and datastore name
            folder_name = new_vm.name
            datastore_name = new_vm.datastore[0].info.name
            file_name = new_vm.name + "-cloud-init.iso"

            # Obtain datacenter name for the datastore
            datacenter_name = self.vcenter_config.get_datacenter_name(vc_vmops.session)

            # Upload iso file
            self.vcenter_fileuploader.upload_file(
                iso_path, datacenter_name, datastore_name, folder_name, file_name
            )
            iso_filename = f"[{datastore_name}] {folder_name}/{file_name}"

            iso_filename_txt = "cloud-init-iso:" + quote(iso_filename)
            created_items[iso_filename_txt] = True

            # Attach iso to vm
            vc_vmops.attach_cdrom(new_vm, iso_filename)

            # Delete tmp_dir
            self.cloudinit_helper.delete_tmp_dir(tmp_dir)

    @staticmethod
    def _generate_short_suffix():
        # Generate a UUID and take the first 8 characters
        return str(uuid.uuid4())[:8]

    def _generate_vm_name(self, vm_name):
        return vm_name + "-" + self._generate_short_suffix()

    def _generate_network_name(self, network_name):
        return network_name + "-" + self._generate_short_suffix()

    @staticmethod
    def _format_raise_exception(exception):
        """Transform a PyVmomi exception into a VimConn exception by analyzing the cause."""
        logger = logging.getLogger("ro.vim.vcenter")
        message_error = str(exception)

        # Log the error before reraising
        logger.error(f"Exception ocurred, message: {message_error}", exc_info=True)

        # Reraise VimConnException directly
        if isinstance(exception, vimconn.VimConnException):
            raise exception
        else:
            # General Errors
            raise vimconn.VimConnException(
                f"Exception: {type(exception).__name__}: {message_error}"
            )

    def _get_vcenter_instance(self):
        self.logger.debug(
            "Connect to vcenter, hostname: %s, port: %s, " "user: %s",
            self.vcenter_hostname,
            self.vcenter_port,
            self.user,
        )
        return self.vc_session_pool.get_session()

    def _disconnect_si(self, server_instance):
        self.logger.debug("Disconnect session")
        self.vc_session_pool.return_session(server_instance)

    def _get_vcenter_content(self, server_instance):
        return server_instance.RetrieveContent()

    def _validate_int(self, value, var_name):
        if not isinstance(value, int):
            raise vimconn.VimConnException(
                f"Variable '{var_name}' must be an int. Got value: {value} ({type(value).__name__})"
            )
