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
Utility class to get configuration information in vcenter
It should be used to get information about datacenters, datastore,
clusters and other configuration objects in vcenter
"""
import logging

from osm_ro_plugin import vimconn
from osm_rovim_vcenter import vcenter_util as vcutil
from pyVmomi import vim


DEFAULT_BASE_FOLDER_NAME = "OSM"
DEFAULT_IMAGES_FOLDER_NAME = "OSM-Images"
DEFAULT_INSTANCES_FOLDER_NAME = "OSM-Instances"


class VCenterConfig:
    """
    Class used to handle vcenter configuration, used to recover
    basic objects information: cluster, datastore, etc
    """

    def __init__(
        self,
        availability_zones,
        tenant_id,
        tenant_name,
        distributed_switches_names=None,
        datastore_name=None,
        log_level=None,
    ):

        if isinstance(availability_zones, str):
            self.availability_zones_names = [availability_zones]
        else:
            self.availability_zones_names = availability_zones

        self.distributed_switches_names = None
        if isinstance(availability_zones, str):
            self.distributed_switches_names = [distributed_switches_names]
        else:
            self.distributed_switches_names = distributed_switches_names

        self.datastore_name = datastore_name
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.datacenter_name = None

        # Initialize vim availability zones to None, it will be set the first time it
        # is recovered
        self.vim_availability_zones = None

        # Configuration of folders
        self.base_folder_name = DEFAULT_BASE_FOLDER_NAME
        self.images_folder_name = DEFAULT_IMAGES_FOLDER_NAME
        self.instances_folder_name = DEFAULT_INSTANCES_FOLDER_NAME

        self.logger = logging.getLogger("ro.vim.vcenter.config")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

    def get_dvs_names(self, session):
        """
        Obtains distributed switches names, in case it is configured just returns the list
        If distributed switches names is not configured then it recovers distributed switches
        names from the distributed switches available for the cluster list
        """
        dvs_names = self.distributed_switches_names
        if not dvs_names:
            self.logger.debug(
                "Recover distributed switches names from cluster configuration"
            )
            self.logger.warning(
                "Method to get distributed switches names from cluster not "
                "implemented"
            )
            dvs_names = []
        return dvs_names

    def get_images_folder(self, session):
        """
        Obtain OSM images folder
        """
        # Improvement: - take into account the tenant_id
        base_folder = vcutil.get_vcenter_folder(session, self.base_folder_name)
        if not base_folder:
            raise vimconn.VimConnNotFoundException(
                "base folder for current tenant not found"
            )

        # Get images folder (inside the osm base folder)
        images_folder = vcutil.get_vcenter_folder(
            session, self.images_folder_name, base_folder
        )
        if not images_folder:
            raise vimconn.VimConnNotFoundException(
                "images folder for current tenant not found"
            )

        return images_folder

    def get_instances_folder(self, session):
        """
        Obtain OSM instances folder
        """
        osm_base_folder = vcutil.get_vcenter_folder(session, self.base_folder_name)
        if not osm_base_folder:
            raise vimconn.VimConnNotFoundException(
                f"base folder name {osm_base_folder} for current tenant not found"
            )

        # Get instances folder (inside the osm base folder)
        base_vms_folder = self._get_or_create_child_folder(
            osm_base_folder, self.instances_folder_name
        )

        # For each tenant there will be a subfolder
        instances_folder = self._get_or_create_child_folder(
            base_vms_folder, self.tenant_name
        )

        return instances_folder

    def _get_or_create_child_folder(self, vm_base_folder, child_folder_name):

        # Check if the folder already exists
        child_folder = None
        for child in vm_base_folder.childEntity:
            if isinstance(child, vim.Folder) and child.name == child_folder_name:
                child_folder = child
                break

        if not child_folder:
            # Create a new folder
            child_folder = vm_base_folder.CreateFolder(child_folder_name)
            self.logger.debug("Folder '%s' created successfully", child_folder)

        return child_folder

    def get_datastore(self, session):
        """
        Get the datastore from the configuration if one datastore is configured, otherwise get
        from the image
        """
        datastore = None

        datastore = vcutil.get_vcenter_obj(
            session, [vim.Datastore], self.datastore_name
        )
        if not datastore:
            raise vimconn.VimConnNotFoundException(
                f"Datastore with name: {self.datastore_name} not found"
            )

        return datastore

    def get_datacenter_name(self, session):
        """
        Obtains the datacenter name, this data is cached
        """
        if not self.datacenter_name:
            self.datacenter_name = self._get_datacenter_from_datastore(session)
        return self.datacenter_name

    def _get_datacenter_from_datastore(self, session):
        datacenter_name = None

        # Create a view of all datastores
        content = session.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.Datastore], True
        )
        datastores = container.view

        for datastore in datastores:
            if datastore.name == self.datastore_name:
                # Traverse up the hierarchy to find the datacenter
                parent = datastore.parent
                while parent and not isinstance(parent, vim.Datacenter):
                    parent = parent.parent
                if isinstance(parent, vim.Datacenter):
                    datacenter_name = parent.name
                    break  # Return the datacenter name and exit the loop
        container.Destroy()

        # Raise exception if no datacenter was found
        if datacenter_name is None:
            raise vimconn.VimConnException("Unable to find datacenter")
        return datacenter_name

    def get_cluster_rp_from_av_zone(
        self, session, availability_zone_index, availability_zone_list
    ):
        """
        Gets the resource pool and cluster corresponding to the indicated avzone
        """

        # get the availability zone from configuration
        avzone_name = self.availability_zones_names[0]
        return self._get_resource_pool_cluster_from_av_zone(session, avzone_name)

    def _get_resource_pool_cluster_from_av_zone(self, session, avzone_name):
        self.logger.debug("Search availability_zone name: %s", avzone_name)
        # We have an availability zone that can correspond to a resource pool or to a cluster
        # If it is a resource pool will find a cluster associated
        # If it is a cluster will get the first resource pool associated

        # Check if there is a resource group with this name
        resource_pool = self._get_resource_pool(session, avzone_name)

        if resource_pool:
            cluster = self._get_cluster_from_resource_pool(session, resource_pool)
            if not cluster:
                raise vimconn.VimConnNotFoundException(
                    "unable to find cluster for resource pool"
                    f"name : {resource_pool.name}"
                )
        else:
            # Check if there is a cluster with this name
            cluster = self._get_vcenter_cluster(session, avzone_name)
            if not cluster:
                raise vimconn.VimConnNotFoundException(
                    f"Unable to find either cluster or resource pool with name {avzone_name}"
                )

            # Obtain resource pool for cluster
            resource_pool = cluster.resourcePool

        self.logger.debug(
            "Recovered cluster name: %s and resource_pool: %s",
            cluster.name,
            resource_pool.name,
        )
        return cluster, resource_pool

    def _get_cluster_from_resource_pool(self, server_instance, resource_pool):
        cluster = None

        parent = resource_pool.parent
        while parent:
            if isinstance(parent, vim.ClusterComputeResource):
                cluster = parent
                self.logger.debug(
                    "Recovered cluster name: %s for resouce pool: %s",
                    cluster.name,
                    resource_pool.name,
                )
                break
            elif isinstance(parent, vim.ClusterComputeResource):
                self.logger.warning("Parent is a host not a cluster")
                cluster = parent
            else:
                parent = parent.parent

        return cluster

    def _get_resource_pool(self, session, resource_pool_name):
        return vcutil.get_vcenter_obj(session, [vim.ResourcePool], resource_pool_name)

    def _get_vcenter_cluster(self, server_instance, cluster_name):
        return vcutil.get_vcenter_obj(
            server_instance, [vim.ClusterComputeResource], cluster_name
        )
