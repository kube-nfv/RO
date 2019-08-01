# -*- coding: utf-8 -*-

__author__='Sergio Gonzalez'
__date__ ='$18-apr-2019 23:59:59$'

import base64

import vimconn
import logging
import netaddr

from os import getenv
from uuid import uuid4

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient



from msrestazure.azure_exceptions import CloudError

if getenv('OSMRO_PDB_DEBUG'):
    import sys
    print(sys.path)
    import pdb
    pdb.set_trace()


class vimconnector(vimconn.vimconnector):

    provision_state2osm = {
        "Deleting": "INACTIVE",
        "Failed": "ERROR",
        "Succeeded": "ACTIVE",
        "Updating": "BUILD",
    }

    def __init__(self, uuid, name, tenant_id, tenant_name, url, url_admin=None, user=None, passwd=None, log_level=None,
                 config={}, persistent_info={}):

        vimconn.vimconnector.__init__(self, uuid, name, tenant_id, tenant_name, url, url_admin, user, passwd, log_level,
                                      config, persistent_info)

        self.vnet_address_space = None
        # LOGGER
        self.logger = logging.getLogger('openmano.vim.azure')
        if log_level:
            logging.basicConfig()
            self.logger.setLevel(getattr(logging, log_level))

        # CREDENTIALS 
        self.credentials = ServicePrincipalCredentials(
            client_id=user,
            secret=passwd,
            tenant=(tenant_id or tenant_name)
        )

        self.tenant=(tenant_id or tenant_name)

        # SUBSCRIPTION
        if 'subscription_id' in config:
            self.subscription_id = config.get('subscription_id')
            self.logger.debug('Setting subscription '+str(self.subscription_id))
        else:
            raise vimconn.vimconnException('Subscription not specified')
        # REGION
        if 'region_name' in config:
            self.region = config.get('region_name')
        else:
            raise vimconn.vimconnException('Azure region_name is not specified at config')
        # RESOURCE_GROUP
        if 'resource_group' in config:
            self.resource_group = config.get('resource_group')
        else:
            raise vimconn.vimconnException('Azure resource_group is not specified at config')
        # VNET_NAME
        if 'vnet_name' in config:
            self.vnet_name = config["vnet_name"]
            
        # public ssh key
        self.pub_key = config.get('pub_key')
            
    def _reload_connection(self):
        """
        Sets connections to work with Azure service APIs
        :return:
        """
        self.logger.debug('Reloading API Connection')
        try:
            self.conn = ResourceManagementClient(self.credentials, self.subscription_id)
            self.conn_compute = ComputeManagementClient(self.credentials, self.subscription_id)
            self.conn_vnet = NetworkManagementClient(self.credentials, self.subscription_id)
            self._check_or_create_resource_group()
            self._check_or_create_vnet()
        except Exception as e:
            self.format_vimconn_exception(e)            

    def _get_resource_name_from_resource_id(self, resource_id):

        try:
            resource=str(resource_id.split('/')[-1])
            return resource
        except Exception as e:
            raise vimconn.vimconnNotFoundException("Resource name '{}' not found".format(resource_id))

    def _get_location_from_resource_group(self, resource_group_name):

        try:
            location=self.conn.resource_groups.get(resource_group_name).location
            return location
        except Exception as e:
            raise vimconn.vimconnNotFoundException("Location '{}' not found".format(resource_group_name))


    def _get_resource_group_name_from_resource_id(self, resource_id):

        try:
            rg=str(resource_id.split('/')[4])
            return rg
        except Exception as e:
            raise vimconn.vimconnNotFoundException("Resource group '{}' not found".format(resource_id))


    def _get_net_name_from_resource_id(self, resource_id):

        try:
            net_name=str(resource_id.split('/')[8])
            return net_name
        except Exception as e:
            raise vimconn.vimconnNotFoundException("Net name '{}' not found".format(resource_id))


    def _check_subnets_for_vm(self, net_list):
        # All subnets must belong to the same resource group and vnet
        # ERROR
        #   File "/root/RO/build/osm_ro/vimconn_azure.py", line 110, in <genexpr>
        # self._get_resource_name_from_resource_id(net['id']) for net in net_list)) != 1:
        #if len(set(self._get_resource_group_name_from_resource_id(net['net_id']) +
        #          self._get_resource_name_from_resource_id(net['net_id']) for net in net_list)) != 2:
        #    raise self.format_vimconn_exception('Azure VMs can only attach to subnets in same VNET')
        self.logger.debug('Checking subnets for VM')
        num_elem_set = len(set(self._get_resource_group_name_from_resource_id(net['net_id']) +
                  self._get_resource_name_from_resource_id(net['net_id']) for net in net_list))

        if ( num_elem_set != 1 ):
            raise self.format_vimconn_exception('Azure VMs can only attach to subnets in same VNET')    

    def format_vimconn_exception(self, e):
        """
        Params: an Exception object
        :param e:
        :return: Raises the proper vimconnException
        """
        self.conn = None
        self.conn_vnet = None
        raise vimconn.vimconnException(type(e).__name__ + ': ' + str(e))

    def _check_or_create_resource_group(self):
        """
        Creates a resource group in indicated region
        :return: None
        """
        self.logger.debug('Creating RG {} in location {}'.format(self.resource_group, self.region))
        self.conn.resource_groups.create_or_update(self.resource_group, {'location': self.region})

    def _check_or_create_vnet(self):

        try:
            vnet = self.conn_vnet.virtual_networks.get(self.resource_group, self.vnet_name)
            self.vnet_address_space = vnet.address_space.address_prefixes[0]
            self.vnet_id = vnet.id

            return
        except CloudError as e:
            if e.error.error == "ResourceNotFound":
                pass
            else:
                raise
        # if not exist, creates it
        try:
            vnet_params = {
                'location': self.region,
                'address_space': {
                    'address_prefixes': ["10.0.0.0/8"]
                },
            }
            self.vnet_address_space = "10.0.0.0/8"

            self.conn_vnet.virtual_networks.create_or_update(self.resource_group, self.vnet_name, vnet_params)
            vnet = self.conn_vnet.virtual_networks.get(self.resource_group, self.vnet_name)
            self.vnet_id = vnet.id
        except Exception as e:
            self.format_vimconn_exception(e)

    def new_network(self, net_name, net_type, ip_profile=None, shared=False, vlan=None):
        """
        Adds a tenant network to VIM
        :param net_name: name of the network
        :param net_type:
        :param ip_profile: is a dict containing the IP parameters of the network (Currently only IPv4 is implemented)
                'ip-version': can be one of ['IPv4','IPv6']
                'subnet-address': ip_prefix_schema, that is X.X.X.X/Y
                'gateway-address': (Optional) ip_schema, that is X.X.X.X
                'dns-address': (Optional) ip_schema,
                'dhcp': (Optional) dict containing
                    'enabled': {'type': 'boolean'},
                    'start-address': ip_schema, first IP to grant
                    'count': number of IPs to grant.
        :param shared:
        :param vlan:
        :return: a tuple with the network identifier and created_items, or raises an exception on error
            created_items can be None or a dictionary where this method can include key-values that will be passed to
            the method delete_network. Can be used to store created segments, created l2gw connections, etc.
            Format is vimconnector dependent, but do not use nested dictionaries and a value of None should be the same
            as not present.
        """
        return self._new_subnet(net_name, ip_profile)

    def _new_subnet(self, net_name, ip_profile):
        """
        Adds a tenant network to VIM. It creates a new VNET with a single subnet
        :param net_name:
        :param ip_profile:
        :return:
        """
        self.logger.debug('Adding a subnet to VNET '+self.vnet_name)
        self._reload_connection()

        if ip_profile is None:
            # get a non used vnet ip range /24 and allocate automatically inside the range self.vnet_address_space
            used_subnets = self.get_network_list()
            for ip_range in netaddr.IPNetwork(self.vnet_address_space).subnet(24):
                for used_subnet in used_subnets:
                    subnet_range = netaddr.IPNetwork(used_subnet["cidr_block"])
                    if subnet_range in ip_range or ip_range in subnet_range:
                        # this range overlaps with an existing subnet ip range. Breaks and look for another
                        break
                else:
                    ip_profile = {"subnet_address": str(ip_range)}
                    self.logger.debug('ip_profile: ' + str(ip_range))
                    break
            else:
                vimconn.vimconnException("Cannot find a non-used subnet range in {}".format(self.vnet_address_space))
        else:
            ip_profile = {"subnet_address": ip_profile['subnet_address']}

        try:
            #subnet_name = "{}-{}".format(net_name[:24], uuid4())
            subnet_name = net_name[:24]
            subnet_params= {
                'address_prefix': ip_profile['subnet_address']
            }
            self.logger.debug('subnet_name    : {}'.format(subnet_name))
            async_creation=self.conn_vnet.subnets.create_or_update(self.resource_group, self.vnet_name, subnet_name, subnet_params)
            async_creation.wait()

            #return "{}/subnet/{}".format(self.vnet_id, subnet_name), None
            return "{}/subnets/{}".format(self.vnet_id, subnet_name), None
        except Exception as e:
            self.format_vimconn_exception(e)

    def _create_nic(self, net, nic_name, static_ip=None):

        self._reload_connection()

        subnet_id = net['net_id']
        location = self._get_location_from_resource_group(self.resource_group)

        try:
            if static_ip:
                async_nic_creation = self.conn_vnet.network_interfaces.create_or_update(
                    self.resource_group,
                    nic_name,
                    {
                        'location': location,
                        'ip_configurations': [{
                            'name': nic_name + '-ipconfiguration',
                            'privateIPAddress': static_ip,
                            'privateIPAllocationMethod': 'Static',
                            'subnet': {
                                'id': subnet_id
                            }
                        }]
                    }
                )
                async_nic_creation.wait()
            else:
                ip_configuration_name = nic_name + '-ipconfiguration'
                self.logger.debug('Create NIC')
                async_nic_creation = self.conn_vnet.network_interfaces.create_or_update(
                    self.resource_group,
                    nic_name,
                    {
                        'location': location,
                        'ip_configurations': [{
                            'name': ip_configuration_name,
                            'subnet': {
                                'id': subnet_id
                            }
                        }]
                    }
                )
                async_nic_creation.wait()

            public_ip = net.get('floating_ip')
            if public_ip and public_ip == True:
                self.logger.debug('Creating PUBLIC IP')
                public_ip_addess_params = {
                    'location': location,
                    'public_ip_allocation_method': 'Dynamic'
                }
                public_ip_name = nic_name + '-public-ip'
                public_ip = self.conn_vnet.public_ip_addresses.create_or_update(
                    self.resource_group,
                    public_ip_name,
                    public_ip_addess_params
                )
                self.logger.debug('Create PUBLIC IP: {}'.format(public_ip.result()))

                # Asociate NIC to Public IP
                self.logger.debug('Getting NIC DATA')
                nic_data = self.conn_vnet.network_interfaces.get(
                    self.resource_group,
                    nic_name)

                nic_data.ip_configurations[0].public_ip_address = public_ip.result()

                self.logger.debug('Updating NIC with public IP')
                self.conn_vnet.network_interfaces.create_or_update(
                    self.resource_group,
                    nic_name,
                    nic_data)

        except Exception as e:
            self.format_vimconn_exception(e)

        result = async_nic_creation.result()
        return async_nic_creation.result()

    def new_flavor(self, flavor_data):

        if flavor_data:
            flavor_id = self.get_flavor_id_from_data(flavor_data)

            if flavor_id != []:
                return flavor_id
            else:
                raise vimconn.vimconnNotFoundException("flavor '{}' not found".format(flavor_data))
        else:
            vimconn.vimconnException("There is no data in the flavor_data input parameter")

    def new_tenant(self,tenant_name,tenant_description):

        raise vimconn.vimconnAuthException("It is not possible to create a TENANT in AZURE")

    def new_image(self, image_dict):

        self._reload_connection()

        try:
            self.logger.debug('new_image - image_dict - {}'.format(image_dict))

            if image_dict.get("name"):
                image_name = image_dict.get("name")
            else:
                raise vimconn.vimconnException("There is no name in the image input data")

            if image_dict.get("location"):
                params = image_dict["location"].split(":")
                if len(params) >= 4:
                    publisher = params[0]
                    offer = params[1]
                    sku = params[2]
                    version = params[3]
                    #image_params = {'location': self.region, 'publisher': publisher, 'offer': offer, 'sku': sku, 'version': version }
                    image_params = {'location': self.region}

                    self.conn_compute.images.create_or_update()
                    async_creation=self.conn_compute.images.create_or_update(self.resource_group, image_name, image_params)
                    image_id = async_creation.result().id
                else:
                    raise vimconn.vimconnException("The image location is not correct: {}".format(image_dict["location"]))
            return image_id

        except Exception as e:
            self.format_vimconn_exception(e)

    def get_image_id_from_path(self, path):
        """Get the image id from image path in the VIM database.
           Returns the image_id or raises a vimconnNotFoundException
        """

    def get_image_list(self, filter_dict={}):
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
        self._reload_connection()

        image_list = []
        if filter_dict.get("name"):
            params = filter_dict["name"].split(":")
            if len(params) >= 3:
                publisher = params[0]
                offer = params[1]
                sku = params[2]
                version = None
                if len(params) == 4:
                    version = params[3]
                images = self.conn_compute.virtual_machine_images.list(self.region, publisher, offer, sku)
                for image in images:
                    if version:
                        image_version = str(image.id).split("/")[-1]
                        if image_version != version:
                            continue
                    image_list.append({
                        'id': str(image.id),
                        'name': self._get_resource_name_from_resource_id(image.id)
                    })

        return image_list

    def get_network_list(self, filter_dict={}):
        """Obtain tenant networks of VIM
        Filter_dict can be:
            name: network name
            id: network uuid
            shared: boolean
            tenant_id: tenant
            admin_state_up: boolean
            status: 'ACTIVE'
        Returns the network list of dictionaries
        """
        self.logger.debug('Getting all subnets from VIM')
        try:
            self._reload_connection()

            vnet = self.conn_vnet.virtual_networks.get(self.resource_group, self.vnet_name)
            subnet_list = []

            for subnet in vnet.subnets:

                if filter_dict:
                    if filter_dict.get("id") and str(subnet.id) != filter_dict["id"]:
                        continue
                    if filter_dict.get("name") and \
                            str(subnet.id) != filter_dict["name"]:
                        continue

                name = self._get_resource_name_from_resource_id(subnet.id)

                subnet_list.append({
                    'id': str(subnet.id),
                    'name': self._get_resource_name_from_resource_id(subnet.id),
                    'status' : self.provision_state2osm[subnet.provisioning_state],
                    'cidr_block': str(subnet.address_prefix),
                    'type': 'bridge',
                    'shared': False
                    }
                )

            return subnet_list
        except Exception as e:
            self.format_vimconn_exception(e)

    def new_vminstance(self, vm_name, description, start, image_id, flavor_id, net_list, cloud_config=None,
                       disk_list=None, availability_zone_index=None, availability_zone_list=None):

        return self._new_vminstance(vm_name, image_id, flavor_id, net_list)
        
    #def _new_vminstance(self, vm_name, image_id, flavor_id, net_list, cloud_config=None, disk_list=None,
    #                    availability_zone_index=None, availability_zone_list=None):
    def new_vminstance(self, name, description, start, image_id, flavor_id, net_list, cloud_config=None,
                           disk_list=None,
                           availability_zone_index=None, availability_zone_list=None):

        self._check_subnets_for_vm(net_list)
        vm_nics = []
        for idx, net in enumerate(net_list):
            # Fault with subnet_id
            # subnet_id=net['subnet_id']
            # subnet_id=net['net_id']

            nic_name = name + '-nic-'+str(idx)
            vm_nic = self._create_nic(net, nic_name)
            vm_nics.append({ 'id': str(vm_nic.id)})

        try:
            # image_id are several fields of the image_id
            image_reference = self.get_image_reference(image_id)

            # The virtual machine name must have less or 64 characters and it can not have the following
            # characters: (~ ! @ # $ % ^ & * ( ) = + _ [ ] { } \ | ; : ' " , < > / ?.)
            vm_name_aux = self.check_vm_name(name)

            # cloud-init configuration
            # cloud config
            if cloud_config:
                config_drive, userdata = self._create_user_data(cloud_config)
                custom_data = base64.b64encode(userdata.encode('utf-8')).decode('latin-1')
                os_profile = {
                    'computer_name': vm_name_aux,  # TODO if vm_name cannot be repeated add uuid4() suffix
                    'admin_username': 'osm',  # TODO is it mandatory???
                    'admin_password': 'Osm-osm',  # TODO is it mandatory???
                    'custom_data': custom_data
                }
            else:
                os_profile = {
                    'computer_name': vm_name_aux,  # TODO if vm_name cannot be repeated add uuid4() suffix
                    'admin_username': 'osm',  # TODO is it mandatory???
                    'admin_password': 'Osm-osm',  # TODO is it mandatory???
                }

            vm_parameters = {
                'location': self.region,
                'os_profile': os_profile,
                'hardware_profile': {
                    'vm_size': flavor_id
                },
                'storage_profile': {
                    'image_reference': image_reference
                },
                'network_profile': {
                    'network_interfaces': [
                        vm_nics[0]
                    ]
                }
            }

            creation_result = self.conn_compute.virtual_machines.create_or_update(
                self.resource_group, 
                vm_name_aux, 
                vm_parameters
            )
            
            #creation_result.wait()
            result = creation_result.result()

            for index, subnet in enumerate(net_list):
                net_list[index]['vim_id'] = result.id

            if start == True:
                #self.logger.debug('Arrancamos VM y esperamos')
                start_result = self.conn_compute.virtual_machines.start(
                    self.resource_group,
                    vm_name_aux)
            #start_result.wait()

            return result.id, None
            
            #run_command_parameters = {
            #    'command_id': 'RunShellScript', # For linux, don't change it
            #    'script': [
            #    'date > /tmp/test.txt'
            #    ]
            #}
        except Exception as e:
            #self.logger.debug('AZURE <=== EX: _new_vminstance', exc_info=True)
            self.format_vimconn_exception(e)

    # It is necesary extract from image_id data to create the VM with this format
    #        'image_reference': {
    #           'publisher': vm_reference['publisher'],
    #           'offer': vm_reference['offer'],
    #           'sku': vm_reference['sku'],
    #           'version': vm_reference['version']
    #        },
    def get_image_reference(self, imagen):

        # The data input format example:
        # /Subscriptions/ca3d18ab-d373-4afb-a5d6-7c44f098d16a/Providers/Microsoft.Compute/Locations/westeurope/
        # Publishers/Canonical/ArtifactTypes/VMImage/
        # Offers/UbuntuServer/
        # Skus/18.04-LTS/
        # Versions/18.04.201809110
        publiser = str(imagen.split('/')[8])
        offer = str(imagen.split('/')[12])
        sku = str(imagen.split('/')[14])
        version = str(imagen.split('/')[16])

        return {
                 'publisher': publiser,
                 'offer': offer,
                 'sku': sku,
                 'version': version
        }

    # Azure VM names can not have some special characters
    def check_vm_name( self, vm_name ):

        #chars_not_allowed_list = ['~','!','@','#','$','%','^','&','*','(',')','=','+','_','[',']','{','}','|',';',':','<','>','/','?','.']
        chars_not_allowed_list = "~!@#$%^&*()=+_[]{}|;:<>/?."

        # First: the VM name max length is 64 characters
        vm_name_aux = vm_name[:64]

        # Second: replace not allowed characters
        for elem in chars_not_allowed_list :
            # Check if string is in the main string
            if elem in vm_name_aux :
                #self.logger.debug('Dentro del IF')
                # Replace the string
                vm_name_aux = vm_name_aux.replace(elem, '-')

        return vm_name_aux


    def get_flavor_id_from_data(self, flavor_dict):
        self.logger.debug("Getting flavor id from data")

        try:
            self._reload_connection()
            vm_sizes_list = [vm_size.serialize() for vm_size in self.conn_compute.virtual_machine_sizes.list(self.region)]

            cpus = flavor_dict['vcpus']
            memMB = flavor_dict['ram']

            filteredSizes = [size for size in vm_sizes_list if size['numberOfCores'] >= cpus and size['memoryInMB'] >= memMB]
            listedFilteredSizes = sorted(filteredSizes, key=lambda k: k['numberOfCores'])

            return listedFilteredSizes[0]['name']

        except Exception as e:
            self.format_vimconn_exception(e)

    def _get_flavor_id_from_flavor_name(self, flavor_name):
        self.logger.debug("Getting flavor id from falvor name {}".format(flavor_name))

        try:
            self._reload_connection()
            vm_sizes_list = [vm_size.serialize() for vm_size in self.conn_compute.virtual_machine_sizes.list(self.region)]

            output_flavor = None
            for size in vm_sizes_list:
                if size['name'] == flavor_name:
                    output_flavor = size

            return output_flavor

        except Exception as e:
            self.format_vimconn_exception(e)

    def check_vim_connectivity(self):
        try:
            self._reload_connection()
            return True
        except Exception as e:
            raise vimconn.vimconnException("Connectivity issue with Azure API: {}".format(e))

    def get_network(self, net_id):

        resName = self._get_resource_name_from_resource_id(net_id)

        self._reload_connection()

        filter_dict = {'name' : net_id}
        network_list = self.get_network_list(filter_dict)

        if not network_list:
            raise vimconn.vimconnNotFoundException("network '{}' not found".format(net_id))
        else:
            return network_list[0]

    # Added created_items because it is neccesary
    #     self.vim.delete_network(net_vim_id, task["extra"].get("created_items"))
    #   TypeError: delete_network() takes exactly 2 arguments (3 given)   
    def delete_network(self, net_id, created_items=None):

        self.logger.debug('Deletting network {} - {}'.format(self.resource_group, net_id))

        resName = self._get_resource_name_from_resource_id(net_id)

        self._reload_connection()

        filter_dict = {'name' : net_id}
        network_list = self.get_network_list(filter_dict)
        if not network_list:
            raise vimconn.vimconnNotFoundException("network '{}' not found".format(net_id))

        try:
            # Subnet API fails (CloudError: Azure Error: ResourceNotFound)
            # Put the initial virtual_network API
            async_delete=self.conn_vnet.subnets.delete(self.resource_group, self.vnet_name, resName)
            return net_id

        except CloudError as e:
            if e.error.error == "ResourceNotFound":
                raise vimconn.vimconnNotFoundException("network '{}' not found".format(net_id))
            else:
                raise
        except Exception as e:
            self.format_vimconn_exception(e)



    # Added third parameter because it is necesary
    def delete_vminstance(self, vm_id, created_items=None):

        self.logger.debug('Deletting VM instance {} - {}'.format(self.resource_group, vm_id))
        self._reload_connection()

        try:

            resName = self._get_resource_name_from_resource_id(vm_id)
            vm = self.conn_compute.virtual_machines.get(self.resource_group, resName)

            # Shuts down the virtual machine and releases the compute resources
            #vm_stop = self.conn_compute.virtual_machines.power_off(self.resource_group, resName)
            #vm_stop.wait()

            vm_delete = self.conn_compute.virtual_machines.delete(self.resource_group, resName)
            vm_delete.wait()

            # Delete OS Disk
            os_disk_name = vm.storage_profile.os_disk.name
            self.logger.debug('Delete OS DISK - ' + os_disk_name)
            self.conn_compute.disks.delete(self.resource_group, os_disk_name)

            # After deletting VM, it is necessary delete NIC, because if is not deleted delete_network
            # does not work because Azure says that is in use the subnet
            network_interfaces = vm.network_profile.network_interfaces

            for network_interface in network_interfaces:

                #self.logger.debug('nic - {}'.format(network_interface))

                nic_name = self._get_resource_name_from_resource_id(network_interface.id)

                #self.logger.debug('nic_name - {}'.format(nic_name))

                nic_data = self.conn_vnet.network_interfaces.get(
                    self.resource_group,
                    nic_name)

                exist_public_ip = nic_data.ip_configurations[0].public_ip_address
                if exist_public_ip:
                    public_ip_id = nic_data.ip_configurations[0].public_ip_address.id
                    self.logger.debug('Public ip id - ' + public_ip_id)

                    self.logger.debug('Delete NIC - ' + nic_name)
                    nic_delete = self.conn_vnet.network_interfaces.delete(self.resource_group, nic_name)
                    nic_delete.wait()

                    # Delete public_ip
                    public_ip_name = self._get_resource_name_from_resource_id(public_ip_id)

                    self.logger.debug('Delete PUBLIC IP - ' + public_ip_name)
                    public_ip = self.conn_vnet.public_ip_addresses.delete(self.resource_group, public_ip_name)
        except CloudError as e:
            if e.error.error == "ResourceNotFound":
                raise vimconn.vimconnNotFoundException("No vminstance found '{}'".format(vm_id))
            else:
                raise
        except Exception as e:
            self.format_vimconn_exception(e)

    def action_vminstance(self, vm_id, action_dict, created_items={}):
        """Send and action over a VM instance from VIM
        Returns the vm_id if the action was successfully sent to the VIM"""

        self.logger.debug("Action over VM '%s': %s", vm_id, str(action_dict))
        try:
            self._reload_connection()
            resName = self._get_resource_name_from_resource_id(vm_id)
            if "start" in action_dict:
                self.conn_compute.virtual_machines.start(self.resource_group,resName)
            elif "stop" in action_dict or "shutdown" in action_dict or "shutoff" in action_dict:
                self.conn_compute.virtual_machines.power_off(self.resource_group,resName)
            elif "terminate" in action_dict:
                self.conn_compute.virtual_machines.delete(self.resource_group,resName)
            elif "reboot" in action_dict:
                self.conn_compute.virtual_machines.restart(self.resource_group,resName)
            return None
        except CloudError as e:
            if e.error.error == "ResourceNotFound":
                raise vimconn.vimconnNotFoundException("No vm found '{}'".format(vm_id))
            else:
                raise
        except Exception as e:
            self.format_vimconn_exception(e)

    def delete_flavor(self, flavor_id):

        raise vimconn.vimconnAuthException("It is not possible to delete a FLAVOR in AZURE")

    def delete_tenant(self,tenant_id,):

        raise vimconn.vimconnAuthException("It is not possible to delete a TENANT in AZURE")

    def delete_image(self, image_id):

        raise vimconn.vimconnAuthException("It is not possible to delete a IMAGE in AZURE")

    def get_vminstance(self, vm_id):

        self._reload_connection()
        try:
            resName = self._get_resource_name_from_resource_id(vm_id)
            vm=self.conn_compute.virtual_machines.get(self.resource_group, resName)
        except CloudError as e:
            if e.error.error == "ResourceNotFound":
                raise vimconn.vimconnNotFoundException("No vminstance found '{}'".format(vm_id))
            else:
                raise
        except Exception as e:
            self.format_vimconn_exception(e)

        return vm

    def get_flavor(self, flavor_id):
        self._reload_connection()

        flavor_data = self._get_flavor_id_from_flavor_name(flavor_id)
        if flavor_data:
            flavor = {
                'id': flavor_id,
                'name': flavor_id,
                'ram': flavor_data['memoryInMB'],
                'vcpus': flavor_data['numberOfCores'],
                'disk': flavor_data['resourceDiskSizeInMB']
            }
            return flavor
        else:
            raise vimconn.vimconnNotFoundException("flavor '{}' not found".format(flavor_id))


    def get_tenant_list(self, filter_dict={}):

        tenants_azure=[{'name': self.tenant, 'id': self.tenant}]
        tenant_list=[]

        for tenant_azure in tenants_azure:
            if filter_dict:
                if filter_dict.get("id") and str(tenant_azure.get("id")) != filter_dict["id"]:
                    continue
                if filter_dict.get("name") and  str(tenant_azure.get("name")) != filter_dict["name"]:
                    continue

            tenant_list.append(tenant_azure)

        return tenant_list

    def refresh_nets_status(self, net_list):

        out_nets = {}
        self._reload_connection()
        for net_id in net_list:
            try:
                netName = self._get_net_name_from_resource_id(net_id)
                resName = self._get_resource_name_from_resource_id(net_id)

                net = self.conn_vnet.subnets.get(self.resource_group, netName, resName)

                out_nets[net_id] ={
                    "status": self.provision_state2osm[net.provisioning_state],
                    "vim_info": str(net)
                }
            except CloudError as e:
                if e.error.error == "ResourceNotFound":
                    out_nets[net_id] = {
                        "status": "DELETED",
                        "error_msg": str(e)
                    }
                else:
                    raise
            except vimconn.vimconnNotFoundException as e:
                out_nets[net_id] = {
                    "status": "DELETED",
                    "error_msg": str(e)
                }
            except Exception as e:
                # TODO distinguish when it is deleted
                out_nets[net_id] = {
                    "status": "VIM_ERROR",
                    "error_msg": str(e)
                }
        return out_nets

    def refresh_vms_status(self, vm_list):

        out_vms = {}
        out_vms_dict = {}
        self._reload_connection()

        for vm_id in vm_list:
            try:

                resName = self._get_resource_name_from_resource_id(vm_id)

                vm = self.conn_compute.virtual_machines.get(self.resource_group, resName)
                out_vms_dict['status'] = self.provision_state2osm[vm.provisioning_state]
                out_vms_dict['interfaces'] = []
                interface_dict = {}

                network_interfaces = vm.network_profile.network_interfaces

                for network_interface in network_interfaces:

                    nic_name = self._get_resource_name_from_resource_id(network_interface.id)
                    interface_dict['vim_interface_id'] = vm_id

                    nic_data = self.conn_vnet.network_interfaces.get(
                        self.resource_group,
                        nic_name)

                    private_ip = nic_data.ip_configurations[0].private_ip_address

                    interface_dict['mac_address'] = nic_data.mac_address
                    interface_dict['ip_address'] = private_ip
                    out_vms_dict['interfaces'].append(interface_dict)

            except Exception as e:
                out_vms_dict['status'] = "DELETED"
                out_vms_dict['error_msg'] = str(e)
                vm = None
            finally:
                if vm:
                    out_vms_dict['vim_info'] = str(vm)

            out_vms[vm_id] = out_vms_dict

        return out_vms


if __name__ == "__main__":

    # Making some basic test
    vim_id='azure'
    vim_name='azure'
    needed_test_params = {
        "client_id": "AZURE_CLIENT_ID",
        "secret": "AZURE_SECRET",
        "tenant": "AZURE_TENANT",
        "resource_group": "AZURE_RESOURCE_GROUP",
        "subscription_id": "AZURE_SUBSCRIPTION_ID",
        "vnet_name": "AZURE_VNET_NAME",
    }
    test_params = {}

    for param, env_var in needed_test_params.items():
        value = getenv(env_var)
        if not value:
            raise Exception("Provide a valid value for env '{}'".format(env_var))
        test_params[param] = value

    config = {
            'region_name': getenv("AZURE_REGION_NAME", 'westeurope'),
            'resource_group': getenv("AZURE_RESOURCE_GROUP"),
            'subscription_id': getenv("AZURE_SUBSCRIPTION_ID"),
            'pub_key': getenv("AZURE_PUB_KEY", None),
            'vnet_name': getenv("AZURE_VNET_NAME", 'myNetwork'),
    }

    virtualMachine = {
        'name': 'sergio',
        'description': 'new VM',
        'status': 'running',
        'image': {
            'publisher': 'Canonical',
            'offer': 'UbuntuServer',
            'sku': '16.04.0-LTS',
            'version': 'latest'
        },
        'hardware_profile': {
            'vm_size': 'Standard_DS1_v2'
        },
        'networks': [
            'sergio'
        ]
    }

    vnet_config = {
        'subnet_address': '10.1.2.0/24',
        #'subnet_name': 'subnet-oam'
    }
    ###########################

    azure = vimconnector(vim_id, vim_name, tenant_id=test_params["tenant"], tenant_name=None, url=None, url_admin=None,
                         user=test_params["client_id"], passwd=test_params["secret"], log_level=None, config=config)

    # azure.get_flavor_id_from_data("here")
    # subnets=azure.get_network_list()
    # azure.new_vminstance(virtualMachine['name'], virtualMachine['description'], virtualMachine['status'],
    #                      virtualMachine['image'], virtualMachine['hardware_profile']['vm_size'], subnets)

    azure.new_network("mynet", None)
    net_id = "/subscriptions/82f80cc1-876b-4591-9911-1fb5788384fd/resourceGroups/osmRG/providers/Microsoft."\
             "Network/virtualNetworks/test"
    net_id_not_found = "/subscriptions/82f80cc1-876b-4591-9911-1fb5788384fd/resourceGroups/osmRG/providers/"\
                       "Microsoft.Network/virtualNetworks/testALF"
    azure.refresh_nets_status([net_id, net_id_not_found])
