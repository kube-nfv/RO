#!/bin/bash

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

rm -rf deb_dist/*
mkdir -p deb_dist

# main RO module
make -C RO clean package BRANCH=master
cp RO/deb_dist/python3-osm-ro_*.deb deb_dist/

# RO client
make -C RO-client clean package
cp RO-client/deb_dist/python3-osm-roclient_*.deb deb_dist/

# VIM vmware plugin
make -C RO-VIM-vmware clean package
cp RO-VIM-vmware/deb_dist/python3-osm-rovim-vmware_*.deb deb_dist/

# VIM Openstack plugin
make -C RO-VIM-openstack clean package
cp RO-VIM-openstack/deb_dist/python3-osm-rovim-openstack_*.deb deb_dist/

# VIM Openvim plugin
make -C RO-VIM-openvim clean package
cp RO-VIM-openvim/deb_dist/python3-osm-rovim-openvim_*.deb deb_dist/

# VIM AWS plugin
make -C RO-VIM-aws clean package
cp RO-VIM-aws/deb_dist/python3-osm-rovim-aws_*.deb deb_dist/

# VIM fos plugin
make -C RO-VIM-fos clean package
cp RO-VIM-fos/deb_dist/python3-osm-rovim-fos_*.deb deb_dist/

# VIM azure plugin
make -C RO-VIM-azure clean package
cp RO-VIM-azure/deb_dist/python3-osm-rovim-azure_*.deb deb_dist/

# VIM Opennebula plugin
make -C RO-VIM-opennebula clean package
cp RO-VIM-opennebula/deb_dist/python3-osm-rovim-opennebula_*.deb deb_dist/

# SDN Dynpack plugin
make -C RO-SDN-dynpac clean package
cp RO-SDN-dynpac/deb_dist/python3-osm-rosdn-dynpac_*.deb deb_dist/

# SDN Tapi plugin
make -C RO-SDN-tapi clean package
cp RO-SDN-tapi/deb_dist/python3-osm-rosdn-tapi_*.deb deb_dist/

# SDN Onos openflow
make -C RO-SDN-onos_openflow clean package
cp RO-SDN-onos_openflow/deb_dist/python3-osm-rosdn-onosof_*.deb deb_dist/

