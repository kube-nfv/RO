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
make -C RO clean package
cp RO/deb_dist/python3-osm-ro_*.deb deb_dist/

# RO client
make -C RO-client clean package
cp RO-client/deb_dist/python3-osm-roclient_*.deb deb_dist/

# RO plugin
make -C RO-plugin clean package
cp RO-plugin/deb_dist/python3-osm-ro-plugin_*.deb deb_dist/

# NG-RO
make -C NG-RO clean package
cp NG-RO/deb_dist/python3-osm-ng-ro_*.deb deb_dist/

# VIM plugings:  vmware, openstack, AWS, fos, azure, Opennebula,
for vim_plugin in RO-VIM-*
do
    make -C $vim_plugin clean package
    cp ${vim_plugin}/deb_dist/python3-osm-rovim*.deb deb_dist/
done

# SDN plugins: DynPac, Ietfl2vpn, Onosof Floodlightof
for sdn_plugin in RO-SDN-*
do
    [[ "$sdn_plugin" == RO-SDN-tapi ]] && continue  # tapi folder appears at Jenkins due to container reuse
    [[ "$sdn_plugin" == RO-SDN-arista ]] && continue  # arista folder appears at Jenkins due to container reuse
    make -C $sdn_plugin clean package
    cp ${sdn_plugin}/deb_dist/python3-osm-rosdn*.deb deb_dist/
done

