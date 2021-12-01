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

set -ex

rm -rf deb_dist/*
mkdir -p deb_dist

# Building packages
tox -e dist_ro_plugin &
tox -e dist_ng_ro &
tox -e dist_ro_sdn_arista_cloudvision &
tox -e dist_ro_sdn_dpb &
tox -e dist_ro_sdn_dynpac &
tox -e dist_ro_sdn_floodlight_of &
tox -e dist_ro_sdn_ietfl2vpn &
tox -e dist_ro_sdn_juniper_contrail &
tox -e dist_ro_sdn_odl_of &
tox -e dist_ro_sdn_onos_of &
tox -e dist_ro_sdn_onos_vpls &
tox -e dist_ro_vim_aws &
tox -e dist_ro_vim_azure &
tox -e dist_ro_vim_fos &
tox -e dist_ro_vim_openstack &
tox -e dist_ro_vim_openvim &
tox -e dist_ro_vim_vmware &
tox -e dist_ro_vim_gcp &

while true; do
  wait -n || {
    code="$?"
    ([[ $code = "127" ]] && exit 0 || exit "$code")
    break
  }
done;
# Copying packages
# RO plugin
cp RO-plugin/deb_dist/python3-osm-ro-plugin_*.deb deb_dist/

# NG-RO
cp NG-RO/deb_dist/python3-osm-ng-ro_*.deb deb_dist/

# VIM plugins:  vmware, openstack, AWS, fos, azure, GCP
for vim_plugin in RO-VIM-*
do
    cp ${vim_plugin}/deb_dist/python3-osm-rovim*.deb deb_dist/
done

# SDN plugins: DynPac, Ietfl2vpn, Onosof Floodlightof
for sdn_plugin in RO-SDN-*
do
    cp ${sdn_plugin}/deb_dist/python3-osm-rosdn*.deb deb_dist/
done
