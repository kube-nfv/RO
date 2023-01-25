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

PACKAGES="
dist_ro_plugin
dist_ng_ro
dist_ro_sdn_arista_cloudvision
dist_ro_sdn_dpb
dist_ro_sdn_dynpac
dist_ro_sdn_floodlight_of
dist_ro_sdn_ietfl2vpn
dist_ro_sdn_juniper_contrail
dist_ro_sdn_odl_of
dist_ro_sdn_onos_of
dist_ro_sdn_onos_vpls
dist_ro_vim_aws
dist_ro_vim_azure
dist_ro_vim_openstack
dist_ro_vim_openvim
dist_ro_vim_vmware
dist_ro_vim_gcp"

TOX_ENV_LIST="$(echo $PACKAGES | sed "s/ /,/g")"
PROCESSES=$(expr `nproc --a` / 2)

TOX_PARALLEL_NO_SPINNER=1 tox -e $TOX_ENV_LIST

# Copying packages
# RO plugin
cp RO-plugin/deb_dist/python3-osm-ro-plugin_*.deb deb_dist/

# NG-RO
cp NG-RO/deb_dist/python3-osm-ng-ro_*.deb deb_dist/

# VIM plugins:  vmware, openstack, AWS, azure, GCP
for vim_plugin in RO-VIM-*
do
    cp ${vim_plugin}/deb_dist/python3-osm-rovim*.deb deb_dist/
done

# SDN plugins: DynPac, Ietfl2vpn, Onosof Floodlightof
for sdn_plugin in RO-SDN-*
do
    cp ${sdn_plugin}/deb_dist/python3-osm-rosdn*.deb deb_dist/
done
