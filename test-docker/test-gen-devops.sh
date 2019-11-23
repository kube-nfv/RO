#!/bin/bash

##
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
# contact with: nfvlabs@tid.es
##

# Generates the debian packages; and then generates a docker image base on Dockerfile-devops and update a
# running docker stack with the generated image

HERE=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
export RO_BASE=$(dirname $HERE)

# clean
docker rm -f ro_pkg 2>/dev/null && echo docker ro_pkg removed
rm -rf $HERE/temp/*
find $RO_BASE  -name "*.pyc" -exec rm {} ";"
mkdir -p $HERE/temp

echo -e "\n\n[STAGE 1] Builind dockerfile userd for the package generation"
docker build $RO_BASE -f $RO_BASE/Dockerfile  -t opensourcemano/ro_pkg
sleep 2

echo "[STAGE 1.1] Generting packages inside docker ro_pkg"
docker run -d --name ro_pkg opensourcemano/ro_pkg bash -c 'sleep 3600'
docker cp $RO_BASE ro_pkg:/RO
docker exec ro_pkg bash -c 'cd /RO;  ./devops-stages/stage-build.sh'
deb_files=`docker exec ro_pkg bash -c 'ls /RO/deb_dist/'`
[ -z "$deb_files" ] && echo "No packages generated" >&2 && exit 1
echo $deb_files

echo -e "\n\n[STAGE 1.2] Print package information and copy to '$HERE/temp/'"
# print package information and copy to "$HERE/temp/"
for deb_file in $deb_files ; do
   echo; echo; echo
   echo $deb_file info:
   echo "===========================" 
   docker cp ro_pkg:/RO/deb_dist/$deb_file $HERE/temp/
   dpkg -I $HERE/temp/$(basename $deb_file)
done

# docker rm -f ro_pkg
echo -e "\n\n[STAGE 2] Building docker image opensourcemano/ro:py3_devops based on debian packages"
docker build $HERE -f $HERE/Dockerfile-devops  -t opensourcemano/ro:py3_devops ||
    ! echo "error generating devops dockerfile" >&2 || exit 1
sleep 2
# docker run -d --name ro_devops opensourcemano/ro:py3_devops
# docker run -ti exec ro_devops ro tenant-list  || ! echo "Cannot exec ro client to get server tenants" >&2 || exit 1

echo -e "\n\n[STAGE 3] Update service osm_ro with generated docker image"
docker service update osm_ro --force --image opensourcemano/ro:py3_devops
sleep 2
docker container prune -f
docker service logs osm_ro
