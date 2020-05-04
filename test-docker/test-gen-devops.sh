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

[[ "$*" == *--help* ]] && echo \
"This script tests docker build based on debian packages. It generates a docker image bases on Dockerfile-devops, " \
"prints package information and if desired updates OSM RO docker with the generated image.
Generated packages are stored at './temp' folder.
Options:
  --help        show this help
  --no-cache    Use if found problems looking for packages
  --update      Use to update OSM, RO docker with this image" && exit 0

[[ "$*" == *--no-cache* ]] && no_cache="--no_cache" || no_cache=""
[[ "$*" == *--update* ]] && update_osm="k8s" || update_osm=""

HERE=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
export RO_BASE=$(dirname $HERE)

# clean
docker rm -f ro_pkg 2>/dev/null && echo docker ro_pkg removed
rm -rf $HERE/temp/*
find $RO_BASE  -name "*.pyc" -exec rm {} ";"
mkdir -p $HERE/temp

echo -e "\n\n[STAGE 1] Building dockerfile used for the package generation"
docker build $RO_BASE -f $RO_BASE/Dockerfile  -t opensourcemano/ro_pkg
sleep 2

echo "[STAGE 1.1] Generating packages inside docker ro_pkg"
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
docker build $HERE -f $HERE/Dockerfile-devops  -t opensourcemano/ro:py3_devops $no_cache ||
    ! echo "error generating devops dockerfile" >&2 || exit 1

[[ -z "$update_osm" ]] && exit 0
sleep 2

echo -e "\n\n[STAGE 3] Update service osm_ro with generated docker image"
# try docker swarm. If fails try kebernetes
if docker service update osm_ro --force --image opensourcemano/ro:py3_devops 2>/dev/null
then
    sleep 2
    docker container prune -f
elif kubectl -n osm patch deployment ro --patch \
        '{"spec": {"template": {"spec": {"containers": [{"name": "ro", "image": "opensourcemano/ro:py3_devops"}]}}}}'
then
    kubectl -n osm scale deployment ro --replicas=0
    kubectl -n osm scale deployment ro --replicas=1
else
    echo "Cannot update OSM" && exit 1
fi
docker service logs osm_ro
