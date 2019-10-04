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

# Generates a docker image base on Dockerfile-local and update a running docker stack with the generated image

HERE=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
export RO_BASE=$(dirname $HERE)

echo -e "\n\n[STAGE 1] Building docker image opensourcemano/ro:py3_local based on debian packages"
docker build $RO_BASE -f $RO_BASE/Dockerfile-local -t opensourcemano/ro:py3_local ||
    ! echo "error generating local dockerfile" >&2 || exit 1
sleep 2
docker service update osm_ro --force --image opensourcemano/ro:py3_local
sleep 2
docker container prune -f
docker service logs osm_ro
