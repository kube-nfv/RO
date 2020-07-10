# Copyright 2018 Telefonica S.A.
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

# This Dockerfile is intented for devops and deb package generation
#
# Use Dockerfile-local for running osm/RO in a docker container from source

FROM ubuntu:18.04
RUN  apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --yes install git tox make python3 python3-pip debhelper wget \
      python3-all apt-utils libmysqlclient-dev mysql-client  && \
    DEBIAN_FRONTEND=noninteractive python3 -m pip install -U setuptools setuptools-version-command stdeb
    # needed for tests:  libmysqlclient-dev mysql-client tox

    # TODO remove apt # libssl-dev
# TODO py3 comment
# Uncomment this block to generate automatically a debian package and show info
# # Set the working directory to /app
# WORKDIR /app
# # Copy the current directory contents into the container at /app
# ADD . /app
# CMD /app/devops-stages/stage-build.sh && find deb_dist -name "*.deb" -exec dpkg -I  {} ";"
