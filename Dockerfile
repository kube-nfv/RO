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
########################################################################################
# This Dockerfile is intented for devops testing and deb package generation
#
# To run stage 2 locally:
#
#   docker build -t stage2 .
#   docker run -ti -v `pwd`:/work -w /work --entrypoint /bin/bash stage2
#   devops-stages/stage-test.sh
#   devops-stages/stage-build.sh
#

FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
        debhelper \
        git \
        python3 \
        python3-all \
        python3-dev \
        python3-setuptools

RUN python3 -m easy_install pip==21.0.1
RUN pip3 install tox==3.22.0

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
