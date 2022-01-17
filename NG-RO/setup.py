#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020 Telefonica S.A.
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

from setuptools import find_packages, setup

_name = "osm_ng_ro"
_version_command = ("git describe --match v* --tags --long --dirty", "pep440-git-full")
_description = "OSM Resource Orchestrator"
_author = "OSM Support"
_author_email = "osmsupport@etsi.org"
_maintainer = "OSM Support"
_maintainer_email = "osmsupport@etsi.org"
_license = "Apache 2.0"
_url = "https://osm.etsi.org/gitweb/?p=osm/RO.git;a=summary"

_readme = "osm-ng-ro is the New Generation Resource Orchestrator for OSM"

setup(
    name=_name,
    description=_description,
    long_description=_readme,
    version_command=_version_command,
    author=_author,
    author_email=_author_email,
    maintainer=_maintainer,
    maintainer_email=_maintainer_email,
    url=_url,
    license=_license,
    packages=find_packages(exclude=["temp", "local"]),
    include_package_data=True,
    setup_requires=["setuptools-version-command"],
)
