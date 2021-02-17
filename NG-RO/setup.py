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

from setuptools import setup, find_packages

_name = "osm_ng_ro"
_readme = "osm-ng-ro is the New Generation Resource Orchestrator for OSM"
setup(
    name=_name,
    description="OSM Resource Orchestrator",
    long_description=_readme,
    version_command=(
        "git describe --match v* --tags --long --dirty",
        "pep440-git-full",
    ),
    author="ETSI OSM",
    author_email="alfonso.tiernosepulveda@telefonica.com",
    maintainer="Alfonso Tierno",
    maintainer_email="alfonso.tiernosepulveda@telefonica.com",
    url="https://osm.etsi.org/gitweb/?p=osm/RO.git;a=summary",
    license="Apache 2.0",
    packages=find_packages(exclude=["temp", "local"]),
    include_package_data=True,
    install_requires=[
        "CherryPy==18.1.2",
        "osm-common @ git+https://osm.etsi.org/gerrit/osm/common.git#egg=osm-common",
        "jsonschema",
        "PyYAML",
        "requests",
        "cryptography",  # >=2.5  installed right version with the debian post-install script
        "osm-ro-plugin @ git+https://osm.etsi.org/gerrit/osm/RO.git#egg=osm-ro-plugin&subdirectory=RO-plugin",
    ],
    setup_requires=["setuptools-version-command"],
)
