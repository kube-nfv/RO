#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##
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
##

from setuptools import setup

_name = "osm_ro_plugin"

README = """
===========
osm-ro_plugin
===========

osm-ro plugin is the base class for RO VIM and SDN plugins
"""

setup(
    name=_name,
    description="OSM ro base class for vim and SDN plugins",
    long_description=README,
    version_command=(
        "git describe --match v* --tags --long --dirty",
        "pep440-git-full",
    ),
    # version=VERSION,
    # python_requires='>3.5.0',
    author="ETSI OSM",
    author_email="alfonso.tiernosepulveda@telefonica.com",
    maintainer="Alfonso Tierno",
    maintainer_email="alfonso.tiernosepulveda@telefonica.com",
    url="https://osm.etsi.org/gitweb/?p=osm/RO.git;a=summary",
    license="Apache 2.0",
    packages=[_name],
    include_package_data=True,
    install_requires=[
        "requests",
        "paramiko",
        "PyYAML",
    ],
    setup_requires=["setuptools-version-command"],
    entry_points={
        "osm_ro.plugins": [
            "rovim_plugin = osm_ro_plugin.vimconn:VimConnector",
            "rosdn_plugin = osm_ro_plugin.sdnconn:SdnConnectorBase",
        ],
    },
)
