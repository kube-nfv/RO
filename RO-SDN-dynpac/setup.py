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

_name = "osm_rosdn_dynpac"

README = """
===========
osm-rosdn_dynpac
===========

osm-ro pluging for dynpac SDN
"""

setup(
    name=_name,
    description='OSM ro sdn plugin for dynpac',
    long_description=README,
    version_command=('git describe --match v* --tags --long --dirty', 'pep440-git-full'),
    # version=VERSION,
    # python_requires='>3.5.0',
    author='ETSI OSM',
    # TODO py3 author_email='',
    maintainer='OSM_TECH@LIST.ETSI.ORG',  # TODO py3
    # TODO py3 maintainer_email='',
    url='https://osm.etsi.org/gitweb/?p=osm/RO.git;a=summary',
    license='Apache 2.0',

    packages=[_name],
    include_package_data=True,
    dependency_links=["git+https://osm.etsi.org/gerrit/osm/RO.git#egg=osm-ro"],
    install_requires=["requests", "osm-ro"],
    setup_requires=['setuptools-version-command'],
    entry_points={
        'osm_rosdn.plugins': ['rosdn_dynpac = osm_rosdn_dynpac.wimconn_dynpac:DynpacConnector'],
    },
)
