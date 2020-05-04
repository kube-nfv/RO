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

_name = "osm_rosdn_arista_cloudvision"

README = """
===========
osm-rosdn_arista_cloudvision
===========

osm-ro pluging for arista_cloudvision SDN
"""

setup(
    name=_name,
    description='OSM ro sdn plugin for arista with CloudVision',
    long_description=README,
    version_command=('git describe --match v* --tags --long --dirty', 'pep440-git-full'),
    # version=VERSION,
    # python_requires='>3.5.0',
    author='ETSI OSM',
    author_email='OSM_TECH@LIST.ETSI.ORG',
    maintainer='Oscar Luis Peral',
    maintainer_email='oscarluis.peral@atos.net',
    url='https://osm.etsi.org/gitweb/?p=osm/RO.git;a=summary',
    license='Apache 2.0',

    packages=[_name],
    include_package_data=True,
    install_requires=[
        "requests",
        "uuid",
        "cvprac",
        "osm-ro-plugin @ git+https://osm.etsi.org/gerrit/osm/RO.git#egg=osm-ro-plugin&subdirectory=RO-plugin"
    ],
    setup_requires=['setuptools-version-command'],
    entry_points={
        'osm_rosdn.plugins': ['rosdn_arista_cloudvision = osm_rosdn_arista_cloudvision.'
                              'wimconn_arista:AristaSdnConnector']
    },
)
