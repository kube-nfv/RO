#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

import os
from setuptools import setup

_name = "osm_roclient"
# version is at first line of osm_roclient/html_public/version
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.rst')) as readme_file:
    README = readme_file.read()

setup(
    name=_name,
    description='OSM ro client',
    long_description=README,
    version_command=('git describe --match v* --tags --long --dirty', 'pep440-git-full'),
    # version=VERSION,
    # python_requires='>3.5.0',
    author='ETSI OSM',
    author_email='alfonso.tiernosepulveda@telefonica.com',
    maintainer='Alfonso Tierno',
    maintainer_email='alfonso.tiernosepulveda@telefonica.com',
    url='https://osm.etsi.org/gitweb/?p=osm/LCM.git;a=summary',
    license='Apache 2.0',

    packages=[_name],
    include_package_data=True,
    # data_files=[('/etc/osm/', ['osm_roclient/lcm.cfg']),
    #             ('/etc/systemd/system/', ['osm_roclient/osm-lcm.service']),
    #             ],
    install_requires=[
        'PyYAML',
        'requests==2.*',
        'argcomplete',
    ],
    setup_requires=['setuptools-version-command'],
    entry_points={
        "console_scripts": [
            "openmano=osm_roclient.roclient:main"
        ]
    },
)
