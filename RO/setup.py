#!/usr/bin/env python3

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

# from distutils.core import setup
# from distutils.command.install_data import install_data
from setuptools import setup
from os import system
# import glob

_name = 'osm_ro'
_description = 'OSM Resource Orchestrator'
_author = 'ETSI OSM'
_author_email = 'alfonso.tiernosepulveda@telefonica.com'
_maintainer = 'garciadeblas'
_maintainer_email = 'gerardo.garciadeblas@telefonica.com'
_license = 'Apache 2.0'
_url = 'https://osm.etsi.org/gitweb/?p=osm/RO.git;a=summary'
_requirements = [
    "osm-im @ git+https://osm.etsi.org/gerrit/osm/IM.git@v8.0#egg=osm-im",
    "PyYAML",
    "bottle",
    "logutils",
    "jsonschema",
    "paramiko",
    "mysqlclient",
    # "MySQLdb",
    # common to  VIMS
    "requests",
    "netaddr",  # openstack, aws, vmware
]

setup(
    name=_name,
    version_command=('git -C .. describe --match v* --tags --long --dirty', 'pep440-git-full'),
    description = _description,
    long_description = open('README.rst').read(),
    author = _author,
    author_email = _author_email,
    maintainer = _maintainer,
    maintainer_email = _maintainer_email,
    url = _url,
    license = _license,
    packages = [_name],
    #packages = ['osm_ro', 'osm_roclient'],
    package_dir = {_name: _name},
    # package_data = {_name: ['vnfs/*.yaml', 'vnfs/examples/*.yaml',
    #                    'scenarios/*.yaml', 'scenarios/examples/*.yaml',
    #                    'instance-scenarios/examples/*.yaml', 'database_utils/*',
    #                    'scripts/*']},
    # data_files = [('/etc/osm/', ['osm_ro/openmanod.cfg']),
    #              ('/etc/systemd/system/', ['osm_ro/osm-ro.service']),
    #              ],
    scripts=['osm_ro/scripts/RO-start.sh'
      #'openmanod', 'openmano', 'osm_ro/scripts/service-openmano', 'osm_ro/scripts/openmano-report',
      ],
    install_requires=_requirements,
    include_package_data=True,
    setup_requires=['setuptools-version-command'],
    #test_suite='nose.collector',
)

