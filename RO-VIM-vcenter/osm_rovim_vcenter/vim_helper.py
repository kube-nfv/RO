# -*- coding: utf-8 -*-
# Copyright 2025 Indra
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
"""
Helper class that will be used for things not related to
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid

from osm_ro_plugin import vimconn


class CloudInitHelper:
    """
    Class that will help to generate iso files needed for cloud-init functionality
    """

    def __init__(self, log_level=None):
        self.logger = logging.getLogger("ro.vim.vcenter.network")
        if log_level:
            self.logger.setLevel(getattr(logging, log_level))

    def generate_cloud_init_iso(self, user_data):
        """
        Generates a cloud init iso with the provided user_data
        """
        self.logger.debug("Generate cloud init iso")
        tmpdir = tempfile.mkdtemp()
        iso_path = os.path.join(tmpdir, "ConfigDrive.iso")
        latest_dir = os.path.join(tmpdir, "openstack", "latest")
        os.makedirs(latest_dir)
        with open(
            os.path.join(latest_dir, "meta_data.json"), "w"
        ) as meta_file_obj, open(
            os.path.join(latest_dir, "user_data"), "w"
        ) as userdata_file_obj:
            userdata_file_obj.write(user_data)
            meta_file_obj.write(
                json.dumps(
                    {
                        "availability_zone": "nova",
                        "launch_index": 0,
                        "name": "ConfigDrive",
                        "uuid": str(uuid.uuid4()),
                    }
                )
            )
        genisoimage_cmd = (
            "genisoimage -J -r -V config-2 -o {iso_path} {source_dir_path}".format(
                iso_path=iso_path, source_dir_path=tmpdir
            )
        )
        self.logger.info(
            'create_config_drive_iso(): Creating ISO by running command "{}"'.format(
                genisoimage_cmd
            )
        )

        try:
            FNULL = open(os.devnull, "w")
            subprocess.check_call(genisoimage_cmd, shell=True, stdout=FNULL)
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            error_msg = "create_config_drive_iso(): Exception executing genisoimage : {}".format(
                e
            )
            self.logger.error(error_msg)
            raise vimconn.VimConnException(error_msg)

        return iso_path, tmpdir

    def delete_tmp_dir(self, tmpdirname):
        """
        Delete the tmp dir with the indicated name
        """
        self.logger.debug("Delete tmp dir: %s", tmpdirname)
        shutil.rmtree(tmpdirname)
