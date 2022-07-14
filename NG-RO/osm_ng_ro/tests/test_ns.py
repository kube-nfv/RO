#######################################################################################
# Copyright ETSI Contributors and Others.
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
#######################################################################################

import unittest
from unittest.mock import Mock, patch

from jinja2 import (
    Environment,
    select_autoescape,
    StrictUndefined,
    TemplateError,
    TemplateNotFound,
    UndefinedError,
)
from osm_ng_ro.ns import Ns, NsException


class TestNs(unittest.TestCase):
    def setUp(self):
        self.ns = Ns()

    @patch("jinja2.Environment.__init__")
    def test__parse_jinja2_undefined_error(self, env_mock: Mock):
        cloud_init_content = None
        params = None
        context = None

        env_mock.side_effect = UndefinedError("UndefinedError occurred.")

        with self.assertRaises(NsException):
            self.ns._parse_jinja2(
                cloud_init_content=cloud_init_content, params=params, context=context
            )

    @patch("jinja2.Environment.__init__")
    def test__parse_jinja2_template_error(self, env_mock: Mock):
        cloud_init_content = None
        params = None
        context = None

        env_mock.side_effect = TemplateError("TemplateError occurred.")

        with self.assertRaises(NsException):
            self.ns._parse_jinja2(
                cloud_init_content=cloud_init_content, params=params, context=context
            )

    @patch("jinja2.Environment.__init__")
    def test__parse_jinja2_template_not_found(self, env_mock: Mock):
        cloud_init_content = None
        params = None
        context = None

        env_mock.side_effect = TemplateNotFound("TemplateNotFound occurred.")

        with self.assertRaises(NsException):
            self.ns._parse_jinja2(
                cloud_init_content=cloud_init_content, params=params, context=context
            )

    def test_rendering_jinja2_temp_without_special_characters(self):
        cloud_init_content = """
        disk_setup:
            ephemeral0:
                table_type: {{type}}
                layout: True
                overwrite: {{is_override}}
        runcmd:
             - [ ls, -l, / ]
             - [ sh, -xc, "echo $(date) '{{command}}'" ]
        """
        params = {
            "type": "mbr",
            "is_override": "False",
            "command": "; mkdir abc",
        }
        context = "cloud-init for VM"
        expected_result = """
        disk_setup:
            ephemeral0:
                table_type: mbr
                layout: True
                overwrite: False
        runcmd:
             - [ ls, -l, / ]
             - [ sh, -xc, "echo $(date) '; mkdir abc'" ]
        """
        result = self.ns._parse_jinja2(
            cloud_init_content=cloud_init_content, params=params, context=context
        )
        self.assertEqual(result, expected_result)

    def test_rendering_jinja2_temp_with_special_characters(self):
        cloud_init_content = """
        disk_setup:
            ephemeral0:
                table_type: {{type}}
                layout: True
                overwrite: {{is_override}}
        runcmd:
             - [ ls, -l, / ]
             - [ sh, -xc, "echo $(date) '{{command}}'" ]
        """
        params = {
            "type": "mbr",
            "is_override": "False",
            "command": "& rm -rf",
        }
        context = "cloud-init for VM"
        expected_result = """
        disk_setup:
            ephemeral0:
                table_type: mbr
                layout: True
                overwrite: False
        runcmd:
             - [ ls, -l, / ]
             - [ sh, -xc, "echo $(date) '& rm -rf /'" ]
        """
        result = self.ns._parse_jinja2(
            cloud_init_content=cloud_init_content, params=params, context=context
        )
        self.assertNotEqual(result, expected_result)

    def test_rendering_jinja2_temp_with_special_characters_autoescape_is_false(self):
        with patch("osm_ng_ro.ns.Environment") as mock_environment:
            mock_environment.return_value = Environment(
                undefined=StrictUndefined,
                autoescape=select_autoescape(default_for_string=False, default=False),
            )
            cloud_init_content = """
                disk_setup:
                    ephemeral0:
                        table_type: {{type}}
                        layout: True
                        overwrite: {{is_override}}
                runcmd:
                     - [ ls, -l, / ]
                     - [ sh, -xc, "echo $(date) '{{command}}'" ]
                """
            params = {
                "type": "mbr",
                "is_override": "False",
                "command": "& rm -rf /",
            }
            context = "cloud-init for VM"
            expected_result = """
                disk_setup:
                    ephemeral0:
                        table_type: mbr
                        layout: True
                        overwrite: False
                runcmd:
                     - [ ls, -l, / ]
                     - [ sh, -xc, "echo $(date) '& rm -rf /'" ]
                """
            result = self.ns._parse_jinja2(
                cloud_init_content=cloud_init_content,
                params=params,
                context=context,
            )
            self.assertEqual(result, expected_result)
