# -*- coding: utf-8 -*-

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

from http import HTTPStatus

from jsonschema import exceptions as js_e, validate as js_v

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"
__version__ = "0.1"
version_date = "Jun 2020"

"""
Validator of input data using JSON schemas
"""

# Basis schemas
name_schema = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "pattern": "^[^,;()'\"]+$",
}
string_schema = {"type": "string", "minLength": 1, "maxLength": 255}
ssh_key_schema = {"type": "string", "minLength": 1}
id_schema = {
    "type": "string",
    "pattern": "^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$",
}
bool_schema = {"type": "boolean"}
null_schema = {"type": "null"}
object_schema = {"type": "object"}

deploy_item_schema = {
    "title": "deploy item validation. Each vld, vdu, flavor, image, ...",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "id": string_schema,
        "vim_info": object_schema,
        "common_id": string_schema,
    },
    "additionalProperties": True,
}

deploy_item_list = {
    "type": "array",
    "items": deploy_item_schema,
}

deploy_vnf_schema = {
    "title": "deploy.vnf.item validation",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "_id": id_schema,
        "vdur": deploy_item_list,
        "vld": deploy_item_list,
    },
    "additionalProperties": True,
    "required": ["_id"],
}

deploy_action_schema = {
    "title": "deploy.action validation",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "action": {"enum": ["inject_ssh_key"]},
        "key": ssh_key_schema,
        "user": string_schema,
        "password": string_schema,
    },
    "additionalProperties": False,
    "required": ["action"],
}

deploy_schema = {
    "title": "deploy input validation",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "action_id": string_schema,
        "cloud_init_content": object_schema,
        "name": string_schema,
        "action": deploy_action_schema,
        "vnf": {
            "type": "array",
            "items": deploy_vnf_schema,
        },
        "image": deploy_item_list,
        "flavor": deploy_item_list,
        "ns": {
            "type": "object",
            "properties": {
                "vld": deploy_item_list,
            },
        },
        "affinity-or-anti-affinity-group": deploy_item_list,
    },
    "additionalProperties": False,
}


class ValidationError(Exception):
    def __init__(self, message, http_code=HTTPStatus.UNPROCESSABLE_ENTITY):
        self.http_code = http_code
        Exception.__init__(self, message)


def validate_input(indata, schema_to_use):
    """
    Validates input data against json schema
    :param indata: user input data. Should be a dictionary
    :param schema_to_use: jsonschema to test
    :return: None if ok, raises ValidationError exception on error
    """
    try:
        if schema_to_use:
            js_v(indata, schema_to_use)

        return None
    except js_e.ValidationError as e:
        if e.path:
            error_pos = "at '" + ":".join(map(str, e.path)) + "'"
        else:
            error_pos = ""

        raise ValidationError("Format error {} '{}' ".format(error_pos, e.message))
    except js_e.SchemaError:
        raise ValidationError(
            "Bad json schema {}".format(schema_to_use),
            http_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
