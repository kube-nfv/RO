#!/usr/bin/env python3
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
##
import importlib.metadata
import logging

version = "8.0.1.post0"
version_date = "2020-06-29"

# Obtain installed package version. Ignore if error, e.g. importlib.metadata not installed
try:
    version = importlib.metadata.version("osm_ng_ro")
except Exception as error:
    logging.warning(f"{error} occured while getting the ro version")
