#!/bin/bash

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
set -e
echo "Launching tox"
tox --parallel=auto

echo "Checking the presence of release notes ..."

nb_rn=$(git diff --diff-filter=A --name-only HEAD~1 |grep "releasenotes\/notes" |wc -l)
if [ "${nb_rn}" -lt 1 ]; then
    echo "The commit needs release notes"
    echo "Run the following command to generate release notes: tox -e release_notes '<release_note_title>'"
    echo "Please read README.md for more details"
    exit 1
elif [ "${nb_rn}" -gt 1 ]; then
    echo "Only one release notes file should be added in a commit"
    exit 1
fi

echo "OK. Release notes present in commit"

