#!/bin/sh
# Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

URL_TO_REDIRECT="https://horusec.io/bin/install.sh"
VERSION_DOWNLOAD=$1

horusecSetVersion () {
    if [ -z "$VERSION_DOWNLOAD" ]; then
        VERSION_DOWNLOAD="latest"
    fi
}

redirect () {
    curl -fsSL "$URL_TO_REDIRECT" | bash -s $VERSION_DOWNLOAD
}

horusecSetVersion

redirect
