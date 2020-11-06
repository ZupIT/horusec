#!/bin/bash
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


checkIfInstallationIsValid () {
    semver &> /dev/null
    RESPONSE=$?
    if [ $RESPONSE != "0" ]
    then
        LOCATION_SEMVER=$(which semver)
        echo "Semver is not installed please remove the binary in location [$LOCATION_SEMVER] and run again"
        exit 1
    else
        echo "Semver was installed with success!"
    fi
}

installSemver () {
    semver &> /dev/null
    RESPONSE=$?
    if [ $RESPONSE != "0" ]
    then
        echo "Installing semver..."
        go build -o semver ./deployments/semver/cmd/app/main.go
        chmod +x semver
        rm -rf "$GOPATH/bin/semver"
        mv semver "$GOPATH/bin"
    fi
}

installSemver

checkIfInstallationIsValid
