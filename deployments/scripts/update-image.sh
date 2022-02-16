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


UPDATE_TYPE=$1
IS_TO_UPDATE_LATEST=$2
ACTUAL_RELEASE_FORMATTED=""
ACTUAL_RELEASE=""

installSemver () {
    mkdir -p ./bin
    curl -fsSL -o ./bin/install-semver.sh https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/install-semver.sh
    chmod +x ./bin/install-semver.sh
    ./bin/install-semver.sh
    if ! semver &> /dev/null
    then
        exit 1
    fi
}

validateUpdateType () {
    case "$UPDATE_TYPE" in
        "alpha") # Used to update an bugfix or an new feature in develop branch
            echo "The Param 1=\"Update type\" the value selected is: $UPDATE_TYPE";;
        "rc") # Used when you finish development and start testing in the test environment and in develop branch
            echo "The Param 1=\"Update type\" the value selected is: $UPDATE_TYPE";;
        "release") # Used when an correction was applied in master branch
            echo "The Param 1=\"Update type\" the value selected is: $UPDATE_TYPE";;
        "minor") # Used when an new feature is enable in production environment and in master branch
            echo "The Param 1=\"Update type\" the value selected is: $UPDATE_TYPE";;
        "major") # Used when an big refactor is necessary to breaking changes in master branch
            echo "The Param 1=\"Update type\" the value selected is: $UPDATE_TYPE";;
        *)
            echo "Param Update type is invalid, please use the examples bellow allowed and try again!"
            echo "Params Update type allowed: alpha, rc, release, minor, major"
            exit 1;;
    esac
}

generateBinaries () {
    resetAlphaRcToMaster

    semver up "$UPDATE_TYPE"

    ACTUAL_RELEASE=""
    if [[ "$UPDATE_TYPE" == "alpha" || "$UPDATE_TYPE" == "rc" ]]
    then
        ACTUAL_RELEASE=$(semver get "$UPDATE_TYPE")
    else
        ACTUAL_RELEASE=$(semver get release)
    fi

    if [[ -z "$ACTUAL_RELEASE" ]]
    then
        echo "Current version not found of the horusec-cli please install and try again"
        echo "To install semver use:"
        echo "$ make install-semver"
        echo "$ semver --help"
        exit 1
    fi

    sed -i -e "s/{{VERSION_NOT_FOUND}}/$ACTUAL_RELEASE/g" "./config/config.go"

    ACTUAL_RELEASE_FORMATTED=$(tr '.' '-' <<<"$ACTUAL_RELEASE")

    mkdir -p "./bin/horusec/$ACTUAL_RELEASE_FORMATTED"

    # Build for linux x86
    if ! env GOOS=linux GOARCH=386 go build -a  -o "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x86" ./cmd/app/main.go;
    then
        echo "Error when generate Build for linux_x86"
    else
        echo "1/5 Binary generated with success in ./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x86"
    fi

    # Build for linux x64
    if ! env GOOS=linux GOARCH=amd64 go build -a  -o "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x64" ./cmd/app/main.go;
    then
        echo "Error when generate Build for linux_x64"
    else
        echo "2/5 Binary generated with success in ./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x64"
    fi

    # Build for Windows x86
    if ! env GOOS=windows GOARCH=386 go build -o "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_win_x86.exe" ./cmd/app/main.go;
    then
        echo "Error when generate Build for win_x86"
    else
        echo "3/5 Binary generated with success in ./bin/horusec/$ACTUAL_RELEASE_FORMATTED/win_x86.exe"
    fi

    # Build for Windows x64
    if ! env GOOS=windows GOARCH=amd64 go build -o "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_win_x64.exe" ./cmd/app/main.go;
    then
        echo "Error when generate Build for win_x64"
    else
        echo "4/5 Binary generated with success in ./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_win_x64.exe"
    fi

    # Build for Mac x64
    if ! env GOOS=darwin GOARCH=amd64 go build -o "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_mac_x64" ./cmd/app/main.go;
    then
        echo "Error when generate Build for mac_x64"
    else
        echo "5/5 Binary generated with success in ./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_mac_x64"
    fi

    chmod +x "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x64"
    cp "./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x64" "$GOPATH/bin/horusec"
    echo "Binary in ./bin/horusec/$ACTUAL_RELEASE_FORMATTED/horusec_linux_x64 was copied to $GOPATH/bin/horusec with success!"
    echo "Please run \"horusec version\" to check installation"

    sed -i -e "s/$ACTUAL_RELEASE/{{VERSION_NOT_FOUND}}/g" "./config/config.go"

    docker build -t "horuszup/horusec-cli:$ACTUAL_RELEASE" -f deployments/Dockerfile .
    docker push "horuszup/horusec-cli:$ACTUAL_RELEASE"

    if [[ "$IS_TO_UPDATE_LATEST" == "true" ]]
    then
        echo "$ACTUAL_RELEASE_FORMATTED" > ./deployments/version-cli-latest.txt
        docker build -t "horuszup/horusec-cli:latest" -f deployments/Dockerfile .
        docker push "horuszup/horusec-cli:latest"
    fi

    echo "$ACTUAL_RELEASE_FORMATTED" >> ./deployments/all-version-cli.txt
}

resetAlphaRcToMaster () {
    if [[ "$UPDATE_TYPE" == "release" || "$UPDATE_TYPE" == "minor" || "$UPDATE_TYPE" == "major" ]]
    then
        alpha_version=$(semver get alpha)
        rc_version=$(semver get rc)
        if [[ "${alpha_version: -2}" != ".0" || "${rc_version: -2}" != ".0" ]]
        then
            echo "Alpha or Release-Candidate found, reseting version to:"
            semver up release
        fi
    fi
}

rollback_version_command () {
    sed -i -e "s/$ACTUAL_RELEASE/{{VERSION_NOT_FOUND}}/g" "./config/config.go"
}

rollback_binaries () {
    rm -rf "./bin/horusec/$ACTUAL_RELEASE_FORMATTED"
}

trap rollback_version_command SIGINT
trap rollback_binaries SIGINT

installSemver

validateUpdateType

generateBinaries
