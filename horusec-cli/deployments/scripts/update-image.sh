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
SEND_NEW_VERSION_TO_S3=$2
IS_TO_UPDATE_LATEST=$3
ACTUAL_RELEASE_FORMATTED=""
ACTUAL_RELEASE=""

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
    chmod +x ./deployments/scripts/install-semver.sh
    ./deployments/scripts/install-semver.sh

    cd ./horusec-cli || echo "Directory not exist!"; exit

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

    cd ..

    sed -i -e "s/{{VERSION_NOT_FOUND}}/$ACTUAL_RELEASE/g" "./horusec-cli/cmd/horusec/version/version.go"

    ACTUAL_RELEASE_FORMATTED=`tr '.' '-' <<<"$ACTUAL_RELEASE"`

    # Build for linux x86
    env GOOS=linux GOARCH=386 go build -o "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x86/horusec" ./horusec-cli/cmd/horusec/main.go
    if [[ $? -eq 0 ]]
    then
        echo "1/5 Binary generated with success in ./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x86/horusec"
    else
        echo "Error when generate Build for linux_x86"
    fi

    # Build for linux x64
    env GOOS=linux GOARCH=amd64 go build -o "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x64/horusec" ./horusec-cli/cmd/horusec/main.go
    if [[ $? -eq 0 ]]
    then
        echo "2/5 Binary generated with success in ./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x64/horusec"
    else
        echo "Error when generate Build for linux_x64"
    fi

    # Build for Windows x86
    env GOOS=windows GOARCH=386 go build -o "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/win_x86/horusec.exe" ./horusec-cli/cmd/horusec/main.go
    if [[ $? -eq 0 ]]
    then
        echo "3/5 Binary generated with success in ./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/win_x86/horusec.exe"
    else
        echo "Error when generate Build for win_x86"
    fi

    # Build for Windows x64
    env GOOS=windows GOARCH=amd64 go build -o "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/win_x64/horusec.exe" ./horusec-cli/cmd/horusec/main.go
    if [[ $? -eq 0 ]]
    then
        echo "4/5 Binary generated with success in ./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/win_x64/horusec.exe"
    else
        echo "Error when generate Build for win_x64"
    fi

    # Build for Mac x64
    env GOOS=darwin GOARCH=amd64 go build -o "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/mac_x64/horusec" ./horusec-cli/cmd/horusec/main.go
    if [[ $? -eq 0 ]]
    then
        echo "5/5 Binary generated with success in ./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/mac_x64/horusec"
    else
        echo "Error when generate Build for mac_x64"
    fi

    chmod +x "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x64/horusec"
    cp "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x64/horusec" "$GOPATH/bin/horusec"
    echo "Binary in ./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED/linux_x86/horusec was copied to $GOPATH/bin/horusec with success!"
    echo "Please run \"horusec version\" to check installation"

    sed -i -e "s/$ACTUAL_RELEASE/{{VERSION_NOT_FOUND}}/g" "./horusec-cli/cmd/horusec/version/version.go"

    if [[ "$SEND_NEW_VERSION_TO_S3" == "true" ]]
    then
        aws s3 cp "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED" "s3://horusec.io/bin/$ACTUAL_RELEASE_FORMATTED" --recursive
    fi
    docker build -t "horuszup/horusec-cli:$ACTUAL_RELEASE" -f horusec-cli/deployments/Dockerfile .
    docker push "horuszup/horusec-cli:$ACTUAL_RELEASE"

    if [[ "$IS_TO_UPDATE_LATEST" == "true" ]]
    then
        echo "$ACTUAL_RELEASE_FORMATTED" > ./horusec-cli/deployments/version-cli-latest.txt
        aws s3 cp ./horusec-cli/deployments/version-cli-latest.txt s3://horusec.io/bin/version-cli-latest.txt
        aws s3 cp "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED" "s3://horusec.io/bin/latest" --recursive
        docker build -t "horuszup/horusec-cli:latest" -f horusec-cli/deployments/Dockerfile .
        docker push "horuszup/horusec-cli:latest"
    fi

    echo "$ACTUAL_RELEASE_FORMATTED" >> ./horusec-cli/deployments/all-version-cli.txt
    aws s3 cp ./horusec-cli/deployments/all-version-cli.txt s3://horusec.io/bin/all-version-cli.txt
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
    sed -i -e "s/$ACTUAL_RELEASE/{{VERSION_NOT_FOUND}}/g" "./horusec-cli/cmd/horusec/version/version.go"
}

rollback_binaries () {
    rm -rf "./horusec-cli/bin/horusec/$ACTUAL_RELEASE_FORMATTED"
}

trap rollback_version_command SIGINT
trap rollback_binaries SIGINT

validateUpdateType

generateBinaries
