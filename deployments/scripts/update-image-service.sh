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


# The purpose of this script is to simplify the way of generating a tag for services in dockerhub.
#  Example:
#   * ./deployments/scripts/update-image-service.sh horusec-account alpha true
#   * ./deployments/scripts/update-image-service.sh horusec-analytic rc false
#   * ./deployments/scripts/update-image-service.sh horusec-api release true
#   * ./deployments/scripts/update-image-service.sh horusec-manager minor false
#   * ./deployments/scripts/update-image-service.sh horusec-messages major true

SERVICE_NAME=$1
UPDATE_TYPE=$2
IS_TO_UPDATE_LATEST=$3
DIRECTORY=""
IMAGE_NAME=""

installSemver () {
    chmod +x ./deployments/scripts/install-semver.sh
    ./deployments/scripts/install-semver.sh
    semver &> /dev/null
    RESPONSE=$?
    if [ $RESPONSE != "0" ]
    then
        exit 1
    fi
}

getDirectoryAndImageNameByToolName () {
    case "$SERVICE_NAME" in
        "horusec-account")
            IMAGE_NAME="horuszup/horusec-account"
            DIRECTORY="./horusec-account";;
        "horusec-analytic")
            IMAGE_NAME="horuszup/horusec-analytic"
            DIRECTORY="./horusec-analytic";;
        "horusec-api")
            IMAGE_NAME="horuszup/horusec-api"
            DIRECTORY="./horusec-api";;
        "horusec-manager")
            IMAGE_NAME="horuszup/horusec-manager"
            DIRECTORY="./horusec-manager";;
        "horusec-messages")
            IMAGE_NAME="horuszup/horusec-messages"
            DIRECTORY="./horusec-messages";;
        *)
            echo "Param Service Name is invalid, please use the examples bellow allowed and try again!"
            echo "Params Service Name allowed: horusec-account, horusec-analytic, horusec-api, horusec-manager, horusec-messages"
            exit 1;;
    esac
    echo "Service selected is: $SERVICE_NAME"
}

validateUpdateType () {
    case "$UPDATE_TYPE" in
        "alpha") # Used to update an bugfix or an new feature in develop branch
            echo "Update type selected is alpha" ;;
        "rc") # Used when you finish development and start testing in the test environment and in develop branch
            echo "Update type selected is rc(release-candidate)" ;;
        "release") # Used when an correction was applied in master branch
            echo "Update type selected is release" ;;
        "minor") # Used when an new feature is enable in production environment and in master branch
            echo "Update type selected is minor" ;;
        "major") # Used when an big refactor is necessary to breaking changes in master branch
            echo "Update type selected is major" ;;
        *)
            echo "Param Update type is invalid, please use the examples bellow allowed and try again!"
            echo "Params Update type allowed: alpha, rc, release, minor, major"
            exit 1;;
    esac
}

validateIsToUpdateLatest () {
    if [[ "$IS_TO_UPDATE_LATEST" != "true" && "$IS_TO_UPDATE_LATEST" != "false" ]]
    then
        echo "Param \"is to update latest\" is invalid, please use the examples bellow allowed and try again!"
        echo "Param \"is to update latest\" allowed: true, false"
        exit 1
    fi
}

updateVersion () {
    cd $DIRECTORY

    resetAlphaRcToMaster

    semver up "$UPDATE_TYPE"

    LATEST_VERSION=""
    if [[ "$UPDATE_TYPE" == "alpha" || "$UPDATE_TYPE" == "rc" ]]
    then
        LATEST_VERSION=$(semver get "$UPDATE_TYPE")
    else
        LATEST_VERSION=$(semver get release)
    fi

    if [[ "$SERVICE_NAME" == "horusec-manager" ]]
    then
        sed -i -e "s/\"version\": \"0.1.0\"/\"version\": \"$LATEST_VERSION\"/g" "./package.json"
    fi

    cd ..

    if [ "$IS_TO_UPDATE_LATEST" == "true" ]
    then
        docker build -t "$IMAGE_NAME:latest" -f $DIRECTORY/deployments/Dockerfile .
        docker push "$IMAGE_NAME:latest"
    fi

    docker build -t "$IMAGE_NAME:$LATEST_VERSION" -f $DIRECTORY/deployments/Dockerfile .
    docker push "$IMAGE_NAME:$LATEST_VERSION"

    rollback_version_packagejson
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

rollback_version_packagejson () {
    if [[ "$SERVICE_NAME" == "horusec-manager" ]]
    then
        sed -i -e "s/\"version\": \"$LATEST_VERSION\"/\"version\": \"0.1.0\"/g" "./horusec-manager/package.json"
    fi
}

trap rollback_version_command SIGINT

getDirectoryAndImageNameByToolName

validateUpdateType

validateIsToUpdateLatest

installSemver

updateVersion