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


# The purpose of this script is to simplify the way of generating a tag for horusec-kotlin service in dockerhub.
#  Example:
#   * ./horusec-kotlin/deployments/scripts/update-image.sh horusec-kotlin alpha false
#   * ./horusec-kotlin/deployments/scripts/update-image.sh horusec-java rc false
#   * ./horusec-kotlin/deployments/scripts/update-image.sh horusec-kotlin release true
#   * ./horusec-kotlin/deployments/scripts/update-image.sh horusec-java minor true
#   * ./horusec-kotlin/deployments/scripts/update-image.sh horusec-kotlin major true

TOOL_NAME=$1
UPDATE_TYPE=$2
IS_TO_UPDATE_LATEST=$3
CURRENT_FOLDER=$(pwd)
DIRECTORY_SEMVER=""
DIRECTORY_CONFIG=""
IMAGE_NAME=""
ACTUAL_RELEASE_IN_CONFIG=""
NEW_RELEASE=""

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
    case "$TOOL_NAME" in
        "bandit")
            IMAGE_NAME="horuszup/bandit"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/python/bandit/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/bandit";;
        "brakeman")
            IMAGE_NAME="horuszup/brakeman"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/ruby/brakeman/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/brakeman";;
        "gitleaks")
            IMAGE_NAME="horuszup/gitleaks"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/leaks/gitleaks/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/gitleaks";;
        "gosec")
            IMAGE_NAME="horuszup/gosec"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/golang/gosec/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/gosec";;
        "npmaudit")
            IMAGE_NAME="horuszup/npmaudit"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/javascript/npmaudit/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/npmaudit";;
        "safety")
            IMAGE_NAME="horuszup/safety"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/python/safety/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/safety";;
        "securitycodescan")
            IMAGE_NAME="horuszup/dotnet-core-3.1"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/dotnet/scs/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/securitycodescan";;
        "hcl")
            IMAGE_NAME="horuszup/tfsec"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/hcl/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/tfsec";;
        "spotbugs")
            IMAGE_NAME="horuszup/spotbugs"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/java/spotbugs/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/deployments/dockerfiles/spotbugs";;
        "horusec-kotlin")
            IMAGE_NAME="horuszup/horusec-kotlin"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/kotlin/horuseckotlin/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-kotlin";;
        "horusec-java")
            IMAGE_NAME="horuszup/horusec-java"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/java/horusecjava/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-java";;
        "horusec-csharp")
            IMAGE_NAME="horuszup/horusec-csharp"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/csharp/horuseccsharp/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-csharp";;
        "horusec-leaks")
            IMAGE_NAME="horuszup/horusec-leaks"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/leaks/horusecleaks/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-leaks";;
        "horusec-nodejs")
            IMAGE_NAME="horuszup/horusec-nodejs"
            DIRECTORY_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/nodejs/horusecnodejs/config.go"
            DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-nodejs";;
        *)
            echo "Param Tool Name is invalid, please use the examples bellow allowed and try again!"
            echo "Params Tool Name allowed: bandit, brakeman, gitleaks, gosec, npmaudit, safety, securitycodescan, hcl, spotbugs, horusec-kotlin, horusec-java, horusec-leaks, horusec-csharp, horusec-nodejs"
            exit 1;;
    esac
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

setActualRelease() {
    ACTUAL_RELEASE_IN_CONFIG=""
    alpha=$(grep -P '.*ImageTag.*alpha' "$DIRECTORY_CONFIG")
    rc=$(grep -P '.*ImageTag.*rc' "$DIRECTORY_CONFIG")

    cd $DIRECTORY_SEMVER
    if [ "$alpha" != "" ]
    then
        ACTUAL_RELEASE_IN_CONFIG=$(semver get alpha)
    elif [ "$rc" != "" ]
    then
        ACTUAL_RELEASE_IN_CONFIG=$(semver get rc)
    else
        ACTUAL_RELEASE_IN_CONFIG=$(semver get release)
    fi
    cd $CURRENT_FOLDER
}

setNewRelease() {
    echo "Update version to:"
    semver up "$UPDATE_TYPE"
    NEW_RELEASE=""
    if [[ "$UPDATE_TYPE" == "alpha" || "$UPDATE_TYPE" == "rc" ]]
    then
        NEW_RELEASE=$(semver get "$UPDATE_TYPE")
    else
        NEW_RELEASE=$(semver get release)
    fi
}

updateImage () {
    setActualRelease

    cd $DIRECTORY_SEMVER

    resetAlphaRcToMaster

    setNewRelease

    cd $CURRENT_FOLDER

    updateVersionInConfigFile
    updateVersionInCliVersionFile

    if [[ "$TOOL_NAME" == "horusec-leaks" || "$TOOL_NAME" == "horusec-kotlin" || "$TOOL_NAME" == "horusec-java" || "$TOOL_NAME" == "horusec-csharp" ]]
    then
        DIRECTORY_SEMVER="$DIRECTORY_SEMVER/deployments"
    fi

    if [ "$IS_TO_UPDATE_LATEST" == "true" ]
    then
        docker build -t "$IMAGE_NAME:latest" -f $DIRECTORY_SEMVER/Dockerfile .
        docker push "$IMAGE_NAME:latest"
    fi

    docker build -t "$IMAGE_NAME:$NEW_RELEASE" -f $DIRECTORY_SEMVER/Dockerfile .
    docker push "$IMAGE_NAME:$NEW_RELEASE"

    rollbackVersionInCliVersionFile
}

updateVersionInConfigFile () {
    sed -i -e "s/$ACTUAL_RELEASE_IN_CONFIG/$NEW_RELEASE/g" $DIRECTORY_CONFIG
    make fmt
}

updateVersionInCliVersionFile () {
    if [[ "$TOOL_NAME" == "horusec-leaks" || "$TOOL_NAME" == "horusec-kotlin" || "$TOOL_NAME" == "horusec-java" || "$TOOL_NAME" == "horusec-csharp" ]]
    then
        sed -i -e "s/{{VERSION_NOT_FOUND}}/$NEW_RELEASE/g" "./development-kit/pkg/cli_standard/cmd/version/version.go"
    fi
}

rollbackVersionInConfigFile () {
    sed -i -e "s/$NEW_RELEASE/$ACTUAL_RELEASE_IN_CONFIG/g" $DIRECTORY_CONFIG
    make fmt
}

rollbackVersionInCliVersionFile () {
    if [[ "$TOOL_NAME" == "horusec-leaks" || "$TOOL_NAME" == "horusec-kotlin" || "$TOOL_NAME" == "horusec-java" || "$TOOL_NAME" == "horusec-csharp" ]]
    then
        sed -i -e "s/$NEW_RELEASE/{{VERSION_NOT_FOUND}}/g" "./development-kit/pkg/cli_standard/cmd/version/version.go"
    fi
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

trap rollbackVersionInCliVersionFile SIGINT
trap rollbackVersionInConfigFile SIGINT

getDirectoryAndImageNameByToolName

validateUpdateType

validateIsToUpdateLatest

installSemver

updateImage
