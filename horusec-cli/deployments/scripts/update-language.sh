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

LANGUAGE_NAME=$1
UPDATE_TYPE=$2
IS_TO_UPDATE_LATEST=$3
CURRENT_FOLDER=$(pwd)
DIRECTORY_SEMVER=""
DIRECTORY_IMAGE_CONFIG="$CURRENT_FOLDER/horusec-cli/internal/enums/images/images.go"
IMAGE_NAME=""
ACTUAL_RELEASE_IN_CONFIG=""
NEW_RELEASE=""

getDirectoryAndImagesNameByLanguageName() {
    case "$LANGUAGE_NAME" in
    "c")
        IMAGE_NAME="horuszup/horusec-c"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/c/deployments"
        ;;
    "csharp")
        IMAGE_NAME="horuszup/horusec-csharp"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/csharp/deployments"
        ;;
    "dart")
        echo "Language dart not contains image on dockerhub!"
        exit 0
        ;;
    "elixir")
        IMAGE_NAME="horuszup/horusec-elixir"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/elixir/deployments"
        ;;
    "generic")
        IMAGE_NAME="horuszup/horusec-generic"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/generic/deployments"
        ;;
    "go")
        IMAGE_NAME="horuszup/horusec-go"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/go/deployments"
        ;;
    "hcl")
        IMAGE_NAME="horuszup/horusec-hcl"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/hcl/deployments"
        ;;
    "java")
        echo "Language java not contains image on dockerhub!"
        exit 0
        ;;
    "javascript")
        IMAGE_NAME="horuszup/horusec-js"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/javascript/deployments"
        ;;
    "kotlin")
        echo "Language kotlin not contains image on dockerhub!"
        exit 0
        ;;
    "leaks")
        IMAGE_NAME="horuszup/horusec-leaks"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/leaks/deployments"
        ;;
    "php")
        IMAGE_NAME="horuszup/horusec-php"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/php/deployments"
        ;;
    "python")
        IMAGE_NAME="horuszup/horusec-python"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/python/deployments"
        ;;
    "ruby")
        IMAGE_NAME="horuszup/horusec-ruby"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/ruby/deployments"
        ;;
    "shell")
        IMAGE_NAME="horuszup/horusec-shell"
        DIRECTORY_SEMVER="$CURRENT_FOLDER/horusec-cli/internal/services/formatters/shell/deployments"
        ;;
    "yaml")
        echo "Language yaml not contains image on dockerhub!"
        exit 0
        ;;
    *)
        echo "Param Language Name is invalid, please use the examples bellow allowed and try again!"
        echo "Params Language Name allowed: c, csharp, dart, elixir, generic, go, hcl, java, javascript, kotlin, leaks, php, python, ruby, shell, yaml"
        exit 1
        ;;
    esac
}

validateUpdateType() {
    case "$UPDATE_TYPE" in
    "alpha") # Used to update an bugfix or an new feature in develop branch
        echo "Update type selected is alpha"
        ;;
    "rc") # Used when you finish development and start testing in the test environment and in develop branch
        echo "Update type selected is rc(release-candidate)"
        ;;
    "release") # Used when an correction was applied in master branch
        echo "Update type selected is release"
        ;;
    "minor") # Used when an new feature is enable in production environment and in master branch
        echo "Update type selected is minor"
        ;;
    "major") # Used when an big refactor is necessary to breaking changes in master branch
        echo "Update type selected is major"
        ;;
    *)
        echo "Param Update type is invalid, please use the examples bellow allowed and try again!"
        echo "Params Update type allowed: alpha, rc, release, minor, major"
        exit 1
        ;;
    esac
}

validateIsToUpdateLatest() {
    if [[ "$IS_TO_UPDATE_LATEST" != "true" && "$IS_TO_UPDATE_LATEST" != "false" ]]; then
        echo "Param \"is to update latest\" is invalid, please use the examples bellow allowed and try again!"
        echo "Param \"is to update latest\" allowed: true, false"
        exit 1
    fi
}

installSemver() {
    chmod +x ./deployments/scripts/install-semver.sh
    ./deployments/scripts/install-semver.sh
    semver &>/dev/null
    RESPONSE=$?
    if [ $RESPONSE != "0" ]; then
        exit 1
    fi
}

setNewRelease() {
    echo "Update version to:"
    semver up "$UPDATE_TYPE"
    NEW_RELEASE=""
    if [[ "$UPDATE_TYPE" == "alpha" || "$UPDATE_TYPE" == "rc" ]]; then
        NEW_RELEASE=$(semver get "$UPDATE_TYPE")
    else
        NEW_RELEASE=$(semver get release)
    fi
}

updateImage() {
    setActualRelease

    cd "$DIRECTORY_SEMVER" || echo "Directory $DIRECTORY_SEMVER not exist!"

    resetAlphaRcToMaster

    setNewRelease

    cd "$CURRENT_FOLDER" || echo "Directory $CURRENT_FOLDER not exist!"

    updateVersionInConfigFile

#    if [ "$IS_TO_UPDATE_LATEST" == "true" ]; then
#        docker build -t "$IMAGE_NAME:latest" -f "$DIRECTORY_SEMVER/Dockerfile" .
#        docker push "$IMAGE_NAME:latest"
#    fi
#
#    docker build -t "$IMAGE_NAME:$NEW_RELEASE" -f "$DIRECTORY_SEMVER/Dockerfile" .
#    docker push "$IMAGE_NAME:$NEW_RELEASE"
}

setActualRelease() {
    ACTUAL_RELEASE_IN_CONFIG=""
    alpha=$(grep -P "${IMAGE_NAME}.*alpha" "$DIRECTORY_IMAGE_CONFIG")
    rc=$(grep -P "${IMAGE_NAME}.*rc" "$DIRECTORY_IMAGE_CONFIG")

    cd "$DIRECTORY_SEMVER" || echo "Directory $DIRECTORY_SEMVER not exist!"
    if [ "$alpha" != "" ]; then
        ACTUAL_RELEASE_IN_CONFIG=$(semver get alpha)
    elif [ "$rc" != "" ]; then
        ACTUAL_RELEASE_IN_CONFIG=$(semver get rc)
    else
        ACTUAL_RELEASE_IN_CONFIG=$(semver get release)
    fi
    cd "$CURRENT_FOLDER" || echo "Directory $CURRENT_FOLDER not exist!"
}

updateVersionInConfigFile() {
    OLD_VALUE="${IMAGE_NAME}:$ACTUAL_RELEASE_IN_CONFIG"
    NEW_VALUE="${IMAGE_NAME}:$NEW_RELEASE"
    EXPRESSION="s/${OLD_VALUE/\//\\\/}/${NEW_VALUE/\//\\\/}/g"
    if ! sed -i -e "${EXPRESSION}" "$DIRECTORY_IMAGE_CONFIG";
    then
        echo "Error on update file $DIRECTORY_IMAGE_CONFIG to new version and expression: $EXPRESSION"
        rollbackVersionInConfigFile
        exit 1
    fi
    make fmt
}

resetAlphaRcToMaster() {
    if [[ "$UPDATE_TYPE" == "release" || "$UPDATE_TYPE" == "minor" || "$UPDATE_TYPE" == "major" ]]; then
        alpha_version=$(semver get alpha)
        rc_version=$(semver get rc)
        if [[ "${alpha_version: -2}" != ".0" || "${rc_version: -2}" != ".0" ]]; then
            echo "Alpha or Release-Candidate found, reseting version to:"
            semver up release
        fi
    fi
}

rollbackVersionInConfigFile() {
    OLD_VALUE="${IMAGE_NAME}:$NEW_RELEASE"
    NEW_VALUE="${IMAGE_NAME}:$ACTUAL_RELEASE_IN_CONFIG"
    EXPRESSION="s/${OLD_VALUE/\//\\\/}/${NEW_VALUE/\//\\\/}/g"
    if ! sed -i -e "${EXPRESSION}" "$DIRECTORY_IMAGE_CONFIG";
    then
        echo "Error on rollback file $DIRECTORY_IMAGE_CONFIG to old version and expression: $EXPRESSION"
        exit 1
    fi
    make fmt
    git stash push "$DIRECTORY_SEMVER/.semver.yaml"
}

trap rollbackVersionInConfigFile SIGINT

getDirectoryAndImagesNameByLanguageName

validateUpdateType

validateIsToUpdateLatest

installSemver

updateImage
