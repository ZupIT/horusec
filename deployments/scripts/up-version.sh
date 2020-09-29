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


# The purpose of this script is to simplify the way of generating a tag for github.
#  Example:
#    * A correction was made and updated the develop branch:
#      * ./deployments/scripts/up-version.sh alpha
#    * A new feature was made and updated the develop branch:
#      * ./deployments/scripts/up-version.sh alpha
#    * We are preparing the branch to develop and send it to production:
#      * ./deployments/scripts/up-version.sh rc
#    * After opening the PR and performing the merge of develop on the master, we must update the master and develop tag:
#      * ./deployments/scripts/up-version.sh minor
#    * We made a correction(hotfix) to the production environment and we have already merged the master branch and automatically need to update the develop branch:
#      * ./deployments/scripts/up-version.sh release
#    * We had to do a refactoring in the services and hear a "breaking changes" in the master branch:
#      * ./deployments/scripts/up-version.sh major

UPDATE_TYPE=$1
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
ACTUAL_RELEASE=""
NEW_RELEASE=""

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

installSemver () {
    chmod +x ./deployments/scripts/install-semver.sh
    ./deployments/scripts/install-semver.sh
}

validateCurrentBranch () {
    # If branch not allowed return errors
    if [[ "$UPDATE_TYPE" == "alpha" || "$UPDATE_TYPE" == "rc" ]]
    then
        if [ "$BRANCH_NAME" != "develop" ]
        then
            echo "Your current branch is \"$BRANCH_NAME\". For this update type only branch enable is \"develop\""
            echo "Please use the follow command to update your project"
            echo "git checkout develop && git pull origin develop"
            exit 1
        fi
        git pull origin develop
    else
        if [ "$BRANCH_NAME" != "master" ]
        then
            echo "Your current branch is \"$BRANCH_NAME\". For this update type only branch enable is \"master\""
            echo "Please use the follow command to update your project"
            echo "git checkout master && git pull origin master"
            exit 1
        fi
        git pull origin master
    fi
}

resetAlphaRcToMaster () {
    alpha_version=$(semver get alpha)
    rc_version=$(semver get rc)
    if [[ "${alpha_version: -2}" != ".0" || "${rc_version: -2}" != ".0" ]]
    then
        echo "Alpha or Release-Candidate found, reseting version to:"
        semver up release
    fi
}

set_actual_release() {
    ACTUAL_RELEASE=""
    alpha=$(grep -P '.*badge\/release-.*alpha' "./README.md")
    rc=$(grep -P '.*badge\/release-.*rc' "./README.md")

    if [ "$alpha" != "" ]
    then
        ACTUAL_RELEASE=$(semver get alpha)
    if [ "$rc" != "" ]
    then
        ACTUAL_RELEASE=$(semver get rc)
    fi
    else
        ACTUAL_RELEASE=$(semver get release)
    fi
}

set_new_release() {
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

upNewVersion () {
    set_actual_release
    if [ "$BRANCH_NAME" == "master" ]
    then
        resetAlphaRcToMaster
    fi
    set_new_release

    sed -i -e "s/$ACTUAL_RELEASE/$NEW_RELEASE/g" "./README.md"
    echo "Tag has been generated in version: $NEW_RELEASE"

    # Commit new version
    git tag "$NEW_RELEASE"
    git add .
    git commit -m "[skip ci] update versioning file"
}

pushChangesAndCheckResponse () {
    # Update version
    git push origin "$BRANCH_NAME"
    RESULT_PUSH=$?
    if [[ $RESULT_PUSH -eq 0 ]]
    then
        git push --tags
        RESULT_PUSH=$?
        if [[ $RESULT_PUSH -eq 0 ]]
        then
            echo "New version was updated!"
            if [ "$BRANCH_NAME" == "master" ]
            then
                git checkout develop
                git pull origin master
                resetAlphaRcToMaster
                CONFLICTS=$(git ls-files -u | wc -l)
                if [ "$CONFLICTS" != "0" ]
                then
                    echo "Found conflicts when merge master into develop, fix and run (./deployments/scripts/up-version.sh alpha)"
                    exit 1
                else
                    ./deployments/scripts/up-version.sh alpha
                fi
            fi
        else
            echo "Error on push to branch develop: $RESULT_PUSH"
            exit 1
        fi
    else
        echo "Error on push to branch develop: $RESULT_PUSH"
        exit 1
    fi
}

rollbackVersionCommand () {
    sed -i -e "s/$NEW_RELEASE/$ACTUAL_RELEASE/g" "./README.md"
}

trap rollbackVersionCommand SIGINT

validateUpdateType

installSemver

validateCurrentBranch

upNewVersion

pushChangesAndCheckResponse

exit 0