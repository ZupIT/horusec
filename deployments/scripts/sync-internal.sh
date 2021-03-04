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

BRANCH_NAME=$1
IS_CLONE=$2
HORUSEC_INTERNAL_FOLDER="tmp-internal"
HORUSEC_OPEN_SOURCE_FOLDER="tmp-open-source"

validateBranchName () {
    case "$BRANCH_NAME" in
        "develop")
            echo "Branch Name selected is develop";;
        "master")
            echo "Branch Name selected is master";;
        *)
            echo "Param Branch Name is invalid, please use the examples bellow allowed and try again!"
            echo "Params Branch Name allowed: develop, master"
            exit 1;;
    esac
}

validateIsClone () {
    if [[ "$IS_CLONE" != "true" && "$IS_CLONE" != "false" ]]
    then
        echo "Param IsClone is invalid, please use the examples bellow allowed and try again!"
        echo "Params IsClone allowed: true, false"
        exit 1
    fi
}

cloneInternalInTmpFolder () {
    if [[ "$IS_CLONE" == "true"]]
    then
        rm -rf $HORUSEC_INTERNAL_FOLDER
        git clone -b "$BRANCH_NAME" "git@github.com:ZupIT/horusec-internal.git" "$HORUSEC_INTERNAL_FOLDER"
        if [ $? != "0" ]
        then
            echo "ERROR on clone internal project!"
            exit 1
        fi
    else
        cd "./$HORUSEC_INTERNAL_FOLDER"
    fi
}

deleteCurrentContent () {
    echo "Deleting all content..."
    find . \
    ! -path './.git*' \
    ! -path './merge-open-source.sh' \
    ! -path './horusec-account' \
    ! -path './horusec-account/deployments*' \
    ! -path './horusec-analytic' \
    ! -path './horusec-analytic/deployments*' \
    ! -path './horusec-api' \
    ! -path './horusec-api/deployments*' \
    ! -path './horusec-auth' \
    ! -path './horusec-auth/deployments*' \
    ! -path './horusec-manager' \
    ! -path './horusec-manager/deployments*' \
    ! -path './horusec-messages' \
    ! -path './horusec-messages/deployments*' \
    ! -path './horusec-webhook' \
    ! -path './horusec-webhook/deployments*' \
    ! -path './horusec-migration' \
    ! -path './horusec-migration/deployments*' \
    -delete
    if [ $? != "0" ]
    then
        echo "ERROR on remove content in internal content!"
        exit 1
    fi
}

cloneOpenSourceInTmpFolder () {
    if [[ "$IS_CLONE" == "true"]]
    then
        git clone -b "$BRANCH_NAME" "git@github.com:ZupIT/horusec.git" "$HORUSEC_OPEN_SOURCE_FOLDER"
        if [ $? != "0" ]
        then
            echo "ERROR on clone open source content!"
            exit 1
        fi
    fi
    rm -rf "./$HORUSEC_OPEN_SOURCE_FOLDER/.git"
}

copyContentFromTmpToInternal () {
    echo "Coping all content of open source to internal..."
    cd "./$HORUSEC_OPEN_SOURCE_FOLDER"
    rsync -a -r -v ./ ../
    if [ $? != "0" ]
    then
        echo "ERROR on copy open source to internal content!"
        exit 1
    fi
    cd ..
}

removeTmpFolder () {
    echo "Removing open source folder..."
    rm -rf "./$HORUSEC_OPEN_SOURCE_FOLDER"
    if [ $? != "0" ]
    then
        echo "ERROR on remove open source folder!"
        exit 1
    fi
}

stashDeployments () {
    echo "Stash all folder of deployments..."
    git config --global apply.whitespace nowarn
    git stash push ./deployments/scripts/set-image-version.sh --all --quiet
    git stash push ./deployments/semver --all --quiet
    git stash push ./horusec-account/deployments --all --quiet
    git stash push ./horusec-analytic/deployments --all --quiet
    git stash push ./horusec-api/deployments --all --quiet
    git stash push ./horusec-auth/deployments --all --quiet
    git stash push ./horusec-manager/deployments --all --quiet
    git stash push ./horusec-messages/deployments --all --quiet
    git stash push ./horusec-webhook/deployments --all --quiet
    git stash push ./horusec-migration/deployments --all --quiet
}

echo "\n"
validateBranchName

echo "\n"
validateIsClone

echo "\n"
cloneInternalInTmpFolder

echo "\n"
deleteCurrentContent

echo "\n"
cloneOpenSourceInTmpFolder

echo "\n"
copyContentFromTmpToInternal

echo "\n"
removeTmpFolder

echo "\n"
stashDeployments

echo "Merge has released, please commit your changes into the origin: "
git remote show origin