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

DIRECTORY=$1

validateSwagger () {
    case "$DIRECTORY" in
        "horusec-account") # Used to update an bugfix or an new feature in develop branch
            echo "Directory selected is horusec-account";;
        "horusec-analytic") # Used when you finish development and start testing in the test environment and in develop branch
            echo "Directory selected is horusec-analytic";;
        "horusec-api") # Used when an correction was applied in master branch
            echo "Directory selected is horusec-api";;
        "horusec-messages") # Used when an new feature is enable in production environment and in master branch
            echo "Directory selected is horusec-messages";;
        "horusec-auth") # Used to update an bugfix or an new feature in develop branch
            echo "Directory selected is horusec-auth";;
        "horusec-webhook") # Used to update an bugfix or an new feature in develop branch
            echo "Directory selected is horusec-webhook";;
        *)
            echo "Param Directory is invalid, please use the examples bellow allowed and try again!"
            echo "Params Directory allowed: horusec-account, horusec-analytic, horusec-api, horusec-messages, horusec-auth, horusec-webhook"
            exit 1;;
    esac

    swag &> /dev/null
    RESPONSE=$?
    if [[ "$RESPONSE" != "0" ]]
    then
        go get -v github.com/swaggo/swag/cmd/swag@v1.6.7
    fi

    swag &> /dev/null
    RESPONSE=$?
    if [[ "$RESPONSE" != "0" ]]
    then
        echo "swag is not installed, please install and try again"
        exit 1
    fi

    echo "Lib swag installed with success!"
}

updateDocs () {
    swag init -d $DIRECTORY -g ./cmd/app/main.go -o $DIRECTORY/docs
}

validateSwagger

updateDocs