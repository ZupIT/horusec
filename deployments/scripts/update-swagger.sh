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
            echo "Directory selected is horusec-account" ;;
        "horusec-analytic") # Used when you finish development and start testing in the test environment and in develop branch
            echo "Directory selected is horusec-analytic" ;;
        "horusec-api") # Used when an correction was applied in master branch
            echo "Directory selected is horusec-api" ;;
        "horusec-messages") # Used when an new feature is enable in production environment and in master branch
            echo "Directory selected is horusec-messages" ;;
        *)
            echo "Param Directory is invalid, please use the examples bellow allowed and try again!"
            echo "Params Directory allowed: horusec-account, horusec-analytic, horusec-api, horusec-messages"
            exit 1;;
    esac

    swag &> /dev/null
    RESPONSE=$?
    if [[ "$RESPONSE" != "0" ]]
    then
        INSTALL_PATH="/usr/local/bin"
        DOWNLOAD_PATH="./tmp/swag"
        echo "The command swag is not installed!"
        echo "Installing swag..."
        mkdir -p $DOWNLOAD_PATH
        curl -L https://github.com/swaggo/swag/releases/download/v1.6.7/swag_1.6.7_Linux_x86_64.tar.gz | tar xvzf - -C "$DOWNLOAD_PATH"
        chmod +x "$DOWNLOAD_PATH/swag"
        sudo mv "$DOWNLOAD_PATH/swag" "$INSTALL_PATH"
        rm -rf "$DOWNLOAD_PATH"
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
    cd $DIRECTORY || echo "Directory not exist!"; exit
    swag init -g ./cmd/app/main.go
    cd ..
}

validateSwagger

updateDocs