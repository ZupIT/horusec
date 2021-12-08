#!/bin/sh
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


URL_DOWNLOAD=""
VERSION_DOWNLOAD=$1
LATEST_RC=$(git ls-remote --exit-code --sort='v:refname' --tags https://github.com/ZupIT/horusec.git --ref 'v*.*.*-rc.*' | cut --delimiter='/' --fields=3 | tail --lines=1 | sed 's/.*\///; s/\^{}//')
LATEST_BETA=$(git ls-remote --exit-code --sort='v:refname' --tags https://github.com/ZupIT/horusec.git --ref 'v*.*.*-beta.*' | cut --delimiter='/' --fields=3 | tail --lines=1 | sed 's/.*\///; s/\^{}//')

regex='^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'

horusecSetVersion () {
    if [ "$VERSION_DOWNLOAD" = "latest-rc" ] ; then
        VERSION_DOWNLOAD=$LATEST_RC
    elif [ "$VERSION_DOWNLOAD" = "latest-beta" ] ; then
        VERSION_DOWNLOAD=$LATEST_BETA
    elif  [ "$VERSION_DOWNLOAD" = "latest" ] ; then
        VERSION_DOWNLOAD='latest'
    elif ! echo $VERSION_DOWNLOAD| grep -Eq  $regex; then
        echo "input not match required params: 'latest-rc' 'latest-beta' 'latest' or a semantic version compliant, check https://github.com/ZupIT/horusec/releases"
        exit 1
    fi
    echo "Downloading version: $VERSION_DOWNLOAD"

}

horusecIdentifyOSLatest () {
    if [ "$(uname)" = "Linux" ]; then
        if [ "$(uname -m)" = "x86_64" ]; then
            echo "Installing Horusec for Linux x64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_linux_x64"
        elif [ "$(uname -m)" = "aarch64" ]; then
            echo "Installing Horusec for Linux arm64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_linux_arm64"
        else
            echo "Installing Horusec for Linux x86"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_linux_x86"
        fi
    elif [ "$(uname)" = "Darwin" ]; then
        if [ "$(uname -m)" = "x86_64" ]; then
            echo "Installing Horusec for Mac x64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_mac_x64"
        elif [ "$(uname -m)" = "arm64" ]; then
            echo "Installing Horusec for Mac arm64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_mac_arm64"
        else
            echo "Not enable Horusec to Mac x86"
            exit 1
        fi
    else
        echo "Unable to identify which OS you're using"
        exit 1
    fi
}

horusecIdentifyOSWithVersion () {
    if [ "$(uname)" = "Linux" ]; then
        if [ "$(uname -m)" = "x86_64" ]; then
            echo "Installing Horusec for Linux x64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_x64"
        elif [ "$(uname -m)" = "aarch64" ]; then
            echo "Installing Horusec for Linux x64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_arm64"
        else
            echo "Installing Horusec for Linux x86"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_x64"
        fi
    elif [ "$(uname)" = "Darwin" ]; then
        if [ "$(uname -m)" = "x86_64" ]; then
            echo "Installing Horusec for Mac x64"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_mac_x64"
        elif [ "$(uname -m)" = "x86_64" ]; then
            echo "Installing Horusec for Mac M1"
            URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_mac_arm64"
        else
            echo "Not enable Horusec to Mac x86"
            exit 1
        fi
    else
        echo "Unable to identify which OS you're using"
        exit 1
    fi
}

horusecDownloadAndInstall () {
    INSTALL_PATH="/usr/local/bin"

    if [ ! -d "$INSTALL_PATH" ]; then
        mkdir -p $INSTALL_PATH
    fi

    rm -r $INSTALL_PATH/horusec >/dev/null 2>&1

    echo "Downloading horusec..."
    echo $URL_DOWNLOAD

    curl -fsSL "$URL_DOWNLOAD" -o ./horusec

    chmod +x ./horusec

    sudo mv ./horusec "$INSTALL_PATH"

    echo "Horusec was downloaded and moved to $INSTALL_PATH/horusec"

    $INSTALL_PATH/horusec version
}

horusecIdentifyOS () {
    if [ "$VERSION_DOWNLOAD" = "latest" ]; then
      horusecIdentifyOSLatest
    else
      horusecIdentifyOSWithVersion
    fi
}

horusecSetVersion

horusecIdentifyOS

horusecDownloadAndInstall
