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
# Contains the value of the latest stable release launched by horusec cli.
LATEST=$(curl -sL https://api.github.com/repos/ZupIT/horusec/releases/latest | jq -r ".tag_name")
LATEST_RC=$(git ls-remote --exit-code --sort='v:refname' --tags https://github.com/ZupIT/horusec.git --ref 'v*.*.*-rc.*' | cut --delimiter='/' --fields=3 | tail --lines=1 | sed 's/.*\///; s/\^{}//')
LATEST_BETA=$(git ls-remote --exit-code --sort='v:refname' --tags https://github.com/ZupIT/horusec.git --ref 'v*.*.*-beta.*' | cut --delimiter='/' --fields=3 | tail --lines=1 | sed 's/.*\///; s/\^{}//')
IS_NEW_URL=false

regex='^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'

horusecSetVersion() {
  if [ -z "$VERSION_DOWNLOAD" ]; then
    echo "invalid input, empty string"
    exit 1
  elif [ "$VERSION_DOWNLOAD" = "latest-rc" ]; then
    latestRc
    echo "Version set to $VERSION_DOWNLOAD"
  elif [ "$VERSION_DOWNLOAD" = "latest-beta" ]; then
    latestBeta
    echo "Version set to $VERSION_DOWNLOAD"
  elif [ "$VERSION_DOWNLOAD" = "latest" ]; then
    echo "Version set to latest"
    VERSION_DOWNLOAD='latest'
  elif echo $VERSION_DOWNLOAD | grep -Eq $regex; then
    echo "Version set to $VERSION_DOWNLOAD"
  else
    echo "input not match required params: 'latest-rc' 'latest-beta' 'latest' or a semantic version compliant, check https://github.com/ZupIT/horusec/releases"
    exit 1
  fi
}

horusecIdentifyOSLatest() {
  if [ "$(uname)" = "Linux" ]; then
    if [ "$(uname -m)" = "x86_64" ]; then
      echo "Installing Horusec for Linux amd64"
      URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_linux_amd64"
    elif [ "$(uname -m)" = "aarch64" ]; then
      echo "Installing Horusec for Linux arm64"
      URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_linux_arm64"
    else
      echo "Installing Horusec for Linux x86"
      URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_linux_x86"
    fi
  elif [ "$(uname)" = "Darwin" ]; then
    if [ "$(uname -m)" = "x86_64" ]; then
      echo "Installing Horusec for Mac amd64"
      URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/${VERSION_DOWNLOAD}/download/horusec_mac_amd64"
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

horusecIdentifyOSWithVersion() {
  if [ "$(uname)" = "Linux" ]; then
    if [ "$(uname -m)" = "x86_64" ]; then
      echo "Installing Horusec for Linux amd64"
      if [ $IS_NEW_URL = true ]; then
        URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_amd64"
      else
        URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_x64"
      fi
    elif [ "$(uname -m)" = "aarch64" ]; then
      echo "Installing Horusec for Linux arm64"
      URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_arm64"
    else
      echo "Installing Horusec for Linux x86"
      URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_linux_x86"
    fi
  elif [ "$(uname)" = "Darwin" ]; then
    if [ "$(uname -m)" = "x86_64" ]; then
      echo "Installing Horusec for Mac amd64"
      if [ $IS_NEW_URL = true ]; then
        URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_mac_amd64"
      else
        URL_DOWNLOAD="https://github.com/ZupIT/horusec/releases/download/${VERSION_DOWNLOAD}/horusec_mac_x64"
      fi
    elif [ "$(uname -m)" = "x86_64" ]; then
      echo "Installing Horusec for amr64"
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

horusecDownloadAndInstall() {
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

horusecIdentifyOS() {
  if [ "$VERSION_DOWNLOAD" = "latest" ]; then
    horusecIdentifyOSLatest
  else
    horusecIdentifyOSWithVersion
  fi
}

# After version 2.6.4 binaries have name changes, which cause a change in the download link.
# This function checks if it is earlier or later than version 2.6.4 and through this we can decide which is the
# correct download link for the version informed by the user.
isOldURLVersion() {
  if [ $VERSION_DOWNLOAD != "latest" ]; then

    VERSION_WITHOUT_V_PREFIX=$(echo "$VERSION_DOWNLOAD" | sed -e "s/v//g")
    VERSION_WITHOUT_BETA_PREFIX=$(echo "$VERSION_WITHOUT_V_PREFIX" | sed -r "s/-beta\.[0-9]+//g")
    VERSION_WITHOUT_RC_PREFIX=$(echo "$VERSION_WITHOUT_BETA_PREFIX" | sed -r "s/-rc\.[0-9]+//g")
    VERSION_WITHOUT_DOTS=$(echo "$VERSION_WITHOUT_RC_PREFIX" | sed -e "s/\.//g")

    if [ "$VERSION_WITHOUT_DOTS" -gt 264 ]; then
      IS_NEW_URL=true
    fi
  fi
}

# Checks if the latest launched rc is in a greater version than the latest version, if the rc is in a lower version
# the latest should be used instead of the rc. This is needed to avoid users missing patch releases, since they will
# not have rc releases.
latestRc() {
      LATEST_RC_WITHOUT_V_PREFIX=$(echo "$LATEST_RC" | sed -e "s/v//g")
      LATEST_RC_WITHOUT_BETA_PREFIX=$(echo "$LATEST_RC_WITHOUT_V_PREFIX" | sed -r "s/-beta\.[0-9]+//g")
      LATEST_RC_WITHOUT_RC_PREFIX=$(echo "$LATEST_RC_WITHOUT_BETA_PREFIX" | sed -r "s/-rc\.[0-9]+//g")
      LATEST_RC_WITHOUT_DOTS=$(echo "$LATEST_RC_WITHOUT_RC_PREFIX" | sed -e "s/\.//g")

      LATEST_WITHOUT_V_PREFIX=$(echo "$LATEST" | sed -e "s/v//g")
      LATEST_WITHOUT_DOTS=$(echo "$LATEST_WITHOUT_V_PREFIX" | sed -e "s/\.//g")

      if [ "$LATEST_RC_WITHOUT_DOTS" -gt "$LATEST_WITHOUT_DOTS" ]; then
        VERSION_DOWNLOAD=$LATEST_RC
      else
        VERSION_DOWNLOAD=$LATEST
      fi
}

# Checks if the latest launched beta is in a greater version than the latest version, if the beta is in a lower version
# the latest should be used instead of the beta. This is needed to avoid users missing patch releases, since they will
# not have beta releases.
latestBeta() {
      LATEST_BETA_WITHOUT_V_PREFIX=$(echo "$LATEST_BETA" | sed -e "s/v//g")
      LATEST_BETA_WITHOUT_BETA_PREFIX=$(echo "$LATEST_BETA_WITHOUT_V_PREFIX" | sed -r "s/-beta\.[0-9]+//g")
      LATEST_BETA_WITHOUT_RC_PREFIX=$(echo "$LATEST_BETA_WITHOUT_BETA_PREFIX" | sed -r "s/-rc\.[0-9]+//g")
      LATEST_BETA_WITHOUT_DOTS=$(echo "$LATEST_BETA_WITHOUT_RC_PREFIX" | sed -e "s/\.//g")

      LATEST_WITHOUT_V_PREFIX=$(echo "$LATEST" | sed -e "s/v//g")
      LATEST_WITHOUT_DOTS=$(echo "$LATEST_WITHOUT_V_PREFIX" | sed -e "s/\.//g")

      if [ "$LATEST_BETA_WITHOUT_DOTS" -gt "$LATEST_WITHOUT_DOTS" ]; then
        VERSION_DOWNLOAD=$LATEST_BETA
      else
        VERSION_DOWNLOAD=$LATEST
      fi
}

horusecSetVersion

isOldURLVersion

horusecIdentifyOS

horusecDownloadAndInstall
