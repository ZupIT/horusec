# Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

IMAGE_BASE_NAME=$1
IMAGE_TAG=$2

setDefaultImageBaseName() {
    if [ -z "$IMAGE_BASE_NAME" ]; then
        IMAGE_BASE_NAME="local"
    fi
    if [ -z "$IMAGE_TAG" ]; then
        IMAGE_TAG="local"
    fi
}

getDirectoryAndImagesNameByLanguageName() {
    # shellcheck disable=SC2044
    for DOCKERFILE in $(find internal -type f -iname "Dockerfile"); do
        LANGUAGE=$(echo $DOCKERFILE | cut -d "/" -f4)
        if ! docker build -t "$IMAGE_BASE_NAME-$LANGUAGE:$IMAGE_TAG" -f "$DOCKERFILE" .; then
            echo "Error on build docker file in path: $DOCKERFILE"
            exit 1
        fi
    done
}

setDefaultImageBaseName

getDirectoryAndImagesNameByLanguageName