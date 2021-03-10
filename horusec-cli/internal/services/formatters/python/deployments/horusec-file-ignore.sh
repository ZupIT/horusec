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


# This script will exclude folders and files written in .horusec from the root of the cloned repository.
#

horusecFile=".horusec"
codePath="/tmp/src"

isHorusecIgnore(){
    line=$1

    if echo "$line" | grep -q "horusec-Ignore"; then
        return 0
    fi

    return 1
}

isCommented(){
    line=$1
    commentRegexp='^[[:space:]]*#'

    if echo "$line" | grep -Eq "$commentRegexp"; then
        return 0
    fi

    return 1
}

isEmpty(){
    line=$1

    if [ ! "$line" ]; then
        return 0
    fi

    return 1
}

leavesCodePath(){
    line=$1

    if echo "$line" | grep -qF "../"; then
        return 0
    fi

    return 1
}

wouldRemoveCurrentWorkdir() {
    line=$1

    if echo "$codePath$line" | grep -qF "//"; then
        return 0
    fi

    return 1
}

if [ -f "$horusecFile" ]; then

    while IFS= read -r line; do

        if isHorusecIgnore $line || isCommented $line || isEmpty $line || leavesCodePath $line || wouldRemoveCurrentWorkdir $line; then
            continue
        fi

        rm -rf "$codePath$line"

    done < "$horusecFile"
fi