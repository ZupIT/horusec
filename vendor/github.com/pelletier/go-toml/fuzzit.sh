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

set -xe

# go-fuzz doesn't support modules yet, so ensure we do everything
# in the old style GOPATH way
export GO111MODULE="off"

# install go-fuzz
go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build

# target name can only contain lower-case letters (a-z), digits (0-9) and a dash (-)
# to add another target, make sure to create it with `fuzzit create target`
# before using `fuzzit create job`
TARGET=toml-fuzzer

go-fuzz-build -libfuzzer -o ${TARGET}.a github.com/pelletier/go-toml
clang -fsanitize=fuzzer ${TARGET}.a -o ${TARGET}

# install fuzzit for talking to fuzzit.dev service
# or latest version:
# https://github.com/fuzzitdev/fuzzit/releases/latest/download/fuzzit_Linux_x86_64
wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v2.4.52/fuzzit_Linux_x86_64
chmod a+x fuzzit

# TODO: change kkowalczyk to go-toml and create toml-fuzzer target there
./fuzzit create job --type $TYPE go-toml/${TARGET} ${TARGET}
