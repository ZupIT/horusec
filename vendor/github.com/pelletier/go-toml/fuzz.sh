#! /bin/sh
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

set -eu

go get github.com/dvyukov/go-fuzz/go-fuzz
go get github.com/dvyukov/go-fuzz/go-fuzz-build

if [ ! -e toml-fuzz.zip ]; then
    go-fuzz-build github.com/pelletier/go-toml
fi

rm -fr fuzz
mkdir -p fuzz/corpus
cp *.toml fuzz/corpus

go-fuzz -bin=toml-fuzz.zip -workdir=fuzz
