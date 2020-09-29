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

AUTHORIZATION=$1
rm -rf ./tmp
rm -rf ./analysis
mkdir -p ./tmp
mkdir -p ./analysis

unzip -d ./analysis/gitleaks ../development-kit/pkg/utils/test/zips/gitleaks/gitleaks.zip
unzip -d ./analysis/go-gosec ../development-kit/pkg/utils/test/zips/go-gosec/go-gosec.zip
unzip -d ./analysis/java-spotbug ../development-kit/pkg/utils/test/zips/java-spotbug/java-spotbug.zip
unzip -d ./analysis/javascript-npm ../development-kit/pkg/utils/test/zips/javascript-npm/javascript-npm.zip
unzip -d ./analysis/javascript-yarn ../development-kit/pkg/utils/test/zips/javascript-yarn/javascript-yarn.zip
unzip -d ./analysis/kotlin-spotbug ../development-kit/pkg/utils/test/zips/kotlin-spotbug/kotlin-spotbug.zip
unzip -d ./analysis/netcore3-1 ../development-kit/pkg/utils/test/zips/netcore3-1/netcore3-1.zip
unzip -d ./analysis/python-bandit ../development-kit/pkg/utils/test/zips/python-bandit/python-bandit.zip
unzip -d ./analysis/python-safety ../development-kit/pkg/utils/test/zips/python-safety/python-safety.zip
unzip -d ./analysis/ruby-brakeman ../development-kit/pkg/utils/test/zips/ruby-brakeman/ruby-brakeman.zip

horusec start -p="./analysis/gitleaks" -a="$AUTHORIZATION" -o=json -O="./tmp/gitleaks.json" &
horusec start -p="./analysis/go-gosec" -a="$AUTHORIZATION" -o=json -O="./tmp/go-gosec.json" &
horusec start -p="./analysis/java-spotbug" -a="$AUTHORIZATION" -o=json -O="./tmp/java-spotbug.json" &
horusec start -p="./analysis/javascript-npm" -a="$AUTHORIZATION" -o=json -O="./tmp/javascript-npm.json" &
horusec start -p="./analysis/javascript-yarn" -a="$AUTHORIZATION" -o=json -O="./tmp/javascript-yarn.json" &
horusec start -p="./analysis/kotlin-spotbug" -a="$AUTHORIZATION" -o=json -O="./tmp/kotlin-spotbug.json" &
horusec start -p="./analysis/netcore3-1" -a="$AUTHORIZATION" -o=json -O="./tmp/netcore3-1.json" &
horusec start -p="./analysis/python-bandit" -a="$AUTHORIZATION" -o=json -O="./tmp/python-bandit.json" &
horusec start -p="./analysis/python-safety" -a="$AUTHORIZATION" -o=json -O="./tmp/python-safety.json" &
horusec start -p="./analysis/ruby-brakeman" -a="$AUTHORIZATION" -o=json -O="./tmp/ruby-brakeman.json" &
