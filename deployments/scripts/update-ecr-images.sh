#! /bin/bash
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


languages=( "dotnet-core-3.1" "npmaudit"  "yarnaudit" "gitleaks"  "brakeman"  "bandit"  "spotbugs"  "gosec" "safety" )

cmdstr=''

# generateDockerCmd generates the formatted string to tag an image to our ECR
# @Returns command
generateDockerCmd() {
  cmdstr="docker -H localhost:2376 tag horuszup/$1 671982376808.dkr.ecr.us-east-1.amazonaws.com/horuszup/$1"
}

langCmd=''
execDockerCmd() {
  echo "Criando tag para $1"
  $langCmd
  $langCmd':1.0.0'
}

pushImageCmd() {
  docker -H localhost:2376 push "671982376808.dkr.ecr.us-east-1.amazonaws.com/horuszup/$1"
}



for lang in "${languages[@]}"
do
  generateDockerCmd $lang

  langCmd=$cmdstr
  execDockerCmd $lang

  pushImageCmd $lang
done
