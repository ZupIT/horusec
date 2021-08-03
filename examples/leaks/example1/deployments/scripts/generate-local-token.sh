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

printf "Generating Local Token      ..." && sleep 60

token=$(curl -s -H "Content-Type: application/json" -H "Authorization: Basic aHVza3lDSVVzZXI6aHVza3lDSVBhc3N3b3Jk" http://localhost:8888/api/1.0/token -X POST -d '{"repositoryURL": "https://github.com/ZupIT/horus.git"}' | awk -F '"' '{print $4}')

if [ $? -eq 0 ]; then
    echo " done"
else
    echo " error. Try running make generate-local-token"
fi

echo "export HORUS_CLIENT_TOKEN=\"$token\"" >> .env
