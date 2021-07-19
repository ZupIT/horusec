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

docker stop horus_API > /dev/null
docker rm horus_API > /dev/null
cd deployments && docker-compose -f docker-compose.yml up -d --build --no-deps api
if [ $? -ne 0 ]; then
  cd ..
  exit 1;
fi
cd ..
while true; do
    if [ "$(curl -s -k -L localhost:8888/healthcheck)" = "WORKING" ]; then
        echo "horus_API is UP!"
        break
    else
        echo "Waiting healthcheck..."
    fi
    sleep 15
done
