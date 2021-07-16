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

# horus client default environment variables
HORUS_CLIENT_REPO_URL="https://github.com/ZupIT/horus.git"
HORUS_CLIENT_REPO_BRANCH="poc-golang-gosec"
HORUS_CLIENT_API_ADDR="http://localhost:8888"
HORUS_CLIENT_API_USE_HTTPS="false"

# Adding default envs vars to run be used by make run-client
echo "export HORUS_CLIENT_REPO_URL=\"$HORUS_CLIENT_REPO_URL\"" > .env
echo "export HORUS_CLIENT_REPO_BRANCH=\"$HORUS_CLIENT_REPO_BRANCH\"" >> .env
echo "export HORUS_CLIENT_API_ADDR=\"$HORUS_CLIENT_API_ADDR\"" >> .env
echo "export HORUS_CLIENT_API_USE_HTTPS=\"$HORUS_CLIENT_API_USE_HTTPS\"" >> .env
