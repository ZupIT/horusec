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


docker build deployments/dockerfiles/bandit/ -t horus/bandit:latest
docker build deployments/dockerfiles/brakeman/ -t horus/brakeman:latest
docker build deployments/dockerfiles/enry/ -t horus/enry:latest
docker build deployments/dockerfiles/gitauthors/ -t horus/gitauthors:latest
docker build deployments/dockerfiles/gosec/ -t horus/gosec:latest
docker build deployments/dockerfiles/npmaudit/ -t horus/npmaudit:latest
docker build deployments/dockerfiles/npmaudit/ -t horus/yarnaudit:latest
docker build deployments/dockerfiles/safety/ -t horus/safety:latest
docker build deployments/dockerfiles/gitleaks/ -t horus/gitleaks:latest
docker build deployments/dockerfiles/spotbugs/ -t horus/spotbugs:latest