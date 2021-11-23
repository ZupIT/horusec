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

FROM python:3.10.0-alpine3.14

RUN apk add --quiet --no-cache wget

RUN wget -O /usr/bin/tfsec https://github.com/aquasecurity/tfsec/releases/download/v0.55.1/tfsec-linux-amd64 && chmod +x /usr/bin/tfsec

# This installation is necessary if we can usage checkov tool
# See more details in: https://github.com/bridgecrewio/checkov/issues/1947
RUN pip install --upgrade pip==21.3.1 && pip install --upgrade setuptools==59.1.1
RUN apk add --no-cache --virtual .build_deps build-base libffi-dev \
 && pip install --no-cache-dir -U checkov \
 && apk del .build_deps


