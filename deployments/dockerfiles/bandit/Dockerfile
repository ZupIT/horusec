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

FROM python:3.6-alpine as builder

# Install and compile bandit + its dependencies
RUN apk add --no-cache jq alpine-sdk
RUN pip install bandit

# Now build a fresh container, copying across the compiled pieces
FROM python:3.6-alpine

COPY --from=builder /usr/local/lib/python3.6 /usr/local/lib/python3.6
COPY --from=builder /usr/local/bin/bandit /usr/local/bin/bandit
COPY ./deployments/dockerfiles/bandit/horusec-file-ignore.sh /usr/local/bin/horusec-file-ignore.sh

# Add packages that we need in the final image on runtime
RUN apk add --no-cache git jq bash openssh-client