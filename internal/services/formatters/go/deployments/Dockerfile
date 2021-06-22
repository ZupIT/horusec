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

FROM golang:alpine AS builder

RUN apk add git

RUN git clone https://github.com/sonatype-nexus-community/nancy.git

RUN cd nancy && GO111MODULE=on CGO_ENABLED=0 go build -o /bin/nancy -v

FROM golang:alpine

COPY --from=builder /bin/nancy /bin/nancy

RUN wget -O - -q https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s latest
