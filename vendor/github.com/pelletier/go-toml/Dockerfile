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

FROM golang:1.12-alpine3.9 as builder
WORKDIR /go/src/github.com/pelletier/go-toml
COPY . .
ENV CGO_ENABLED=0
ENV GOOS=linux
RUN go install ./...

FROM scratch
COPY --from=builder /go/bin/tomll /usr/bin/tomll
COPY --from=builder /go/bin/tomljson /usr/bin/tomljson
COPY --from=builder /go/bin/jsontoml /usr/bin/jsontoml
