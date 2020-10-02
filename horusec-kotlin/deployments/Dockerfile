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

FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

ADD . /go/src/github.com/ZupIT/horusec
WORKDIR /go/src/github.com/ZupIT/horusec
COPY . .

RUN env GOOS=linux GOARCH=amd64 go build -o /bin/horusec-kotlin ./horusec-kotlin/cmd/app/main.go

FROM golang:alpine

COPY --from=builder /bin/horusec-kotlin /bin/horusec-kotlin
RUN chmod +x /bin/horusec-kotlin

