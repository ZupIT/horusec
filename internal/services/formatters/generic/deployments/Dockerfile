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

FROM azul/zulu-openjdk-alpine:14 AS jlink

RUN "$JAVA_HOME/bin/jlink" --compress=2 \
    --module-path /opt/java/openjdk/jmods \
    --add-modules java.base,java.compiler,java.datatransfer,jdk.crypto.ec,java.desktop,java.instrument,java.logging,java.management,java.naming,java.rmi,java.scripting,java.security.sasl,java.sql,java.transaction.xa,java.xml,jdk.unsupported \
    --output /jlinked

FROM python:alpine

RUN pip install semgrep

COPY --from=jlink /jlinked /opt/jdk/

ENV JAVA_HOME=/opt/jdk

RUN apk update && apk add curl

RUN curl -o /bin/dependency-check-6.2.2-release.zip -LO https://github.com/jeremylong/DependencyCheck/releases/download/v6.2.2/dependency-check-6.2.2-release.zip

RUN unzip /bin/dependency-check-6.2.2-release.zip -d  /bin

RUN rm /bin/dependency-check-6.2.2-release.zip
