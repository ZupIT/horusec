// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

import "errors"

var ErrorBrokerIsNotHealth = errors.New("{ERROR_HTTP} broker is not health")
var ErrorDatabaseIsNotHealth = errors.New("{ERROR_HTTP} database is not health")
var ErrorRelationalDatabaseIsNotHealth = errors.New("{ERROR_HTTP} relational database is not healthy")
var ErrorGenericInternalError = errors.New("{ERROR_HTTP} something went wrong, sorry for the inconvenience")

const ErrorGrpcConnectionNotReady = "{ERROR_GRPC} grpc connection is not ready, state: %s"
