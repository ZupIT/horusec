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

var ErrorUnauthorized = errors.New("you do not have enough privileges for this action")
var ErrorTokenExpired = errors.New("this authorization token has expired, please renew it")
var ErrorUnauthorizedCompanyMember = errors.New("user unauthorized as company member")
var ErrorUnauthorizedCompanyAdmin = errors.New("user unauthorized as company admin")
var ErrorUnauthorizedRepositoryMember = errors.New("user unauthorized as repository member")
var ErrorUnauthorizedRepositorySupervisor = errors.New("user unauthorized as repository supervisor")
var ErrorUnauthorizedRepositoryAdmin = errors.New("user unauthorized as repository admin")
var ErrorUnauthorizedApplicationAdmin = errors.New("user unauthorized as application admin")
