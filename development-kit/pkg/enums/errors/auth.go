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

var ErrorInvalidAuthType = errors.New("{AUTH} invalid auth type, should be ldap, keycloak or horus")
var ErrorTokenCanNotBeEmpty = errors.New("{AUTH} token can not be empty in authorization header")

const (
	ErrorAuthTypeNotActive          = "{AUTH} this auth type it is no active, should be %s"
	ErrorFailedToVerifyIsAuthorized = "{AUTH} failed to verify is authorized request"
	ErrorFailedToGetAccountID       = "{AUTH} failed to get account id from token"
)
