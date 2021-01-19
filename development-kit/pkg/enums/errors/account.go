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

var ErrorWrongEmailOrPassword = errors.New("{ACCOUNT} invalid username or password")
var ErrorAccountEmailNotConfirmed = errors.New("{ACCOUNT} account email not confirmed")
var ErrorEmailAlreadyInUse = errors.New("{ACCOUNT} email already in use")
var ErrorNewPasswordNotEqualOldPassword = errors.New("{ACCOUNT} new password is can't equals current password")
var ErrorNewPasswordOrPasswordHashNotBeEmpty = errors.New("{ACCOUNT} password or password hash can't be empty")
var ErrorInvalidResetPasswordCode = errors.New("{ACCOUNT} invalid reset password data")
var ErrorDoNotHavePermissionToThisAction = errors.New("{ACCOUNT} user do not have permission to this action")
var ErrorMissingOrInvalidPassword = errors.New("{ACCOUNT} missing or invalid password")
var ErrorInvalidPassword = errors.New("{ACCOUNT} password is not valid")
var ErrorInvalidAccountID = errors.New("{ACCOUNT} invalid account id")
var ErrorUserAlreadyLogged = errors.New("{ACCOUNT} user already logged")
var ErrorEmptyAuthorizationToken = errors.New("{ACCOUNT} empty authorization token")
var ErrorEmptyOrInvalidRefreshToken = errors.New("{ACCOUNT} empty or invalid token")
var ErrorNotFoundRefreshTokenInCache = errors.New("{ACCOUNT} refresh token not found in cache")
var ErrorAccessAndRefreshTokenNotMatch = errors.New("{ACCOUNT} access and refresh token does not match")
var ErrorErrorEmptyBody = errors.New("{ACCOUNT} empty request body")
var ErrorUsernameAlreadyInUse = errors.New("{ACCOUNT} username already in use")
var ErrorRepositoryNameAlreadyInUse = errors.New("{ACCOUNT} repository name already in use")
var ErrorInvalidKeycloakToken = errors.New("{ACCOUNT} keycloak token without email or username")
var ErrorUserLoggedIsNotApplicationAdmin = errors.New("{ACCOUNT} user logged is not application admin")
var ErrorInvalidUpdateAccountData = errors.New("{ACCOUNT} the data to update account is not valid")
var ErrorInvalidLdapGroup = errors.New("{ACCOUNT} ldap group is not a valid one for this user")
