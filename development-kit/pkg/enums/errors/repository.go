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

var ErrNotFoundRecords = errors.New("{ERROR_REPOSITORY} database not found records")
var ErrDatabaseNotConnected = errors.New("{ERROR_REPOSITORY} database not connected")
var ErrorInvalidCompanyID = errors.New("{ERROR_REPOSITORY} invalid company id")
var ErrorInvalidRepositoryID = errors.New("{ERROR_REPOSITORY} invalid repository id")
var ErrorUserNotMemberOfCompany = errors.New("{ERROR_REPOSITORY} this user is not member of this company")
var ErrorUserAlreadyInThisRepository = errors.New("{ERROR_REPOSITORY} this account already in this repository")
var ErrorRepositoryNotFound = errors.New("repository not found, wrong token or repository name")
var ErrorAlreadyExistsVulnerabilityInDB = errors.New("already exists vulnerability in database")

const ErrorAlreadyExistingRepositoryID = "pq: duplicate key value violates unique constraint" +
	" \"account_repository_repository_id_account_id_key\""

const ErrorAlreadyExistingAnalyseVulnerabilityID = "pq: duplicate key value violates unique constraint" +
	" \"analysis_vulnerabilities_pkey\""
