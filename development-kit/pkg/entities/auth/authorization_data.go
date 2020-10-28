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

package auth

import (
	"encoding/json"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

type AuthorizationData struct {
	Token        string                 `json:"token"`
	Role         authEnums.HorusecRoles `json:"role"`
	CompanyID    uuid.UUID              `json:"companyID"`
	RepositoryID uuid.UUID              `json:"repositoryID"`
}

func (a *AuthorizationData) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.Token, validation.Required, validation.Length(1, 1500), validation.Required),
		validation.Field(&a.Role, validation.Required, validation.In(authEnums.CompanyMember, authEnums.CompanyAdmin,
			authEnums.RepositoryMember, authEnums.RepositorySupervisor, authEnums.RepositoryAdmin,
			authEnums.ApplicationAdmin)),
		validation.Field(&a.CompanyID, is.UUID),
		validation.Field(&a.RepositoryID, is.UUID),
	)
}

func (a *AuthorizationData) ToBytes() []byte {
	bytes, _ := json.Marshal(a)
	return bytes
}
