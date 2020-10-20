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
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

type AuthorizationData struct {
	Token        string    `json:"token"`
	Groups       []string  `json:"groups"`
	CompanyID    uuid.UUID `json:"companyID"`
	RepositoryID uuid.UUID `json:"repositoryID"`
}

func (a *AuthorizationData) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.Token, validation.Required, validation.Length(1, 500), validation.Required),
		validation.Field(&a.Groups, validation.NotNil, validation.Required),
		validation.Field(&a.CompanyID, is.UUID),
		validation.Field(&a.RepositoryID, is.UUID),
	)
}

func (a *AuthorizationData) ToBytes() []byte {
	bytes, _ := json.Marshal(a)
	return bytes
}
