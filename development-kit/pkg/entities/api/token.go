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

package api

import (
	"encoding/json"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/crypto"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
)

type Token struct {
	TokenID      uuid.UUID  `json:"tokenID" swaggerignore:"true" gorm:"Column:token_id"`
	Description  string     `json:"description" gorm:"Column:description"`
	RepositoryID *uuid.UUID `json:"repositoryID" swaggerignore:"true" gorm:"Column:repository_id"`
	CompanyID    uuid.UUID  `json:"companyID" swaggerignore:"true" gorm:"Column:company_id"`
	SuffixValue  string     `json:"suffixValue" swaggerignore:"true" gorm:"Column:suffix_value"`
	Value        string     `json:"value" swaggerignore:"true" gorm:"Column:value"`
	CreatedAt    time.Time  `json:"createdAt" swaggerignore:"true" gorm:"Column:created_at"`
	ExpiresAt    time.Time  `json:"expiresAt" swaggerignore:"true" gorm:"Column:expires_at"`
	key          uuid.UUID  `gorm:"-"`
}

func (t *Token) TableName() string {
	return t.GetTable()
}

func (t *Token) ToBytes() []byte {
	bytes, _ := json.Marshal(t)
	return bytes
}

func (t *Token) GetID() uuid.UUID {
	return t.TokenID
}

func (t *Token) ToString() string {
	return string(t.ToBytes())
}

func (t *Token) Map() map[string]interface{} {
	return map[string]interface{}{
		"tokenID":      t.TokenID,
		"description":  t.Description,
		"repositoryID": t.RepositoryID,
		"companyID":    t.CompanyID,
		"suffixValue":  t.SuffixValue,
		"value":        t.Value,
		"createdAt":    t.CreatedAt,
	}
}

func (t *Token) Validate(isRequiredRepositoryID bool) error {
	validationRepositoryID := validation.Field(&t.RepositoryID)
	if isRequiredRepositoryID {
		validationRepositoryID = validation.Field(&t.RepositoryID, validation.Required)
	}
	return validation.ValidateStruct(t,
		validation.Field(&t.Description, validation.Required),
		validation.Field(&t.CompanyID, validation.Required),
		validationRepositoryID,
	)
}

func (t *Token) SetCreateData() *Token {
	t.CreatedAt = time.Now()
	t.TokenID = uuid.New()
	t.ExpiresAt = t.CreatedAt.AddDate(0, 3, 0)

	return t
}

func (t *Token) SetKey(value uuid.UUID) *Token {
	t.key = value
	t.setHashValue()
	t.setSuffixValue()

	return t
}

func (t *Token) GetKey() uuid.UUID {
	return t.key
}

func (t *Token) GetTable() string {
	return "tokens"
}

func (t *Token) setHashValue() {
	t.Value = crypto.HashToken(t.key.String())
}

func (t *Token) setSuffixValue() {
	valueStr := t.key.String()

	// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxx => xxxxx
	t.SuffixValue = valueStr[31:]
}
