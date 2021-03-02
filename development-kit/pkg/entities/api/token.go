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
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/hash"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"time"

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
	ExpiresAt    time.Time  `json:"expiresAt" gorm:"Column:expires_at"`
	IsExpirable  bool       `json:"isExpirable" gorm:"Column:is_expirable"`
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
		"expiresAt":    t.ExpiresAt,
		"isExpirable":  t.IsExpirable,
	}
}

func (t *Token) Validate(isRequiredRepositoryID bool) error {
	return validation.ValidateStruct(t, validation.Field(&t.Description, validation.Required),
		validation.Field(&t.CompanyID, validation.Required),
		validation.Field(&t.ExpiresAt, validation.By(t.validateExpiresAt)),
		validation.Field(&t.RepositoryID, validation.By(func(value interface{}) error {
			return t.validateRepositoryID(isRequiredRepositoryID)
		})),
	)
}

func (t *Token) SetCreateData() *Token {
	t.CreatedAt = time.Now()
	t.TokenID = uuid.New()
	if !t.IsExpirable {
		t.ExpiresAt = time.Time{}
	}

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

func (t *Token) SetExpiresAtTimeDefault() *Token {
	year, month, day := t.ExpiresAt.Date()
	location := t.ExpiresAt.Local().Location()
	t.ExpiresAt = time.Date(year, month, day, 0, 0, 0, 0, location)
	return t
}

func (t *Token) setHashValue() {
	value, err := hash.GenerateSHA256(t.key.String())
	logger.LogError("Error on generate hash value", err)
	t.Value = value
}

func (t *Token) setSuffixValue() {
	valueStr := t.key.String()

	// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxx => xxxxx
	t.SuffixValue = valueStr[31:]
}

func (t *Token) validateExpiresAt(_ interface{}) error {
	if t.IsExpirable && t.ExpiresAt.Before(time.Now()) {
		return errors.New("ExpiresAt is expected to be at least one day longer at now")
	}
	return nil
}

func (t *Token) validateRepositoryID(isRequiredRepositoryID bool) error {
	if isRequiredRepositoryID && (t.RepositoryID == nil || t.RepositoryID == &uuid.Nil) {
		return errors.New("RepositoryID is required")
	}
	return nil
}
