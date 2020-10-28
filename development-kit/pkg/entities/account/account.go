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

package account

import (
	"encoding/json"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/crypto"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

// nolint
type Account struct {
	AccountID          uuid.UUID    `json:"accountID" gorm:"primary_key"`
	Email              string       `json:"email"`
	Password           string       `json:"password"`
	Username           string       `json:"username"`
	IsConfirmed        bool         `json:"isConfirmed"`
	IsApplicationAdmin bool         `json:"isApplicationAdmin"`
	CreatedAt          time.Time    `json:"createdAt"`
	UpdatedAt          time.Time    `json:"updatedAt"`
	Companies          []Company    `gorm:"many2many:account_company;association_jointable_foreignkey:company_id;jointable_foreignkey:account_id"`       // nolint
	Repositories       []Repository `gorm:"many2many:account_repository;association_jointable_foreignkey:repository_id;jointable_foreignkey:account_id"` // nolint
}

func (a *Account) SetPasswordHash() {
	hash, _ := crypto.HashPassword(a.Password)
	a.Password = hash
}

func (a *Account) SetAccountData() *Account {
	a.SetAccountID()
	a.SetCreatedAt()
	a.SetUpdatedAt()
	a.SetPasswordHash()
	return a
}

func (a *Account) SetAccountID() {
	a.AccountID = uuid.New()
}

func (a *Account) SetCreatedAt() {
	a.CreatedAt = time.Now()
}

func (a *Account) SetUpdatedAt() *Account {
	a.UpdatedAt = time.Now()
	return a
}

func (a *Account) SetIsConfirmed() *Account {
	a.IsConfirmed = true
	return a
}

func (a *Account) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.Email, validation.Required, validation.Length(1, 255), is.Email),
		validation.Field(&a.Password, validation.Length(1, 255), validation.Required),
		validation.Field(&a.Username, validation.Length(1, 255), validation.Required),
	)
}

func (a *Account) GetTable() string {
	return "accounts"
}

func (a *Account) IsAccountConfirmed() error {
	if !a.IsConfirmed {
		return errors.ErrorAccountEmailNotConfirmed
	}

	return nil
}

func (a *Account) ToBytes() []byte {
	bytes, _ := json.Marshal(a)
	return bytes
}

func (a *Account) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"account_id":           a.AccountID,
		"password":             a.Password,
		"email":                a.Email,
		"username":             a.Username,
		"is_confirmed":         a.IsConfirmed,
		"is_application_admin": a.IsApplicationAdmin,
		"created_at":           a.CreatedAt,
		"updated_at":           a.UpdatedAt,
	}
}

func (a *Account) ToLoginResponse(accessToken, refreshToken string, expiresAt time.Time) *LoginResponse {
	return &LoginResponse{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		ExpiresAt:          expiresAt,
		Username:           a.Username,
		IsApplicationAdmin: a.IsApplicationAdmin,
		Email:              a.Email,
	}
}

func (a *Account) IsNotApplicationAdminAccount() bool {
	return !a.IsApplicationAdmin
}
