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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"io"
)

type IAccount interface {
	NewLoginFromReadCloser(body io.ReadCloser) (loginData *dto.LoginData, err error)
	ValidateResetPasswordCode(validCode []byte, informedCode string) error
	ValidateEmail(email string) error
}

type Account struct {
}

func NewAccountUseCases() IAccount {
	return &Account{}
}

func (a *Account) NewLoginFromReadCloser(body io.ReadCloser) (loginData *dto.LoginData, err error) {
	err = json.NewDecoder(body).Decode(&loginData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return loginData, loginData.Validate()
}

func (a *Account) ValidateResetPasswordCode(validCode []byte, informedCode string) error {
	if string(validCode) != informedCode {
		return errors.ErrorInvalidResetPasswordCode
	}

	return nil
}

func (a *Account) ValidateEmail(email string) error {
	return validation.Validate(email, validation.Required, validation.Length(1, 255), is.Email)
}
