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

package dto

import (
	"encoding/json"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/crypto"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type LoginData struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (l *LoginData) IsInvalid(email, passwordHash string) bool {
	if l.Email == email && crypto.CheckPasswordHash(l.Password, passwordHash) {
		return false
	}

	return true
}

func (l *LoginData) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.Email, validation.Required, validation.Length(1, 255), is.EmailFormat),
		validation.Field(&l.Password, validation.Length(1, 255), validation.Required),
	)
}

func (l *LoginData) ToBytes() []byte {
	bytes, _ := json.Marshal(l)
	return bytes
}
