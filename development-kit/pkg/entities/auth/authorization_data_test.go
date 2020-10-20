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
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthorizationDataValidate(t *testing.T) {
	t.Run("should return no error when valid data", func(t *testing.T) {
		token, _, _ := jwt.CreateToken(&accountEntities.Account{
			AccountID:   uuid.New(),
			Email:       "test@test.com",
			Password:    "safePassword!123",
			Username:    "test",
			IsConfirmed: false,
		}, map[string]string{"role": "admin"})

		authorizationData := &AuthorizationData{
			Token:  token,
			Groups: []string{"admin"},
		}

		assert.NoError(t, authorizationData.Validate())
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		authorizationData := &AuthorizationData{}

		assert.Error(t, authorizationData.Validate())
	})
}

func TestAuthorizationData_ToBytes(t *testing.T) {
	authorizationData := &AuthorizationData{}

	assert.NotEmpty(t, authorizationData.ToBytes())
}