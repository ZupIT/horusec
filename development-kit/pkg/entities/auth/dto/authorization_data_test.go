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
	"testing"

	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationDataValidate(t *testing.T) {
	t.Run("should return no error when valid data", func(t *testing.T) {
		token, _, _ := jwt.CreateToken(&authEntities.Account{
			AccountID:   uuid.New(),
			Email:       "test@test.com",
			Password:    "safePassword!123",
			Username:    "test",
			IsConfirmed: false,
		}, nil)

		authorizationData := &AuthorizationData{
			Token: token,
			Role:  authEnums.CompanyAdmin,
		}

		assert.NoError(t, authorizationData.Validate())
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		authorizationData := &AuthorizationData{}

		assert.Error(t, authorizationData.Validate())
	})
}

func TestToBytes(t *testing.T) {
	t.Run("should parse to bytes", func(t *testing.T) {
		authorizationData := &AuthorizationData{}
		assert.NotEmpty(t, authorizationData.ToBytes())
	})
}
