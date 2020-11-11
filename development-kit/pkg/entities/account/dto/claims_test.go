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
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValid(t *testing.T) {
	t.Run("should return no error when valid claim", func(t *testing.T) {
		claim := ClaimsJWT{
			Email:    "test@test.com",
			Username: "test",
			StandardClaims: jwt.StandardClaims{
				Subject: uuid.New().String(),
			},
		}

		assert.NoError(t, claim.Valid())
	})

	t.Run("should return error missing email", func(t *testing.T) {
		claim := ClaimsJWT{}
		assert.Error(t, claim.Valid())
	})
}
