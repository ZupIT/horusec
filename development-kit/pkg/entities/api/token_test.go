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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTokenSetCreateData(t *testing.T) {
	t.Run("should set the token id, createdAt and updatedAt", func(t *testing.T) {
		token := &Token{}
		token = token.SetCreateData()

		assert.NotEmpty(t, token.TokenID)
		assert.NotEmpty(t, token.CreatedAt)
	})
}

func TestTokenGetTable(t *testing.T) {
	t.Run("should return the name of the collection", func(t *testing.T) {
		token := &Token{}
		token = token.SetCreateData()

		assert.Equal(t, token.GetTable(), "tokens")
	})
}

func TestTokenTableName(t *testing.T) {
	t.Run("should return the name of the collection", func(t *testing.T) {
		token := &Token{}
		token = token.SetCreateData()

		assert.Equal(t, token.TableName(), "tokens")
	})
}

func TestTokenGetID(t *testing.T) {
	t.Run("should return the tokenID", func(t *testing.T) {
		tokenID := uuid.New()
		token := &Token{
			TokenID: tokenID,
		}

		assert.Equal(t, token.GetID(), tokenID)
	})
}

func TestTokenMap(t *testing.T) {
	t.Run("should return the token map", func(t *testing.T) {
		tokenID := uuid.New()
		token := &Token{
			TokenID: tokenID,
		}

		assert.Equal(t, token.Map()["tokenID"], tokenID)
	})
}

func TestTokenValidate(t *testing.T) {
	t.Run("validate should return an error when repositoryID is empty", func(t *testing.T) {
		token := &Token{
			CompanyID: uuid.New(),
		}
		assert.Error(t, token.Validate(true))
	})

	t.Run("validate should return nil when repositoryID is not empty", func(t *testing.T) {
		repositoryID := uuid.New()
		token := &Token{
			CompanyID:    uuid.New(),
			RepositoryID: &repositoryID,
			Description:  "test",
		}
		assert.Nil(t, token.Validate(true))
	})

	t.Run("validate should return nil when repositoryID is empty but not required", func(t *testing.T) {
		token := &Token{
			CompanyID:   uuid.New(),
			Description: "test",
		}
		assert.Nil(t, token.Validate(false))
	})
}

func TestTokenSetHashValue(t *testing.T) {
	t.Run("should hash the Value attr", func(t *testing.T) {
		tokenValueStr := "passphrase"
		token := &Token{Value: tokenValueStr}
		token.setHashValue()

		assert.NotEmpty(t, token.Value)
		assert.NotEqual(t, token.Value, tokenValueStr)
	})
}

func TestTokenSetSuffixValue(t *testing.T) {
	t.Run("should set the suffix with the last 5 uuid digits", func(t *testing.T) {
		token := &Token{}

		token.SetKey(uuid.New())
		token.setSuffixValue()

		assert.NotEmpty(t, token.SuffixValue)
		assert.True(t, strings.HasSuffix(token.key.String(), token.SuffixValue))
	})
}

func TestTokenToBytes(t *testing.T) {
	t.Run("should success parse to bytes", func(t *testing.T) {
		token := &Token{}
		assert.NotEmpty(t, token.ToBytes())
	})
}

func TestTokenToString(t *testing.T) {
	t.Run("should success parse to string", func(t *testing.T) {
		token := &Token{}
		assert.NotEmpty(t, token.ToString())
	})
}

func TestTokenGetKey(t *testing.T) {
	t.Run("should success get key", func(t *testing.T) {
		token := &Token{key: uuid.New()}
		assert.NotEmpty(t, token.GetKey())
	})
}

func TestToken_SetExpiresAtTimeDefault(t *testing.T) {
	t.Run("Should setup always time default", func(t *testing.T) {
		token := &Token{ExpiresAt: time.Now()}
		expected := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Now().Local().Location())
		assert.Equal(t, expected, token.SetExpiresAtTimeDefault().ExpiresAt)
	})
}
