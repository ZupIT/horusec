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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSetPassword(t *testing.T) {
	t.Run("should success set password", func(t *testing.T) {
		account := &Account{Password: "test"}
		account.SetPasswordHash()
		assert.NotEmpty(t, account.Password)
	})
}

func TestSetAccountID(t *testing.T) {
	t.Run("should success set account id", func(t *testing.T) {
		account := &Account{}
		account.SetAccountID()
		assert.IsType(t, uuid.UUID{}, account.AccountID)
		assert.NotEmpty(t, account.AccountID)
	})
}

func TestValidate(t *testing.T) {
	t.Run("should return no error for valid account", func(t *testing.T) {
		account := &Account{
			Email:    "test@test.com",
			Password: "test",
			Username: "test",
		}
		assert.NoError(t, account.Validate())
	})

	t.Run("should return error when invalid account", func(t *testing.T) {
		account := &Account{}
		assert.Error(t, account.Validate())
	})
}

func TestGetTable(t *testing.T) {
	t.Run("should success get table name", func(t *testing.T) {
		account := &Account{}
		assert.Equal(t, "accounts", account.GetTable())
	})
}

func TestIsAccountConfirmed(t *testing.T) {
	t.Run("should should return no error when account email is confirmed", func(t *testing.T) {
		account := &Account{IsConfirmed: true}
		assert.NoError(t, account.IsAccountConfirmed())
	})

	t.Run("should should return error when email its not confirmed", func(t *testing.T) {
		account := &Account{IsConfirmed: false}
		assert.Error(t, account.IsAccountConfirmed())
	})
}

func TestSetAccountData(t *testing.T) {
	t.Run("should success set account data", func(t *testing.T) {
		account := &Account{}
		account.SetAccountData()
		assert.NotEmpty(t, account.CreatedAt)
		assert.NotEmpty(t, account.CreatedAt)
	})
}

func TestSetIsConfirmed(t *testing.T) {
	t.Run("should success set account data", func(t *testing.T) {
		account := &Account{}
		account.SetIsConfirmed()
		assert.True(t, account.IsConfirmed)
	})
}

func TestToBytes(t *testing.T) {
	t.Run("should success parse to bytes", func(t *testing.T) {
		account := &Account{}
		assert.NotEmpty(t, account.ToBytes())
	})
}

func TestToMap(t *testing.T) {
	t.Run("should success parse to map", func(t *testing.T) {
		account := &Account{
			AccountID:   uuid.New(),
			Email:       "test",
			Password:    "test",
			Username:    "test",
			IsConfirmed: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		assert.NotEmpty(t, account.ToMap())
	})
}

func TestToLoginResponse(t *testing.T) {
	t.Run("should success parse to login response", func(t *testing.T) {
		account := &Account{
			AccountID:   uuid.New(),
			Email:       "test",
			Password:    "test",
			Username:    "test",
			IsConfirmed: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		assert.NotEmpty(t, account.ToLoginResponse("test", "test", time.Now()))
	})
}
