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

package cache

import (
	"testing"
	"time"

	entitiesAccount "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/stretchr/testify/assert"
)

func TestCache_GetTable(t *testing.T) {
	c := &Cache{}
	assert.Equal(t, c.GetTable(), "cache")
}

func TestCache_SetExpiresAt(t *testing.T) {
	c := &Cache{}
	assert.Equal(t, c.ExpiresAt, time.Time{})
	c = c.SetExpiresAt(time.Now())
	assert.NotEqual(t, c.ExpiresAt, time.Time{})
}

func TestCache_SetCreatedAt(t *testing.T) {
	c := &Cache{}
	assert.Equal(t, c.CreatedAt, time.Time{})
	c = c.SetCreatedAt()
	assert.NotEqual(t, c.CreatedAt, time.Time{})
}

func TestToBytes(t *testing.T) {
	c := &Cache{}
	assert.NotEmpty(t, c.ToBytes())
}

func TestConvertValueToEntity(t *testing.T) {
	c := &Cache{}

	account := &entitiesAccount.Account{
		Email: "test@test.com",
	}

	c.Value = account.ToBytes()

	toParse := &entitiesAccount.Account{}

	err := c.ConvertValueToEntity(toParse)
	assert.NoError(t, err)

	assert.NotEmpty(t, toParse.Email)
}
