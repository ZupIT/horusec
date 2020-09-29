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
	"encoding/json"
	"time"
)

type Cache struct {
	Key       string    `json:"key" gorm:"primary_key"`
	Value     []byte    `json:"value" gorm:"type:text"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

func (c *Cache) SetCreatedAt() *Cache {
	c.CreatedAt = time.Now()
	return c
}

func (c *Cache) SetExpiresAt(expiresAt time.Time) *Cache {
	c.ExpiresAt = expiresAt
	return c
}

func (c *Cache) GetTable() string {
	return "cache"
}

func (c *Cache) ToBytes() []byte {
	bytes, _ := json.Marshal(c)
	return bytes
}

func (c *Cache) ConvertValueToEntity(entity interface{}) error {
	return json.Unmarshal(c.Value, entity)
}
