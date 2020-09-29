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

package entities

import (
	"encoding/json"
	"github.com/google/uuid"
	"time"
)

type Test struct {
	ID        uuid.UUID `json:"id" gorm:"primary_key; Column:id"`
	CreatedAt time.Time `json:"createdAt" gorm:"Column:createdAt"`
	UpdatedAt time.Time `json:"updatedAt" gorm:"Column:updatedAt"`
	Name      string    `json:"name" gorm:"Column:name"`
}

func (t *Test) TableName() string {
	return "test"
}

func (t *Test) ToBytes() []byte {
	bytes, _ := json.Marshal(t)
	return bytes
}
