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

import "github.com/google/uuid"

type Computer struct {
	ID                 uuid.UUID `gorm:"type:uuid;primary_key;"`
	Name               string
	ComputersLanguages []ComputersLanguages `gorm:"foreignKey:ComputerID;references:ID"`
}
type Language struct {
	ID                 uuid.UUID `gorm:"type:uuid;primary_key;"`
	Name               string
	ComputersLanguages []ComputersLanguages `gorm:"foreignkey:ComputerID;association_foreignkey:ID"`
}
type ComputersLanguages struct {
	ID         uuid.UUID `gorm:"type:uuid;primary_key;"`
	ComputerID uuid.UUID `sql:"type:uuid REFERENCES computers(id) ON DELETE CASCADE"`
	LanguageID uuid.UUID `sql:"type:uuid REFERENCES languages(id) ON DELETE CASCADE"`
	Language   Language  `gorm:"foreignKey:LanguageID;references:ID"`
	Computer   Computer  `gorm:"foreignKey:ComputerID;references:ID"`
}
