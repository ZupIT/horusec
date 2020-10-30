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
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type UpdateVulnType struct {
	Type horusecEnums.VulnerabilityType `json:"type"`
}

func (u *UpdateVulnType) Validate() error {
	return validation.ValidateStruct(u,
		validation.Field(&u.Type, validation.In(u.TypeValues()...)),
	)
}

func (u *UpdateVulnType) ToBytes() []byte {
	content, _ := json.Marshal(u)
	return content
}

func (u UpdateVulnType) TypeValues() []interface{} {
	return []interface{}{
		horusecEnums.FalsePositive,
		horusecEnums.RiskAccepted,
		horusecEnums.Vulnerability,
		horusecEnums.Corrected,
		"",
	}
}
