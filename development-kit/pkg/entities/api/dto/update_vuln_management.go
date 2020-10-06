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
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type UpdateVulnManagementData struct {
	Status horusecEnums.AnalysisVulnerabilitiesStatus `json:"status"`
	Type   horusecEnums.AnalysisVulnerabilitiesType   `json:"type"`
}

func (u *UpdateVulnManagementData) Validate() error {
	return validation.ValidateStruct(u,
		validation.Field(&u.Status, validation.In(u.StatusValues()...)),
		validation.Field(&u.Type, validation.In(u.TypeValues()...)),
	)
}

func (u UpdateVulnManagementData) StatusValues() []interface{} {
	return []interface{}{
		horusecEnums.Approved,
		horusecEnums.Reproved,
		horusecEnums.NoAction,
		"",
	}
}

func (u UpdateVulnManagementData) TypeValues() []interface{} {
	return []interface{}{
		horusecEnums.FalsePositive,
		horusecEnums.RiskAccepted,
		horusecEnums.Vulnerability,
		"",
	}
}
