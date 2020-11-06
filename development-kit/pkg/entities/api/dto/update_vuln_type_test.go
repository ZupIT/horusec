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
	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateUpdateVulnType(t *testing.T) {
	t.Run("should return no error when valid data", func(t *testing.T) {
		updateManagementData := &UpdateVulnType{
			Type: horusecEnum.RiskAccepted,
		}

		err := updateManagementData.Validate()
		assert.NoError(t, err)
	})

	t.Run("should return error invalid type", func(t *testing.T) {
		updateManagementData := &UpdateVulnType{
			Type: "test",
		}

		err := updateManagementData.Validate()
		assert.Error(t, err)
		assert.Equal(t, "type: must be a valid value.", err.Error())
	})
	t.Run("Should not return empty content and parse to bytes", func(t *testing.T) {
		updateManagementData := &UpdateVulnType{
			Type: "test",
		}

		assert.NotEmpty(t, updateManagementData.ToBytes())
	})
}
