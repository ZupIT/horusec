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

package json

import (
	"testing"

	"github.com/stretchr/testify/assert"

	horusecEntities "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
)

func TestConvertInterfaceToOutput(t *testing.T) {
	t.Run("should success parse with no errors", func(t *testing.T) {
		analysis := horusecEntities.Analysis{}

		err := ConvertInterfaceToOutput(analysis, &analysis)
		assert.NoError(t, err)
	})

	t.Run("should return error when parsing wrong interface", func(t *testing.T) {
		analysis := horusecEntities.Analysis{}

		err := ConvertInterfaceToOutput("test", &analysis)
		assert.Error(t, err)
	})

	t.Run("should return error while marshall unsupported type", func(t *testing.T) {
		analysis := horusecEntities.Analysis{}

		err := ConvertInterfaceToOutput(make(chan int), &analysis)
		assert.Error(t, err)
	})
}

func TestConvertStringToOutput(t *testing.T) {
	t.Run("should success parse string to struct", func(t *testing.T) {
		analysis := horusecEntities.Analysis{}

		err := ConvertStringToOutput(analysis.ToString(), &analysis)
		assert.NoError(t, err)
	})
}

func TestConvertInterfaceToString(t *testing.T) {
	t.Run("should success parse interface to string", func(t *testing.T) {
		analysis := horusecEntities.Analysis{}

		result, err := ConvertInterfaceToString(analysis)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})
}

func TestConvertInterfaceToMapString(t *testing.T) {
	t.Run("should success parse interface to map string", func(t *testing.T) {
		analysis := horusecEntities.Analysis{}

		result, err := ConvertInterfaceToMapString(analysis)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})
}
