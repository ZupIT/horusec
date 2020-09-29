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

package cli

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should success normalize config", func(t *testing.T) {
		configs := &config.Config{
			ProjectPath:    "./cli",
			OutputFilePath: "./output.json",
		}

		configs = useCases.NormalizeConfigs(configs)
		assert.NotEqual(t, configs.GetProjectPath(), "./cli")
		assert.NotEqual(t, configs.GetProjectPath(), "")
		assert.NotEqual(t, configs.GetOutputFilePath(), "./output.json")
		assert.NotEqual(t, configs.GetOutputFilePath(), "")
	})
}

func TestValidateConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should return no errors when valid", func(t *testing.T) {
		configs := config.NewConfig()

		err := useCases.ValidateConfigs(configs)
		assert.NoError(t, err)
	})

	t.Run("Should return errors when is not valid project path", func(t *testing.T) {
		configs := config.NewConfig()
		configs.SetProjectPath("./ not exists path")

		err := useCases.ValidateConfigs(configs)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "ProjectPath: project path is invalid: .")
	})
	t.Run("Should return errors when is not valid output file path", func(t *testing.T) {
		configs := config.NewConfig()
		configs.SetOutputFilePath("./ not exists file")

		err := useCases.ValidateConfigs(configs)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "OutputFilePath: output file path is invalid: is not valid .json file.")
	})
}
