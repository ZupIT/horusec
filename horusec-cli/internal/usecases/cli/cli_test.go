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

	"github.com/ZupIT/horusec/development-kit/pkg/enums/cli"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should success normalize config", func(t *testing.T) {
		config := &cliConfig.Config{
			JSONOutputFilePath: "./cli",
			ProjectPath:        "./cli",
		}

		assert.NotEmpty(t, useCases.NormalizeConfigs(config))
	})
}

func TestValidateConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should return no errors when valid", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.SetConfigsFromEnvironments()

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})

	t.Run("Should return no errors when is not valid path", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.SetConfigsFromEnvironments()
		config.SetProjectPath("./not-exist-path")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "ProjectPath: project path is invalid: .")
	})

	t.Run("Should return no errors when valid config with ignore", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.SetConfigsFromEnvironments()
		config.SetTypesOfVulnerabilitiesToIgnore("LOW")

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})

	t.Run("Should return error when invalid ignore value", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.SetConfigsFromEnvironments()
		config.SetTypesOfVulnerabilitiesToIgnore("test")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "TypesOfVulnerabilitiesToIgnore: Type of severity not valid:  test."+
			" See severities enable: [NOSEC LOW MEDIUM HIGH AUDIT].", err.Error())
	})

	t.Run("Should return error when invalid json output file is empty", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.SetConfigsFromEnvironments()
		config.SetPrintOutputType(cli.JSON.ToString())
		config.SetJSONOutputFilePath("")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "JSONOutputFilePath: JSON File path is required or is invalid: .json file path is required.",
			err.Error())
	})

	t.Run("Should return error when invalid json output file is invalid", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.SetConfigsFromEnvironments()
		config.SetPrintOutputType(cli.JSON.ToString())
		config.SetJSONOutputFilePath("test.test")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "JSONOutputFilePath: JSON File path is required or is invalid: is not valid .json file.",
			err.Error())
	})

	t.Run("Should return error when invalid workdir", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir("{\"go\": \"test\"}")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
	})
}
