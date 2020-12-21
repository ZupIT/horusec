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

func TestValidateConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should return no errors when valid", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.NewConfigsFromEnvironments()

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})

	t.Run("Should return no errors when is not valid path", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.NewConfigsFromEnvironments()
		config.SetProjectPath("./not-exist-path")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "projectPath: project path is invalid: .")
	})

	t.Run("Should return no errors when valid config with ignore", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.NewConfigsFromEnvironments()
		config.SetSeveritiesToIgnore([]string{"LOW"})

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})

	t.Run("Should return error when invalid ignore value", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.NewConfigsFromEnvironments()
		config.SetSeveritiesToIgnore([]string{"test"})

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "severitiesToIgnore: Type of severity not valid:  test. "+
			"See severities enable: [NOSEC LOW MEDIUM HIGH AUDIT INFO].", err.Error())
	})

	t.Run("Should return error when invalid json output file is empty", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.NewConfigsFromEnvironments()
		config.SetPrintOutputType(cli.JSON.ToString())
		config.SetJSONOutputFilePath("")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "jSONOutputFilePath: JSON File path is required or is invalid: .json file path is required.",
			err.Error())
	})

	t.Run("Should return error when invalid json output file is invalid", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.NewConfigsFromEnvironments()
		config.SetPrintOutputType(cli.JSON.ToString())
		config.SetJSONOutputFilePath("test.test")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "jSONOutputFilePath: JSON File path is required or is invalid: is not valid .json file.",
			err.Error())
	})
	t.Run("Should return error when invalid workdir", func(t *testing.T) {
		config := &cliConfig.Config{}

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
	})
	t.Run("Should return success because exists path in workdir", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{
			Go:         []string{"./"},
			CSharp:     []string{""},
			Ruby:       []string{},
			Python:     []string{},
			Java:       []string{},
			Kotlin:     []string{},
			JavaScript: []string{},
			Leaks:      []string{},
			HCL:        []string{},
		})
		config.NewConfigsFromEnvironments()

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
	t.Run("Should return error because not exists path in workdir", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{
			Go:         []string{"NOT EXISTS PATH"},
			CSharp:     []string{},
			Ruby:       []string{},
			Python:     []string{},
			Java:       []string{},
			Kotlin:     []string{},
			JavaScript: []string{},
			Leaks:      []string{},
			HCL:        []string{},
		})
		config.NewConfigsFromEnvironments()

		err := useCases.ValidateConfigs(config)
		assert.Contains(t, err.Error(), "workDir: stat ")
		assert.Contains(t, err.Error(), "horusec-cli/internal/usecases/cli/NOT EXISTS PATH: no such file or directory.")
	})
	t.Run("Should return error because cert path is not valid", func(t *testing.T) {
		config := cliConfig.NewConfig()
		config.SetCertPath("INVALID PATH")

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "certPath: project path is invalid: .",
			err.Error())
	})
	t.Run("Should return error when is duplicated false positive and risk accepted", func(t *testing.T) {
		hash := "1e836029-4e90-4151-bb4a-d86ef47f96b6"
		config := cliConfig.NewConfig()
		config.SetFalsePositiveHashes([]string{hash})
		config.SetRiskAcceptHashes([]string{hash})

		err := useCases.ValidateConfigs(config)
		assert.Equal(t, "falsePositiveHashes: False positive is not valid because is duplicated in risk accept: 1e836029-4e90-4151-bb4a-d86ef47f96b6; riskAcceptHashes: Risk Accept is not valid because is duplicated in false positive: 1e836029-4e90-4151-bb4a-d86ef47f96b6.",
			err.Error())
	})
	t.Run("Should return not error when validate false positive and risk accepted", func(t *testing.T) {
		config := cliConfig.NewConfig()
		config.SetFalsePositiveHashes([]string{"1e836029-4e90-4151-bb4a-d86ef47f96b6"})
		config.SetRiskAcceptHashes([]string{"c0d0c85c-8597-49c4-b4fa-b92ecad2a991"})

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
}
