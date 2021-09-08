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

	"github.com/ZupIT/horusec/internal/enums/outputtype"

	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
)

func TestValidateConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should return no errors when valid", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
	t.Run("Should return no errors when is not valid path", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.ProjectPath = "./not-exist-path"

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "projectPath: project path is invalid: .")
	})
	t.Run("Should return no errors when valid config with ignore", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.SeveritiesToIgnore = []string{"LOW"}

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
	t.Run("Should return error when invalid ignore value", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.SeveritiesToIgnore = []string{"test"}

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "severitiesToIgnore: Type of severity not valid:  test. "+
			"See severities enable: [CRITICAL HIGH MEDIUM LOW UNKNOWN INFO].", err.Error())
	})
	t.Run("Should return error when invalid json output file is empty", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.PrintOutputType = outputtype.JSON
		config.JSONOutputFilePath = ""

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "jSONOutputFilePath: Output File path is required or is invalid: not valid file of type .json.",
			err.Error())
	})
	t.Run("Should return error when invalid json output file is invalid", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.PrintOutputType = outputtype.JSON
		config.JSONOutputFilePath = "test.test"

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "jSONOutputFilePath: Output File path is required or is invalid: not valid file of type .json.",
			err.Error())
	})
	t.Run("Should return error when the text output file is invalid", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.MergeFromEnvironmentVariables()
		config.PrintOutputType = outputtype.Text
		config.JSONOutputFilePath = "test.test"

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.EqualError(t, err, "jSONOutputFilePath: Output File path is required or is invalid: not valid file of type .txt.")
	})
	t.Run("Should not return error when the text output file is valid", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{}
		config.MergeFromEnvironmentVariables()
		config.PrintOutputType = (outputtype.Text)
		config.JSONOutputFilePath = "test.txt"

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
	t.Run("Should return error when invalid workdir", func(t *testing.T) {
		config := &cliConfig.Config{}

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
	})
	t.Run("Should return success because exists path in workdir", func(t *testing.T) {
		config := cliConfig.New()
		config.WorkDir = &workdir.WorkDir{
			Go:         []string{"./"},
			CSharp:     []string{""},
			Ruby:       []string{},
			Python:     []string{},
			Java:       []string{},
			Kotlin:     []string{},
			JavaScript: []string{},
			Leaks:      []string{},
			HCL:        []string{},
		}

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
	t.Run("Should return error because not exists path in workdir", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{
			Go:         []string{"NOT EXISTS PATH"},
			CSharp:     []string{},
			Ruby:       []string{},
			Python:     []string{},
			Java:       []string{},
			Kotlin:     []string{},
			JavaScript: []string{},
			Leaks:      []string{},
			HCL:        []string{},
		}

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "workDir: stat ")
		assert.Contains(t, err.Error(), "internal/usecases/cli/NOT EXISTS PATH: no such file or directory.")
	})
	t.Run("Should return error because cert path is not valid", func(t *testing.T) {
		config := cliConfig.New()
		config.CertPath = "INVALID PATH"

		err := useCases.ValidateConfigs(config)
		assert.Error(t, err)
		assert.Equal(t, "certPath: project path is invalid: .",
			err.Error())
	})
	t.Run("Should return error when is duplicated false positive and risk accepted", func(t *testing.T) {
		hash := "1e836029-4e90-4151-bb4a-d86ef47f96b6"
		config := cliConfig.New()
		config.FalsePositiveHashes = []string{hash}
		config.RiskAcceptHashes = []string{hash}

		err := useCases.ValidateConfigs(config)
		assert.Equal(t, "falsePositiveHashes: False positive is not valid because is duplicated in risk accept: 1e836029-4e90-4151-bb4a-d86ef47f96b6; riskAcceptHashes: Risk Accept is not valid because is duplicated in false positive: 1e836029-4e90-4151-bb4a-d86ef47f96b6.",
			err.Error())
	})
	t.Run("Should return not error when validate false positive and risk accepted", func(t *testing.T) {
		config := cliConfig.New()
		config.FalsePositiveHashes = []string{"1e836029-4e90-4151-bb4a-d86ef47f96b6"}
		config.RiskAcceptHashes = []string{"c0d0c85c-8597-49c4-b4fa-b92ecad2a991"}

		err := useCases.ValidateConfigs(config)
		assert.NoError(t, err)
	})
}
