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
	"errors"
	"os"
	"testing"

	"github.com/ZupIT/horusec/internal/enums/outputtype"
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
)

func TestValidateConfigs(t *testing.T) {
	useCases := NewCLIUseCases()

	t.Run("Should return no errors when valid", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		err := useCases.ValidateConfig(cfg)
		assert.NoError(t, err)
	})
	t.Run("Should return no errors when is not valid path", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.ProjectPath = "./not-exist-path"

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
		assert.Equal(t, "project_path: invalid path: .", err.Error())
	})
	t.Run("Should return no errors when valid config with ignore", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.SeveritiesToIgnore = []string{"LOW"}

		err := useCases.ValidateConfig(cfg)
		assert.NoError(t, err)
	})
	t.Run("Should return error when invalid ignore value", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.SeveritiesToIgnore = []string{"test"}

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
		expected := "severities_to_ignore: Type of severity not valid:  test. See severities enable: [CRITICAL HIGH MEDIUM LOW UNKNOWN INFO]."
		assert.Equal(t, expected, err.Error())
	})
	t.Run("Should return error when invalid json output file is empty", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.PrintOutputType = outputtype.JSON
		cfg.JSONOutputFilePath = ""

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
		assert.Equal(t, "json_output_file_path: Output File path is required or is invalid: not valid file of type .json.",
			err.Error())
	})
	t.Run("Should return error when invalid json output file is invalid", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.PrintOutputType = outputtype.JSON
		cfg.JSONOutputFilePath = "test.test"

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
		assert.Equal(t, "json_output_file_path: Output File path is required or is invalid: not valid file of type .json.",
			err.Error())
	})
	t.Run("Should return error when the text output file is invalid", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.LoadFromEnvironmentVariables()
		cfg.PrintOutputType = outputtype.Text
		cfg.JSONOutputFilePath = "test.test"

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
		assert.EqualError(t, err, "json_output_file_path: Output File path is required or is invalid: not valid file of type .txt.")
	})
	t.Run("Should not return error when the text output file is valid", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}
		cfg.LoadFromEnvironmentVariables()
		cfg.PrintOutputType = (outputtype.Text)
		cfg.JSONOutputFilePath = "test.txt"

		err := useCases.ValidateConfig(cfg)
		assert.NoError(t, err)
	})
	t.Run("Should return error when invalid workdir", func(t *testing.T) {
		cfg := &config.Config{}

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
	})
	t.Run("Should return success because exists path in workdir", func(t *testing.T) {
		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{
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

		err := useCases.ValidateConfig(cfg)
		assert.NoError(t, err)
	})
	t.Run("Should return error because not exists path in workdir", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				WorkDir: &workdir.WorkDir{
					Go:         []string{"NOT EXISTS PATH"},
					CSharp:     []string{},
					Ruby:       []string{},
					Python:     []string{},
					Java:       []string{},
					Kotlin:     []string{},
					JavaScript: []string{},
					Leaks:      []string{},
					HCL:        []string{},
				},
			},
		}

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)

		var vErrors validation.Errors
		assert.True(t, errors.As(err, &vErrors), "Expected that error should be validation.Errors")

		workDirErr, exists := vErrors["work_dir"]
		assert.True(t, exists, "Expected error from work dir config")

		assert.ErrorIs(t, workDirErr, os.ErrNotExist)
	})
	t.Run("Should return error because cert path is not valid", func(t *testing.T) {
		cfg := config.New()
		cfg.CertPath = "INVALID PATH"

		err := useCases.ValidateConfig(cfg)
		assert.Error(t, err)
		assert.Equal(t, "cert_path: invalid path: .", err.Error())
	})
	t.Run("Should return error when is duplicated false positive and risk accepted", func(t *testing.T) {
		hash := "1e836029-4e90-4151-bb4a-d86ef47f96b6"
		cfg := config.New()
		cfg.FalsePositiveHashes = []string{hash}
		cfg.RiskAcceptHashes = []string{hash}

		err := useCases.ValidateConfig(cfg)
		expected := "false_positive_hashes: False positive is not valid because is duplicated in risk accept: 1e836029-4e90-4151-bb4a-d86ef47f96b6; risk_accept_hashes: Risk Accept is not valid because is duplicated in false positive: 1e836029-4e90-4151-bb4a-d86ef47f96b6."
		assert.Equal(t, expected, err.Error())
	})
	t.Run("Should return not error when validate false positive and risk accepted", func(t *testing.T) {
		cfg := config.New()
		cfg.FalsePositiveHashes = []string{"1e836029-4e90-4151-bb4a-d86ef47f96b6"}
		cfg.RiskAcceptHashes = []string{"c0d0c85c-8597-49c4-b4fa-b92ecad2a991"}

		err := useCases.ValidateConfig(cfg)
		assert.NoError(t, err)
	})
}
