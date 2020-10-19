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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/cli"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type UseCases struct{}

type Interface interface {
	ValidateConfigs(config *cliConfig.Config) error
	NormalizeConfigs(configs *cliConfig.Config) *cliConfig.Config
}

func NewCLIUseCases() Interface {
	return &UseCases{}
}
func (au *UseCases) NormalizeConfigs(c *cliConfig.Config) *cliConfig.Config {
	if c.JSONOutputFilePath != "" {
		c.JSONOutputFilePath, _ = filepath.Abs(c.JSONOutputFilePath)
	}
	c.ProjectPath, _ = filepath.Abs(c.ProjectPath)
	c.FilesOrPathsToIgnore = strings.TrimSpace(c.FilesOrPathsToIgnore)
	c.TypesOfVulnerabilitiesToIgnore = strings.TrimSpace(c.TypesOfVulnerabilitiesToIgnore)
	c.IsTimeout = false
	return c
}

//nolint
func (au *UseCases) ValidateConfigs(config *cliConfig.Config) error {
	return validation.ValidateStruct(config,
		validation.Field(&config.HorusecAPIUri, validation.Required),
		validation.Field(&config.TimeoutInSecondsRequest, validation.Required, validation.Min(10)),
		validation.Field(&config.TimeoutInSecondsAnalysis, validation.Required, validation.Min(10)),
		validation.Field(&config.MonitorRetryInSeconds, validation.Required, validation.Min(10)),
		validation.Field(&config.RepositoryAuthorization, validation.Required, is.UUID),
		validation.Field(&config.PrintOutputType, validation.Required, au.validationOutputTypes()),
		validation.Field(&config.JSONOutputFilePath, validation.By(au.checkAndValidateJSONOutputFilePath(config))),
		validation.Field(&config.TypesOfVulnerabilitiesToIgnore, validation.By(au.validationSeverities)),
		validation.Field(&config.FilesOrPathsToIgnore),
		validation.Field(&config.ReturnErrorIfFoundVulnerability, validation.In(true, false)),
		validation.Field(&config.ProjectPath, validation.By(au.validateIfIsValidPath(config.ProjectPath))),
		validation.Field(&config.WorkDir, validation.By(au.validateWorkDir(config.WorkDir, config.ProjectPath))),
		validation.Field(&config.CertInsecureSkipVerify, validation.In(true, false)),
		validation.Field(&config.CertPath, validation.By(au.validateCertPath(config.CertPath))),
		validation.Field(&config.FalsePositiveHashes, validation.By(au.checkIfExistsDuplicatedFalsePositiveHashes(config))),
		validation.Field(&config.RiskAcceptHashes, validation.By(au.checkIfExistsDuplicatedRiskAcceptHashes(config))),
	)
}

func (au *UseCases) checkIfExistsDuplicatedFalsePositiveHashes(config *cliConfig.Config) func(value interface{}) error {
	return func(value interface{}) error {
		for _, falsePositive := range config.GetFalsePositiveHashesList() {
			for _, riskAccept := range config.GetRiskAcceptHashesList() {
				if falsePositive == riskAccept {
					return errors.New(messages.MsgErrorFalsePositiveNotValid + falsePositive)
				}
			}
		}
		return nil
	}
}

func (au *UseCases) checkIfExistsDuplicatedRiskAcceptHashes(config *cliConfig.Config) func(value interface{}) error {
	return func(value interface{}) error {
		for _, riskAccept := range config.GetRiskAcceptHashesList() {
			for _, falsePositive := range config.GetFalsePositiveHashesList() {
				if riskAccept == falsePositive {
					return errors.New(messages.MsgErrorRiskAcceptNotValid + riskAccept)
				}
			}
		}
		return nil
	}
}

func (au *UseCases) checkAndValidateJSONOutputFilePath(config *cliConfig.Config) func(value interface{}) error {
	return func(value interface{}) error {
		if config.PrintOutputType == cli.JSON.ToString() || config.PrintOutputType == cli.SonarQube.ToString() {
			if err := au.validateJSONOutputFilePath(config); err != nil {
				return err
			}
		}
		return nil
	}
}

func (au *UseCases) validateJSONOutputFilePath(config *cliConfig.Config) error {
	if len(config.JSONOutputFilePath) < 5 {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + ".json file path is required")
	}
	totalChars := len(config.JSONOutputFilePath) - 1
	ext := config.JSONOutputFilePath[totalChars-4:]
	if ext != ".json" {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + "is not valid .json file")
	}

	if output, err := filepath.Abs(config.JSONOutputFilePath); err != nil || output == "" {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + err.Error())
	}
	return nil
}

func (au *UseCases) validationOutputTypes() validation.InRule {
	return validation.In(
		cli.JSON.ToString(),
		cli.SonarQube.ToString(),
		cli.Text.ToString(),
	)
}

func (au *UseCases) validationSeverities(value interface{}) error {
	if value != nil {
		if value.(string) == "" {
			return nil
		}
		for _, item := range strings.Split(value.(string), ",") {
			if !au.checkIfExistItemInSliceOfSeverity(strings.TrimSpace(item)) {
				return fmt.Errorf("%s %s. See severities enable: %v",
					messages.MsgErrorSeverityNotValid, item, au.sliceSeverityEnable())
			}
		}
	}
	return nil
}

func (au *UseCases) checkIfExistItemInSliceOfSeverity(item string) bool {
	for _, severityName := range au.sliceSeverityEnable() {
		if severityName.ToString() == item {
			return true
		}
	}
	return false
}

func (au *UseCases) sliceSeverityEnable() []severity.Severity {
	return []severity.Severity{
		severity.NoSec,
		severity.Low,
		severity.Medium,
		severity.High,
		severity.Audit,
	}
}

func (au *UseCases) validateIfIsValidPath(dir string) func(value interface{}) error {
	return func(value interface{}) error {
		if _, errStat := os.Stat(dir); errStat != nil || dir == "" {
			return fmt.Errorf(messages.MsgErrorProjectPathNotValid)
		}
		return nil
	}
}

func (au *UseCases) validateCertPath(dir string) func(value interface{}) error {
	if dir == "" {
		return func(value interface{}) error {
			return nil
		}
	}

	return au.validateIfIsValidPath(dir)
}

func (au *UseCases) validateWorkDir(workDir *workdir.WorkDir, projectPath string) func(value interface{}) error {
	return func(value interface{}) error {
		for _, pathsByLanguage := range workDir.Map() {
			for _, projectSubPath := range pathsByLanguage {
				err := au.validateIfExistPathInProjectToWorkDir(projectPath, projectSubPath)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func (au *UseCases) validateIfExistPathInProjectToWorkDir(projectPath, internalPath string) error {
	projectPathAbs, _ := filepath.Abs(projectPath)
	if internalPath != "" {
		_, err := os.Stat(projectPathAbs + "/" + internalPath)
		return err
	}
	return nil
}
