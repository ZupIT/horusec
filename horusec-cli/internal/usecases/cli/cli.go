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

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/enums/outputtype"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type ConfigToValidate struct {
	horusecAPIUri                   string
	timeoutInSecondsRequest         int64
	timeoutInSecondsAnalysis        int64
	monitorRetryInSeconds           int64
	repositoryAuthorization         string
	printOutputType                 string
	jSONOutputFilePath              string
	severitiesToIgnore              []string
	filesOrPathsToIgnore            []string
	returnErrorIfFoundVulnerability bool
	projectPath                     string
	workDir                         *workdir.WorkDir
	certInsecureSkipVerify          bool
	certPath                        string
	falsePositiveHashes             []string
	riskAcceptHashes                []string
}

type UseCases struct{}

type Interface interface {
	ValidateConfigs(config cliConfig.IConfig) error
}

func NewCLIUseCases() Interface {
	return &UseCases{}
}

//nolint
func (au *UseCases) ValidateConfigs(config cliConfig.IConfig) error {
	c := au.parseConfigsToConfigValidate(config)
	return validation.ValidateStruct(&c,
		validation.Field(&c.horusecAPIUri, validation.Required),
		validation.Field(&c.timeoutInSecondsRequest, validation.Required, validation.Min(10)),
		validation.Field(&c.timeoutInSecondsAnalysis, validation.Required, validation.Min(10)),
		validation.Field(&c.monitorRetryInSeconds, validation.Required, validation.Min(10)),
		validation.Field(&c.repositoryAuthorization, validation.Required, is.UUID),
		validation.Field(&c.printOutputType, validation.Required, au.validationOutputTypes()),
		validation.Field(&c.jSONOutputFilePath, validation.By(au.checkAndValidateJSONOutputFilePath(config))),
		validation.Field(&c.severitiesToIgnore, validation.By(au.validationSeverities(config))),
		validation.Field(&c.filesOrPathsToIgnore),
		validation.Field(&c.returnErrorIfFoundVulnerability, validation.In(true, false)),
		validation.Field(&c.projectPath, validation.By(au.validateIfIsValidPath(config.GetProjectPath()))),
		validation.Field(&c.workDir, validation.By(au.validateWorkDir(config.GetWorkDir(), config.GetProjectPath()))),
		validation.Field(&c.certInsecureSkipVerify, validation.In(true, false)),
		validation.Field(&c.certPath, validation.By(au.validateCertPath(config.GetCertPath()))),
		validation.Field(&c.falsePositiveHashes, validation.By(au.checkIfExistsDuplicatedFalsePositiveHashes(config))),
		validation.Field(&c.riskAcceptHashes, validation.By(au.checkIfExistsDuplicatedRiskAcceptHashes(config))),
	)
}

//nolint:funlen parse struct is necessary > 15 lines
func (au *UseCases) parseConfigsToConfigValidate(config cliConfig.IConfig) ConfigToValidate {
	return ConfigToValidate{
		horusecAPIUri:                   config.GetHorusecAPIUri(),
		timeoutInSecondsRequest:         config.GetTimeoutInSecondsRequest(),
		timeoutInSecondsAnalysis:        config.GetTimeoutInSecondsAnalysis(),
		monitorRetryInSeconds:           config.GetMonitorRetryInSeconds(),
		repositoryAuthorization:         config.GetRepositoryAuthorization(),
		printOutputType:                 config.GetPrintOutputType(),
		jSONOutputFilePath:              config.GetJSONOutputFilePath(),
		severitiesToIgnore:              config.GetSeveritiesToIgnore(),
		filesOrPathsToIgnore:            config.GetFilesOrPathsToIgnore(),
		returnErrorIfFoundVulnerability: config.GetReturnErrorIfFoundVulnerability(),
		projectPath:                     config.GetProjectPath(),
		workDir:                         config.GetWorkDir(),
		certInsecureSkipVerify:          config.GetCertInsecureSkipVerify(),
		certPath:                        config.GetCertPath(),
		falsePositiveHashes:             config.GetFalsePositiveHashes(),
		riskAcceptHashes:                config.GetRiskAcceptHashes(),
	}
}

func (au *UseCases) checkIfExistsDuplicatedFalsePositiveHashes(config cliConfig.IConfig) func(value interface{}) error {
	return func(value interface{}) error {
		for _, falsePositive := range config.GetFalsePositiveHashes() {
			for _, riskAccept := range config.GetRiskAcceptHashes() {
				if falsePositive == riskAccept {
					return errors.New(messages.MsgErrorFalsePositiveNotValid + falsePositive)
				}
			}
		}
		return nil
	}
}

func (au *UseCases) checkIfExistsDuplicatedRiskAcceptHashes(config cliConfig.IConfig) func(value interface{}) error {
	return func(value interface{}) error {
		for _, riskAccept := range config.GetRiskAcceptHashes() {
			for _, falsePositive := range config.GetFalsePositiveHashes() {
				if riskAccept == falsePositive {
					return errors.New(messages.MsgErrorRiskAcceptNotValid + riskAccept)
				}
			}
		}
		return nil
	}
}

func (au *UseCases) checkAndValidateJSONOutputFilePath(config cliConfig.IConfig) func(value interface{}) error {
	return func(value interface{}) error {
		if config.GetPrintOutputType() == outputtype.JSON.ToString() ||
			config.GetPrintOutputType() == outputtype.SonarQube.ToString() {
			if err := au.validateJSONOutputFilePath(config); err != nil {
				return err
			}
		}
		return nil
	}
}

func (au *UseCases) validateJSONOutputFilePath(config cliConfig.IConfig) error {
	if len(config.GetJSONOutputFilePath()) < 5 {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + ".json file path is required")
	}
	totalChars := len(config.GetJSONOutputFilePath()) - 1
	ext := config.GetJSONOutputFilePath()[totalChars-4:]
	if ext != ".json" {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + "is not valid .json file")
	}

	if output, err := filepath.Abs(config.GetJSONOutputFilePath()); err != nil || output == "" {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + err.Error())
	}
	return nil
}

func (au *UseCases) validationOutputTypes() validation.InRule {
	return validation.In(
		outputtype.JSON.ToString(),
		outputtype.SonarQube.ToString(),
		outputtype.Text.ToString(),
	)
}

func (au *UseCases) validationSeverities(config cliConfig.IConfig) func(value interface{}) error {
	return func(value interface{}) error {
		for _, item := range config.GetSeveritiesToIgnore() {
			if !au.checkIfExistItemInSliceOfSeverity(strings.TrimSpace(item)) {
				return fmt.Errorf("%s %s. See severities enable: %v",
					messages.MsgErrorSeverityNotValid, item, au.sliceSeverityEnable())
			}
		}
		return nil
	}
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
		severity.Critical,
		severity.High,
		severity.Medium,
		severity.Low,
		severity.Unknown,
		severity.Info,
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
		if workDir == nil {
			return errors.New(messages.MsgErrorParseStringToWorkDir)
		}
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
