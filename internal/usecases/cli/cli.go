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
	"path"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/enums/outputtype"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/git"
)

type UseCases struct{}

func NewCLIUseCases() *UseCases {
	return &UseCases{}
}

//nolint
func (au *UseCases) ValidateConfig(cfg *config.Config) error {
	return validation.ValidateStruct(cfg,
		validation.Field(&cfg.HorusecAPIUri, validation.Required),
		validation.Field(&cfg.TimeoutInSecondsRequest, validation.Required, validation.Min(10)),
		validation.Field(&cfg.TimeoutInSecondsAnalysis, validation.Required, validation.Min(10)),
		validation.Field(&cfg.MonitorRetryInSeconds, validation.Required, validation.Min(10)),
		validation.Field(&cfg.RepositoryAuthorization, validation.Required, is.UUID),
		validation.Field(&cfg.PrintOutputType, au.validationOutputTypes()),
		validation.Field(&cfg.JSONOutputFilePath, validation.By(au.checkAndValidateJSONOutputFilePath(cfg))),
		validation.Field(&cfg.SeveritiesToIgnore, validation.By(au.validationSeverities(cfg))),
		validation.Field(&cfg.FilesOrPathsToIgnore),
		validation.Field(&cfg.ReturnErrorIfFoundVulnerability, validation.In(true, false)),
		validation.Field(&cfg.ProjectPath, validation.By(au.validateIfIsValidPath(cfg.ProjectPath))),
		validation.Field(&cfg.WorkDir, validation.By(au.validateWorkDir(cfg.WorkDir, cfg.ProjectPath))),
		validation.Field(&cfg.CertInsecureSkipVerify, validation.In(true, false)),
		validation.Field(&cfg.CertPath, validation.By(au.validateCertPath(cfg.CertPath))),
		validation.Field(&cfg.FalsePositiveHashes, validation.By(au.checkIfExistsDuplicatedFalsePositiveHashes(cfg))),
		validation.Field(&cfg.RiskAcceptHashes, validation.By(au.checkIfExistsDuplicatedRiskAcceptHashes(cfg))),
		validation.Field(&cfg.ShowVulnerabilitiesTypes, validation.By(au.checkIfIsValidVulnerabilitiesTypes(cfg))),
		validation.Field(&cfg.EnableCommitAuthor, validation.By(au.checkGitDepthClone(cfg))),
	)
}

func (au *UseCases) checkGitDepthClone(cfg *config.Config) validation.RuleFunc {
	return func(_ interface{}) error {
		if (cfg.EnableCommitAuthor || cfg.EnableGitHistoryAnalysis) && git.RepositoryIsShallow(cfg) {
			logger.LogWarn(messages.MsgWarnGitRepositoryIsNotFullCloned)
		}
		return nil
	}
}

func (au *UseCases) checkIfExistsDuplicatedFalsePositiveHashes(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for _, falsePositive := range cfg.FalsePositiveHashes {
			for _, riskAccept := range cfg.RiskAcceptHashes {
				riskAccept = strings.TrimSpace(riskAccept)
				if falsePositive == riskAccept {
					return errors.New(messages.MsgErrorFalsePositiveNotValid + falsePositive)
				}
			}
		}
		return nil
	}
}

func (au *UseCases) checkIfExistsDuplicatedRiskAcceptHashes(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for _, riskAccept := range cfg.RiskAcceptHashes {
			for _, falsePositive := range cfg.FalsePositiveHashes {
				falsePositive = strings.TrimSpace(falsePositive)
				if riskAccept == falsePositive {
					return errors.New(messages.MsgErrorRiskAcceptNotValid + riskAccept)
				}
			}
		}
		return nil
	}
}

func (au *UseCases) checkAndValidateJSONOutputFilePath(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		switch cfg.PrintOutputType {
		case outputtype.JSON, outputtype.SonarQube:
			return au.validateFilePathAndExtension(cfg, ".json")
		case outputtype.Text:
			return au.validateTextOutputFilePath(cfg)
		}
		return nil
	}
}

func (au *UseCases) validateTextOutputFilePath(cfg *config.Config) error {
	if cfg.JSONOutputFilePath == "" {
		return nil
	}
	return au.validateFilePathAndExtension(cfg, ".txt")
}

func (au *UseCases) validateFilePathAndExtension(cfg *config.Config, extension string) error {
	if filepath.Ext(cfg.JSONOutputFilePath) != extension {
		return fmt.Errorf("%snot valid file of type %s", messages.MsgErrorJSONOutputFilePathNotValid, extension)
	}
	if output, err := filepath.Abs(cfg.JSONOutputFilePath); err != nil || output == "" {
		return errors.New(messages.MsgErrorJSONOutputFilePathNotValid + err.Error())
	}
	return nil
}

func (au *UseCases) validationOutputTypes() validation.InRule {
	return validation.In(
		outputtype.JSON,
		outputtype.SonarQube,
		outputtype.Text,
	)
}

func (au *UseCases) validationSeverities(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for _, item := range cfg.SeveritiesToIgnore {
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

func (au *UseCases) sliceSeverityEnable() []severities.Severity {
	return []severities.Severity{
		severities.Critical,
		severities.High,
		severities.Medium,
		severities.Low,
		severities.Unknown,
		severities.Info,
	}
}

func (au *UseCases) validateIfIsValidPath(dir string) validation.RuleFunc {
	return func(value interface{}) error {
		if _, errStat := os.Stat(dir); errStat != nil || dir == "" {
			return fmt.Errorf(messages.MsgErrorPathNotValid)
		}
		return nil
	}
}

func (au *UseCases) validateCertPath(dir string) validation.RuleFunc {
	if dir == "" {
		return func(value interface{}) error {
			return nil
		}
	}

	return au.validateIfIsValidPath(dir)
}

func (au *UseCases) validateWorkDir(workDir *workdir.WorkDir, projectPath string) validation.RuleFunc {
	return func(value interface{}) error {
		if workDir == nil {
			return errors.New(messages.MsgErrorParseStringToWorkDir)
		}
		for _, pathsByLanguage := range workDir.LanguagePaths() {
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
		if _, err := os.Stat(path.Join(projectPathAbs, internalPath)); err != nil {
			if os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func (au *UseCases) checkIfIsValidVulnerabilitiesTypes(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for _, vulnType := range cfg.ShowVulnerabilitiesTypes {
			if !au.isVulnerabilityValid(strings.TrimSpace(vulnType)) {
				return fmt.Errorf("%s %s", messages.MsgVulnerabilityTypeToShowInvalid, vulnType)
			}
		}
		return nil
	}
}

func (au *UseCases) isVulnerabilityValid(vulnType string) bool {
	for _, valid := range vulnerability.Values() {
		if strings.EqualFold(valid.ToString(), vulnType) {
			return true
		}
	}
	return false
}
