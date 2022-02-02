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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/enums/outputtype"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/git"
)

// ValidateConfig validate if the fields from config has valid values.
//
// nolint
func ValidateConfig(cfg *config.Config) error {
	return validation.ValidateStruct(cfg,
		validation.Field(&cfg.HorusecAPIUri, validation.Required, validation.By(checkIfIsURL(cfg.HorusecAPIUri))),
		validation.Field(&cfg.TimeoutInSecondsRequest, validation.Required, validation.Min(10)),
		validation.Field(&cfg.TimeoutInSecondsAnalysis, validation.Required, validation.Min(10)),
		validation.Field(&cfg.MonitorRetryInSeconds, validation.Required, validation.Min(10)),
		validation.Field(&cfg.RepositoryAuthorization, validation.Required, is.UUID),
		validation.Field(&cfg.PrintOutputType, validation.In(outputtype.JSON, outputtype.Sarif, outputtype.SonarQube, outputtype.Text)),
		validation.Field(&cfg.JSONOutputFilePath, validation.By(validateJSONOutputFilePath(cfg))),
		validation.Field(&cfg.SeveritiesToIgnore, validation.By(validationSeverities(cfg))),
		validation.Field(&cfg.ReturnErrorIfFoundVulnerability, validation.In(true, false)),
		validation.Field(&cfg.ProjectPath, validation.By(validateIfIsValidPath(cfg.ProjectPath))),
		validation.Field(&cfg.WorkDir, validation.By(validateWorkDir(cfg.WorkDir, cfg.ProjectPath))),
		validation.Field(&cfg.CertInsecureSkipVerify, validation.In(true, false)),
		validation.Field(&cfg.CertPath, validation.By(validateCertPath(cfg.CertPath))),
		validation.Field(&cfg.FalsePositiveHashes, validation.By(validateDuplicatedFalsePositiveHashes(cfg))),
		validation.Field(&cfg.RiskAcceptHashes, validation.By(validateDuplicatedRiskAcceptHashes(cfg))),
		validation.Field(&cfg.ShowVulnerabilitiesTypes, validation.By(validateVulnerabilitiesTypes(cfg))),
		validation.Field(&cfg.EnableCommitAuthor, validation.By(validateGitDepthClone(cfg))),
	)
}

func validateGitDepthClone(cfg *config.Config) validation.RuleFunc {
	return func(_ interface{}) error {
		if (cfg.EnableCommitAuthor || cfg.EnableGitHistoryAnalysis) && git.RepositoryIsShallow(cfg) {
			logger.LogWarn(messages.MsgWarnGitRepositoryIsNotFullCloned)
		}
		return nil
	}
}

func validateDuplicatedFalsePositiveHashes(cfg *config.Config) validation.RuleFunc {
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

func validateDuplicatedRiskAcceptHashes(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for _, riskAccept := range cfg.RiskAcceptHashes {
			for _, falsePositive := range cfg.FalsePositiveHashes {
				falsePositive = strings.TrimSpace(falsePositive)
				if riskAccept == falsePositive {
					return fmt.Errorf("%s %s", messages.MsgErrorRiskAcceptNotValid, riskAccept)
				}
			}
		}
		return nil
	}
}

func validateJSONOutputFilePath(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		switch cfg.PrintOutputType {
		case outputtype.JSON, outputtype.SonarQube:
			return validateFilePathAndExtension(cfg, ".json")
		case outputtype.Text:
			return validateTextOutputFilePath(cfg)
		}
		return nil
	}
}

func validateTextOutputFilePath(cfg *config.Config) error {
	if cfg.JSONOutputFilePath == "" {
		return nil
	}
	return validateFilePathAndExtension(cfg, ".txt")
}

func validateFilePathAndExtension(cfg *config.Config, extension string) error {
	if filepath.Ext(cfg.JSONOutputFilePath) != extension {
		return fmt.Errorf("%s %s", messages.MsgErrorJSONOutputFilePathNotValidExtension, extension)
	}
	return nil
}

func validationSeverities(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for idx := range cfg.SeveritiesToIgnore {
			cfg.SeveritiesToIgnore[idx] = strings.TrimSpace(cfg.SeveritiesToIgnore[idx])
			if !checkIfExistItemInSliceOfSeverity(cfg.SeveritiesToIgnore[idx]) {
				return fmt.Errorf("%s %s %v",
					cfg.SeveritiesToIgnore[idx], messages.MsgErrorSeverityNotValid, sliceSeverityEnable())
			}
		}
		return nil
	}
}

func checkIfExistItemInSliceOfSeverity(item string) bool {
	for _, severityName := range sliceSeverityEnable() {
		if severityName.ToString() == item {
			return true
		}
	}
	return false
}

func sliceSeverityEnable() []severities.Severity {
	return []severities.Severity{
		severities.Critical,
		severities.High,
		severities.Medium,
		severities.Low,
		severities.Unknown,
		severities.Info,
	}
}

func validateIfIsValidPath(dir string) validation.RuleFunc {
	return func(value interface{}) error {
		if _, errStat := os.Stat(dir); errStat != nil || dir == "" {
			return fmt.Errorf("%s %s", messages.MsgErrorPathNotValid, dir)
		}
		return nil
	}
}

func validateCertPath(dir string) validation.RuleFunc {
	if dir == "" {
		return func(value interface{}) error {
			return nil
		}
	}

	return validateIfIsValidPath(dir)
}

func validateWorkDir(workDir *workdir.WorkDir, projectPath string) validation.RuleFunc {
	return func(value interface{}) error {
		if workDir == nil {
			return errors.New(messages.MsgErrorInvalidWorkDir)
		}
		for _, pathsByLanguage := range workDir.LanguagePaths() {
			for _, projectSubPath := range pathsByLanguage {
				err := validateIfExistPathInProjectToWorkDir(projectPath, projectSubPath)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func validateIfExistPathInProjectToWorkDir(projectPath, internalPath string) error {
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

func validateVulnerabilitiesTypes(cfg *config.Config) validation.RuleFunc {
	return func(value interface{}) error {
		for _, vulnType := range cfg.ShowVulnerabilitiesTypes {
			if !isVulnerabilityValid(strings.TrimSpace(vulnType)) {
				return fmt.Errorf("%s %s", messages.MsgVulnerabilityTypeToShowInvalid, vulnType)
			}
		}
		return nil
	}
}

func isVulnerabilityValid(vulnType string) bool {
	for _, valid := range vulnerability.Values() {
		if strings.EqualFold(valid.ToString(), vulnType) {
			return true
		}
	}
	return false
}

func checkIfIsURL(rawURL string) validation.RuleFunc {
	return func(value interface{}) error {
		_, err := url.ParseRequestURI(rawURL)
		if err != nil {
			return err
		}
		return nil
	}
}
