// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package toolsconfig

import (
	"encoding/json"

	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

// ToolsConfig is a map of a tool to config for easily index access.
type ToolsConfig map[tools.Tool]Config

// Config represents the configuration options for all tools.
type Config struct {
	IsToIgnore bool `json:"istoignore"`
}

// toolsConfig represents the schema of configuration tools.
type toolsConfig struct {
	Bandit               Config `json:"bandit"`
	BundlerAudit         Config `json:"bundleraudit"`
	Brakeman             Config `json:"brakeman"`
	Checkov              Config `json:"checkov"`
	Flawfinder           Config `json:"flawfinder"`
	GitLeaks             Config `json:"gitleaks"`
	GoSec                Config `json:"gosec"`
	HorusecEngine        Config `json:"horusecengine"`
	MixAudit             Config `json:"mixaudit"`
	NpmAudit             Config `json:"npmaudit"`
	PhpCS                Config `json:"phpcs"`
	Safety               Config `json:"safety"`
	SecurityCodeScan     Config `json:"securitycodescan"`
	Semgrep              Config `json:"semgrep"`
	ShellCheck           Config `json:"shellcheck"`
	Sobelow              Config `json:"sobelow"`
	TfSec                Config `json:"tfsec"`
	YarnAudit            Config `json:"yarnaudit"`
	OwaspDependencyCheck Config `json:"owaspDependencyCheck"`
	DotnetCli            Config `json:"dotnetCli"`
	Nancy                Config `json:"nancy"`
	Trivy                Config `json:"trivy"`
}

// toMap return the tools configuration as ToolsConfig for easily access.
//
// nolint:funlen
func (t *toolsConfig) toMap() ToolsConfig {
	return ToolsConfig{
		tools.Bandit:               t.Bandit,
		tools.BundlerAudit:         t.BundlerAudit,
		tools.Brakeman:             t.Brakeman,
		tools.Checkov:              t.Checkov,
		tools.Flawfinder:           t.Flawfinder,
		tools.GitLeaks:             t.GitLeaks,
		tools.GoSec:                t.GoSec,
		tools.HorusecEngine:        t.HorusecEngine,
		tools.MixAudit:             t.MixAudit,
		tools.NpmAudit:             t.NpmAudit,
		tools.PhpCS:                t.PhpCS,
		tools.Safety:               t.Safety,
		tools.SecurityCodeScan:     t.SecurityCodeScan,
		tools.Semgrep:              t.Semgrep,
		tools.ShellCheck:           t.ShellCheck,
		tools.Sobelow:              t.Sobelow,
		tools.TfSec:                t.TfSec,
		tools.YarnAudit:            t.YarnAudit,
		tools.OwaspDependencyCheck: t.OwaspDependencyCheck,
		tools.DotnetCli:            t.DotnetCli,
		tools.Nancy:                t.Nancy,
		tools.Trivy:                t.Trivy,
	}
}

// Default return the default configuration of tools.
//
// The default configuration is enabled for all tools.
func Default() ToolsConfig {
	return (&toolsConfig{}).toMap()
}

// MustParseToolsConfig parse a input to ToolsConfig.
//
// If some error occur the default values will be returned and the error
// will be logged.
func MustParseToolsConfig(input map[string]interface{}) ToolsConfig {
	cfg, err := parseToolsConfig(input)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err)
		return Default()
	}
	return cfg
}

// parseToolsConfig parse input to ToolsConfig.
func parseToolsConfig(input map[string]interface{}) (ToolsConfig, error) {
	var config toolsConfig

	bytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, err
	}

	return config.toMap(), nil
}
