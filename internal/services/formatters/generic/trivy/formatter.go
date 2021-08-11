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

package trivy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/trivy/entities"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.Trivy) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Trivy.ToString())
		return
	}

	f.SetAnalysisError(f.startTrivy(projectSubPath), tools.ShellCheck, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Trivy, images.Generic)
}

func (f *Formatter) startTrivy(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Trivy, images.Generic)

	configOutput, fileSystemOutput, err := f.executeContainers(projectSubPath)
	if err != nil {
		return err
	}
	return f.parse(projectSubPath, configOutput, fileSystemOutput)
}

func (f *Formatter) executeContainers(projectSubPath string) (string, string, error) {
	configOutput, err := f.ExecuteContainer(f.getDockerConfig(CmdConfig, projectSubPath))
	if err != nil {
		return "", "", nil
	}
	fileSystemOutput, err := f.ExecuteContainer(f.getDockerConfig(CmdFs, projectSubPath))
	if err != nil {
		return "", "", nil
	}
	return configOutput, fileSystemOutput, err
}

func (f *Formatter) parse(projectSubPath, configOutput, fileSystemOutput string) error {
	err := f.parseOutput(configOutput, CmdConfig, projectSubPath)
	if err != nil {
		return err
	}
	return f.parseOutput(fileSystemOutput, CmdFs, projectSubPath)
}
func (f *Formatter) getDockerConfig(cmd Cmd, projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(cmd.ToString(), projectSubPath, tools.Trivy),
		Language: languages.Generic,
	}
	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Generic), images.Generic)
}

func (f *Formatter) parseOutput(output string, cmd Cmd, projectsubpath string) error {
	report := &entities.Report{}
	if err := json.Unmarshal([]byte(output), report); err != nil {
		return err
	}
	for _, result := range report.Results {
		path := filepath.Join(projectsubpath, result.Target)
		f.setVulnerabilities(cmd, result, path)
	}
	return nil
}

func (f *Formatter) setVulnerabilities(cmd Cmd, result *entities.Result, path string) {
	switch cmd {
	case CmdFs:
		f.setVulnerabilitiesOutput(result.Vulnerabilities, path)
	case CmdConfig:
		f.setVulnerabilitiesOutput(result.Vulnerabilities, path)
		f.setMisconfigurationOutput(result.Misconfigurations, path)
	}
}

func (f *Formatter) setVulnerabilitiesOutput(result []*types.DetectedVulnerability, target string) {
	for _, vuln := range result {
		addVuln := f.getVulnBase()
		addVuln.File = target
		addVuln.Code = vuln.PkgName
		addVuln.Details = f.getDetails(vuln)
		addVuln.Severity = severities.GetSeverityByString(vuln.Severity)
		addVuln = vulnhash.Bind(addVuln)
		f.AddNewVulnerabilityIntoAnalysis(addVuln)
	}
}

func (f *Formatter) getDetails(vuln *types.DetectedVulnerability) string {
	details := f.getBaseDetailsWithoutCWEs(vuln)

	if len(vuln.CweIDs) > 0 {
		return f.getDetailsWithCWEs(details, vuln)
	}

	return strings.TrimRight(details, "\n")
}

func (f *Formatter) getBaseDetailsWithoutCWEs(vuln *types.DetectedVulnerability) (details string) {
	if vuln.Description != "" {
		details += vuln.Description + "\n"
	}
	if vuln.InstalledVersion != "" && vuln.FixedVersion != "" {
		details += fmt.Sprintf("Installed Version: \"%s\", Update to Version: \"%s\" for fix this issue.\n",
			vuln.InstalledVersion, vuln.FixedVersion)
	}
	if vuln.PrimaryURL != "" {
		details += fmt.Sprintf("PrimaryURL: %s.\n", vuln.PrimaryURL)
	}
	return details
}

// nolint:gomnd // magic number "2" is not necessary to check
func (f *Formatter) getDetailsWithCWEs(details string, vuln *types.DetectedVulnerability) string {
	details += "Cwe Links: "
	for _, ID := range vuln.CweIDs {
		idAfterSplit := strings.SplitAfter(ID, "-")
		if len(idAfterSplit) >= 2 {
			details += f.addCWELinkInDetails(details, idAfterSplit[1])
		}
	}
	return strings.TrimRight(details, ",")
}

func (f *Formatter) addCWELinkInDetails(details, cweID string) string {
	basePath := "https://cwe.mitre.org/data/definitions/"
	cweLink := basePath + cweID + ".html"
	if !strings.Contains(details, cweLink) {
		return fmt.Sprintf("(%s),", cweLink)
	}
	return ""
}

func (f *Formatter) setMisconfigurationOutput(result []*types.DetectedMisconfiguration, target string) {
	for _, vuln := range result {
		addVuln := f.getVulnBase()
		addVuln.File = target
		addVuln.Code = vuln.Title
		addVuln.Details = fmt.Sprintf("%s - %s - %s - %s", vuln.Description, vuln.Message, vuln.Resolution, vuln.References)
		addVuln.Severity = severities.GetSeverityByString(vuln.Severity)
		addVuln = vulnhash.Bind(addVuln)
		f.AddNewVulnerabilityIntoAnalysis(addVuln)
	}
}

func (f *Formatter) getVulnBase() *vulnerability.Vulnerability {
	return &vulnerability.Vulnerability{
		VulnerabilityID: uuid.New(),
		Line:            "0",
		Column:          "0",
		Confidence:      confidence.Medium,
		SecurityTool:    tools.Trivy,
		Language:        languages.Generic,
		Type:            enumsVulnerability.Vulnerability,
	}
}
