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
	"sync"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	enumvulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

// trivyResult represents the results after execute Trivy commands.
type trivyResult struct {
	config string // Result of misconfigurations files.
	fs     string // Result of filesystem vulnerabilities and misconfigurations.
	err    error  // Error if exists.
}

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

	output, err := f.startTrivy(projectSubPath)
	f.SetAnalysisError(err, tools.Trivy, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Trivy, languages.Generic)
}

func (f *Formatter) startTrivy(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Trivy, languages.Generic)

	configOutput, fileSystemOutput, err := f.executeContainers(projectSubPath)
	if err != nil {
		return "", err
	}

	return f.parse(projectSubPath, configOutput, fileSystemOutput)
}

// nolint:funlen
func (f *Formatter) executeContainers(projectSubPath string) (string, string, error) {
	var (
		result     trivyResult
		configDone = make(chan bool)
		fsDone     = make(chan bool)
		mutex      = new(sync.Mutex)
	)

	// Scan Directory for Misconfigurations
	go func() {
		config, err := f.ExecuteContainer(f.getDockerConfig(CmdConfig, projectSubPath))
		if err != nil {
			mutex.Lock()
			result.err = fmt.Errorf("trivy config cmd: %w", err)
			mutex.Unlock()
		}
		result.config = config
		configDone <- true
	}()

	// Scan Filesystem for Vulnerabilities and Misconfigurations
	go func() {
		fs, err := f.ExecuteContainer(f.getDockerConfig(CmdFs, projectSubPath))
		if err != nil {
			mutex.Lock()
			result.err = fmt.Errorf("trivy filesystem cmd: %w", err)
			mutex.Unlock()
		}
		result.fs = fs
		fsDone <- true
	}()

	// Wait for go routines to finish
	<-configDone
	<-fsDone

	return result.config, result.fs, result.err
}

func (f *Formatter) parse(projectSubPath, configOutput, fileSystemOutput string) (string, error) {
	if err := f.parseOutput(configOutput, CmdConfig, projectSubPath); err != nil {
		return configOutput, err
	}

	return fileSystemOutput, f.parseOutput(fileSystemOutput, CmdFs, projectSubPath)
}

func (f *Formatter) getDockerConfig(cmd, projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.AddWorkDirInCmd(cmd, projectSubPath, tools.Trivy),
		Language: languages.Generic,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Generic), images.Generic)
}

func (f *Formatter) parseOutput(output, cmd, projectSubPath string) error {
	report := new(trivyOutput)

	if output == "" {
		return nil
	}

	if err := json.Unmarshal([]byte(output), report); err != nil {
		return err
	}

	for _, result := range report.Results {
		f.addVulnerabilities(cmd, result, filepath.Join(projectSubPath, result.Target))
	}

	return nil
}

func (f *Formatter) addVulnerabilities(cmd string, result *trivyOutputResult, path string) {
	switch cmd {
	case CmdFs:
		f.addVulnerabilitiesOutput(result.Vulnerabilities, path)
	case CmdConfig:
		f.addVulnerabilitiesOutput(result.Vulnerabilities, path)
		f.addMisconfigurationOutput(result.Misconfigurations, path)
	}
}

func (f *Formatter) addVulnerabilitiesOutput(vulnerabilities []*trivyVulnerability, target string) {
	for _, vuln := range vulnerabilities {
		addVuln := f.getVulnBase()
		addVuln.RuleID = vuln.VulnerabilityID
		addVuln.Code = fmt.Sprintf("%s v%s", vuln.PkgName, vuln.InstalledVersion)
		_, _, addVuln.Line = file.GetDependencyInfo(addVuln.Code, target)
		addVuln.File = target
		addVuln.Details = vuln.getDetails()
		addVuln.Severity = severities.GetSeverityByString(vuln.Severity)
		addVuln.VulnHash = f.getOldHash(vuln.PkgName, *addVuln)
		f.AddNewVulnerabilityIntoAnalysis(addVuln)
	}
}

// getOldHash func necessary to avoid a breaking change in the trivy hash generation. Since the pull request
// https://github.com/ZupIT/horusec/pull/882 some changes were made in the line and code, and this data influences
// directly the hash generation. This func will avoid this hash change by using the same data as before, but for the
// users the data will be showed with the fixes made in the pull request 882, leading to no braking changes and keeping
// the fixes.
// nolint:gocritic // it has to be without pointer
func (f *Formatter) getOldHash(pkgName string, vuln vulnerability.Vulnerability) string {
	vuln.Line = "0"
	vuln.Code = pkgName

	return vulnhash.Bind(&vuln).VulnHash
}

func (f *Formatter) addMisconfigurationOutput(result []*trivyMisconfiguration, target string) {
	for _, vuln := range result {
		addVuln := f.getVulnBase()
		addVuln.File = target
		addVuln.Code = vuln.Title
		addVuln.Details = fmt.Sprintf(
			"%s - %s - %s - %s", vuln.Description, vuln.Message, vuln.Resolution, vuln.References,
		)
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
		Type:            enumvulnerability.Vulnerability,
	}
}
