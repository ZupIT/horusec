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

package bundler

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

// ErrGemLockNotFound occurs when project path does not have the Gemfile.lock file.
//
// nolint: stylecheck
// We actually want that this error message be capitalized since the file name that was
// not found is capitalized.
var ErrGemLockNotFound = errors.New(messages.MsgWarnGemfileIsRequiredForBundler)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.BundlerAudit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.BundlerAudit.ToString())
		return
	}

	output, err := f.startBundlerAudit(projectSubPath)
	f.SetAnalysisError(err, tools.BundlerAudit, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.BundlerAudit, languages.Ruby)
}

func (f *Formatter) startBundlerAudit(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.BundlerAudit, languages.Ruby)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}
	if err := f.validateOutput(output); err != nil {
		return output, err
	}
	return output, f.parseOutput(output, projectSubPath)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(
			CMD,
			file.GetSubPathByExtension(f.GetConfigProjectPath(), projectSubPath, "Gemfile.lock"),
			tools.BundlerAudit,
		),
		Language: languages.Ruby,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Ruby), images.Ruby)
}

func (f *Formatter) parseOutput(output, projectSubPath string) error {
	auditOutput := AuditOutput{}
	if err := json.Unmarshal([]byte(output), &auditOutput); err != nil {
		return err
	}

	return f.processOutput(auditOutput, projectSubPath)
}

func (f *Formatter) processOutput(outputData AuditOutput, projectSubPath string) error {
	for index := range outputData.Results {
		vuln, err := f.newVulnerability(&outputData.Results[index], outputData.Version, projectSubPath)
		if err != nil {
			return err
		}
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
	return nil
}

// nolint: funlen // needs to be bigger
func (f *Formatter) newVulnerability(result *Result, securityToolVersion,
	projectSubPath string,
) (*vulnerability.Vulnerability, error) {
	vuln := f.getVulnBase(result, securityToolVersion)
	gemFilePath, err := f.GetFilepathFromFilename("Gemfile.lock", projectSubPath)
	if err != nil {
		return nil, err
	}
	dependencyInfo, err := file.GetDependencyInfo(
		[]string{result.Gem.Name, result.Gem.Version}, []string{filepath.Join(f.GetConfigProjectPath(), gemFilePath)})
	if err != nil {
		return nil, err
	}
	vuln.Line = dependencyInfo.Line
	vuln.File = f.removeHorusecFolder(dependencyInfo.Path)
	vuln.Code = dependencyInfo.Code
	return f.SetCommitAuthor(vulnhash.Bind(vuln)), nil
}

// validateOutput will check if output from container contains the error in your response
// "fatal: unable to access 'https://github.com/rubysec/ruby-advisory-db.git/': Could not resolve host: github.com"
func (f *Formatter) validateOutput(output string) error {
	// When not found "Gemfile.lock" file the output is empty
	// Or not found any vulnerability in your project
	if output == "" {
		return ErrGemLockNotFound
	}
	if strings.HasPrefix(strings.ToLower(output), "fatal: unable to access") &&
		strings.Contains(strings.ToLower(output), "could not resolve host") {
		return errors.New(messages.MsgErrorBundlerNotAccessDB)
	}
	return nil
}

func (f *Formatter) removeHorusecFolder(path string) string {
	return filepath.Clean(strings.ReplaceAll(path, filepath.Join(".horusec", f.GetAnalysisID()), ""))
}

func (f *Formatter) getVulnBase(result *Result, securityToolVersion string) *vulnerability.Vulnerability {
	return &vulnerability.Vulnerability{
		VulnerabilityID:     uuid.New(),
		Column:              "0",
		Confidence:          confidence.Medium,
		Details:             result.getDetails(),
		SecurityTool:        tools.BundlerAudit,
		Language:            languages.Ruby,
		Severity:            result.getSeverity(),
		RuleID:              result.Advisory.ID,
		SecurityToolVersion: securityToolVersion,
	}
}
