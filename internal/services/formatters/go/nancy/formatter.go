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

package nancy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnHash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

const (
	goModulesExt        = ".mod"
	goSumExt            = ".sum"
	rateLimitValidation = "this is most likely due to github rate-limiting on unauthenticated requests"
	rateLimitPrefix     = "error: failed to query the github api for updates"
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
	if f.ToolIsToIgnore(tools.Nancy) || f.IsDockerDisabled() || os.Getenv("GITHUB_TOKEN") == "" {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Nancy.ToString())
		return
	}

	output, err := f.startNancy(projectSubPath)
	f.SetAnalysisError(err, tools.Nancy, output, projectSubPath)

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Nancy, languages.Go)
}

func (f *Formatter) startNancy(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Nancy, languages.Go)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}
	if output == "" {
		return output, nil
	}
	if strings.Contains(strings.ToLower(output), rateLimitPrefix) &&
		strings.Contains(strings.ToLower(output), rateLimitValidation) {
		return "", errors.New(messages.MsgErrorNancyRateLimit)
	}

	return output, f.processOutput(output, projectSubPath)
}

func (f *Formatter) processOutput(output, projectSubPath string) error {
	var analysis *nancyAnalysis

	if err := json.Unmarshal([]byte(f.getOutputText(output)), &analysis); err != nil {
		return err
	}

	f.addVulnIntoAnalysis(analysis, projectSubPath)

	return nil
}

func (f *Formatter) addVulnIntoAnalysis(analysis *nancyAnalysis, projectSubPath string) {
	for _, vulnerable := range analysis.Vulnerable {
		vuln, err := f.newVulnerability(vulnerable.getVulnerability(), vulnerable, projectSubPath)
		if err != nil {
			f.SetAnalysisError(err, tools.Nancy, err.Error(), "")
			logger.LogErrorWithLevel(messages.MsgErrorGetDependencyCodeFilepathAndLine, err)
			continue
		}
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (f *Formatter) getOutputText(output string) string {
	index := strings.Index(output, "{")
	if index < 0 {
		return output
	}

	return output[index:]
}

// nolint:funlen
func (f *Formatter) newVulnerability(vulnData *nancyVulnerability, vulnerable *nancyVulnerable,
	projectSubPath string,
) (*vulnerability.Vulnerability, error) {
	code, filePath, line, err := file.GetDependencyCodeFilepathAndLine(
		f.GetConfigProjectPath(), projectSubPath, vulnerable.getDependency(), goModulesExt, goSumExt,
	)
	if err != nil {
		return nil, err
	}

	vuln := &vulnerability.Vulnerability{
		Language:     languages.Go,
		SecurityTool: tools.Nancy,
		Severity:     vulnData.getSeverity(),
		Details:      vulnData.getDescription(),
		Confidence:   confidence.High,
		Code:         code,
		Line:         line,
		File:         f.removeHorusecFolder(filePath),
	}
	return f.SetCommitAuthor(vulnHash.Bind(vuln)), err
}

func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD: f.AddWorkDirInCmd(
			CMD,
			file.GetSubPathByExtension(f.GetConfigProjectPath(), projectSubPath, goModulesExt),
			tools.Nancy,
		),
		Language: languages.Go,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Go), images.Go)
}

func (f *Formatter) removeHorusecFolder(path string) string {
	return filepath.Clean(strings.ReplaceAll(path, filepath.Join(".horusec", f.GetAnalysisID()), ""))
}
