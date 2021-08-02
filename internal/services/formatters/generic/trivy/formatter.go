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
	err = f.parse(projectSubPath, configOutput, fileSystemOutput)
	if err != nil {
		return err
	}
	return err
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
	err = f.parseOutput(fileSystemOutput, CmdFs, projectSubPath)
	if err != nil {
		return err
	}
	return nil
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

// nolint:funlen // setVulnerabilitiesOutput is necessary more 15 lines
func (f *Formatter) setVulnerabilitiesOutput(result []*types.DetectedVulnerability, target string) {
	for _, vuln := range result {
		addVuln := &vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "0",
			Column:          "0",
			Confidence:      confidence.Medium,
			File:            target,
			Code:            vuln.PkgName,
			Details:         fmt.Sprintf("%s\n%s\n%s", vuln.Description, vuln.PrimaryURL, getDetails(vuln)),
			SecurityTool:    tools.Trivy,
			Language:        languages.Generic,
			Severity:        severities.GetSeverityByString(vuln.Severity),
			Type:            enumsVulnerability.Vulnerability,
		}
		addVuln = vulnhash.Bind(addVuln)
		f.AddNewVulnerabilityIntoAnalysis(addVuln)
	}
}

func getDetails(vuln *types.DetectedVulnerability) string {
	basePath := "https://cwe.mitre.org/data/definitions/"
	var result string

	for _, id := range vuln.CweIDs {
		idAfterSplit := strings.SplitAfter(id, "-")
		result = result + basePath + idAfterSplit[1] + ".html\n"
	}
	return result
}

// nolint:funlen // setMisconfigurationOutput is necessary more 15 lines
func (f *Formatter) setMisconfigurationOutput(result []*types.DetectedMisconfiguration, target string) {
	for _, vuln := range result {
		addVuln := &vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "0",
			Column:          "0",
			Confidence:      confidence.Medium,
			File:            target,
			Code:            vuln.Title,
			Details:         fmt.Sprintf("%s - %s - %s", vuln.Description, vuln.Resolution, vuln.References),
			SecurityTool:    tools.Trivy,
			Language:        languages.Generic,
			Severity:        severities.GetSeverityByString(vuln.Severity),
			Type:            enumsVulnerability.Vulnerability,
		}
		addVuln = vulnhash.Bind(addVuln)
		f.AddNewVulnerabilityIntoAnalysis(addVuln)
	}
}
