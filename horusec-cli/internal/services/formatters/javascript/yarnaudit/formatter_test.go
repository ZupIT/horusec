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

package yarnaudit

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
)

func TestParseOutputYarn(t *testing.T) {
	t.Run("Should run analysis with no errors", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := "{\"advisories\":[{\"findings\":[{\"version\":\"4.0.0\",\"paths\":[\"express\"]}],\"id\":8,\"created\":\"2015-10-17T19:41:46.382Z\",\"updated\":\"2018-02-22T21:55:47.925Z\",\"deleted\":null,\"title\":\"No Charset in Content-Type Header\",\"found_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"reported_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"module_name\":\"express\",\"cves\":[\"CVE-2014-6393\"],\"vulnerable_versions\":\"<3.11 || >= 4 <4.5\",\"patched_versions\":\">=3.11 <4 || >=4.5\",\"overview\":\"Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.\",\"recommendation\":\"For express 3.x, update express to version 3.11 or later.\\nFor express 4.x, update express to version 4.5 or later. \",\"references\":\"\",\"access\":\"public\",\"severity\":\"low\",\"cwe\":\"CWE-79\",\"metadata\":{\"module_type\":\"Network.Library\",\"exploitability\":2,\"affected_components\":\"\"},\"url\":\"https://npmjs.com/advisories/8\"},{\"findings\":[{\"version\":\"4.0.0\",\"paths\":[\"express\"]}],\"id\":8,\"created\":\"2015-10-17T19:41:46.382Z\",\"updated\":\"2018-02-22T21:55:47.925Z\",\"deleted\":null,\"title\":\"No Charset in Content-Type Header\",\"found_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"reported_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"module_name\":\"express\",\"cves\":[\"CVE-2014-6393\"],\"vulnerable_versions\":\"<3.11 || >= 4 <4.5\",\"patched_versions\":\">=3.11 <4 || >=4.5\",\"overview\":\"Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.\",\"recommendation\":\"For express 3.x, update express to version 3.11 or later.\\nFor express 4.x, update express to version 4.5 or later. \",\"references\":\"\",\"access\":\"public\",\"severity\":\"moderate\",\"cwe\":\"CWE-79\",\"metadata\":{\"module_type\":\"Network.Library\",\"exploitability\":2,\"affected_components\":\"\"},\"url\":\"https://npmjs.com/advisories/8\"},{\"findings\":[{\"version\":\"4.0.0\",\"paths\":[\"express\"]}],\"id\":8,\"created\":\"2015-10-17T19:41:46.382Z\",\"updated\":\"2018-02-22T21:55:47.925Z\",\"deleted\":null,\"title\":\"No Charset in Content-Type Header\",\"found_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"reported_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"module_name\":\"express\",\"cves\":[\"CVE-2014-6393\"],\"vulnerable_versions\":\"<3.11 || >= 4 <4.5\",\"patched_versions\":\">=3.11 <4 || >=4.5\",\"overview\":\"Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.\",\"recommendation\":\"For express 3.x, update express to version 3.11 or later.\\nFor express 4.x, update express to version 4.5 or later. \",\"references\":\"\",\"access\":\"public\",\"severity\":\"high\",\"cwe\":\"CWE-79\",\"metadata\":{\"module_type\":\"Network.Library\",\"exploitability\":2,\"affected_components\":\"\"},\"url\":\"https://npmjs.com/advisories/8\"},{\"findings\":[{\"version\":\"4.0.0\",\"paths\":[\"express\"]}],\"id\":8,\"created\":\"2015-10-17T19:41:46.382Z\",\"updated\":\"2018-02-22T21:55:47.925Z\",\"deleted\":null,\"title\":\"No Charset in Content-Type Header\",\"found_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"reported_by\":{\"name\":\"Pawe\u0142 Ha\u0142drzy\u0144ski\"},\"module_name\":\"express\",\"cves\":[\"CVE-2014-6393\"],\"vulnerable_versions\":\"<3.11 || >= 4 <4.5\",\"patched_versions\":\">=3.11 <4 || >=4.5\",\"overview\":\"Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.\",\"recommendation\":\"For express 3.x, update express to version 3.11 or later.\\nFor express 4.x, update express to version 4.5 or later. \",\"references\":\"\",\"access\":\"public\",\"severity\":\"test\",\"cwe\":\"CWE-79\",\"metadata\":{\"module_type\":\"Network.Library\",\"exploitability\":2,\"affected_components\":\"\"},\"url\":\"https://npmjs.com/advisories/8\"}],\"metadata\":{\"vulnerabilities\":{\"info\":0,\"low\":6,\"moderate\":6,\"high\":7,\"critical\":0},\"dependencies\":27,\"devDependencies\":0,\"optionalDependencies\":0,\"totalDependencies\":27}}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 4)
	})

	t.Run("Should run analysis with output empty", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should parse output with not found error", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := "ERROR_YARN_LOCK_NOT_FOUND"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should parse output with audit error", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := "ERROR_RUNNING_YARN_AUDIT"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should return error when executing container", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})
}

func TestParseOutputNpm(t *testing.T) {
	t.Run("Should return error when invalid output", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.parseOutput("invalid output")
		assert.Error(t, err)
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})
}
