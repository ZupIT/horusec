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

package trivy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestParseOutput(t *testing.T) {
	t.Run("Should return 2 vulnerabilities with no errors", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		analysis := &entitiesAnalysis.Analysis{}
		c := &config.Config{}
		c.WorkDir = &workdir.WorkDir{}

		output := `{"SchemaVersion":2,"ArtifactName":"./","ArtifactType":"filesystem","Metadata":{},"Results":[{"Target":"go.sum","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[{"VulnerabilityID":"CVE-2020-26160","PkgName":"github.com/dgrijalva/jwt-go","InstalledVersion":"3.2.0+incompatible","Layer":{"DiffID":"sha256:f792cd543fb8711f2afbe7990dddf572b57b29f982ea03c11010972b07a28b36"},"SeveritySource":"nvd","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2020-26160","Title":"jwt-go: access restriction bypass vulnerability","Description":"jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrictions in situations with []string{} for m[\"aud\"] (which is allowed by the specification). Because the type assertion fails, \"\" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check.","Severity":"HIGH","CweIDs":["CWE-862"],"CVSS":{"nvd":{"V2Vector":"AV:N/AC:L/Au:N/C:P/I:N/A:N","V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","V2Score":5,"V3Score":7.5},"redhat":{"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","V3Score":7.5}},"References":["https://github.com/dgrijalva/jwt-go/pull/426","https://nvd.nist.gov/vuln/detail/CVE-2020-26160","https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515"],"PublishedDate":"2020-09-30T18:15:00Z","LastModifiedDate":"2021-07-21T11:39:00Z"}]}]}`

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, c)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 2)
	})

	t.Run("Should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		analysis := &entitiesAnalysis.Analysis{}
		c := &config.Config{}
		c.WorkDir = &workdir.WorkDir{}

		output := "!!"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, c)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		c := &config.Config{}
		c.WorkDir = &workdir.WorkDir{}
		c.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{Trivy: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, c)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
