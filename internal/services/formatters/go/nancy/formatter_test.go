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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseOutput(t *testing.T) {
	t.Run("should success parse output to analysis", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "1243567890")
		analysis := new(analysis.Analysis)

		cfg := config.New()
		cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysis, testutil.GoExample1)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.False(t, analysis.HasErrors(), "Expected no errors on analysis: %s", analysis.Errors)
		assert.Len(t, analysis.AnalysisVulnerabilities, 4)

		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			expectedGoModPath := filepath.Join(cfg.ProjectPath, "go.mod")
			expectedGoSumPath := filepath.Join(cfg.ProjectPath, "go.sum")

			assert.Equal(t, languages.Go, vuln.Language, "Expected Go as vulnerability language")
			assert.Equal(t, tools.Nancy, vuln.SecurityTool, "Expected nancy as security tool")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty vulnerability severity")
			assert.NotEmpty(t, vuln.Details, "Expected not empty vulnerability details")
			assert.Equal(t, confidence.High, vuln.Confidence, "Expected high as vulnerability confidence")
			assert.NotEmpty(t, vuln.Code, "Expected not empty vulnerability code")
			assert.NotEmpty(t, vuln.Line, "Expected not empty vulnerability line")

			assert.Condition(
				t,
				func() bool {
					return vuln.File == expectedGoModPath || vuln.File == expectedGoSumPath
				},
				"Expected vulnerability file %q to be %q or %q", vuln.File, expectedGoModPath, expectedGoSumPath,
			)
		}
	})

	t.Run("should success parse output empty to analysis", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "1243567890")
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("should add error on analysis when parsing invalid output", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "1243567890")
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should not run nancy tool because not exists environment", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "")
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputRateLimit, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.False(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add error on analysis when output return rate limit requests", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "1243567890")
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputRateLimit, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
		assert.Contains(t, analysis.Errors, messages.MsgErrorNancyRateLimit)
	})

	t.Run("should add error on analysis when something went wrong executing container", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "1243567890")
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		cfg := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		_ = os.Setenv("GITHUB_TOKEN", "1243567890")
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Nancy: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

const output = `
{
    "audited":[
        {
            "Coordinates":"pkg:golang/cloud.google.com/go@0.34.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/cloud.google.com/go@0.34.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/dmitri.shuralyov.com/gpu/mtl@0.0.0-20190408044501-666a987793e9",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/dmitri.shuralyov.com/gpu/mtl@0.0.0-20190408044501-666a987793e9?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/Azure/go-ansiterm@0.0.0-20170929234023-d6e3b3328b78",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/Azure/go-ansiterm@0.0.0-20170929234023-d6e3b3328b78?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/Azure/go-ntlmssp@0.0.0-20200615164410-66371956d46c",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/Azure/go-ntlmssp@0.0.0-20200615164410-66371956d46c?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/BurntSushi/toml@0.3.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/BurntSushi/toml@0.3.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/BurntSushi/xgb@0.0.0-20160522181843-27f122750802",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/BurntSushi/xgb@0.0.0-20160522181843-27f122750802?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/Microsoft/go-winio@0.4.15",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/Microsoft/go-winio@0.4.15?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/OneOfOne/xxhash@1.2.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/OneOfOne/xxhash@1.2.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/PuerkitoBio/purell@1.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/PuerkitoBio/purell@1.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/PuerkitoBio/urlesc@0.0.0-20170810143723-de5bf2ad4578",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/PuerkitoBio/urlesc@0.0.0-20170810143723-de5bf2ad4578?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/Shopify/sarama@1.19.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/Shopify/sarama@1.19.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/Shopify/toxiproxy@2.1.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/Shopify/toxiproxy@2.1.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/VividCortex/gohistogram@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/VividCortex/gohistogram@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/ZupIT/horusec-engine@0.2.8",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/ZupIT/horusec-engine@0.2.8?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/afex/hystrix-go@0.0.0-20180502004556-fa1af6a1f4f5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/afex/hystrix-go@0.0.0-20180502004556-fa1af6a1f4f5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/alecthomas/template@0.0.0-20190718012654-fb15b899a751",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/alecthomas/template@0.0.0-20190718012654-fb15b899a751?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/alecthomas/units@0.0.0-20190717042225-c3de453c63f4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/alecthomas/units@0.0.0-20190717042225-c3de453c63f4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/antchfx/xpath@1.1.11",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/antchfx/xpath@1.1.11?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/armon/consul-api@0.0.0-20180202201655-eb2c6b5be1b6",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/armon/consul-api@0.0.0-20180202201655-eb2c6b5be1b6?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/aryann/difflib@0.0.0-20170710044230-e206f873d14a",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/aryann/difflib@0.0.0-20170710044230-e206f873d14a?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/asaskevich/govalidator@0.0.0-20200907205600-7a23bdc65eef",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/asaskevich/govalidator@0.0.0-20200907205600-7a23bdc65eef?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/auth0/go-jwt-middleware@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/auth0/go-jwt-middleware@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/beorn7/perks@1.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/beorn7/perks@1.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/bmatcuk/doublestar@1.3.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/bmatcuk/doublestar@1.3.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/bmatcuk/doublestar/v2@2.0.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/bmatcuk/doublestar/v2@2.0.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/cenkalti/backoff@2.2.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/cenkalti/backoff@2.2.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/census-instrumentation/opencensus-proto@0.2.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/census-instrumentation/opencensus-proto@0.2.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/cespare/xxhash@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/cespare/xxhash@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/cespare/xxhash/v2@2.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/cespare/xxhash/v2@2.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/chzyer/logex@1.1.10",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/chzyer/logex@1.1.10?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/chzyer/readline@0.0.0-20180603132655-2972be24d48e",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/chzyer/readline@0.0.0-20180603132655-2972be24d48e?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/chzyer/test@0.0.0-20180213035817-a1ea475d72b1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/chzyer/test@0.0.0-20180213035817-a1ea475d72b1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/clbanning/x2j@0.0.0-20191024224557-825249438eec",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/clbanning/x2j@0.0.0-20191024224557-825249438eec?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/client9/misspell@0.3.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/client9/misspell@0.3.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/cncf/udpa/go@0.0.0-20201120205902-5459f2c99403",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/cncf/udpa/go@0.0.0-20201120205902-5459f2c99403?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/codegangsta/inject@0.0.0-20150114235600-33e0aa1cb7c0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/codegangsta/inject@0.0.0-20150114235600-33e0aa1cb7c0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/containerd/containerd@1.4.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/containerd/containerd@1.4.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/coreos/bbolt@1.3.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/bbolt@1.3.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/coreos/etcd@3.3.10",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/etcd@3.3.10?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"bba60acb-c7b5-4621-af69-f4085a8301d0",
                    "Title":"[CVE-2020-15114] In etcd before versions 3.3.23 and 3.4.10, the etcd gateway is a simple TCP prox...",
                    "Description":"In etcd before versions 3.3.23 and 3.4.10, the etcd gateway is a simple TCP proxy to allow for basic service discovery and access. However, it is possible to include the gateway address as an endpoint. This results in a denial of service, since the endpoint can become stuck in a loop of requesting itself until there are no more available file descriptors to accept connections on the gateway.",
                    "CvssScore":"7.7",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
                    "Cve":"CVE-2020-15114",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/bba60acb-c7b5-4621-af69-f4085a8301d0?component-type=golang\u0026component-name=github.com%2Fcoreos%2Fetcd\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                },
                {
                    "ID":"5def94e5-b89c-4a94-b9c6-ae0e120784c2",
                    "Title":"[CVE-2020-15115] etcd before versions 3.3.23 and 3.4.10 does not perform any password length vali...",
                    "Description":"etcd before versions 3.3.23 and 3.4.10 does not perform any password length validation, which allows for very short passwords, such as those with a length of one. This may allow an attacker to guess or brute-force users' passwords with little computational effort.",
                    "CvssScore":"5.8",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
                    "Cve":"CVE-2020-15115",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/5def94e5-b89c-4a94-b9c6-ae0e120784c2?component-type=golang\u0026component-name=github.com%2Fcoreos%2Fetcd\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                },
                {
                    "ID":"d373dc3f-aa88-483b-b501-20fe5382cc80",
                    "Title":"[CVE-2020-15136] In ectd before versions 3.4.10 and 3.3.23, gateway TLS authentication is only ap...",
                    "Description":"In ectd before versions 3.4.10 and 3.3.23, gateway TLS authentication is only applied to endpoints detected in DNS SRV records. When starting a gateway, TLS authentication will only be attempted on endpoints identified in DNS SRV records for a given domain, which occurs in the discoverEndpoints function. No authentication is performed against endpoints provided in the --endpoints flag. This has been fixed in versions 3.4.10 and 3.3.23 with improved documentation and deprecation of the functionality.",
                    "CvssScore":"6.5",
                    "CvssVector":"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "Cve":"CVE-2020-15136",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/d373dc3f-aa88-483b-b501-20fe5382cc80?component-type=golang\u0026component-name=github.com%2Fcoreos%2Fetcd\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/coreos/go-semver@0.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/go-semver@0.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/coreos/go-systemd@0.0.0-20190321100706-95778dfbb74e",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/go-systemd@0.0.0-20190321100706-95778dfbb74e?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/coreos/pkg@0.0.0-20180928190104-399ea9e2e55f",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/pkg@0.0.0-20180928190104-399ea9e2e55f?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/cpuguy83/go-md2man/v2@2.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/cpuguy83/go-md2man/v2@2.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/creack/pty@1.1.9",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/creack/pty@1.1.9?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/davecgh/go-spew@1.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/davecgh/go-spew@1.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/dgrijalva/jwt-go@3.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/dgrijalva/jwt-go@3.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"c16fb56d-9de6-4065-9fca-d2b4cfb13020",
                    "Title":"[CVE-2020-26160] jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrict...",
                    "Description":"jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrictions in situations with []string{} for m[\"aud\"] (which is allowed by the specification). Because the type assertion fails, \"\" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check.",
                    "CvssScore":"7.5",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "Cve":"CVE-2020-26160",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/c16fb56d-9de6-4065-9fca-d2b4cfb13020?component-type=golang\u0026component-name=github.com%2Fdgrijalva%2Fjwt-go\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/dgrijalva/jwt-go/v4@4.0.0-preiew1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/dgrijalva/jwt-go/v4@4.0.0-preiew1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/dgryski/go-sip13@0.0.0-20181026042036-e10d5fee7954",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/dgryski/go-sip13@0.0.0-20181026042036-e10d5fee7954?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/dhui/dktest@0.3.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/dhui/dktest@0.3.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/docker/distribution@2.7.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/docker/distribution@2.7.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/docker/docker@20.10.5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/docker/docker@20.10.5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/docker/go-connections@0.4.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/docker/go-connections@0.4.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/docker/go-units@0.4.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/docker/go-units@0.4.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/eapache/go-resiliency@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/eapache/go-resiliency@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/eapache/go-xerial-snappy@0.0.0-20180814174437-776d5712da21",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/eapache/go-xerial-snappy@0.0.0-20180814174437-776d5712da21?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/eapache/queue@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/eapache/queue@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/edsrzf/mmap-go@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/edsrzf/mmap-go@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/envoyproxy/go-control-plane@0.9.9-0.20201210154907-fd9021fe5dad",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/envoyproxy/go-control-plane@0.9.9-0.20201210154907-fd9021fe5dad?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/envoyproxy/protoc-gen-validate@0.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/envoyproxy/protoc-gen-validate@0.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/erikstmartin/go-testdb@0.0.0-20160219214506-8d10e4a1bae5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/erikstmartin/go-testdb@0.0.0-20160219214506-8d10e4a1bae5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/form3tech-oss/jwt-go@3.2.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/form3tech-oss/jwt-go@3.2.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/franela/goreq@0.0.0-20171204163338-bcd34c9993f8",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/franela/goreq@0.0.0-20171204163338-bcd34c9993f8?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/fsnotify/fsnotify@1.4.9",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/fsnotify/fsnotify@1.4.9?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/ghodss/yaml@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/ghodss/yaml@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gin-contrib/sse@0.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gin-contrib/sse@0.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gin-gonic/gin@1.6.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gin-gonic/gin@1.6.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-asn1-ber/asn1-ber@1.5.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-asn1-ber/asn1-ber@1.5.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-chi/chi@4.1.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-chi/chi@4.1.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-chi/cors@1.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-chi/cors@1.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-enry/go-enry/v2@2.6.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-enry/go-enry/v2@2.6.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-enry/go-oniguruma@1.2.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-enry/go-oniguruma@1.2.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-kit/kit@0.9.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-kit/kit@0.9.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-logfmt/logfmt@0.5.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-logfmt/logfmt@0.5.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-martini/martini@0.0.0-20170121215854-22fa46961aab",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-martini/martini@0.0.0-20170121215854-22fa46961aab?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-openapi/jsonpointer@0.19.5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-openapi/jsonpointer@0.19.5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-openapi/jsonreference@0.19.5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-openapi/jsonreference@0.19.5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-openapi/swag@0.19.12",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-openapi/swag@0.19.12?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-ozzo/ozzo-validation/v4@4.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-ozzo/ozzo-validation/v4@4.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-playground/assert/v2@2.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-playground/assert/v2@2.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-playground/locales@0.13.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-playground/locales@0.13.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-playground/universal-translator@0.17.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-playground/universal-translator@0.17.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-playground/validator/v10@10.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-playground/validator/v10@10.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-resty/resty/v2@2.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-resty/resty/v2@2.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-sql-driver/mysql@1.5.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-sql-driver/mysql@1.5.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-stack/stack@1.8.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-stack/stack@1.8.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gocarina/gocsv@0.0.0-20201208093247-67c824bc04d4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gocarina/gocsv@0.0.0-20201208093247-67c824bc04d4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gofrs/uuid@3.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gofrs/uuid@3.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gogo/googleapis@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gogo/googleapis@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gogo/protobuf@1.3.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gogo/protobuf@1.3.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"dcf6da03-f9dd-4a4e-b792-0262de36a0b1",
                    "Title":"[CVE-2021-3121] An issue was discovered in GoGo Protobuf before 1.3.2. plugin/unmarshal/unmarsha...",
                    "Description":"An issue was discovered in GoGo Protobuf before 1.3.2. plugin/unmarshal/unmarshal.go lacks certain index validation, aka the \"skippy peanut butter\" issue.",
                    "CvssScore":"9.8",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "Cve":"CVE-2021-3121",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/dcf6da03-f9dd-4a4e-b792-0262de36a0b1?component-type=golang\u0026component-name=github.com%2Fgogo%2Fprotobuf\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/golang-sql/civil@0.0.0-20190719163853-cb61b32ac6fe",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/golang-sql/civil@0.0.0-20190719163853-cb61b32ac6fe?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/golang/glog@0.0.0-20160126235308-23def4e6c14b",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/golang/glog@0.0.0-20160126235308-23def4e6c14b?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/golang/groupcache@0.0.0-20190129154638-5b532d6fd5ef",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/golang/groupcache@0.0.0-20190129154638-5b532d6fd5ef?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/golang/mock@1.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/golang/mock@1.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/golang/protobuf@1.4.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/golang/protobuf@1.4.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/golang/snappy@0.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/golang/snappy@0.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/google/btree@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/google/btree@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/google/go-cmp@0.5.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/google/go-cmp@0.5.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/google/gofuzz@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/google/gofuzz@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/google/renameio@0.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/google/renameio@0.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/google/uuid@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/google/uuid@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gopherjs/gopherjs@0.0.0-20200217142428-fce0ec30dd00",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gopherjs/gopherjs@0.0.0-20200217142428-fce0ec30dd00?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gorilla/context@1.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gorilla/context@1.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gorilla/mux@1.7.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gorilla/mux@1.7.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gorilla/websocket@1.4.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gorilla/websocket@1.4.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/graphql-go/graphql@0.7.9",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/graphql-go/graphql@0.7.9?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/grpc-ecosystem/go-grpc-middleware@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/grpc-ecosystem/go-grpc-middleware@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/grpc-ecosystem/go-grpc-prometheus@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/grpc-ecosystem/go-grpc-prometheus@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/grpc-ecosystem/grpc-gateway@1.9.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/grpc-ecosystem/grpc-gateway@1.9.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/hashicorp/errwrap@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/hashicorp/errwrap@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/hashicorp/go-multierror@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/hashicorp/go-multierror@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/hashicorp/go-version@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/hashicorp/go-version@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/hashicorp/hcl@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/hashicorp/hcl@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/hpcloud/tail@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/hpcloud/tail@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/hudl/fargo@1.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/hudl/fargo@1.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/iancoleman/strcase@0.1.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/iancoleman/strcase@0.1.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/inconshreveable/mousetrap@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/inconshreveable/mousetrap@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/chunkreader@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/chunkreader@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/chunkreader/v2@2.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/chunkreader/v2@2.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/pgio@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/pgio@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/pgpassfile@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/pgpassfile@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/pgproto3@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/pgproto3@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/pgproto3/v2@2.0.6",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/pgproto3/v2@2.0.6?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/pgservicefile@0.0.0-20200714003250-2b9c44734f2b",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/pgservicefile@0.0.0-20200714003250-2b9c44734f2b?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jackc/puddle@1.1.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jackc/puddle@1.1.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jinzhu/inflection@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jinzhu/inflection@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jinzhu/now@1.1.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jinzhu/now@1.1.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jonboulle/clockwork@0.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jonboulle/clockwork@0.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/josharian/intern@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/josharian/intern@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jpillora/backoff@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jpillora/backoff@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/json-iterator/go@1.1.10",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/json-iterator/go@1.1.10?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jstemmer/go-junit-report@0.9.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jstemmer/go-junit-report@0.9.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/jtolds/gls@4.20.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/jtolds/gls@4.20.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/juju/ansiterm@0.0.0-20180109212912-720a0952cc2a",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/juju/ansiterm@0.0.0-20180109212912-720a0952cc2a?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/julienschmidt/httprouter@1.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/julienschmidt/httprouter@1.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kisielk/errcheck@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kisielk/errcheck@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kisielk/gotool@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kisielk/gotool@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kofalt/go-memoize@0.0.0-20200917044458-9b55a8d73e1c",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kofalt/go-memoize@0.0.0-20200917044458-9b55a8d73e1c?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/konsorten/go-windows-terminal-sequences@1.0.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/konsorten/go-windows-terminal-sequences@1.0.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kr/logfmt@0.0.0-20140226030751-b84e30acd515",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kr/logfmt@0.0.0-20140226030751-b84e30acd515?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kr/pretty@0.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kr/pretty@0.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kr/pty@1.1.8",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kr/pty@1.1.8?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/kr/text@0.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/kr/text@0.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/labstack/echo@3.3.10",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/labstack/echo@3.3.10?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/labstack/gommon@0.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/labstack/gommon@0.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/leodido/go-urn@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/leodido/go-urn@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/lib/pq@1.10.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/lib/pq@1.10.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/lunixbochs/vtclean@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/lunixbochs/vtclean@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/lyft/protoc-gen-validate@0.0.13",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/lyft/protoc-gen-validate@0.0.13?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/magiconair/properties@1.8.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/magiconair/properties@1.8.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mailru/easyjson@0.7.6",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mailru/easyjson@0.7.6?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/manifoldco/promptui@0.8.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/manifoldco/promptui@0.8.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mattn/go-colorable@0.1.8",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mattn/go-colorable@0.1.8?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mattn/go-isatty@0.0.12",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mattn/go-isatty@0.0.12?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mattn/go-sqlite3@1.14.5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mattn/go-sqlite3@1.14.5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/matttproud/golang_protobuf_extensions@1.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/matttproud/golang_protobuf_extensions@1.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mitchellh/go-homedir@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mitchellh/go-homedir@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mitchellh/mapstructure@1.3.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mitchellh/mapstructure@1.3.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/modern-go/concurrent@0.0.0-20180306012644-bacd9c7ef1dd",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/modern-go/concurrent@0.0.0-20180306012644-bacd9c7ef1dd?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/modern-go/reflect2@1.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/modern-go/reflect2@1.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/morikuni/aec@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/morikuni/aec@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/mwitkow/go-conntrack@0.0.0-20190716064945-2f068394615f",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/mwitkow/go-conntrack@0.0.0-20190716064945-2f068394615f?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/niemeyer/pretty@0.0.0-20200227124842-a10e7caefd8e",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/niemeyer/pretty@0.0.0-20200227124842-a10e7caefd8e?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/oklog/oklog@0.3.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/oklog/oklog@0.3.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/oklog/run@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/oklog/run@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/oklog/ulid@1.3.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/oklog/ulid@1.3.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/onsi/ginkgo@1.7.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/onsi/ginkgo@1.7.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/onsi/gomega@1.4.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/onsi/gomega@1.4.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/op/go-logging@0.0.0-20160315200505-970db520ece7",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/op/go-logging@0.0.0-20160315200505-970db520ece7?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/opencontainers/go-digest@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/opencontainers/go-digest@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/opencontainers/image-spec@1.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/opencontainers/image-spec@1.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/opentracing-contrib/go-observer@0.0.0-20170622124052-a52f23424492",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/opentracing-contrib/go-observer@0.0.0-20170622124052-a52f23424492?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/opentracing/opentracing-go@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/opentracing/opentracing-go@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/openzipkin-contrib/zipkin-go-opentracing@0.4.5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/openzipkin-contrib/zipkin-go-opentracing@0.4.5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/openzipkin/zipkin-go@0.2.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/openzipkin/zipkin-go@0.2.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/otiai10/copy@1.5.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/otiai10/copy@1.5.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/otiai10/curr@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/otiai10/curr@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/otiai10/mint@1.3.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/otiai10/mint@1.3.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/patrickmn/go-cache@2.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/patrickmn/go-cache@2.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/pborman/uuid@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/pborman/uuid@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/pelletier/go-toml@1.8.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/pelletier/go-toml@1.8.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/performancecopilot/speed@3.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/performancecopilot/speed@3.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/pierrec/lz4@1.0.2-0.20190131084431-473cd7ce01a1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/pierrec/lz4@1.0.2-0.20190131084431-473cd7ce01a1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/pkg/errors@0.8.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/pkg/errors@0.8.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/pkg/profile@1.2.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/pkg/profile@1.2.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/pmezard/go-difflib@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/pmezard/go-difflib@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/prometheus/client_golang@1.7.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/prometheus/client_golang@1.7.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/prometheus/client_model@0.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/prometheus/client_model@0.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/prometheus/common@0.10.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/prometheus/common@0.10.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/prometheus/procfs@0.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/prometheus/procfs@0.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/prometheus/tsdb@0.7.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/prometheus/tsdb@0.7.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/rcrowley/go-metrics@0.0.0-20181016184325-3113b8401b8a",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/rcrowley/go-metrics@0.0.0-20181016184325-3113b8401b8a?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/rogpeppe/fastuuid@0.0.0-20150106093220-6724a57986af",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/rogpeppe/fastuuid@0.0.0-20150106093220-6724a57986af?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/rogpeppe/go-internal@1.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/rogpeppe/go-internal@1.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/russross/blackfriday/v2@2.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/russross/blackfriday/v2@2.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/segmentio/ksuid@1.0.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/segmentio/ksuid@1.0.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/shopspring/decimal@0.0.0-20200227202807-02e2044944cc",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/shopspring/decimal@0.0.0-20200227202807-02e2044944cc?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/shurcooL/sanitized_anchor_name@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/shurcooL/sanitized_anchor_name@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/sirupsen/logrus@1.4.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/sirupsen/logrus@1.4.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/smartystreets/assertions@1.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/smartystreets/assertions@1.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/smartystreets/goconvey@1.6.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/smartystreets/goconvey@1.6.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/smartystreets/gunit@1.4.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/smartystreets/gunit@1.4.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/soheilhy/cmux@0.1.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/soheilhy/cmux@0.1.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/sony/gobreaker@0.4.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/sony/gobreaker@0.4.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spaolacci/murmur3@0.0.0-20180118202830-f09979ecbc72",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spaolacci/murmur3@0.0.0-20180118202830-f09979ecbc72?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spf13/afero@1.2.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spf13/afero@1.2.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spf13/cast@1.3.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spf13/cast@1.3.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spf13/cobra@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spf13/cobra@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spf13/jwalterweatherman@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spf13/jwalterweatherman@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spf13/pflag@1.0.5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spf13/pflag@1.0.5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/spf13/viper@1.4.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/spf13/viper@1.4.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/streadway/amqp@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/streadway/amqp@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/stretchr/objx@0.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/stretchr/objx@0.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/stretchr/testify@1.7.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/stretchr/testify@1.7.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/tmc/grpc-websocket-proxy@0.0.0-20190109142713-0ad062ec5ee5",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/tmc/grpc-websocket-proxy@0.0.0-20190109142713-0ad062ec5ee5?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/ugorji/go@1.1.7",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/ugorji/go@1.1.7?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/ugorji/go/codec@1.1.7",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/ugorji/go/codec@1.1.7?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/urfave/cli/v2@2.3.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/urfave/cli/v2@2.3.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/urfave/negroni@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/urfave/negroni@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/valyala/bytebufferpool@1.0.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/valyala/bytebufferpool@1.0.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/valyala/fasttemplate@1.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/valyala/fasttemplate@1.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/xiang90/probing@0.0.0-20190116061207-43a291ad63a2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/xiang90/probing@0.0.0-20190116061207-43a291ad63a2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/xordataexchange/crypt@0.0.3-0.20170626215501-b2862e3d0a77",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/xordataexchange/crypt@0.0.3-0.20170626215501-b2862e3d0a77?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/go.etcd.io/bbolt@1.3.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/go.etcd.io/bbolt@1.3.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/go.uber.org/atomic@1.6.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/go.uber.org/atomic@1.6.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/go.uber.org/multierr@1.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/go.uber.org/multierr@1.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/go.uber.org/tools@0.0.0-20190618225709-2cfd321de3ee",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/go.uber.org/tools@0.0.0-20190618225709-2cfd321de3ee?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/go.uber.org/zap@1.10.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/go.uber.org/zap@1.10.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/crypto@0.0.0-20190308221718-c2843e01d9a2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@0.0.0-20190308221718-c2843e01d9a2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"5121f5ff-9831-44a6-af2e-24f7301d1df7",
                    "Title":"[CVE-2019-11840]  Use of Insufficiently Random Values",
                    "Description":"An issue was discovered in supplementary Go cryptography libraries, aka golang-googlecode-go-crypto, before 2019-03-20. A flaw was found in the amd64 implementation of golang.org/x/crypto/salsa20 and golang.org/x/crypto/salsa20/salsa. If more than 256 GiB of keystream is generated, or if the counter otherwise grows greater than 32 bits, the amd64 implementation will first generate incorrect output, and then cycle back to previously generated keystream. Repeated keystream bytes can lead to loss of confidentiality in encryption applications, or to predictability in CSPRNG applications.",
                    "CvssScore":"5.9",
                    "CvssVector":"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "Cve":"CVE-2019-11840",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/5121f5ff-9831-44a6-af2e-24f7301d1df7?component-type=golang\u0026component-name=golang.org%2Fx%2Fcrypto\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/exp@0.0.0-20190306152737-a1d7652674e8",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/exp@0.0.0-20190306152737-a1d7652674e8?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/image@0.0.0-20190802002840-cff245a6509b",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/image@0.0.0-20190802002840-cff245a6509b?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/lint@0.0.0-20190930215403-16217165b5de",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/lint@0.0.0-20190930215403-16217165b5de?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/mobile@0.0.0-20190719004257-d2bd2a29d028",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/mobile@0.0.0-20190719004257-d2bd2a29d028?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/net@0.0.0-20210226172049-e18ecbb05110",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/net@0.0.0-20210226172049-e18ecbb05110?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/oauth2@0.0.0-20200107190931-bf48bf16ab8d",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/oauth2@0.0.0-20200107190931-bf48bf16ab8d?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/sync@0.0.0-20201020160332-67f06af15bc9",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/sync@0.0.0-20201020160332-67f06af15bc9?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/sys@0.0.0-20201214210602-f9fddec55a1e",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/sys@0.0.0-20201214210602-f9fddec55a1e?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/term@0.0.0-20201126162022-7de9c90e9dd1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/term@0.0.0-20201126162022-7de9c90e9dd1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/text@0.3.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/text@0.3.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/time@0.0.0-20200630173020-3af7569d3a1e",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/time@0.0.0-20200630173020-3af7569d3a1e?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/tools@0.0.0-20191029041327-9cc4af7d6b2c",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/tools@0.0.0-20191029041327-9cc4af7d6b2c?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/xerrors@0.0.0-20200804184101-5ec99f83aff1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/xerrors@0.0.0-20200804184101-5ec99f83aff1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/google.golang.org/appengine@1.6.6",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/google.golang.org/appengine@1.6.6?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/google.golang.org/genproto@0.0.0-20201106154455-f9bfe239b0ba",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/google.golang.org/genproto@0.0.0-20201106154455-f9bfe239b0ba?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/google.golang.org/grpc@1.36.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/google.golang.org/grpc@1.36.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/google.golang.org/grpc/cmd/protoc-gen-go-grpc@1.0.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/google.golang.org/grpc/cmd/protoc-gen-go-grpc@1.0.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/google.golang.org/protobuf@1.25.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/google.golang.org/protobuf@1.25.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/alecthomas/kingpin@2.2.6",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/alecthomas/kingpin@2.2.6?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/alexcesaro/quotedprintable@3.0.0-20150716171945-2caba252f4dc",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/alexcesaro/quotedprintable@3.0.0-20150716171945-2caba252f4dc?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-asn1-ber/asn1-ber@1.0.0-20181015200546-f715ec2f112d",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-asn1-ber/asn1-ber@1.0.0-20181015200546-f715ec2f112d?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-check/check@1.0.0-20200227125254-8fa46927fb4f",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-check/check@1.0.0-20200227125254-8fa46927fb4f?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-errgo/errgo@2.1.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-errgo/errgo@2.1.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-fsnotify/fsnotify@1.4.7",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-fsnotify/fsnotify@1.4.7?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-gcfg/gcfg@1.2.3",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-gcfg/gcfg@1.2.3?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-gomail/gomail@2.0.0-20160411212932-81ebce5c23df",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-gomail/gomail@2.0.0-20160411212932-81ebce5c23df?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-ini/ini@1.62.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-ini/ini@1.62.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-ldap/ldap@2.5.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-ldap/ldap@2.5.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-resty/resty@1.12.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-resty/resty@1.12.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-tomb/tomb@1.0.0-20141024135613-dd632973f1e7",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-tomb/tomb@1.0.0-20141024135613-dd632973f1e7?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-warnings/warnings@0.1.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-warnings/warnings@0.1.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-yaml/yaml@2.4.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@2.4.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/go-yaml/yaml@3.0.0-20200615113413-eeeca48fe776",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@3.0.0-20200615113413-eeeca48fe776?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/gorm.io/driver/sqlite@1.1.4",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/gorm.io/driver/sqlite@1.1.4?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/gorm.io/gorm@1.20.12",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/gorm.io/gorm@1.20.12?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/gotest.tools/v3@3.0.2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/gotest.tools/v3@3.0.2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/honnef.co/go/tools@0.0.0-20190523083050-ea95bdfd59fc",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/honnef.co/go/tools@0.0.0-20190523083050-ea95bdfd59fc?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/sourcegraph.com/sourcegraph/appdash@0.0.0-20190731080439-ebfcffb1b5c0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/sourcegraph.com/sourcegraph/appdash@0.0.0-20190731080439-ebfcffb1b5c0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                
            ],
            "InvalidSemVer":false
        }
    ],
    "excluded":null,
    "exclusions":[
        
    ],
    "invalid":[
        
    ],
    "num_audited":266,
    "num_exclusions":0,
    "num_vulnerable":4,
    "version":"1.0.29",
    "vulnerable":[
        {
            "Coordinates":"pkg:golang/github.com/coreos/etcd@3.3.10",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/etcd@3.3.10?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"bba60acb-c7b5-4621-af69-f4085a8301d0",
                    "Title":"[CVE-2020-15114] In etcd before versions 3.3.23 and 3.4.10, the etcd gateway is a simple TCP prox...",
                    "Description":"In etcd before versions 3.3.23 and 3.4.10, the etcd gateway is a simple TCP proxy to allow for basic service discovery and access. However, it is possible to include the gateway address as an endpoint. This results in a denial of service, since the endpoint can become stuck in a loop of requesting itself until there are no more available file descriptors to accept connections on the gateway.",
                    "CvssScore":"7.7",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
                    "Cve":"CVE-2020-15114",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/bba60acb-c7b5-4621-af69-f4085a8301d0?component-type=golang\u0026component-name=github.com%2Fcoreos%2Fetcd\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                },
                {
                    "ID":"5def94e5-b89c-4a94-b9c6-ae0e120784c2",
                    "Title":"[CVE-2020-15115] etcd before versions 3.3.23 and 3.4.10 does not perform any password length vali...",
                    "Description":"etcd before versions 3.3.23 and 3.4.10 does not perform any password length validation, which allows for very short passwords, such as those with a length of one. This may allow an attacker to guess or brute-force users' passwords with little computational effort.",
                    "CvssScore":"5.8",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
                    "Cve":"CVE-2020-15115",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/5def94e5-b89c-4a94-b9c6-ae0e120784c2?component-type=golang\u0026component-name=github.com%2Fcoreos%2Fetcd\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                },
                {
                    "ID":"d373dc3f-aa88-483b-b501-20fe5382cc80",
                    "Title":"[CVE-2020-15136] In ectd before versions 3.4.10 and 3.3.23, gateway TLS authentication is only ap...",
                    "Description":"In ectd before versions 3.4.10 and 3.3.23, gateway TLS authentication is only applied to endpoints detected in DNS SRV records. When starting a gateway, TLS authentication will only be attempted on endpoints identified in DNS SRV records for a given domain, which occurs in the discoverEndpoints function. No authentication is performed against endpoints provided in the --endpoints flag. This has been fixed in versions 3.4.10 and 3.3.23 with improved documentation and deprecation of the functionality.",
                    "CvssScore":"6.5",
                    "CvssVector":"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "Cve":"CVE-2020-15136",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/d373dc3f-aa88-483b-b501-20fe5382cc80?component-type=golang\u0026component-name=github.com%2Fcoreos%2Fetcd\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/dgrijalva/jwt-go@3.2.0",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/dgrijalva/jwt-go@3.2.0?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"c16fb56d-9de6-4065-9fca-d2b4cfb13020",
                    "Title":"[CVE-2020-26160] jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrict...",
                    "Description":"jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrictions in situations with []string{} for m[\"aud\"] (which is allowed by the specification). Because the type assertion fails, \"\" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check.",
                    "CvssScore":"7.5",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "Cve":"CVE-2020-26160",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/c16fb56d-9de6-4065-9fca-d2b4cfb13020?component-type=golang\u0026component-name=github.com%2Fdgrijalva%2Fjwt-go\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/github.com/gogo/protobuf@1.3.1",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/github.com/gogo/protobuf@1.3.1?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"dcf6da03-f9dd-4a4e-b792-0262de36a0b1",
                    "Title":"[CVE-2021-3121] An issue was discovered in GoGo Protobuf before 1.3.2. plugin/unmarshal/unmarsha...",
                    "Description":"An issue was discovered in GoGo Protobuf before 1.3.2. plugin/unmarshal/unmarshal.go lacks certain index validation, aka the \"skippy peanut butter\" issue.",
                    "CvssScore":"9.8",
                    "CvssVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "Cve":"CVE-2021-3121",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/dcf6da03-f9dd-4a4e-b792-0262de36a0b1?component-type=golang\u0026component-name=github.com%2Fgogo%2Fprotobuf\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        },
        {
            "Coordinates":"pkg:golang/golang.org/x/crypto@0.0.0-20190308221718-c2843e01d9a2",
            "Reference":"https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@0.0.0-20190308221718-c2843e01d9a2?utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
            "Vulnerabilities":[
                {
                    "ID":"5121f5ff-9831-44a6-af2e-24f7301d1df7",
                    "Title":"[CVE-2019-11840]  Use of Insufficiently Random Values",
                    "Description":"An issue was discovered in supplementary Go cryptography libraries, aka golang-googlecode-go-crypto, before 2019-03-20. A flaw was found in the amd64 implementation of golang.org/x/crypto/salsa20 and golang.org/x/crypto/salsa20/salsa. If more than 256 GiB of keystream is generated, or if the counter otherwise grows greater than 32 bits, the amd64 implementation will first generate incorrect output, and then cycle back to previously generated keystream. Repeated keystream bytes can lead to loss of confidentiality in encryption applications, or to predictability in CSPRNG applications.",
                    "CvssScore":"5.9",
                    "CvssVector":"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "Cve":"CVE-2019-11840",
                    "Reference":"https://ossindex.sonatype.org/vulnerability/5121f5ff-9831-44a6-af2e-24f7301d1df7?component-type=golang\u0026component-name=golang.org%2Fx%2Fcrypto\u0026utm_source=nancy-client\u0026utm_medium=integration\u0026utm_content=1.0.29",
                    "Excluded":false
                }
            ],
            "InvalidSemVer":false
        }
    ]
}
`

const outputRateLimit = `Error: Failed to query the GitHub API for updates.

This is most likely due to GitHub rate-limiting on unauthenticated requests.

To make authenticated requests please:

  1. Generate a token at https://github.com/settings/tokens
  2. Set the token by either adding it to your ~/.gitconfig or
     setting the GITHUB_TOKEN environment variable.

Instructions for generating a token can be found at:
https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/

We call the GitHub releases API to look for new releases.
More information about that API can be found here: https://developer.github.com/v3/repos/releases/

: Get \"https://api.github.com/repos/sonatype-nexus-community/nancy/releases\": net/http: TLS handshake timeout

For more information, check the log file at /root/.ossindex/nancy.combined.log
nancy version: 1.0.28

Usage:
  nancy sleuth [flags]

Examples:
  go list -json -deps | nancy sleuth --username your_user --token your_token
  nancy sleuth -p Gopkg.lock --username your_user --token your_token

Flags:
  -e, --exclude-vulnerability CveListFlag   Comma separated list of CVEs or OSS Index IDs to exclude (default [])
  -x, --exclude-vulnerability-file string   Path to a file containing newline separated CVEs or OSS Index IDs to be excluded (default \"./.nancy-ignore\")
  -h, --help                                help for sleuth
  -n, --no-color                            indicate output should not be colorized
  -o, --output string                       Styling for output format. json, json-pretty, text, csv (default \"text\")

Global Flags:
  -v, -- count                 Set log level, multiple v's is more verbose
  -d, --db-cache-path string   Specify an alternate path for caching responses from OSS Inde, example: /tmp
      --loud                   indicate output should include non-vulnerable packages
  -p, --path string            Specify a path to a dep Gopkg.lock file for scanning
  -q, --quiet                  indicate output should contain only packages with vulnerabilities (default true)
      --skip-update-check      Skip the check for updates.
  -t, --token string           Specify OSS Index API token for request
  -u, --username string        Specify OSS Index username for request
  -V, --version                Get the version

go list -m: dmitri.shuralyov.com/gpu/mtl@v0.0.0-20190408044501-666a987793e9: Get \"https://proxy.golang.org/dmitri.shuralyov.com/gpu/mtl/@v/v0.0.0-20190408044501-666a987793e9.mod\": net/http: TLS handshake timeout`
