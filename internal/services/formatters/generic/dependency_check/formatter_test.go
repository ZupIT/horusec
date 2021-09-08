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

package dependencycheck

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

const output = "{ \"dependencies\":[ { \"isVirtual\":false, \"fileName\":\"app.js\", \"filePath\":\"\\/src\\/app.js" +
	"\", \"md5\":\"d3bf3a62b0f02ffaa11516d7f1aa7c83\", \"sha1\":\"eac9ad35db19d0f30eee6f4704e57634ea4f6f9c\", \"sh" +
	"a256\":\"39bf0d903ffaef9ecddbdb40a3658a2bd5a3fdb1741ccd58a6cf58be841ec692\", \"evidenceCollected\":{ \"vendor" +
	"Evidence\":[ ], \"productEvidence\":[ ], \"versionEvidence\":[ ] } }, { \"isVirtual\":true, \"fileName\":\"co" +
	"okie-signature:1.0.3\", \"filePath\":\"\\/src\\/package-lock.json?cookie-signature\", \"projectReferences\":[" +
	" \"package-lock.json: transitive\" ], \"evidenceCollected\":{ \"vendorEvidence\":[ { \"type\":\"vendor\", \"c" +
	"onfidence\":\"HIGH\", \"source\":\"package.json\", \"name\":\"name\", \"value\":\"cookie-signature\" } ], \"p" +
	"roductEvidence\":[ { \"type\":\"product\", \"confidence\":\"HIGHEST\", \"source\":\"package.json\", \"name\"" +
	":\"name\", \"value\":\"cookie-signature\" } ], \"versionEvidence\":[ { \"type\":\"version\", \"confidence\"" +
	":\"HIGHEST\", \"source\":\"package.json\", \"name\":\"version\", \"value\":\"1.0.3\" } ] }, \"packages\":[ { " +
	"\"id\":\"pkg:npm\\/cookie-signature@1.0.3\", \"confidence\":\"HIGHEST\", \"url\":\"https:\\/\\/ossindex.sona" +
	"type.org\\/component\\/pkg:npm\\/cookie-signature@1.0.3?utm_source=dependency-check&utm_medium=integration&ut" +
	"m_content=6.2.2\" } ], \"vulnerabilities\":[ { \"source\":\"NPM\", \"name\":\"134\", \"unscored\":\"true\"," +
	" \"severity\":\"moderate\", \"cwes\":[ ], \"description\":\"Affected versions of `cookie-signature` are vul" +
	"nerable to timing attacks as a result of using a fail-early comparison instead of a constant-time comparison" +
	". \\n\\nTiming attacks remove the exponential increase in entropy gained from increased secret length, by pr" +
	"oviding per-character feedback on the correctness of a guess via miniscule timing differences.\\n\\nUnder fav" +
	"orable network conditions, an attacker can exploit this to guess the secret in no more than `charset*length` " +
	"guesses, instead of `charset^length` guesses required were the timing attack not present. \\n\", \"notes\":\"" +
	"\", \"references\":[ { \"source\":\"Advisory 134: Timing Attack\", \"name\":\"- [Commit #3979108](https:\\/\\" +
	"/github.com\\/tj\\/node-cookie-signature\\/commit\\/39791081692e9e14aa62855369e1c7f80fbfd50e)\" } ], \"vulnera" +
	"bleSoftware\":[ { \"software\":{ \"id\":\"cpe:2.3:a:*:cookie-signature:\\\\<\\\\=1.0.5:*:*:*:*:*:*:*\" } } ]" +
	" }, { \"source\":\"OSSINDEX\", \"name\":\"CWE-208: Information Exposure Through Timing Discrepancy\", \"unsc" +
	"ored\":\"true\", \"severity\":\"Unknown\", \"cwes\":[ \"CWE-208\" ], \"description\":\"Two separate operatio" +
	"ns in a product require different amounts of time to complete, in a way that is observable to an actor and " +
	"reveals security-relevant information about the state of the product, such as whether a particular operation" +
	" was successful or not.\", \"notes\":\"\", \"references\":[ { \"source\":\"OSSINDEX\", \"url\":\"https:\\/\\" +
	"/ossindex.sonatype.org\\/vulnerability\\/bf671e3a-9d6a-4d46-a724-01b92b80e7a3?component-type=npm&component-n" +
	"ame=cookie-signature&utm_source=dependency-check&utm_medium=integration&utm_content=6.2.2\", \"name\":\"CWE-" +
	"208: Information Exposure Through Timing Discrepancy\" } ], \"vulnerableSoftware\":[ { \"software\":{ \"id\"" +
	":\"cpe:2.3:a:*:cookie-signature:1.0.3:*:*:*:*:*:*:*\", \"vulnerabilityIdMatched\":\"true\" } } ] } ] } ] }"

func TestStartGenericOwaspDependencyCheck(t *testing.T) {
	t.Run("should success execute container and process output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		config.EnableOwaspDependencyCheck = true
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.NotEmpty(t, analysis)
		assert.Len(t, analysis.AnalysisVulnerabilities, 1)
	})

	t.Run("should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("{", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return nil when empty output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{OwaspDependencyCheck: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
