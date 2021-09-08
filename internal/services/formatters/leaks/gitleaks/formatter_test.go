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

package gitleaks

import (
	"errors"
	"testing"
	"time"

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumsAnalysis "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func AnalysisMock() *entitiesAnalysis.Analysis {
	return &entitiesAnalysis.Analysis{
		ID:           uuid.New(),
		CreatedAt:    time.Now(),
		RepositoryID: uuid.New(),
		Status:       enumsAnalysis.Running,
	}
}

func TestLeaks_StartAnalysis(t *testing.T) {
	t.Run("Should run analysis without panics and save on cache with success", func(t *testing.T) {
		analysis := AnalysisMock()
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		outputAnalysis := `[
			{"line":"-----BEGIN RSA PRIVATE KEY----- # nohorus","offender":"-----BEGIN RSA PRIVATE KEY-----","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Asymmetric Private Key","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/ca-key.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, AsymmetricPrivateKey"},
			{"line":"MKOflkTJ5RBPwsdKWCpK7JqJxnn2e272n0pC3ypXmCS712HfTaKlVygmI9v/QTqv","offender":"PwsdKWCpK7JqJxnn2e272n0pC3ypXmCS712HfTaKlVygmI9v","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/ca-key.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"lxVW5OXCiGs7ONS61vXKT/so0NzczB0Jt1WUpW4soG6kv7W3SpHzbd7z","offender":"pW4soG6kv7W3SpHzbd7z","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/ca.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"Ntlbml+n7NguIMBx+zwKEY+3SDlgLkb28Z7hVpaKQ88SfJo9C1P83GFQpKdmA1ob","offender":"KEY+3SDlgLkb28Z7hVpaKQ88SfJo9C1P83GFQpKdmA1ob","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/client-horusecapi-cert.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"-----BEGIN RSA PRIVATE KEY-----","offender":"-----BEGIN RSA PRIVATE KEY-----","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Asymmetric Private Key","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/client-horusecapi-key.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, AsymmetricPrivateKey"},
			{"line":"xNt/c91dcZ8b0NGwGuvPrt+YfUVMhFJFkfZIWR/PWm5J9PNnepEiE0iNWVu+Rfeo","offender":"PWm5J9PNnepEiE0iNWVu","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/server-cert.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"-----BEGIN RSA PRIVATE KEY-----","offender":"-----BEGIN RSA PRIVATE KEY-----","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Asymmetric Private Key","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/server-key.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, AsymmetricPrivateKey"},
			{"line":"FTvN6nFxgkX+r7h8WlypuQgAXKMPWRe1b+kpYgVNXAI1hZIojvYrWjeFMYakTL95","offender":"PWRe1b+kpYgVNXAI1hZIojvYrWjeFMYakTL95","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/server-key.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"raF4c43wos78OqvYCPwvdVvFJnwfrx16C6QeYpB0kQKCAQEA/coKlLrp0Y/k2WKv","offender":"PwvdVvFJnwfrx16C6QeYpB0kQKCAQEA","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/certs/server-key.pem","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"    ./deployments/scripts/create-certs.sh -m ca -pw \"horusecCertPassphrase\" -t deployments/certs -e 900","offender":"pw \"horusecCertPassphrase","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/scripts/run-create-certs.sh","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"    ./deployments/scripts/create-certs.sh -m server -h dockerapi -pw \"horusecCertPassphrase\" -t deployments/certs -e 365","offender":"pw \"horusecCertPassphrase","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/scripts/run-create-certs.sh","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"    ./deployments/scripts/create-certs.sh -m client -h horusecapi -pw \"horusecCertPassphrase\" -t deployments/certs -e 365","offender":"pw \"horusecCertPassphrase","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/scripts/run-create-certs.sh","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"},
			{"line":"    ./deployments/scripts/create-certs.sh -m tls -h dockerapi -pw \"horusecCertPassphrase\" -t api -e 365","offender":"pw \"horusecCertPassphrase","commit":"736d81a5a1dc3a14a88a526c01c99a9ba50b7af7","repo":"code","rule":"Generic Credential","commitMessage":"Adding gitleaks\n","author":"Wilian Gabriel","email":"wilian.silva@zup.com.br","file":"deployments/scripts/run-create-certs.sh","date":"2020-05-06T16:15:25-03:00","tags":"key, API, generic"}
		]`

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		leaksAnalyzer := NewFormatter(service)

		assert.NotPanics(t, func() {
			leaksAnalyzer.StartAnalysis("")
		})
	})

	t.Run("Should run no error when empty output", func(t *testing.T) {
		analysis := AnalysisMock()
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		leaksAnalyzer := NewFormatter(service)

		assert.NotPanics(t, func() {
			leaksAnalyzer.StartAnalysis("")
		})
	})

	t.Run("Should run analysis and return error and up docker_api and save on cache with error", func(t *testing.T) {
		analysis := AnalysisMock()
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("some error"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		leaksAnalyzer := NewFormatter(service)

		assert.NotPanics(t, func() {
			leaksAnalyzer.StartAnalysis("")
		})
	})

	t.Run("Should run analysis and return error and up docker_api and save on cache with error", func(t *testing.T) {
		analysis := AnalysisMock()
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		outputAnalysis := "is some a text aleatory"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		leaksAnalyzer := NewFormatter(service)

		assert.NotPanics(t, func() {
			leaksAnalyzer.StartAnalysis("")
		})
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{GitLeaks: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
