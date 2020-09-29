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

package brakeman

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

func TestParseOutput(t *testing.T) {
	t.Run("Should success parse output to analysis", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		output := "{\"warnings\":[{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"Low\"},{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"Medium\"},{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"High\"},{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"Test\"}]}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})

		assert.Len(t, analysis.Vulnerabilities, 4)
	})

	t.Run("Should return error when parsing invalid output", func(t *testing.T) {
		analysis := &horusec.Analysis{}

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})

	t.Run("Should return error when something went wrong in container", func(t *testing.T) {
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
	})
}
