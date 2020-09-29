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

package gosec

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

func TestGoLang_StartAnalysis(t *testing.T) {
	t.Run("Should run analysis and return error because output is empty", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(&horusec.Analysis{}, dockerAPIControllerMock, config, &horusec.Monitor{})

		golangAnalyser := NewFormatter(service)

		assert.NotPanics(t, func() {
			golangAnalyser.StartAnalysis("")
		})
	})

	t.Run("Should run analysis without panics and save on cache with success", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		outputAnalysis := `{
		"Golang errors":{
			"/go/src/code/api/server.go":[{"line":20,"column":42,"error":"Healthcheck not declared by package routes"}]
		},
		"Issues":[
			{"severity":"MEDIUM","confidence":"HIGH","cwe":{"ID":"327","URL":"https://cwe.mitre.org/data/definitions/327.html"},"rule_id":"G501","details":"Blacklisted import crypto/md5: weak cryptographic primitive","file":"/go/src/code/api/util/util.go","code":"\"crypto/md5\"","line":"4","column":"2"},
			{"severity":"MEDIUM","confidence":"HIGH","cwe":{"ID":"326","URL":"https://cwe.mitre.org/data/definitions/326.html"},"rule_id":"G401","details":"Use of weak cryptographic primitive","file":"/go/src/code/api/util/util.go","code":"md5.New()","line":"23","column":"7"},
			{"severity":"LOW","confidence":"HIGH","cwe":{"ID":"703","URL":"https://cwe.mitre.org/data/definitions/703.html"},"rule_id":"G104","details":"Errors unhandled.","file":"/go/src/code/api/util/util.go","code":"io.WriteString(h, s)","line":"24","column":"2"},
			{"severity":"HIGH","confidence":"HIGH","cwe":{"ID":"746","URL":"https://cwe.mitre.org/data/definitions/746.html"},"rule_id":"G746","details":"Password hard codede","file":"/go/src/code/api/server.go","code":"password","line":"2","column":"6"},
			{"severity":"LOW","confidence":"HIGH","cwe":{"ID":"001","URL":"https://cwe.mitre.org/data/definitions/001.html"},"rule_id":"G001","details":"Rename Import","file":"/go/src/code/api/server.go","code":"cache := cache.NewCache() //nohorus","line":"15","column":"2"}
		],
		"Stats":{"files":4,"lines":70,"nosec":1,"found":4}
		}`

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		service := formatters.NewFormatterService(&horusec.Analysis{}, dockerAPIControllerMock, config, &horusec.Monitor{})

		golangAnalyser := NewFormatter(service)

		assert.NotPanics(t, func() {
			golangAnalyser.StartAnalysis("")
		})
	})

	t.Run("Should run analysis and return error and up docker_api and save on cache with error", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("some error"))

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(&horusec.Analysis{}, dockerAPIControllerMock, config, &horusec.Monitor{})

		golangAnalyser := NewFormatter(service)

		assert.NotPanics(t, func() {
			golangAnalyser.StartAnalysis("")
		})
	})

	t.Run("Should run analysis and return error because output is wrong", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		outputAnalysis := "is some a text aleatory"

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		service := formatters.NewFormatterService(&horusec.Analysis{}, dockerAPIControllerMock, config, &horusec.Monitor{})

		golangAnalyser := NewFormatter(service)

		assert.NotPanics(t, func() {
			golangAnalyser.StartAnalysis("")
		})
	})
}
