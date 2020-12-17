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

package flawfinder

import (
	"bytes"
	"encoding/csv"
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
)

func getCsvString() string {
	pairs := [][]string{
		{"File", "./test.c"},
		{"Line", "16"},
		{"Column", "9"},
		{"Level", "5"},
		{"Category", "4"},
		{"Name", "test"},
		{"Warning", "test"},
		{"Suggestion", "test"},
		{"Note", "test"},
		{"CWEs", "test"},
		{"Context", "test"},
		{"Fingerprint", "test"},
	}

	buffer := new(bytes.Buffer)
	writer := csv.NewWriter(buffer)

	_ = writer.WriteAll(pairs)
	return buffer.String()
}

func TestStartCFlawfinder(t *testing.T) {
	t.Run("should success execute container and process output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		output := getCsvString()

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.NotEmpty(t, analysis)
		assert.Len(t, analysis.AnalysisVulnerabilities, 11)
	})

	t.Run("should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.SetToolsToIgnore([]string{"flawfinder"})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
