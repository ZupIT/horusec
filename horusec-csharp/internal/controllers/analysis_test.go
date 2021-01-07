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

package controllers

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/stretchr/testify/assert"
)

func TestNewAnalysis(t *testing.T) {
	assert.IsType(t, NewAnalysis(config.NewConfig()), &Analysis{})
}

func TestAnalysis_StartAnalysis(t *testing.T) {
	t.Run("should return success when read analysis and return 5 vulnerabilities", func(t *testing.T) {
		configs := config.NewConfig()

		configs.SetOutputFilePath("./csharp-tmp.output.json")
		configs.SetProjectPath("../../../examples/csharp/example1")

		assert.NoError(t, NewAnalysis(configs).StartAnalysis())

		fileBytes, err := ioutil.ReadFile("./csharp-tmp.output.json")
		assert.NoError(t, err)

		var data []engine.Finding
		_ = json.Unmarshal(fileBytes, &data)

		assert.NoError(t, os.RemoveAll(configs.GetOutputFilePath()))
		assert.Equal(t, len(data), 5)
	})

	t.Run("should return error when create file", func(t *testing.T) {
		configs := config.NewConfig()

		configs.SetOutputFilePath("./////")

		assert.Error(t, NewAnalysis(configs).StartAnalysis())
	})

	t.Run("should return error when get units in project path", func(t *testing.T) {
		configs := config.NewConfig()

		configs.SetOutputFilePath("./////")
		configs.SetProjectPath("./not exists path")

		assert.Error(t, NewAnalysis(configs).StartAnalysis())
	})
}
