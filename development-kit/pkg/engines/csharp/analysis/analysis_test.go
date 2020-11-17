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

package analysis

import (
	"encoding/json"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

func TestNewAnalysis(t *testing.T) {
	assert.IsType(t, NewAnalysis(config.NewConfig()), &Analysis{})
}

func TestAnalysis_StartAnalysis(t *testing.T) {
	t.Run("Should return success when read analysis and return seven vulnerabilities", func(t *testing.T) {
		configs := config.NewConfig()
		configs.SetOutputFilePath("./csharp-tmp.output.json")
		configs.SetProjectPath("../../examples/csharp-generic-vuln")
		err := NewAnalysis(configs).StartAnalysis()
		assert.NoError(t, err)
		fileBytes, err := ioutil.ReadFile("./csharp-tmp.output.json")
		data := []engine.Finding{}
		_ = json.Unmarshal(fileBytes, &data)
		assert.NoError(t, os.RemoveAll(configs.GetOutputFilePath()))
		assert.Equal(t, len(data), 7)
	})
	t.Run("Should return error when create file", func(t *testing.T) {
		configs := config.NewConfig()
		configs.SetOutputFilePath("./////")
		err := NewAnalysis(configs).StartAnalysis()
		assert.Error(t, err)
	})
	t.Run("Should return error when get units in project path", func(t *testing.T) {
		configs := config.NewConfig()
		configs.SetOutputFilePath("./////")
		configs.SetProjectPath("./not exists path")
		err := NewAnalysis(configs).StartAnalysis()
		assert.Error(t, err)
	})
}
