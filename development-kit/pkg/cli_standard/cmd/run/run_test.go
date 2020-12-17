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

package run

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/engines/java/regular"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/jvm/and"

	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type TestController struct {
}

func (t *TestController) StartAnalysis() error {
	return nil
}

func TestNewRunCommand(t *testing.T) {
	t.Run("Should create new run and not return empty", func(t *testing.T) {
		assert.IsType(t, NewRunCommand(&config.Config{}, nil), &Run{})
	})
}

func TestRun_CreateCobraCmd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Run("Should return error because not exists path to run in analysis", func(t *testing.T) {
		configs := config.NewConfig()
		configs.OutputFilePath = uuid.New().String() + "-tmp.json"
		configs.ProjectPath = "./not exists path"
		cmd := NewRunCommand(configs, &TestController{})

		cobraCmd := cmd.CreateCobraCmd()

		stdoutMock := bytes.NewBufferString("")
		cobraCmd.SetOut(stdoutMock)
		logrus.SetOutput(stdoutMock)

		assert.Error(t, cobraCmd.Execute())
	})
	t.Run("Should return error because output is empty to run in analysis", func(t *testing.T) {
		configs := config.NewConfig()
		configs.OutputFilePath = ""
		configs.ProjectPath = "./"
		cmd := NewRunCommand(configs, &TestController{})

		cobraCmd := cmd.CreateCobraCmd()

		stdoutMock := bytes.NewBufferString("")
		cobraCmd.SetOut(stdoutMock)
		logrus.SetOutput(stdoutMock)

		assert.Error(t, cobraCmd.Execute())
	})
	t.Run("Should return success in analysis with kotlin", func(t *testing.T) {
		configs := config.NewConfig()
		configs.OutputFilePath = uuid.New().String() + "-tmp.json"
		configs.ProjectPath = "../../../engines/examples/kotlin-hardcodedpass"
		cmd := NewRunCommand(configs, &TestController{})

		cobraCmd := cmd.CreateCobraCmd()

		stdoutMock := bytes.NewBufferString("")
		cobraCmd.SetOut(stdoutMock)
		logrus.SetOutput(stdoutMock)

		assert.NoError(t, cobraCmd.Execute())
		content, err := ioutil.ReadFile(configs.OutputFilePath)
		assert.NoError(t, err)
		strContent := string(content)
		assert.Contains(t, strContent, and.NewJvmAndPotentialAndroidSQLInjection().Metadata.ID)
		assert.NoError(t, os.RemoveAll(configs.OutputFilePath))
	})
	t.Run("Should return success in analysis with java", func(t *testing.T) {
		configs := config.NewConfig()
		configs.OutputFilePath = uuid.New().String() + "-tmp.json"
		configs.ProjectPath = "../../../engines/examples/java-hardcodedpass"
		cmd := NewRunCommand(configs, &TestController{})

		cobraCmd := cmd.CreateCobraCmd()

		stdoutMock := bytes.NewBufferString("")
		cobraCmd.SetOut(stdoutMock)
		logrus.SetOutput(stdoutMock)

		assert.NoError(t, cobraCmd.Execute())
		content, err := ioutil.ReadFile(configs.OutputFilePath)
		assert.NoError(t, err)
		assert.Contains(t, string(content), regular.NewJavaRegularInsecureRandomNumberGenerator().Metadata.ID)
		assert.NoError(t, os.RemoveAll(configs.OutputFilePath))
	})
}
