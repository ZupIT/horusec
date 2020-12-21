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

package start

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/requirements"
	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/zip"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/analyser"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/usecases/cli"
	"github.com/ZupIT/horusec/horusec-cli/internal/utils/prompt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("analysis")

	code := m.Run()

	_ = os.RemoveAll("analysis")
	os.Exit(code)
}

func TestNewStartCommand(t *testing.T) {
	t.Run("Should run NewStartCommand and return type correctly", func(t *testing.T) {
		assert.IsType(t, NewStartCommand(&config.Config{}), &Start{})
	})
}

func TestStartCommand_Execute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	globalCmd := &cobra.Command{}
	_ = globalCmd.PersistentFlags().String("log-level", "", "Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"")
	_ = globalCmd.PersistentFlags().String("config-file-path", "", "Path of the file horusec-config.json to setup content of horusec")
	t.Run("Should execute command exec without error and ask to user if is to run in current directory", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := config.NewConfig()
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			globalCmd:              globalCmd,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.Empty(t, output)

		promptMock.AssertCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error and not ask if is to run in current directory", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./"})

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.Empty(t, output)

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec and return error because found vulnerabilities", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(10, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./", "-e", "true"})

		assert.Error(t, cobraCmd.Execute())

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec and return error because found error when ask", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("", errors.New("some error"))

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-e", "true"})

		assert.Error(t, cobraCmd.Execute())

		promptMock.AssertCalled(t, "Ask")
	})
	t.Run("Should execute command exec and return error because found not accept proceed", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("N", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-e", "true"})

		assert.Error(t, cobraCmd.Execute())

		promptMock.AssertCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error and not ask because is different project path", func(t *testing.T) {
		_ = os.Setenv(config.EnvProjectPath, "/tmp")
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-e", "true"})

		assert.NoError(t, cobraCmd.Execute())

		promptMock.AssertNotCalled(t, "Ask")
		_ = os.Setenv(config.EnvProjectPath, "")
	})
	t.Run("Should execute command exec without error and validate if git is installed", func(t *testing.T) {
		_ = os.Setenv(config.EnvEnableGitHistoryAnalysis, "true")
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")
		requirementsMock.On("ValidateGit")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-e", "true"})

		assert.NoError(t, cobraCmd.Execute())

		promptMock.AssertCalled(t, "Ask")
		_ = os.Setenv(config.EnvEnableGitHistoryAnalysis, "")
	})
	t.Run("Should execute command exec and return error because found error in configs", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()
		analyserControllerMock := &analyser.Mock{}
		analyserControllerMock.On("AnalysisDirectory").Return(10, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     analyserControllerMock,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./", "-a", "NOT_VALID_AUTHORIZATION", "-e", "true"})

		assert.Error(t, cobraCmd.Execute())

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error using json output", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     nil,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./", "-o", "json", "-O", "./tmp-json.json"})

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location:")
		assert.Contains(t, output, "Hold on! Horusec still analysis your code. Timeout in: 600s")
		assert.Contains(t, output, "{HORUSEC_CLI} Writing output JSON to file in the path:")
		assert.Contains(t, output, "horusec-cli/cmd/horusec/start/tmp-json.json")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		bytesFile, err := ioutil.ReadFile("./tmp-json.json")
		assert.NoError(t, err)
		bytesFileString := string(bytesFile)
		assert.Contains(t, bytesFileString, "\"analysisVulnerabilities\": null")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll("./tmp-json.json"))
	})
	t.Run("Should execute command exec without error using sonarqube output", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     nil,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./", "-o", "sonarqube", "-O", "./tmp-sonarqube.json"})

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location:")
		assert.Contains(t, output, "Hold on! Horusec still analysis your code. Timeout in: 600s")
		assert.Contains(t, output, "{HORUSEC_CLI} Writing output JSON to file in the path:")
		assert.Contains(t, output, "horusec-cli/cmd/horusec/start/tmp-sonarqube.json")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		bytesFile, err := ioutil.ReadFile("./tmp-sonarqube.json")
		assert.NoError(t, err)
		bytesFileString := string(bytesFile)
		assert.Contains(t, bytesFileString, "\"issues\": null")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll("./tmp-sonarqube.json"))
	})
	t.Run("Should execute command exec without error and return vulnerabilities of gitleaks but ignore vulnerabilities of the HIGH", func(t *testing.T) {
		srcZip := "../../../../development-kit/pkg/utils/test/zips/gitleaks/gitleaks.zip"
		dstZip := "./analysis/" + uuid.New().String()
		err := zip.NewZip().UnZip(srcZip, dstZip)
		assert.NoError(t, err)
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     nil,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", dstZip, "-s", "HIGH"})

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location:")
		assert.Contains(t, output, "Hold on! Horusec still analysis your code. Timeout in: 600s")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(dstZip))
	})
	t.Run("Should execute command exec without error and return vulnerabilities of gitleaks and return error", func(t *testing.T) {
		srcZip := "../../../../development-kit/pkg/utils/test/zips/gitleaks/gitleaks.zip"
		dstZip := "./analysis/" + uuid.New().String()
		err := zip.NewZip().UnZip(srcZip, dstZip)
		assert.NoError(t, err)
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})
		configs.NewConfigsFromEnvironments()

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			globalCmd:              globalCmd,
			useCases:               cli.NewCLIUseCases(),
			configs:                configs,
			startPrompt:            promptMock,
			analyserController:     nil,
			requirementsController: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", dstZip})

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location:")
		assert.Contains(t, output, "Hold on! Horusec still analysis your code. Timeout in: 600s")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "[HORUSEC] 6 VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, TO SEE MORE DETAILS USE THE LOG LEVEL AS DEBUG AND TRY AGAIN")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(dstZip))
	})
}
