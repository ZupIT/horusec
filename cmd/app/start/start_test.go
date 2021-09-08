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
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec/internal/controllers/requirements"

	"github.com/sirupsen/logrus"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/controllers/analyzer"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/usecases/cli"
	"github.com/ZupIT/horusec/internal/utils/copy"
	"github.com/ZupIT/horusec/internal/utils/prompt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {

	_ = os.RemoveAll("./examples")
	_ = os.RemoveAll("./tmp")
	_ = os.MkdirAll("./tmp", 0750)
	code := m.Run()

	_ = os.RemoveAll("./examples")
	_ = os.RemoveAll("./tmp")
	os.Exit(code)
}

func TestNewStartCommand(t *testing.T) {
	t.Run("Should run NewStartCommand and return type correctly", func(t *testing.T) {
		assert.IsType(t, NewStartCommand(config.New()), &Start{})
	})
}

func TestStartCommand_Execute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	t.Run("Should execute command exec without error and ask to user if is to run in current directory", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)

		assert.NoError(t, cobraCmd.Execute())

		promptMock.AssertCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error and not ask if is to run in current directory", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./"})

		assert.NoError(t, cobraCmd.Execute())

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec and return error because found vulnerabilities", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(10, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-p", "./", "-e", "true"})

		assert.Error(t, cobraCmd.Execute())

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec and return error because found error when ask but run in current folder", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("", errors.New("some error"))

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
		}

		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(stdoutMock)
		cobraCmd.SetArgs([]string{"-e", "true"})

		assert.NoError(t, cobraCmd.Execute())

		promptMock.AssertCalled(t, "Ask")
	})
	t.Run("Should execute command exec and return error because found not accept proceed", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("N", nil)

		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
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

		configs := config.New().MergeFromEnvironmentVariables()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
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

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(0, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")
		requirementsMock.On("ValidateGit")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
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

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		analyzerControllerMock := &analyzer.Mock{}
		analyzerControllerMock.On("AnalysisDirectory").Return(10, nil)

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     analyzerControllerMock,
			requirements: requirementsMock,
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

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}

		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "-o", "json", "-O", "./tmp-json.json"})

		cobra.OnInitialize(func() {
			assert.NoError(t, configs.Normalize().Eval(), "Expected nil error to eval config")
		})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		assert.NoError(t, err)
		os.Stdout = oldStdout
		output := <-outC

		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} Writing output JSON to file in the path:")
		assert.Contains(t, output, "cmd/app/start/tmp-json.json")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")

		bytesFile, err := ioutil.ReadFile("./tmp-json.json")
		assert.NoError(t, err)
		bytesFileString := string(bytesFile)
		assert.Contains(t, bytesFileString, "\"analysisVulnerabilities\": null")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll("./tmp-json.json"))
	})
	t.Run("Should execute command exec without error showing info vulnerabilities", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}
		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "--information-severity", "true"})

		cobra.OnInitialize(func() {
			require.Nil(t, configs.Normalize().Eval(), "Expected nil error to eval config")
		})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		assert.NotContains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error sending to web application", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}
		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "-u", "https://google.com", "-a", uuid.NewString()})

		cobra.OnInitialize(func() {
			require.Nil(t, configs.Normalize().Eval(), "Expected nil error to eval config")
		})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.NotContains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error using sonarqube output", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}

		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "-o", "sonarqube", "-O", "./tmp-sonarqube.json"})

		cobra.OnInitialize(func() {
			require.Nil(t, configs.Normalize().Eval(), "Expected nil error to eval config")
		})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} Writing output JSON to file in the path:")
		assert.Contains(t, output, "cmd/app/start/tmp-sonarqube.json")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")

		bytesFile, err := ioutil.ReadFile("./tmp-sonarqube.json")
		assert.NoError(t, err)
		bytesFileString := string(bytesFile)
		assert.Contains(t, bytesFileString, "\"issues\": []")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll("./tmp-sonarqube.json"))
	})
	t.Run("Should execute command exec without error and return vulnerabilities of gitleaks but ignore vulnerabilities of the HIGH", func(t *testing.T) {
		srcProject := "../../../examples/leaks/example1"
		dstProject := "./examples/" + uuid.New().String()
		assert.NoError(t, copy.Copy(srcProject, dstProject, func(src string) bool {
			return false
		}))
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		configs := config.New()
		configs.SetConfigFilePath("./not-exists.json")
		configs.SetWorkDir(&workdir.WorkDir{})

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}

		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", dstProject, "-s", "CRITICAL, LOW"})

		cobra.OnInitialize(func() {
			require.Nil(t, configs.Normalize().Eval(), "Expected nil error to eval config")
		})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "Total of Vulnerability MEDIUM is: 5")
		assert.Contains(t, output, "Total of Vulnerability HIGH is: 11")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "[HORUSEC] 16 VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, TO SEE MORE DETAILS USE THE LOG LEVEL AS DEBUG AND TRY AGAIN")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(dstProject))
	})
	t.Run("Should execute command exec without error and return vulnerabilities of gitleaks and return error", func(t *testing.T) {
		srcProject := "../../../examples/leaks/example1"
		dstProject := "./examples/" + uuid.New().String()
		assert.NoError(t, copy.Copy(srcProject, dstProject, func(src string) bool {
			return false
		}))
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		configs := config.New()
		configs.SetWorkDir(&workdir.WorkDir{})

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      configs,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}
		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", dstProject})

		cobra.OnInitialize(func() {
			require.Nil(t, configs.Normalize().Eval(), "Expected nil error to eval config")
		})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC
		assert.NoError(t, err)
		assert.NotEmpty(t, output)

		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "[HORUSEC] 25 VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, TO SEE MORE DETAILS USE THE LOG LEVEL AS DEBUG AND TRY AGAIN")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")
		assert.Contains(t, output, "")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(dstProject))
	})
}
