package generate

import (
	"bytes"
	"fmt"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./tmp")
	_ = os.MkdirAll("./tmp", 0750)
	code := m.Run()
	_ = os.RemoveAll("./tmp")
	os.Exit(code)
}

func TestGenerate_SetGlobalCmd(t *testing.T) {
	t.Run("Should set global command when run generate config", func(t *testing.T) {
		globalCmd := &cobra.Command{}
		_ = globalCmd.PersistentFlags().String("log-level", "", "Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"")
		_ = globalCmd.PersistentFlags().String("config-file-path", "", "Path of the file horusec-config.json to setup content of horusec")
		assert.NotPanics(t, func() {
			NewGenerateCommand().SetGlobalCmd(globalCmd)
		})
	})
}

func TestGenerate_CreateCobraCmd(t *testing.T) {
	globalCmd := &cobra.Command{}
	_ = globalCmd.PersistentFlags().String("log-level", "", "Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"")
	_ = globalCmd.PersistentFlags().String("config-file-path", "./tmp/horusec-config.json", "Path of the file horusec-config.json to setup content of horusec")
	t.Run("Should create file with default configuration", func(t *testing.T) {
		configs := config.NewConfig()
		configs.SetConfigFilePath("./tmp/horusec-config1.json")
		cmd := &Generate{
			configs:   configs,
			globalCmd: globalCmd,
		}
		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)
		cobraCmd := cmd.CreateCobraCmd()
		cobraCmd.SetOut(stdoutMock)

		assert.NoError(t, cobraCmd.Execute())
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.Contains(t, output, messages.MsgInfoConfigFileCreatedSuccess)
		file, _ := os.Open(configs.GetConfigFilePath())
		defer func() {
			_ = file.Close()
		}()
		fileBytes, _ := ioutil.ReadAll(file)
		assert.Contains(t, string(fileBytes), fmt.Sprintf("\"%s\": 600", strcase.ToLowerCamel(strcase.ToSnake(config.EnvTimeoutInSecondsAnalysis))))
	})
	t.Run("Should update file already exists with default configuration", func(t *testing.T) {
		// Create configuration
		configs := config.NewConfig()
		configs.SetConfigFilePath("./tmp/horusec-config2.json")
		cmd := &Generate{
			configs:   configs,
			globalCmd: globalCmd,
		}

		// Create existing file and write empry object
		_, err := os.Create(configs.GetConfigFilePath())
		assert.NoError(t, err)
		fileExisting, err := os.OpenFile(configs.GetConfigFilePath(), os.O_CREATE|os.O_WRONLY, 0600)
		assert.NoError(t, err)
		_, err = fileExisting.Write([]byte("{}"))
		assert.NoError(t, err)
		_ = fileExisting.Close()
		fileExisting, err = os.Open(configs.GetConfigFilePath())
		assert.NoError(t, err)
		fileExistingBytes, err := ioutil.ReadAll(fileExisting)
		assert.NoError(t, err)
		assert.Equal(t, "{}", string(fileExistingBytes))

		// Setup cobra command
		stdoutMock := bytes.NewBufferString("")
		logrus.SetOutput(stdoutMock)
		cobraCmd := cmd.CreateCobraCmd()
		cobraCmd.SetOut(stdoutMock)
		assert.NoError(t, cobraCmd.Execute())

		// Validate ouput from cobra
		outputBytes, err := ioutil.ReadAll(stdoutMock)
		output := string(outputBytes)
		assert.NoError(t, err)
		assert.Contains(t, output, messages.MsgInfoConfigAlreadyExist)

		// Check content on file created
		file, _ := os.Open(configs.GetConfigFilePath())
		fileBytes, _ := ioutil.ReadAll(file)
		assert.NotEmpty(t, string(fileBytes))
		assert.NotEqual(t, "{}", string(fileBytes))
		assert.Contains(t, string(fileBytes), fmt.Sprintf("\"%s\": 600", strcase.ToLowerCamel(strcase.ToSnake(config.EnvTimeoutInSecondsAnalysis))))
		_ = file.Close()
	})
}
