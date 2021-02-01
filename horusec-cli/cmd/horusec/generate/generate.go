package generate

import (
	"encoding/json"
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/spf13/cobra"
	"os"
)

type IGenerate interface {
	SetGlobalCmd(globalCmd *cobra.Command)
	CreateCobraCmd() *cobra.Command
}

type Generate struct {
	globalCmd *cobra.Command
	configs   config.IConfig
}

func NewGenerateCommand() IGenerate {
	return &Generate{
		configs: config.NewConfig(),
	}
}

func (g *Generate) SetGlobalCmd(globalCmd *cobra.Command) {
	g.globalCmd = globalCmd
}

func (g *Generate) CreateCobraCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "generate",
		Short:   "Generate horusec configuration",
		Long:    "Generate the Horusec configuration",
		Example: "horusec generate",
		RunE:    g.runE,
	}
}

func (g *Generate) runE(_ *cobra.Command, _ []string) error {
	if _, err := os.Stat(g.configs.GetConfigFilePath()); os.IsNotExist(err) {
		if err := g.createAndWriteOnFile(); err != nil {
			logger.LogError(messages.MsgErrorErrorOnCreateConfigFile, err)
			return err
		}
		logger.LogInfoWithLevel(messages.MsgInfoConfigFileCreatedSuccess, g.configs.GetConfigFilePath())
		return nil
	}
	logger.LogInfo(messages.MsgInfoConfigAlreadyExist, g.configs.GetConfigFilePath())
	return g.readFileAndCreateNewKeys()
}

func (g *Generate) createAndWriteOnFile() error {
	outputFile, err := g.createAndOpenFile()
	if err != nil {
		return err
	}
	defer func() {
		logger.LogError(messages.MsgErrorErrorOnCreateConfigFile, outputFile.Close())
	}()
	return g.writeConfigOnFile(outputFile)
}

func (g *Generate) createAndOpenFile() (outputFile *os.File, err error) {
	if _, err = os.Create(g.configs.GetConfigFilePath()); err != nil {
		return nil, err
	}
	outputFile, err = os.OpenFile(g.configs.GetConfigFilePath(), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return outputFile, outputFile.Truncate(0)
}

func (g *Generate) writeConfigOnFile(outputFile *os.File) error {
	configMap := g.configs.ToMapLowerCase()
	configBytes, _ := json.MarshalIndent(configMap, "", "  ")
	bytesWritten, err := outputFile.Write(configBytes)
	if err != nil {
		return err
	}
	if bytesWritten != len(configBytes) {
		return errors.New("BytesWritten is not equals in ConfigBytes")
	}
	return nil
}

func (g *Generate) readFileAndCreateNewKeys() error {
	configFile, err := os.OpenFile(g.configs.GetConfigFilePath(), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logger.LogError(messages.MsgErrorErrorOnReadConfigFile+g.configs.GetConfigFilePath(), err)
		return err
	}
	defer func() {
		logger.LogError(
			messages.MsgErrorErrorOnReadConfigFile+g.configs.GetConfigFilePath(), configFile.Close())
	}()
	g.configs = g.configs.NewConfigsFromViper()
	return g.writeConfigOnFile(configFile)
}
