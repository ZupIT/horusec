// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package generate

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

type Generate struct {
	configs *config.Config
}

func NewGenerateCommand(cfg *config.Config) *Generate {
	return &Generate{
		configs: cfg,
	}
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

//nolint:gomnd // magic number
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
	_, err := outputFile.Write(configBytes)
	return err
}

//nolint:gomnd // magic number
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
	return g.writeConfigOnFile(configFile)
}
