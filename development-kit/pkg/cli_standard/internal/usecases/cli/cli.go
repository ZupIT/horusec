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

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/internal/helpers/messages"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type UseCases struct{}

type Interface interface {
	ValidateConfigs(config *config.Config) error
	NormalizeConfigs(configs *config.Config) *config.Config
}

func NewCLIUseCases() Interface {
	return &UseCases{}
}
func (au *UseCases) NormalizeConfigs(c *config.Config) *config.Config {
	c.OutputFilePath, _ = filepath.Abs(c.OutputFilePath)
	c.ProjectPath, _ = filepath.Abs(c.ProjectPath)
	return c
}

func (au *UseCases) ValidateConfigs(configs *config.Config) error {
	return validation.ValidateStruct(configs,
		validation.Field(&configs.OutputFilePath, validation.By(au.checkIfIsJSONFile(configs.OutputFilePath))),
		validation.Field(&configs.ProjectPath, validation.By(au.validateIfIsValidPath(configs.ProjectPath))),
	)
}

func (au *UseCases) validateIfIsValidPath(dir string) validation.RuleFunc {
	return func(value interface{}) error {
		if _, errStat := os.Stat(dir); errStat != nil || dir == "" {
			return fmt.Errorf(messages.MsgErrorProjectPathNotValid)
		}
		return nil
	}
}

func (au *UseCases) checkIfIsJSONFile(path string) validation.RuleFunc {
	return func(value interface{}) error {
		if len(path) < 5 {
			return errors.New(messages.MsgErrorOutputFilePathNotValid + ".json file path is required")
		}
		totalChars := len(path) - 1
		ext := path[totalChars-4:]
		if ext != ".json" {
			return errors.New(messages.MsgErrorOutputFilePathNotValid + "is not valid .json file")
		}
		return nil
	}
}
