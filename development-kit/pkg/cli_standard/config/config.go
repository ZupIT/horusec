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

package config

import "github.com/ZupIT/horusec/development-kit/pkg/utils/logger"

type Config struct {
	LogLevel       string
	ProjectPath    string
	OutputFilePath string
}

func NewConfig() *Config {
	c := &Config{
		LogLevel:       "info",
		ProjectPath:    "./",
		OutputFilePath: "output.json",
	}
	return c
}

func (c *Config) GetLogLevel() string {
	return c.LogLevel
}

func (c *Config) SetLogLevel(logLevel string) {
	c.LogLevel = logLevel
}

func (c *Config) GetOutputFilePath() string {
	logger.LogDebugWithLevel("Sending units and rules to engine and expected response in path: ",
		logger.DebugLevel, c.OutputFilePath)
	return c.OutputFilePath
}

func (c *Config) SetOutputFilePath(outputFilePath string) {
	c.OutputFilePath = outputFilePath
}

func (c *Config) GetProjectPath() string {
	return c.ProjectPath
}

func (c *Config) SetProjectPath(projectPath string) {
	c.ProjectPath = projectPath
}
