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

package tfsec

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"

	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestStartHCLTfSec(t *testing.T) {
	t.Run("should success execute container and process output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := `{"results":[{"rule_id":"AWS018","link":"https://github.com/liamg/tfsec/wiki/AWS018","location":{"filename":"/src/terraform/main.tf","start_line":2,"end_line":5},"description":"Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes.","severity":"ERROR"},{"rule_id":"AWS006","link":"https://github.com/liamg/tfsec/wiki/AWS006","location":{"filename":"/src/terraform/main.tf","start_line":4,"end_line":4},"description":"Resource 'aws_security_group_rule.my-rule' defines a fully open ingress security group rule.","severity":"WARNING"},{"rule_id":"AWS004","link":"https://github.com/liamg/tfsec/wiki/AWS004","location":{"filename":"/src/terraform/main.tf","start_line":9,"end_line":9},"description":"Resource 'aws_alb_listener.my-alb-listener' uses plain HTTP instead of HTTPS.","severity":"ERROR"},{"rule_id":"AWS003","link":"https://github.com/liamg/tfsec/wiki/AWS003","location":{"filename":"/src/terraform/main.tf","start_line":12,"end_line":14},"description":"Resource 'aws_db_security_group.my-group' uses EC2 Classic. Use a VPC instead.","severity":"ERROR"},{"rule_id":"AZU003","link":"https://github.com/liamg/tfsec/wiki/AZU003","location":{"filename":"/src/terraform/main.tf","start_line":18,"end_line":18},"description":"Resource 'azurerm_managed_disk.source' defines an unencrypted managed disk.","severity":"ERROR"}]}`

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.NotEmpty(t, analysis)
		assert.Len(t, analysis.AnalysisVulnerabilities, 5)
	})

	t.Run("should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := "!@#!@#"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{TfSec: toolsconfig.ToolConfig{IsToIgnore: true}},
		)
		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
