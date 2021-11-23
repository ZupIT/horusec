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

package toolsconfig_test

import (
	"bytes"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

func TestDefaultValues(t *testing.T) {
	cfg := toolsconfig.Default()

	tools := tools.Values()

	assert.Len(t, cfg, len(tools), "Expected all tools on default values")

	for tool, cfg := range cfg {
		assert.Contains(t, tools, tool, "Tool %s is invalid", tool)
		assert.False(t, cfg.IsToIgnore, "Expected default value as false to IsToIgnore")
	}
}

func TestParseToolsConfig(t *testing.T) {
	testcases := []struct {
		name     string
		input    map[string]interface{}
		expected toolsconfig.ToolsConfig
		output   string
	}{
		{
			name: "Should parse values incomplete correctly and return all tools",
			input: map[string]interface{}{
				"bandit": map[string]bool{
					"istoignore": false,
				},
				"gosec": map[string]bool{
					"istoignore": true,
				},
			},
			expected: toolsconfig.ToolsConfig{
				tools.Bandit:               toolsconfig.Config{false},
				tools.BundlerAudit:         toolsconfig.Config{false},
				tools.Brakeman:             toolsconfig.Config{false},
				tools.Checkov:              toolsconfig.Config{false},
				tools.Flawfinder:           toolsconfig.Config{false},
				tools.GitLeaks:             toolsconfig.Config{false},
				tools.GoSec:                toolsconfig.Config{true},
				tools.HorusecEngine:        toolsconfig.Config{false},
				tools.MixAudit:             toolsconfig.Config{false},
				tools.NpmAudit:             toolsconfig.Config{false},
				tools.PhpCS:                toolsconfig.Config{false},
				tools.Safety:               toolsconfig.Config{false},
				tools.SecurityCodeScan:     toolsconfig.Config{false},
				tools.Semgrep:              toolsconfig.Config{false},
				tools.ShellCheck:           toolsconfig.Config{false},
				tools.Sobelow:              toolsconfig.Config{false},
				tools.TfSec:                toolsconfig.Config{false},
				tools.YarnAudit:            toolsconfig.Config{false},
				tools.OwaspDependencyCheck: toolsconfig.Config{false},
				tools.DotnetCli:            toolsconfig.Config{false},
				tools.Nancy:                toolsconfig.Config{false},
				tools.Trivy:                toolsconfig.Config{false},
			},
		},
		{
			name: "Should error on invalid configuration and use default values",
			input: map[string]interface{}{
				"gosec": map[string]string{
					"istoigore": "invalid data type",
				},
				"bandit": "invalid type",
			},
			expected: toolsconfig.Default(),
			output:   messages.MsgErrorParseStringToToolsConfig,
		},
		{
			name: "Should parse using lower and upper case",
			input: map[string]interface{}{
				"trivy": map[string]bool{
					"istoignore": true,
				},
				"HorusecEngine": map[string]bool{
					"istoignore": true,
				},
			},
			expected: toolsconfig.ToolsConfig{
				tools.Bandit:               toolsconfig.Config{false},
				tools.BundlerAudit:         toolsconfig.Config{false},
				tools.Brakeman:             toolsconfig.Config{false},
				tools.Checkov:              toolsconfig.Config{false},
				tools.Flawfinder:           toolsconfig.Config{false},
				tools.GitLeaks:             toolsconfig.Config{false},
				tools.GoSec:                toolsconfig.Config{false},
				tools.HorusecEngine:        toolsconfig.Config{true},
				tools.MixAudit:             toolsconfig.Config{false},
				tools.NpmAudit:             toolsconfig.Config{false},
				tools.PhpCS:                toolsconfig.Config{false},
				tools.Safety:               toolsconfig.Config{false},
				tools.SecurityCodeScan:     toolsconfig.Config{false},
				tools.Semgrep:              toolsconfig.Config{false},
				tools.ShellCheck:           toolsconfig.Config{false},
				tools.Sobelow:              toolsconfig.Config{false},
				tools.TfSec:                toolsconfig.Config{false},
				tools.YarnAudit:            toolsconfig.Config{false},
				tools.OwaspDependencyCheck: toolsconfig.Config{false},
				tools.DotnetCli:            toolsconfig.Config{false},
				tools.Nancy:                toolsconfig.Config{false},
				tools.Trivy:                toolsconfig.Config{true},
			},
		},
	}

	output := bytes.NewBufferString("")
	logger.LogSetOutput(output)

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			config := toolsconfig.MustParseToolsConfig(tt.input)

			assert.Equal(t, tt.expected, config)
			assert.Contains(t, output.String(), tt.output)
		})
	}
}
