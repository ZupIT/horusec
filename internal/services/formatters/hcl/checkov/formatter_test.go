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

package checkov

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestCheckovParseOutput(t *testing.T) {
	t.Run("should add 1 vulnerability on analysis with no errors", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := new(analysis.Analysis)
		config := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 3)
		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability
			assert.Equal(t, tools.Checkov, vuln.SecurityTool)
			assert.Equal(t, languages.HCL, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Exepcted not empty details")
			assert.NotContains(t, vuln.Details, "()")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")
		}
	})

	t.Run("should add error on analysis when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid", nil)

		analysis := new(analysis.Analysis)

		config := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add error from executing container on analysis", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		analysis := new(analysis.Analysis)

		config := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()

		analysis := new(analysis.Analysis)
		config := config.New()
		config.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Checkov: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

const output = `
{
  "check_type": "terraform",
  "results": {
    "passed_checks": [],
    "failed_checks": [
      {
        "check_id": "CKV_AWS_158",
        "bc_check_id": null,
        "check_name": "Ensure that CloudWatch Log Group is encrypted by KMS",
        "check_result": {
          "result": "FAILED",
          "evaluated_keys": [
            "kms_key_id"
          ]
        },
        "file_path": "/terraform/main.tf",
        "file_abs_path": "/tf/terraform/main.tf",
        "repo_file_path": "/tf/terraform/main.tf",
        "file_line_range": [
          528,
          531
        ],
        "resource": "aws_cloudwatch_log_group.log_group",
        "evaluations": null,
        "check_class": "checkov.terraform.checks.resource.aws.CloudWatchLogGroupKMSKey",
        "fixed_definition": null,
        "entity_tags": null,
        "caller_file_path": null,
        "caller_file_line_range": null
      },
      {
        "check_id": "CKV_AWS_147",
        "bc_check_id": null,
        "check_name": "Ensure that CodeBuild projects are encrypted",
        "check_result": {
          "result": "FAILED",
          "evaluated_keys": [
            "encryption_key"
          ]
        },
        "file_path": "/terraform/main.tf",
        "file_abs_path": "/tf/terraform/main.tf",
        "repo_file_path": "/tf/terraform/main.tf",
        "file_line_range": [
          677,
          733
        ],
        "resource": "aws_codebuild_project.legacy",
        "evaluations": null,
        "check_class": "checkov.terraform.checks.resource.aws.CodeBuildEncrypted",
        "fixed_definition": null,
        "entity_tags": null,
        "caller_file_path": null,
        "caller_file_line_range": null
      },
      {
        "check_id": "CKV_AWS_78",
        "bc_check_id": null,
        "check_name": "Ensure that CodeBuild Project encryption is not disabled",
        "check_result": {
          "result": "FAILED",
          "evaluated_keys": [
            "artifacts/[0]/encryption_disabled"
          ]
        },
        "file_path": "/terraform/main.tf",
        "file_abs_path": "/tf/terraform/main.tf",
        "repo_file_path": "/tf/terraform/main.tf",
        "file_line_range": [
          677,
          733
        ],
        "resource": "aws_codebuild_project.legacy",
        "evaluations": null,
        "check_class": "checkov.terraform.checks.resource.aws.CodeBuildProjectEncryption",
        "fixed_definition": null,
        "entity_tags": null,
        "caller_file_path": null,
        "caller_file_line_range": null,
        "guideline": "https://docs.bridgecrew.io/docs/bc_aws_general_30"
      }
    ],
    "skipped_checks": [],
    "parsing_errors": []
  },
  "summary": {
    "passed": 0,
    "failed": 3,
    "skipped": 0,
    "parsing_errors": 0,
    "resource_count": 7,
    "checkov_version": "2.0.330"
  }
}
`
