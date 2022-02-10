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

package phpcs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestStartPHPCodeSniffer(t *testing.T) {
	dirName := filepath.Join(".horusec", "00000000-0000-0000-0000-000000000000", "src", "tool-examples")
	err := os.MkdirAll(dirName, 0o777)
	assert.NoError(t, err)
	srcFiles := []string{"sql-injection.php", "sql-injection_2.php", "basic-collection.php", "cross-site-scripting-xss.php"}
	toolExamplesFiles := []string{"progpilot.php", "phpcs-security-audit.php", "php-security-scanner.php"}
	for _, file := range srcFiles {
		newFile, err := os.Create(filepath.Join(".horusec", "00000000-0000-0000-0000-000000000000", "src", file))
		defer newFile.Close()
		assert.NoError(t, err)
	}
	for _, file := range toolExamplesFiles {
		newFile, err := os.Create(filepath.Join(dirName, file))
		defer newFile.Close()
		assert.NoError(t, err)
	}
	t.Cleanup(func() {
		err = os.RemoveAll(".horusec")
		assert.NoError(t, err)
	})
	t.Run("should success execute container and process output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		totalBySeverity := map[severities.Severity]int{}
		for _, v := range analysis.AnalysisVulnerabilities {
			totalBySeverity[v.Vulnerability.Severity]++
		}
		assert.Equal(t, 0, totalBySeverity[severities.Unknown])
		assert.Equal(t, 96, totalBySeverity[severities.Info])
		assert.Equal(t, 23, totalBySeverity[severities.Critical])
		assert.Equal(t, 0, totalBySeverity[severities.Low])
		assert.Equal(t, 0, totalBySeverity[severities.Medium])
		assert.Equal(t, 0, totalBySeverity[severities.High])
	})
	t.Run("should ignore the problems with contains fail in your scan", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		analysis := &entitiesAnalysis.Analysis{}
		config := cliConfig.New()

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputToIgnoreInAnalysis, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
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
		dockerAPIControllerMock := testutil.NewDockerMock()
		config := &cliConfig.Config{}
		config.ToolsConfig = toolsconfig.ToolsConfig{
			tools.PhpCS: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

const outputToIgnoreInAnalysis = `
{
   "totals":{
      "errors":0,
      "warnings":1,
      "fixable":0
   },
   "files":{
      "\/src\/src\/tool-examples\/phpcs-security-audit.php":{
         "errors":23,
         "warnings":73,
         "messages":[
            {
               "message":"No file extension has been found in a include\/require function. This implies that some PHP code is not scanned by PHPCS.",
               "source":"PHPCS_SecurityAudit.Misc.IncludeMismatch.ErrMiscIncludeMismatchNoExt",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":25,
               "column":1
            }
         ]
      }
   }
}
`

const outputAnalysis = `
{
   "totals":{
      "errors":24,
      "warnings":96,
      "fixable":0
   },
   "files":{
      "\/src\/src\/sql-injection_2.php":{
         "errors":0,
         "warnings":3,
         "messages":[
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":4,
               "column":52
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":7,
               "column":7
            },
            {
               "message":"Possible XSS detected with $customer on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":14,
               "column":10
            }
         ]
      },
      "\/src\/src\/basic-collection.php":{
         "errors":0,
         "warnings":6,
         "messages":[
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":4,
               "column":9
            },
            {
               "message":"Possible XSS detected with . on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":5,
               "column":15
            },
            {
               "message":"User input detetected with $_POST.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":8,
               "column":7
            },
            {
               "message":"SQL function mysql_query() detected with dynamic parameter ",
               "source":"PHPCS_SecurityAudit.BadFunctions.SQLFunctions.WarnSQLFunction",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":9,
               "column":1
            },
            {
               "message":"User input detetected with $_COOKIE.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":12,
               "column":8
            },
            {
               "message":"System program execution function exec() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.SystemExecFunctions.WarnSystemExec",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":13,
               "column":1
            }
         ]
      },
      "\/src\/src\/tool-examples\/progpilot.php":{
         "errors":0,
         "warnings":2,
         "messages":[
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":3,
               "column":9
            },
            {
               "message":"Possible XSS detected with \"$var4\" on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":5,
               "column":6
            }
         ]
      },
      "\/src\/src\/tool-examples\/phpcs-security-audit.php":{
         "errors":23,
         "warnings":73,
         "messages":[
            {
               "message":"Possible XSS detected with . on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":6,
               "column":13
            },
            {
               "message":"User input detetected with $_POST.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":6,
               "column":15
            },
            {
               "message":"Easy XSS detected because of direct user input with $_POST on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":6,
               "column":15
            },
            {
               "message":"db_query() is deprecated except when doing a static query",
               "source":"PHPCS_SecurityAudit.Drupal7.SQLi.D7NoDbQuery",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":8,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":8,
               "column":10
            },
            {
               "message":"Potential SQL injection found in db_query()",
               "source":"PHPCS_SecurityAudit.Drupal7.SQLi.D7DbQuerySQLi",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":8,
               "column":10
            },
            {
               "message":"Usage of preg_replace with \/e modifier is not recommended.",
               "source":"PHPCS_SecurityAudit.BadFunctions.PregReplace.PregReplaceE",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":9,
               "column":1
            },
            {
               "message":"Usage of preg_replace with \/e modifier is not recommended.",
               "source":"PHPCS_SecurityAudit.BadFunctions.PregReplace.PregReplaceE",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":10,
               "column":1
            },
            {
               "message":"User input and \/e modifier found in preg_replace, remote code execution possible.",
               "source":"PHPCS_SecurityAudit.BadFunctions.PregReplace.PregReplaceUserInputE",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":10,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":10,
               "column":24
            },
            {
               "message":"User input found in preg_replace, \/e modifier could be used for malicious intent.",
               "source":"PHPCS_SecurityAudit.BadFunctions.PregReplace.PregReplaceUserInput",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":11,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":11,
               "column":14
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":11,
               "column":26
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":11,
               "column":38
            },
            {
               "message":"Dynamic usage of preg_replace, please check manually for \/e modifier or user input.",
               "source":"PHPCS_SecurityAudit.BadFunctions.PregReplace.PregReplaceDyn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":12,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":12,
               "column":18
            },
            {
               "message":"Weird usage of preg_replace, please check manually for \/e modifier.",
               "source":"PHPCS_SecurityAudit.BadFunctions.PregReplace.PregReplaceWeird",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":13,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":13,
               "column":21
            },
            {
               "message":"Crypto function md5 used.",
               "source":"PHPCS_SecurityAudit.BadFunctions.CryptoFunctions.WarnCryptoFunc",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":17,
               "column":1
            },
            {
               "message":"phpinfo() function detected",
               "source":"PHPCS_SecurityAudit.BadFunctions.Phpinfos.WarnPhpinfo",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":18,
               "column":1
            },
            {
               "message":"Function handling function create_function() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.FunctionHandlingFunctions.WarnFunctionHandling",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":19,
               "column":1
            },
            {
               "message":"Unusual function ftp_exec() detected",
               "source":"PHPCS_SecurityAudit.BadFunctions.FringeFunctions.WarnFringestuff",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":20,
               "column":1
            },
            {
               "message":"Filesystem function fread() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.FilesystemFunctions.WarnFilesystem",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":21,
               "column":1
            },
            {
               "message":"Function array_map() that supports callback detected",
               "source":"PHPCS_SecurityAudit.BadFunctions.CallbackFunctions.WarnCallbackFunctions",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":22,
               "column":1
            },
            {
               "message":"System execution with backticks detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.Backticks.WarnSystemExec",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":23,
               "column":1
            },
            {
               "message":"System execution with backticks detected with dynamic parameter directly from user input",
               "source":"PHPCS_SecurityAudit.BadFunctions.Backticks.ErrSystemExec",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":24,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":24,
               "column":2
            },
            {
               "message":"No file extension has been found in a include\/require function. This implies that some PHP code is not scanned by PHPCS.",
               "source":"PHPCS_SecurityAudit.Misc.IncludeMismatch.ErrMiscIncludeMismatchNoExt",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":25,
               "column":1
            },
            {
               "message":"Possible RFI detected with $a on include",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyRFI.WarnEasyRFI",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":25,
               "column":9
            },
            {
               "message":"Assert eval function assert() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.Asserts.WarnFunctionHandling",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":26,
               "column":1
            },
            {
               "message":"Assert eval function assert() detected with dynamic parameter directly from user input",
               "source":"PHPCS_SecurityAudit.BadFunctions.Asserts.ErrFunctionHandling",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":27,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":27,
               "column":8
            },
            {
               "message":"System program execution function exec() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.SystemExecFunctions.WarnSystemExec",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":28,
               "column":1
            },
            {
               "message":"System program execution function exec() detected with dynamic parameter directly from user input",
               "source":"PHPCS_SecurityAudit.BadFunctions.SystemExecFunctions.ErrSystemExec",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":29,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":29,
               "column":6
            },
            {
               "message":"SQL function mysql_query() detected with dynamic parameter ",
               "source":"PHPCS_SecurityAudit.BadFunctions.SQLFunctions.WarnSQLFunction",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":30,
               "column":1
            },
            {
               "message":"SQL function mysql_query() detected with dynamic parameter  directly from user input",
               "source":"PHPCS_SecurityAudit.BadFunctions.SQLFunctions.ErrSQLFunction",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":31,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":31,
               "column":13
            },
            {
               "message":"Crypto function mcrypt_encrypt used.",
               "source":"PHPCS_SecurityAudit.BadFunctions.CryptoFunctions.WarnCryptoFunc",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":35,
               "column":1
            },
            {
               "message":"Bad use of openssl_public_encrypt without OPENSSL_PKCS1_OAEP_PADDING",
               "source":"PHPCS_SecurityAudit.BadFunctions.CryptoFunctions.ErrPCKS1Crypto",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":36,
               "column":36
            },
            {
               "message":"CVE-2013-4113 ext\/xml\/xml.c in PHP before 5.3.27 does not properly consider parsing depth, which allows remote attackers to cause a denial of service (heap memory corruption) or possibly have unspecified other impact via a crafted document that is processed by the xml_parse_into_struct function.",
               "source":"PHPCS_SecurityAudit.Drupal8.CVE20134113.CVE-2013-4113",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":39,
               "column":1
            },
            {
               "message":"CVE-2013-2110 Heap-based buffer overflow in the php_quot_print_encode function in ext\/standard\/quot_print.c in PHP before 5.3.26 and 5.4.x before 5.4.16 allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted argument to the quoted_printable_encode function.",
               "source":"PHPCS_SecurityAudit.Drupal8.CVE20132110.CVE-2013-2110",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":40,
               "column":1
            },
            {
               "message":"Bad CORS header detected.",
               "source":"PHPCS_SecurityAudit.Misc.BadCorsHeader.WarnPCKS1Crypto",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":43,
               "column":16
            },
            {
               "message":"The file extension '.xyz' that is not specified by --extensions has been used in a include\/require function. Please add it to the scan process.",
               "source":"PHPCS_SecurityAudit.Misc.IncludeMismatch.ErrMiscIncludeMismatch",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":44,
               "column":1
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":47,
               "column":1
            },
            {
               "message":"Possible XSS detected with . on print",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":48,
               "column":13
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":48,
               "column":15
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on print",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":48,
               "column":15
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":49,
               "column":6
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":49,
               "column":6
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":50,
               "column":6
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":50,
               "column":6
            },
            {
               "message":"Possible XSS detected with \"{$_GET['a']}\" on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":51,
               "column":6
            },
            {
               "message":"Possible XSS detected with \"${_GET['a']}\" on print",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":52,
               "column":7
            },
            {
               "message":"Possible XSS detected with a on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":53,
               "column":6
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":53,
               "column":8
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":53,
               "column":8
            },
            {
               "message":"Possible XSS detected with allo on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":54,
               "column":6
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":54,
               "column":13
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":54,
               "column":13
            },
            {
               "message":"User input detetected with arg.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":55,
               "column":6
            },
            {
               "message":"Easy XSS detected because of direct user input with arg on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":55,
               "column":6
            },
            {
               "message":"Possible XSS detected with . on die",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":56,
               "column":8
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":56,
               "column":10
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on die",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":56,
               "column":10
            },
            {
               "message":"Possible XSS detected with . on exit",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":57,
               "column":13
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":57,
               "column":15
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on exit",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":57,
               "column":15
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":59,
               "column":5
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on <?=",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":59,
               "column":5
            },
            {
               "message":"Filesystem function file_create_filename() detected with dynamic parameter directly from user input",
               "source":"PHPCS_SecurityAudit.BadFunctions.FilesystemFunctions.ErrFilesystem",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":63,
               "column":1
            },
            {
               "message":"User input detetected with arg.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":63,
               "column":22
            },
            {
               "message":"Allowing symlink() while open_basedir is used is actually a security risk. Disabled by default in Suhosin >= 0.9.6",
               "source":"PHPCS_SecurityAudit.BadFunctions.FilesystemFunctions.WarnSymlink",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":64,
               "column":1
            },
            {
               "message":"Filesystem function symlink() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.FilesystemFunctions.WarnFilesystem",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":64,
               "column":1
            },
            {
               "message":"Filesystem function delete() detected with dynamic parameter",
               "source":"PHPCS_SecurityAudit.BadFunctions.FilesystemFunctions.WarnFilesystem",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":65,
               "column":1
            },
            {
               "message":"Potential SQL injection with direct variable usage in join with param #3",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":69,
               "column":27
            },
            {
               "message":"Potential SQL injection with direct variable usage in innerJoin with param #3",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":70,
               "column":32
            },
            {
               "message":"Potential SQL injection with direct variable usage in leftJoin with param #3",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":71,
               "column":31
            },
            {
               "message":"Potential SQL injection with direct variable usage in rightJoin with param #3",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":72,
               "column":32
            },
            {
               "message":"Potential SQL injection with direct variable usage in addExpression with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":73,
               "column":23
            },
            {
               "message":"Potential SQL injection with direct variable usage in groupBy with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":74,
               "column":17
            },
            {
               "message":"Potential SQL injection with direct variable usage in orderBy with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":76,
               "column":17
            },
            {
               "message":"Potential SQL injection with direct variable usage in orderBy with param #2",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":76,
               "column":21
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":81,
               "column":31
            },
            {
               "message":"SQL injection found in condition with param #3",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesSQLi",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":81,
               "column":31
            },
            {
               "message":"Potential SQL injection with direct variable usage in where with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":83,
               "column":13
            },
            {
               "message":"Potential SQL injection with direct variable usage in havingCondition with param #3",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":84,
               "column":36
            },
            {
               "message":"Potential SQL injection with direct variable usage in having with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":85,
               "column":14
            },
            {
               "message":"Possible XSS detected with $count on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":88,
               "column":6
            },
            {
               "message":"Potential SQL injection with direct variable usage in expression with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":91,
               "column":18
            },
            {
               "message":"Potential SQL injection with direct variable usage in expression with param #2",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":91,
               "column":22
            },
            {
               "message":"Potential SQL injection with direct variable usage in fields with param #1 with array key value",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":96,
               "column":9
            },
            {
               "message":"Potential SQL injection with direct variable usage in fields with param #1 with array key value",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesDirectVar",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":97,
               "column":9
            },
            {
               "message":"Dynamic query with db_select on table node should be tagged for access restrictions",
               "source":"PHPCS_SecurityAudit.Drupal7.DbQueryAC.D7DbQueryACErr",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":106,
               "column":10
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":108,
               "column":14
            },
            {
               "message":"SQL injection found in fields with param #1",
               "source":"PHPCS_SecurityAudit.Drupal7.DynQueries.D7DynQueriesSQLi",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":108,
               "column":14
            }
         ]
      },
      "\/src\/src\/tool-examples\/php-security-scanner.php":{
         "errors":0,
         "warnings":2,
         "messages":[
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":4,
               "column":9
            },
            {
               "message":"SQL function mysql_query() detected with dynamic parameter ",
               "source":"PHPCS_SecurityAudit.BadFunctions.SQLFunctions.WarnSQLFunction",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":8,
               "column":5
            }
         ]
      },
      "\/src\/src\/cross-site-scripting-xss.php":{
         "errors":1,
         "warnings":5,
         "messages":[
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":4,
               "column":52
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":7,
               "column":13
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":7,
               "column":28
            },
            {
               "message":"Possible XSS detected with . on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":9,
               "column":24
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":9,
               "column":26
            },
            {
               "message":"Easy XSS detected because of direct user input with $_GET on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr",
               "severity":5,
               "fixable":false,
               "type":"ERROR",
               "line":9,
               "column":26
            }
         ]
      },
      "\/src\/src\/sql-injection.php":{
         "errors":0,
         "warnings":5,
         "messages":[
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":4,
               "column":52
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":9,
               "column":13
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":9,
               "column":26
            },
            {
               "message":"User input detetected with $_GET.",
               "source":"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":11,
               "column":56
            },
            {
               "message":"Possible XSS detected with $employee on echo",
               "source":"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSwarn",
               "severity":5,
               "fixable":false,
               "type":"WARNING",
               "line":16,
               "column":10
            }
         ]
      }
   }
}
`
