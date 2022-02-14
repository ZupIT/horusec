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

package dart

import (
	"fmt"
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-DART-1",
			Rule:     NewUsageLocalDataWithoutCryptography(),
			Src:      SampleVulnerableHSDART1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-1", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "SharedPreferences prefs = await SharedPreferences.getInstance();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-1", ".test")),
						Line:     8,
						Column:   34,
					},
				},
			},
		},
		{
			Name:     "HS-DART-2",
			Rule:     NewNoSendSensitiveInformation(),
			Src:      SampleVulnerableHSDART2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "_firebaseMessaging.configure(",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-2", ".test")),
						Line:     9,
						Column:   5,
					},
				},
			},
		},
		{
			Name:     "HS-DART-3",
			Rule:     NewNoUseBiometricsTypeIOS(),
			Src:      SampleVulnerableHSDART3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-3", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "await auth.getAvailableBiometrics();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-3", ".test")),
						Line:     3,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-DART-4",
			Rule:     NewXmlReaderExternalEntityExpansion(),
			Src:      SampleVulnerableHSDART4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-4", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "final file = new File(FileFromUserInput);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-4", ".test")),
						Line:     3,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-DART-5",
			Rule:     NewNoUseConnectionWithoutSSL(),
			Src:      SampleVulnerableHSDART5,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-5", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "return _HttpServer.bindSecure('http://my-api.com.br', port, context, backlog, v6Only, requestClientCertificate, shared);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-5", ".test")),
						Line:     12,
						Column:   22,
					},
				},
			},
		},
		{
			Name:     "HS-DART-6",
			Rule:     NewSendSMS(),
			Src:      SampleVulnerableHSDART6,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-6", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "import 'package:flutter_sms/flutter_sms.dart';",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-6", ".test")),
						Line:     1,
						Column:   28,
					},
				},
			},
		},
		{
			Name:     "HS-DART-7",
			Rule:     NewXSSAttack(),
			Src:      SampleVulnerableHSDART7,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-7", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "var element = new Element.html(sprintf(\"<div class=\"foo\">%s</div>\", [content]));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-7", ".test")),
						Line:     8,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-DART-8",
			Rule:     NewNoLogSensitive(),
			Src:      SampleVulnerableHSDART8,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-8", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "print(sprintf(\"User identity is: %s\", [identity]));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-8", ".test")),
						Line:     9,
						Column:   1,
					},
				},
				{
					CodeSample: "_logger.info(sprintf(\"User identity is: %s\", [identity]));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-8", ".test")),
						Line:     11,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-DART-9",
			Rule:     NewWeakHashingFunctionMd5OrSha1(),
			Src:      SampleVulnerableHSDART9,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-9", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "var digest = md5.convert(content);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-9", ".test")),
						Line:     11,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-DART-10",
			Rule:     NewNoUseSelfSignedCertificate(),
			Src:      SampleVulnerableHSDART10,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-10", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "context.setTrustedCertificates(\"client.cer\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-10", ".test")),
						Line:     4,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-DART-11",
			Rule:     NewNoUseBiometricsTypeAndroid(),
			Src:      SampleVulnerableHSDART11,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-11", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "authenticated = await auth.authenticateWithBiometrics(",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-11", ".test")),
						Line:     4,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-DART-12",
			Rule:     NewNoListClipboardChanges(),
			Src:      SampleVulnerableHSDART12,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-12", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "Map<String, dynamic> result = await SystemChannels.platform.invokeMethod('Clipboard.getData');",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-12", ".test")),
						Line:     4,
						Column:   75,
					},
				},
			},
		},
		{
			Name:     "HS-DART-13",
			Rule:     NewSQLInjection(),
			Src:      SampleVulnerableHSDART13,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-13", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "List<Map> list = await database.rawQuery(\"SELECT * FROM Users WHERE username = '\" + username + \"';\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-13", ".test")),
						Line:     10,
						Column:   34,
					},
				},
			},
		},
		{
			Name:     "HS-DART-14",
			Rule:     NewNoUseNSTemporaryDirectory(),
			Src:      SampleVulnerableHSDART14,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-14", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-14", ".test")),
						Line:     3,
						Column:   49,
					},
				},
			},
		},
		{
			Name:     "HS-DART-15",
			Rule:     NewNoUseCipherMode(),
			Src:      SampleVulnerableHSDART15,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-15", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "final encrypter = Encrypter(AES(key, mode: AESMode.cts));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-15", ".test")),
						Line:     3,
						Column:   43,
					},
				},
			},
		},
		{
			Name:     "HS-DART-16",
			Rule:     NewCorsAllowOriginWildCard(),
			Src:      SampleVulnerableHSDART16,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-16", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `request.response.headers.add("Access-Control-Allow-Origin", "*");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-16", ".test")),
						Line:     9,
						Column:   32,
					},
				},
			},
		},
		{
			Name:     "HS-DART-17",
			Rule:     NewUsingShellInterpreterWhenExecutingOSCommand(),
			Src:      SampleVulnerableHSDART17,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-17", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `var result = await Process.run("netcfg", [UserParams]);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-17", ".test")),
						Line:     4,
						Column:   20,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-DART-1",
			Rule:     NewUsageLocalDataWithoutCryptography(),
			Src:      SampleSafeHSDART1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-1", ".test")),
		},
		{
			Name:     "HS-DART-2",
			Rule:     NewNoSendSensitiveInformation(),
			Src:      SampleSafeHSDART2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-2", ".test")),
		},
		{
			Name:     "HS-DART-3",
			Rule:     NewNoUseBiometricsTypeIOS(),
			Src:      "",
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-3", ".test")),
		},
		{
			Name:     "HS-DART-4",
			Rule:     NewXmlReaderExternalEntityExpansion(),
			Src:      SampleSafeHSDART4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-4", ".test")),
		},
		{
			Name:     "HS-DART-5",
			Rule:     NewNoUseConnectionWithoutSSL(),
			Src:      SampleSafeHSDART5,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-5", ".test")),
		},
		{
			Name:     "HS-DART-6",
			Rule:     NewSendSMS(),
			Src:      "",
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-6", ".test")),
		},
		{
			Name:     "HS-DART-7",
			Rule:     NewXSSAttack(),
			Src:      SampleSafeHSDART7,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-7", ".test")),
		},
		{
			Name:     "HS-DART-8",
			Rule:     NewNoLogSensitive(),
			Src:      SampleSafeHSDART8,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-8", ".test")),
		},
		{
			Name:     "HS-DART-9",
			Rule:     NewWeakHashingFunctionMd5OrSha1(),
			Src:      SampleSafeHSDART9,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-9", ".test")),
		},
		{
			Name:     "HS-DART-10",
			Rule:     NewNoUseSelfSignedCertificate(),
			Src:      SampleSafeHSDART10,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-10", ".test")),
		},
		{
			Name:     "HS-DART-11",
			Rule:     NewNoUseBiometricsTypeAndroid(),
			Src:      SampleSafeHSDART11,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-11", ".test")),
		},
		{
			Name:     "HS-DART-12",
			Rule:     NewNoListClipboardChanges(),
			Src:      SampleSafeHSDART12,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-12", ".test")),
		},
		{
			Name:     "HS-DART-13",
			Rule:     NewSQLInjection(),
			Src:      SampleSafeHSDART13,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-13", ".test")),
		},
		{
			Name:     "HS-DART-14",
			Rule:     NewNoUseNSTemporaryDirectory(),
			Src:      SampleSafeHSDART14,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-14", ".test")),
		},
		{
			Name:     "HS-DART-15",
			Rule:     NewNoUseCipherMode(),
			Src:      SampleSafeHSDART15,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-15", ".test")),
		},
		{
			Name:     "HS-DART-16",
			Rule:     NewCorsAllowOriginWildCard(),
			Src:      SampleSafeHSDART16,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-16", ".test")),
		},
		{
			Name:     "HS-DART-17",
			Rule:     NewUsingShellInterpreterWhenExecutingOSCommand(),
			Src:      SampleSafeHSDART17,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-DART-17", ".test")),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
