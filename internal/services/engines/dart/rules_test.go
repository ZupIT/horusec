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
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-DART-1",
			Rule: NewUsageLocalDataWithoutCryptography(),
			Src:  SampleVulnerableHSDART1,
			Findings: []engine.Finding{
				{
					CodeSample: "SharedPreferences prefs = await SharedPreferences.getInstance();",
					SourceLocation: engine.Location{
						Line:   8,
						Column: 34,
					},
				},
			},
		},
		{
			Name: "HS-DART-2",
			Rule: NewNoSendSensitiveInformation(),
			Src:  SampleVulnerableHSDART2,
			Findings: []engine.Finding{
				{
					CodeSample: "_firebaseMessaging.configure(",
					SourceLocation: engine.Location{
						Line:   9,
						Column: 5,
					},
				},
			},
		},
		{
			Name: "HS-DART-3",
			Rule: NewNoUseBiometricsTypeIOS(),
			Src:  SampleVulnerableHSDART3,
			Findings: []engine.Finding{
				{
					CodeSample: "await auth.getAvailableBiometrics();",
					SourceLocation: engine.Location{
						Line:   3,
						Column: 15,
					},
				},
			},
		},
		{
			Name: "HS-DART-4",
			Rule: NewXmlReaderExternalEntityExpansion(),
			Src:  SampleVulnerableHSDART4,
			Findings: []engine.Finding{
				{
					CodeSample: "final file = new File(FileFromUserInput);",
					SourceLocation: engine.Location{
						Line:   3,
						Column: 13,
					},
				},
			},
		},
		{
			Name: "HS-DART-5",
			Rule: NewNoUseConnectionWithoutSSL(),
			Src:  SampleVulnerableHSDART5,
			Findings: []engine.Finding{
				{
					CodeSample: "return _HttpServer.bindSecure('http://my-api.com.br', port, context, backlog, v6Only, requestClientCertificate, shared);",
					SourceLocation: engine.Location{
						Line:   12,
						Column: 22,
					},
				},
			},
		},
		{
			Name: "HS-DART-6",
			Rule: NewSendSMS(),
			Src:  SampleVulnerableHSDART6,
			Findings: []engine.Finding{
				{
					CodeSample: "import 'package:flutter_sms/flutter_sms.dart';",
					SourceLocation: engine.Location{
						Line:   1,
						Column: 28,
					},
				},
			},
		},
		{
			Name: "HS-DART-7",
			Rule: NewXSSAttack(),
			Src:  SampleVulnerableHSDART7,
			Findings: []engine.Finding{
				{
					CodeSample: "var element = new Element.html(sprintf(\"<div class=\"foo\">%s</div>\", [content]));",
					SourceLocation: engine.Location{
						Line:   8,
						Column: 19,
					},
				},
			},
		},
		{
			Name: "HS-DART-8",
			Rule: NewNoLogSensitive(),
			Src:  SampleVulnerableHSDART8,
			Findings: []engine.Finding{
				{
					CodeSample: "print(sprintf(\"User identity is: %s\", [identity]));",
					SourceLocation: engine.Location{
						Line:   9,
						Column: 1,
					},
				},
				{
					CodeSample: "_logger.info(sprintf(\"User identity is: %s\", [identity]));",
					SourceLocation: engine.Location{
						Line:   11,
						Column: 2,
					},
				},
			},
		},
		{
			Name: "HS-DART-9",
			Rule: NewWeakHashingFunctionMd5OrSha1(),
			Src:  SampleVulnerableHSDART9,
			Findings: []engine.Finding{
				{
					CodeSample: "var digest = md5.convert(content);",
					SourceLocation: engine.Location{
						Line:   11,
						Column: 15,
					},
				},
			},
		},
		{
			Name: "HS-DART-10",
			Rule: NewNoUseSelfSignedCertificate(),
			Src:  SampleVulnerableHSDART10,
			Findings: []engine.Finding{
				{
					CodeSample: "context.setTrustedCertificates(\"client.cer\");",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 8,
					},
				},
			},
		},
		{
			Name: "HS-DART-11",
			Rule: NewNoUseBiometricsTypeAndroid(),
			Src:  SampleVulnerableHSDART11,
			Findings: []engine.Finding{
				{
					CodeSample: "authenticated = await auth.authenticateWithBiometrics(",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 29,
					},
				},
			},
		},
		{
			Name: "HS-DART-12",
			Rule: NewNoListClipboardChanges(),
			Src:  SampleVulnerableHSDART12,
			Findings: []engine.Finding{
				{
					CodeSample: "Map<String, dynamic> result = await SystemChannels.platform.invokeMethod('Clipboard.getData');",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 75,
					},
				},
			},
		},
		{
			Name: "HS-DART-13",
			Rule: NewSQLInjection(),
			Src:  SampleVulnerableHSDART13,
			Findings: []engine.Finding{
				{
					CodeSample: "List<Map> list = await database.rawQuery(\"SELECT * FROM Users WHERE username = '\" + username + \"';\");",
					SourceLocation: engine.Location{
						Line:   10,
						Column: 34,
					},
				},
			},
		},
		{
			Name: "HS-DART-14",
			Rule: NewNoUseNSTemporaryDirectory(),
			Src:  SampleVulnerableHSDART14,
			Findings: []engine.Finding{
				{
					CodeSample: "let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true);",
					SourceLocation: engine.Location{
						Line:   3,
						Column: 49,
					},
				},
			},
		},
		{
			Name: "HS-DART-15",
			Rule: NewNoUseCipherMode(),
			Src:  SampleVulnerableHSDART15,
			Findings: []engine.Finding{
				{
					CodeSample: "final encrypter = Encrypter(AES(key, mode: AESMode.cts));",
					SourceLocation: engine.Location{
						Line:   3,
						Column: 43,
					},
				},
			},
		},
		{
			Name: "HS-DART-16",
			Rule: NewCorsAllowOriginWildCard(),
			Src:  SampleVulnerableHSDART16,
			Findings: []engine.Finding{
				{
					CodeSample: `request.response.headers.add("Access-Control-Allow-Origin", "*");`,
					SourceLocation: engine.Location{
						Line:   9,
						Column: 32,
					},
				},
			},
		},
		{
			Name: "HS-DART-17",
			Rule: NewUsingShellInterpreterWhenExecutingOSCommand(),
			Src:  SampleVulnerableHSDART17,
			Findings: []engine.Finding{
				{
					CodeSample: `var result = await Process.run("netcfg", [UserParams]);`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 20,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-DART-1",
			Rule: NewUsageLocalDataWithoutCryptography(),
			Src:  SampleSafeHSDART1,
		},
		{
			Name: "HS-DART-2",
			Rule: NewNoSendSensitiveInformation(),
			Src:  SampleSafeHSDART2,
		},
		{
			Name: "HS-DART-3",
			Rule: NewNoUseBiometricsTypeIOS(),
			Src:  "",
		},
		{
			Name: "HS-DART-4",
			Rule: NewXmlReaderExternalEntityExpansion(),
			Src:  SampleSafeHSDART4,
		},
		{
			Name: "HS-DART-5",
			Rule: NewNoUseConnectionWithoutSSL(),
			Src:  SampleSafeHSDART5,
		},
		{
			Name: "HS-DART-6",
			Rule: NewSendSMS(),
			Src:  "",
		},
		{
			Name: "HS-DART-7",
			Rule: NewXSSAttack(),
			Src:  SampleSafeHSDART7,
		},
		{
			Name: "HS-DART-8",
			Rule: NewNoLogSensitive(),
			Src:  SampleSafeHSDART8,
		},
		{
			Name: "HS-DART-9",
			Rule: NewWeakHashingFunctionMd5OrSha1(),
			Src:  SampleSafeHSDART9,
		},
		{
			Name: "HS-DART-10",
			Rule: NewNoUseSelfSignedCertificate(),
			Src:  SampleSafeHSDART10,
		},
		{
			Name: "HS-DART-11",
			Rule: NewNoUseBiometricsTypeAndroid(),
			Src:  SampleSafeHSDART11,
		},
		{
			Name: "HS-DART-12",
			Rule: NewNoListClipboardChanges(),
			Src:  SampleSafeHSDART12,
		},
		{
			Name: "HS-DART-13",
			Rule: NewSQLInjection(),
			Src:  SampleSafeHSDART13,
		},
		{
			Name: "HS-DART-14",
			Rule: NewNoUseNSTemporaryDirectory(),
			Src:  SampleSafeHSDART14,
		},
		{
			Name: "HS-DART-15",
			Rule: NewNoUseCipherMode(),
			Src:  SampleSafeHSDART15,
		},
		{
			Name: "HS-DART-16",
			Rule: NewCorsAllowOriginWildCard(),
			Src:  SampleSafeHSDART16,
		},
		{
			Name: "HS-DART-17",
			Rule: NewUsingShellInterpreterWhenExecutingOSCommand(),
			Src:  SampleSafeHSDART17,
		},
	}

	testutil.TestSafeCode(t, testcases)
}
