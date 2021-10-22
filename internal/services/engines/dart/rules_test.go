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
			Src:  SampleVulnerableUsageLocalDataWithoutCryptography,
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
			Src:  SampleVulnerableNoSendSensitiveInformation,
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
			Src:  SampleVulnerableNoUseBiometricsTypeIOS,
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
			Src:  SampleVulnerableXmlReaderExternalEntityExpansion,
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
			Src:  SampleVulnerableNoUseConnectionWithoutSSL,
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
			Src:  SampleVulnerableDartSendSMS,
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
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-DART-1",
			Rule: NewUsageLocalDataWithoutCryptography(),
			Src:  SampleSafeUsageLocalDataWithoutCryptography,
		},
		{
			Name: "HS-DART-2",
			Rule: NewNoSendSensitiveInformation(),
			Src:  SampleSafeNoSendSensitiveInformation,
		},
		{
			Name: "HS-DART-3",
			Rule: NewNoUseBiometricsTypeIOS(),
			Src:  "",
		},
		{
			Name: "HS-DART-4",
			Rule: NewXmlReaderExternalEntityExpansion(),
			Src:  SampleSafeXmlReaderExternalEntityExpansion,
		},
		{
			Name: "HS-DART-5",
			Rule: NewNoUseConnectionWithoutSSL(),
			Src:  SampleSafeNoUseConnectionWithoutSSL,
		},
		{
			Name: "HS-DART-6",
			Rule: NewSendSMS(),
			Src:  "",
		},
	}

	testutil.TestSafeCode(t, testcases)
}
