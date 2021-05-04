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
//nolint:lll // multiple regex is not possible broken lines
package or

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewDartOrNoUseConnectionWithoutSSL() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3897bea8-4c4b-4ada-b5c3-614c93c6b05e",
			Name:        "No use connection without SSL",
			Description: "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.bindSecure\(\n?('|")http:\/\/`),
			regexp.MustCompile(`\.parse\(\n?('|")http:\/\/`),
			regexp.MustCompile(`(.parse\(('|")|.bindSecure\(('|"))(([^h]|h[^t]|ht[^t]|htt[^p])*)(\))`),
		},
	}
}

func NewDartOrSendSMS() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "859e6499-7fe8-4595-afe7-698750f94f4b",
			Name:        "Send SMS",
			Description: "Send SMS. For more information checkout the OWASP-M3 (https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`flutter_sms\.dart`),
			regexp.MustCompile(`sendSMS`),
		},
	}
}
