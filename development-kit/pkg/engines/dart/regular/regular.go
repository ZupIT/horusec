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

//nolint:lll multiple regex is not possible broken lines
package regular

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewDartRegularXSSAttack() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9d55aa22-d8ef-49d0-b798-40f94da34cac",
			Name:        "Prevent XSS Attack",
			Description: "A potential Cross-Site Scripting (XSS) was found. The endpoint returns a variable from the client entry that has not been coded. Always encode untrusted input before output, regardless of validation or cleaning performed. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Element\.html\(`),
		},
	}
}

func NewDartRegularNoLogSensitive() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0aae9f47-048d-40a7-b07d-d1fe1313d993",
			Name:        "No Log Sensitive Information in console",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`print\(.*\$`),
			regexp.MustCompile(`window\.console.*\(`),
			regexp.MustCompile(`log.*\.(finest|finer|fine|config|info|warning|severe|shout|erro).*\(`),
		},
	}
}

func NewDartRegularWeakHashingFunctionMd5OrSha1() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "00857c3e-5f0f-4806-930d-9347d319e860",
			Name:        "Weak hashing function md5 or sha1",
			Description: "MD5 or SHA1 have known collision weaknesses and are no longer considered strong hashing algorithms. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`md5\..*\(`),
			regexp.MustCompile(`hmacMd5\..*\(`),
			regexp.MustCompile(`sha1\..*\(`),
			regexp.MustCompile(`hmacSha1\..*\(`),
		},
	}
}

func NewDartRegularNoUseSelfSignedCertificate() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7b67c2b2-3e22-4738-b202-8e6360560f2b",
			Name:        "No Use Self Signed Certificate",
			Description: "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setTrustedCertificates`),
			regexp.MustCompile(`setAllowsAnyHTTPSCertificate`),
		},
	}
}
