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
package and

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewNodeJSAndNoUseRequestMethodUsingDataFromRequestOfUserInput() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "74736e94-926c-41bc-b4e8-61aad62ba11b",
			Name:        "No use request method using data from request of user input",
			Description: "Allows user input data to be used as parameters for the 'request' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/918.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`require\((?:'|\")request(?:'|\")\)`),
			regexp.MustCompile(`request\(.*(req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSAndNoUseGetMethodUsingDataFromRequestOfUserInput() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "af548d16-c6d4-46eb-bb35-630cab1c00f1",
			Name:        "No use .get method using data from request of user input",
			Description: "Allows user input data to be used as parameters for the 'request.get' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/918.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`require\((?:'|\")request(?:'|\")\)`),
			regexp.MustCompile(`\.get\(.*(req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSAndCryptographicRsaShouldBeRobust() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f434338d-0480-4f80-9af0-cd6a3e61f2d1",
			Name:        "Cryptographic RSA should be robust",
			Description: "Most of cryptographic systems require a sufficient key size to be robust against brute-force attacks. n ≥ 2048 for RSA (n is the key length). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.generateKeyPairSync\(.*rsa`),
			regexp.MustCompile(`(modulusLength:\s*)([0-9][^\d]|[0-9]{2}[^\d]|[0-9]{3}[^\d]|[0-1][0-9]{3}[^\d]|20[0-3][0-9]|204[0-7])`),
		},
	}
}

func NewNodeJSAndCryptographicEcShouldBeRobust() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4e4bc6ed-9be5-41a6-97f6-34d2b365d8c5",
			Name:        "Cryptographic EC should be robust",
			Description: "Most of cryptographic systems require a sufficient key size to be robust against brute-force attacks. n ≥ 224 for ECDH and ECMQV (Examples: secp192r1 is a non-compliant curve (n < 224) but secp224k1 is compliant (n >= 224)). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.generateKeyPairSync\(.*ec`),
			regexp.MustCompile(`(namedCurve:.*secp)([0-9][^\d]|[0-9]{2}[^\d]|[0-2][0-2][0-3][^\d])`),
		},
	}
}

func NewNodeJSAndJWTNeedStrongCipherAlgorithms() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f8c6b5bb-2e8c-4e63-9db2-7a075e9fe3fc",
			Name:        "JWT should be signed and verified with strong cipher algorithms",
			Description: "If a JSON Web Token (JWT) is not signed with a strong cipher algorithm (or not signed at all) an attacker can forge it and impersonate user identities. Don't use none algorithm to sign or verify the validity of an algorithm. Don't use a token without verifying its signature before. For more information checkout the CWE-347 (https://cwe.mitre.org/data/definitions/347.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`require('jsonwebtoken')`),
			regexp.MustCompile(`\.sign\(`),
			regexp.MustCompile(`((algorithm[s]?:.*none)|(algorithm[s]?:.*RS256))`),
		},
	}
}
