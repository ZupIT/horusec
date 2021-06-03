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

package and

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewSwiftAndSQLiteDatabase() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "80f1ff7a-c2db-11eb-a035-13ab0aa767e8",
			Name:        "SQLite Database",
			Description: "App uses SQLite Database. Sensitive Information should be encrypted.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sqlite3_exec`),
			regexp.MustCompile(`sqlite3_finalize`),
		},
	}
}

func NewSwiftAndCoreDataDatabase() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a2394cb6-c2da-11eb-a035-13ab0aa767e8",
			Name:        "CoreData Database",
			Description: "App uses CoreData Database. Sensitive Information should be encrypted.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSManagedObjectContext`),
			regexp.MustCompile(`\.save\(\)`),
		},
	}
}

func NewSwiftAndDTLS12NotUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fa479b38-c23f-11eb-a035-13ab0aa767e8",
			Name:        "DTLS 1.2 not used",
			Description: "DTLS 1.2 should be used. Detected old version - DTLS 1.0.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.TLSMinimumSupportedProtocolVersion`),
			regexp.MustCompile(`tls_protocol_version_t\.DTLSv10`),
		},
	}
}

func NewSwiftAndTLS13NotUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "50264a8c-c23f-11eb-a035-13ab0aa767e8",
			Name:        "TLS 1.3 not used",
			Description: "TLS 1.3 should be used. Detected old version - TLS 1.2.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.TLSMinimumSupportedProtocolVersion`),
			regexp.MustCompile(`tls_protocol_version_t\.TLSv12`),
		},
	}
}

func NewSwiftAndReverseEngineering() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "36e370d6-c23a-11eb-a035-13ab0aa767e8",
			Name:        "Reverse engineering",
			Description: "This App may have Reverse engineering detection capabilities.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`"FridaGadget"`),
			regexp.MustCompile(`"cynject"`),
			regexp.MustCompile(`"libcycript"`),
			regexp.MustCompile(`"/usr/sbin/frida-server"`),
		},
	}
}

func NewSwiftAndWeakMD5CryptoCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "81e073b6-c205-11eb-a035-13ab0aa767e8",
			Name:        "Weak Cipher Mode",
			Description: "MD5 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import CryptoSwift`),
			regexp.MustCompile(`\.md5()`),
		},
	}
}

func NewSwiftAndWeakCommonDesCryptoCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "90e9196c-c205-11eb-a035-13ab0aa767e8",
			Name:        "Weak Cipher Mode",
			Description: "DES is a weak hash, which can generate repeated hashes",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import CommonCrypto`),
			regexp.MustCompile(`CCAlgorithm\(kCCAlgorithmDES\)`),
		},
	}
}

func NewSwiftAndWeakIDZDesCryptoCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9b0d9d46-c205-11eb-a035-13ab0aa767e8",
			Name:        "Weak Cipher Mode",
			Description: "Cipher algorithms should be robust",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import IDZSwiftCommonCrypto`),
			regexp.MustCompile(`\.des`),
		},
	}
}

func NewSwiftAndWeakBlowfishCryptoCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a07288dc-c205-11eb-a035-13ab0aa767e8",
			Name:        "Weak Cipher Mode",
			Description: "Cipher algorithms should be robust",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import CryptoSwift`),
			regexp.MustCompile(`Blowfish\(.*\)`),
		},
	}
}
