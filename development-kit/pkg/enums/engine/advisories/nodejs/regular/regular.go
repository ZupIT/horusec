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

func NewNodeJSRegularNoUseEval() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "458736c7-8b9a-49f5-9102-f36b12b5a6c2",
			Name:        "No use eval",
			Description: "The eval function is extremely dangerous. Because if any user input is not handled correctly and passed to it, it will be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion). For more information checkout the CWE-94 (https://cwe.mitre.org/data/definitions/94.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(eval\(.+)(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularNoDisableTlsRejectUnauthorized() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "eb3a06aa-b8a2-4249-a605-24799b0691c7",
			Name:        "No disable tls reject unauthorized",
			Description: "If the NODE_TLS_REJECT_UNAUTHORIZED option is disabled, the Node.js server will accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?:\[|)(?:'|\")NODE_TLS_REJECT_UNAUTHORIZED(?:'|\")(?:\]|)\s*=\s*(?:'|\")*0(?:'|\")`),
		},
	}
}

func NewNodeJSRegularNoUseMD5Hashing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6ca794ec-a8bd-48a3-be37-b535069744f8",
			Name:        "No use MD5 hashing",
			Description: "The MD5 hash algorithm that was used is considered weak. It can also cause hash collisions. It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`createHash\((?:'|\")md5(?:'|\")`),
		},
	}
}

func NewNodeJSRegularNoUseSAH1Hashing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "af6492f1-6b64-45f8-807c-ebf52466e74b",
			Name:        "No use SAH1 hashing",
			Description: "The SHA1 hash algorithm that was used is considered weak. It can also cause hash collisions. It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`createHash\((?:'|\")sha1(?:'|\")`),
		},
	}
}

func NewNodeJSRegularNoReadFileUsingDataFromRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6573c53c-88a8-48cd-a118-6866055a72cf",
			Name:        "No read file using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.readFile\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularNoCreateReadStreamUsingDataFromRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3f6700f2-c9b5-49d0-99e6-367a2c75c6ed",
			Name:        "No create read stream using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.createReadStream\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularSQLInjectionUsingParams() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "624eda63-cfff-4b5c-b13d-be8c0d5f1fcc",
			Name:        "SQL Injection Using params",
			Description: "Passing untreated parameters to queries in the database can cause an injection of SQL / NoSQL. The attacker is able to insert a custom and improper SQL statement through the data entry of an application. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*\$where(?:'|\"|):.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularXMLParsersShouldNotBeVulnerableToXXEAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8226ed10-a4f0-4683-89a0-2ad782b58340",
			Name:        "XML parsers should not be vulnerable to XXE attacks",
			Description: "XML specification allows the use of entities that can be internal or external (file system / network access ...) which could lead to vulnerabilities such as confidential file disclosures or SSRFs. For more information checkout the CWE-827 (https://cwe.mitre.org/data/definitions/827.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.parseXmlString\(.*,.*\)`),
		},
	}
}
