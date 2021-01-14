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

func NewDartRegularNoUseBiometricsTypeAndroid() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bf7dd90d-389a-40a2-a9b6-25c798dba6f5",
			Name:        "No use biometrics types face or fingerprint for login in account",
			Description: "If the mobile app uses a feature like TouchID, it suffers from insecure authentication. For more information checkout the OWSAP M4:2016 (https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`authenticateWithBiometrics`),
		},
	}
}

func NewDartRegularNoListClipboardChanges() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "87e333a1-3a6c-4263-9784-a6b40bd638e4",
			Name:        "No List changes on the clipboard",
			Description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Clipboard\.getData|StreamController.*broadcast\(`),
		},
	}
}

func NewDartRegularSQLInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b6c606f3-61d2-4aac-9053-79841b6af5d6",
			Name:        "SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(rawQuery|rawDelete|rawUpdate|rawInsert|query).*\(\s*.*(SELECT|UPDATE|DELETE|INSERT).*((\$(\{)?)|(\+))+`),
		},
	}
}

func NewDartRegularNoUseNSTemporaryDirectory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b0924392-9957-45c7-a86f-4945ae996b63",
			Name:        "No use NSTemporaryDirectory",
			Description: "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory. For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSTemporaryDirectory\(\),`),
		},
	}
}

func NewDartRegularNoUseCipherMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6abd99e3-0698-4eca-a11b-59269ff9ab5f",
			Name:        "No Use Cipher mode",
			Description: "This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB and OFB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)AesMode\.ECB`),
			regexp.MustCompile(`(?i)AesMode\.OFB`),
			regexp.MustCompile(`(?i)AesMode\.CTS`),
			regexp.MustCompile(`(?i)AesMode\.CFB`),
		},
	}
}

func NewDartRegularCorsAllowOriginWildCard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f0935a93-2ad0-4953-80fd-48205065c1b7",
			Name:        "Cors Allow Origin Wild Card",
			Description: "Cross-Origin Resource Sharing (CORS) allows a service to disable the browser’s Same-origin policy, which prevents scripts on an attacker-controlled domain from accessing resources and data hosted on a different domain. The CORS Access-Control-Allow-Origin HTTP header specifies the domain with permission to invoke a cross-origin service and view the response data. Configuring the Access-Control-Allow-Origin header with a wildcard (*) can allow code running on an attacker-controlled domain to view responses containing sensitive data. For more information checkout the CWE-942 (https://cwe.mitre.org/data/definitions/942.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Access-Control-Allow-Origin.*\*`),
		},
	}
}

func NewDartRegularUsingShellInterpreterWhenExecutingOSCommand() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "50cb4744-421c-4804-89db-858dece86e92",
			Name:        "Using shell interpreter when executing OS commands",
			Description: "Arbitrary OS command injection vulnerabilities are more likely when a shell is spawned rather than a new process, indeed shell meta-chars can be used (when parameters are user-controlled for instance) to inject OS commands. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Process\.run`),
		},
	}
}
