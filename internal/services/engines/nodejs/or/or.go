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

func NewNodeJSOrEncryptionAlgorithmsWeak() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "62435d12-f9ae-48a9-a7db-e3b6db988a98",
			Name:        "Encryption Algorithms Weak",
			Description: "To perform secure cryptography, operation modes and padding scheme are essentials and should be used correctly according to the encryption algorithm:For block cipher encryption algorithms (like AES), the GCM (Galois Counter Mode) mode that works internally with zero/no padding scheme, is recommended. At the opposite, these modes and/or schemes are highly discouraged:Electronic Codebook (ECB) mode is vulnerable because it doesn't provide serious message confidentiality: under a given key any given plaintext block always gets encrypted to the same ciphertext block.Cipher Block Chaining (CBC) with PKCS#5 padding (or PKCS#7) is vulnerable to padding oracle attacks.RSA encryption algorithm should be used with the recommended padding scheme (OAEP). More specifically for block cipher, it's not recommended to use algorithm with a block size inferior than 128 bits. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.createCipheriv\(.*(AES-([0-9][^\d]|[0-9]{2}[^\d]|[0-1][0-9]{2}[^\d]|2[0-5][0-5][^\d]))`),
			regexp.MustCompile(`\.createCipheriv\(.*(DES|DES-EDE|DES-EDE3|RC2|RC4|BF)`),
		},
	}
}

func NewNodeJSOrFileUploadsShouldBeRestricted() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "165b5ea3-bf81-4350-aaf1-d4fd3f0d3e48",
			Name:        "File uploads should be restricted",
			Description: "These minimum restrictions should be applied when handling file uploads: the file upload folder to restrict untrusted files to a specific folder. the file extension of the uploaded file to prevent remote code execution. Also the size of the uploaded file should be limited to prevent denial of service attacks. For more information checkout the CWE-434 (https://cwe.mitre.org/data/definitions/434.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sFormidable\(\)(.|\n)*(uploadDir.*=.*(["|']\s*["|']|null|undefined))`),
			regexp.MustCompile(`new\sFormidable\(\)(.|\n)*(keepExtensions.*=.*true)`),
			regexp.MustCompile(`(\.diskStorage\(\s*\{)(([^d]|d[^e]|de[^s]|des[^t]|dest[^i]|desti[^n]|destin[^a]|destina[^t]|destinat[^i]|destinati[^o]|destinatio[^n]|destination[^:])*)(\}\s*\))`),
		},
	}
}

func NewNodeJSOrAllowingRequestsWithExcessiveContentLengthSecurity() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "14fe5ebe-037e-4720-97c5-1c3c2db4d714",
			Name:        "Allowing requests with excessive content length is security-sensitive",
			Description: "Rejecting requests with significant content length is a good practice to control the network traffic intensity and thus resource consumption in order to prevents DoS attacks, In your multer by default is no limit and maximum accept in Formidable and multer is 8mb. Ask Yourself Whether: Size limits are not defined for the different resources of the web application? The web application is not protected by rate limiting features? The web application infrastructure has limited resources? There is a risk if you answered yes to any of those questions. For more information checkout the CWE-770 (https://cwe.mitre.org/data/definitions/770.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sFormidable(.|\n)*)maxFileSize\s*=\s*([8-9][0-9]{6}|[1-9][0-9]{6}[0-9]+)`),
			regexp.MustCompile(`(multer(.|\n)*)fileSize\s*:\s*([8-9][0-9]{6}|[1-9][0-9]{6}[0-9]+)`),
			regexp.MustCompile(`(multer\(\s*\{)(([^f]|f[^i]|fi[^l]|fil[^e]|file[^S]|fileS[^i]|fileSi[^z]|fileSiz[^e])*)(\}\s*\))`),
		},
	}
}

func NewNodeJSOrNoDisableSanitizeHtml() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3137ce82-02b2-4894-a5e1-8e46b766321d",
			Name:        "No Disable Sanitize Html",
			Description: "To reduce the risk of cross-site scripting attacks, templating systems, such as Twig, Django, Smarty, Groovy's template engine, allow configuration of automatic variable escaping before rendering templates. When escape occurs, characters that make sense to the browser (eg: <a>) will be transformed/replaced with escaped/sanitized values (eg: & lt;a& gt; ). Enable auto-escaping by default and continue to review the use of inputs in order to be sure that the chosen auto-escaping strategy is the right one. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Mustache.escape`),
			regexp.MustCompile(`(?i)(Handlebars)?\.compile(.|\s)*noEscape`),
			regexp.MustCompile(`(?i)(markdownIt|markdown-it)(.|\s)*html.*true`),
			regexp.MustCompile(`(?i)(marked)?\.setOptions(.|\s)*sanitize.*false`),
			regexp.MustCompile(`(?i)(kramed)?\.Renderer(.|\s)*sanitize.*false`),
		},
	}
}

func NewNodeJSOrSQLInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "88519d1e-6225-418b-8048-9697ef3fbe78",
			Name:        "SQL Injection",
			Description: "SQL queries often need to use a hardcoded SQL string with a dynamic parameter coming from a user request. Formatting a string to add those parameters to the request is a bad practice as it can result in an SQL injection. The safe way to add parameters to a SQL query is to use SQL binding mechanisms. For more information checkout the CWE-564 (https://cwe.mitre.org/data/definitions/564.html) and OWASP A1:2017 (https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)query\(.*(SELECT|UPDATE|DELETE|INSERT).*(\+|\$\{)`),
			regexp.MustCompile(`(?i)((?:var|let|const)?\s*\w+.?\s*(=|:).*(SELECT|UPDATE|DELETE|INSERT).*(\+|\$\{)\s*\w+$)`),
		},
	}
}
