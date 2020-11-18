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
package or

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewNodeJSOrEncryptionAlgorithmsWeek() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "62435d12-f9ae-48a9-a7db-e3b6db988a98",
			Name:        "Encryption Algorithms Week",
			Description: "To perform secure cryptography, operation modes and padding scheme are essentials and should be used correctly according to the encryption algorithm:For block cipher encryption algorithms (like AES), the GCM (Galois Counter Mode) mode that works internally with zero/no padding scheme, is recommended. At the opposite, these modes and/or schemes are highly discouraged:Electronic Codebook (ECB) mode is vulnerable because it doesn't provide serious message confidentiality: under a given key any given plaintext block always gets encrypted to the same ciphertext block.Cipher Block Chaining (CBC) with PKCS#5 padding (or PKCS#7) is vulnerable to padding oracle attacks.RSA encryption algorithm should be used with the recommended padding scheme (OAEP). More specifically for block cipher, it's not recommended to use algorithm with a block size inferior than 128 bits. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.Medium.ToString(),
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
			ID:          "04b93a07-d0cf-435b-9a3b-54cb5ff22ce6",
			Name:        "File uploads should be restricted",
			Description: "These minimum restrictions should be applied when handling file uploads: the file upload folder to restrict untrusted files to a specific folder. the file extension of the uploaded file to prevent remote code execution. Also the size of the uploaded file should be limited to prevent denial of service attacks. This requirement is covered by the rule S5693. For more information checkout the CWE-434 (https://cwe.mitre.org/data/definitions/434.html) advisory.",
			Severity:    severity.Medium.ToString(),
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
