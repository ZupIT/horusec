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

func NewJavaOrFileIsWorldReadable() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "69ff7607-1a15-4c77-bc06-40da03c2aa2a",
			Name:        "File Is World Readable",
			Description: "The file is World Readable. Any App can read from the file. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE`),
			regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*1\s*\)`),
		},
	}
}

func NewJavaOrFileIsWorldWritable() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ce5d3c63-f2c8-4304-b9a5-f937c2279267",
			Name:        "File Is World Writable",
			Description: "The file is World Writable. Any App can write to the file. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE`),
			regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*2\s*\)`),
		},
	}
}

func NewJavaOrNoWriteExternalContent() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e76a5e61-5112-4156-9587-743fefcaba70",
			Name:        "No Write External Content",
			Description: "App can read/write to External Storage. Any App can read data written to External Storage. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.getExternalStorage`),
			regexp.MustCompile(`.getExternalFilesDir\(`),
		},
	}
}

func NewJavaOrNoUseIVsWeak() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6737a1bd-5eeb-40fd-a2e1-2a621203583a",
			Name:        "No use IVs weak",
			Description: "The App may use weak IVs like \"0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00\" or \"0x01,0x02,0x03,0x04,0x05,0x06,0x07\". Not using a random IV makes the resulting ciphertext much more predictable and susceptible to a dictionary attack. For more information checkout the CWE-329 (https://cwe.mitre.org/data/definitions/329.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00`),
			regexp.MustCompile(`0x01,0x02,0x03,0x04,0x05,0x06,0x07`),
		},
	}
}

func NewJavaOrRootDetectionCapabilities() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a80563e9-b277-41f5-818c-e64492b3500a",
			Name:        "This App may have root detection capabilities.",
			Description: "This App may have root detection capabilities.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.contains\(\"test-keys\"\)`),
			regexp.MustCompile(`/system/app/Superuser.apk`),
			regexp.MustCompile(`isDeviceRooted\(\)`),
			regexp.MustCompile(`/system/bin/failsafe/su`),
			regexp.MustCompile(`/system/sd/xbin/su`),
			regexp.MustCompile(`\"/system/xbin/which\", \"su\"`),
			regexp.MustCompile(`RootTools.isAccessGiven\(\)`),
		},
	}
}

func NewJavaOrJARURLConnection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5e355c6a-6c97-4fbd-824d-fb8861e3759c",
			Name:        "JAR URL Connection",
			Description: "JAR URL Connection",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`net.JarURLConnection`),
			regexp.MustCompile(`JarURLConnection`),
			regexp.MustCompile(`jar:`),
		},
	}
}

func NewJavaOrSetOrReadClipboardData() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "48e1a6de-9eaa-48ad-b945-58e58c9350b2",
			Name:        "Set or Read Clipboard data",
			Description: "Set or Read Clipboard data",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`content.ClipboardManager`),
			regexp.MustCompile(`CLIPBOARD_SERVICE`),
			regexp.MustCompile(`ClipboardManager`),
		},
	}
}

func NewJavaOrMessageDigest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "963fc7b7-e61c-4d74-9264-fd15b70d6306",
			Name:        "Message Digest",
			Description: "The MD5 algorithm and its successor, SHA-1, are no longer considered secure, because it is too easy to create hash collisions with them. That is, it takes too little computational effort to come up with a different input that produces the same MD5 or SHA-1 hash, and using the new, same-hash value gives an attacker the same access as if he had the originally-hashed value. This applies as well to the other Message-Digest algorithms: MD2, MD4, MD6, HAVAL-128, HMAC-MD5, DSA (which uses SHA-1), RIPEMD, RIPEMD-128, RIPEMD-160, HMACRIPEMD160.\n\n",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`java.security.MessageDigest`),
			regexp.MustCompile(`MessageDigestSpi`),
			regexp.MustCompile(`MessageDigest`),
		},
	}
}

func NewJavaOrOverlyPermissiveFilePermission() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "da6592b2-75f8-45a0-bd0f-52914e7c3a0b",
			Name:        "Overly permissive file permission",
			Description: "It is generally a bad practices to set overly permissive file permission such as read+write+exec for all users. If the file affected is a configuration, a binary, a script or sensitive data, it can lead to privilege escalation or information leakage. For more information checkout the CWE-732 (https://cwe.mitre.org/data/definitions/732.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Files.setPosixFilePermissions\(.*, PosixFilePermissions.fromString\("rw-rw-rw-"\)\)`),
			regexp.MustCompile(`PosixFilePermission.OTHERS_READ`),
			regexp.MustCompile(`PosixFilePermission.OTHERS_WRITE`),
			regexp.MustCompile(`PosixFilePermission.OTHERS_EXECUTE`),
		},
	}
}

func NewJavaOrCipherGetInstanceInsecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7072d384-d1d5-4753-8adc-2faebfaedf54",
			Name:        "DES, DESede, RSA is insecure",
			Description: "DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage of AES block ciphers instead of DES. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Cipher\..*DES`),
			regexp.MustCompile(`Cipher\..*DESede`),
			regexp.MustCompile(`Cipher\..*RC2`),
			regexp.MustCompile(`Cipher\..*RC4`),
			regexp.MustCompile(`Cipher\..*Blowfish`),
			regexp.MustCompile(`Cipher\..*((RSA).*(NoPadding)|(NoPadding).*(RSA))`),
		},
	}
}
