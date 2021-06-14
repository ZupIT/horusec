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

package or

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewSwiftOrMD6Collision() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b3523bc0-c235-11eb-a035-13ab0aa767e8",
			Name:        "Weak MD6 hash using",
			Description: "MD6 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)MD6\(`),
			regexp.MustCompile(`CC_MD6\(`),
		},
	}
}

func NewSwiftOrMD5Collision() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7754d218-c235-11eb-a035-13ab0aa767e8",
			Name:        "Weak MD5 hash using",
			Description: "MD5 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)MD5\(`),
			regexp.MustCompile(`CC_MD5\(`),
		},
	}
}

func NewSwiftOrSha1Collision() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "791eee9a-c234-11eb-a035-13ab0aa767e8",
			Name:        "Weak SHA1 hash using",
			Description: "SHA1 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SHA1\(`),
			regexp.MustCompile(`CC_SHA1\(`),
		},
	}
}

func NewSwiftOrJailbreakDetect() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4ecac5b6-c233-11eb-a035-13ab0aa767e8",
			Name:        "Jailbreak detection",
			Description: "This App may have Jailbreak detection capabilities.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`/Applications/Cydia\.app`),
			regexp.MustCompile(`/Library/MobileSubstrate/MobileSubstrate\.dylib`),
			regexp.MustCompile(`/usr/sbin/sshd`),
			regexp.MustCompile(`/etc/apt`),
			regexp.MustCompile(`cydia://`),
			regexp.MustCompile(`/var/lib/cydia`),
			regexp.MustCompile(`/Applications/FakeCarrier\.app`),
			regexp.MustCompile(`/Applications/Icy\.app`),
			regexp.MustCompile(`/Applications/IntelliScreen\.app`),
			regexp.MustCompile(`/Applications/SBSettings\.app`),
			regexp.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/LiveClock\.plist`),
			regexp.MustCompile(`/System/Library/LaunchDaemons/com\.ikey\.bbot\.plist`),
			regexp.MustCompile(`/System/Library/LaunchDaemons/com\.saurik\.Cydia\.Startup\.plist`),
			regexp.MustCompile(`/etc/ssh/sshd_config`),
			regexp.MustCompile(`/private/var/tmp/cydia\.log`),
			regexp.MustCompile(`/usr/libexec/ssh-keysign`),
			regexp.MustCompile(`/Applications/MxTube\.app`),
			regexp.MustCompile(`/Applications/RockApp\.app`),
			regexp.MustCompile(`/Applications/WinterBoard\.app`),
			regexp.MustCompile(`/Applications/blackra1n\.app`),
			regexp.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/Veency\.plist`),
			regexp.MustCompile(`/private/var/lib/apt`),
			regexp.MustCompile(`/private/var/lib/cydia`),
			regexp.MustCompile(`/private/var/mobile/Library/SBSettings/Themes`),
			regexp.MustCompile(`/private/var/stash`),
			regexp.MustCompile(`/usr/bin/sshd`),
			regexp.MustCompile(`/usr/libexec/sftp-server`),
			regexp.MustCompile(`/var/cache/apt`),
			regexp.MustCompile(`/var/lib/apt`),
			regexp.MustCompile(`/usr/sbin/frida-server`),
			regexp.MustCompile(`/usr/bin/cycript`),
			regexp.MustCompile(`/usr/local/bin/cycript`),
			regexp.MustCompile(`/usr/lib/libcycript.dylib`),
			regexp.MustCompile(`frida-server`),
			regexp.MustCompile(`/etc/apt/sources\.list\.d/electra\.list`),
			regexp.MustCompile(`/etc/apt/sources\.list\.d/sileo\.sources`),
			regexp.MustCompile(`/.bootstrapped_electra`),
			regexp.MustCompile(`/usr/lib/libjailbreak\.dylib`),
			regexp.MustCompile(`/jb/lzma`),
			regexp.MustCompile(`/\.cydia_no_stash`),
			regexp.MustCompile(`/\.installed_unc0ver`),
			regexp.MustCompile(`/jb/offsets\.plist`),
			regexp.MustCompile(`/usr/share/jailbreak/injectme\.plist`),
			regexp.MustCompile(`/Library/MobileSubstrate/MobileSubstrate\.dylib`),
			regexp.MustCompile(`/usr/libexec/cydia/firmware\.sh`),
			regexp.MustCompile(`/private/var/cache/apt/`),
			regexp.MustCompile(`/Library/MobileSubstrate/CydiaSubstrate\.dylib`),
		},
	}
}

func NewSwiftOrLoadHTMLString() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "18447476-c231-11eb-a035-13ab0aa767e8",
			Name:        "Javascript injection",
			Description: `User input not sanitized in "loadHTMLString" can result in an injection of JavaScript in the context of your application, allowing access to private data. For more information checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory.`,
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`loadHTMLString`),
			regexp.MustCompile(`webView`),
		},
	}
}

func NewSwiftOrWeakDesCryptoCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a6eec2ac-c205-11eb-a035-13ab0aa767e8",
			Name:        "Weak Cipher Mode",
			Description: "DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage of AES block ciphers instead of DES. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Cryptor\((.*algorithm: \.des)`),
			regexp.MustCompile(`\.CryptAlgorithm((\s+=)|=)+((\s)|)+\"3des"`),
		},
	}
}
