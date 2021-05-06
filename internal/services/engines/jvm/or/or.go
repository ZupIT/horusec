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

func NewJvmOrSuperUserPrivileges() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "259bf097-21e3-4ef7-9601-136d1119014f",
			Name:        "Super User Privileges",
			Description: "This App may request root (Super User) privileges. For more information checkout the CWE-250 (https://cwe.mitre.org/data/definitions/250.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`com.noshufou.android.su`),
			regexp.MustCompile(`com.thirdparty.superuser`),
			regexp.MustCompile(`eu.chainfire.supersu`),
			regexp.MustCompile(`com.koushikdutta.superuser`),
			regexp.MustCompile(`eu.chainfire.`),
		},
	}
}

func NewJvmOrSendSMS() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "92680eb9-9408-43a4-a098-1c6fda2713ff",
			Name:        "Send SMS",
			Description: "Send SMS. For more information checkout the OWASP-M3 (https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.SmsManager`),
			regexp.MustCompile(`sendMultipartTextMessage`),
			regexp.MustCompile(`sendTextMessage`),
			regexp.MustCompile(`vnd.android-dir/mms-sms`),
		},
	}
}

func NewJvmOrBase64Encode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "dfa01ba1-a2eb-4db9-a169-23e5484b5bfa",
			Name:        "Base64 Encode",
			Description: "Basic authentication's only means of obfuscation is Base64 encoding. Since Base64 encoding is easily recognized and reversed, it offers only the thinnest veil of protection to your users, and should not be used.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.util.Base64`),
			regexp.MustCompile(`.encodeToString`),
			regexp.MustCompile(`.encode`),
		},
	}
}

func NewJvmOrGpsLocation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1c2fc6a5-540a-4cfa-bf4f-8ef85dd7cedf",
			Name:        "GPS Location",
			Description: "GPS Location",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.location`),
			regexp.MustCompile(`getLastKnownLocation\(`),
			regexp.MustCompile(`requestLocationUpdates\(`),
			regexp.MustCompile(`getLatitude\(`),
			regexp.MustCompile(`getLongitude\(`),
		},
	}
}

func NewJvmOrApplicationMayContainJailbreakDetectionMechanisms() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4467e0e0-a41e-4e0b-9011-53d657c0f599",
			Name:        "The application may contain Jailbreak detection mechanisms",
			Description: "The application may contain Jailbreak detection mechanisms.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`/Applications/Cydia.app`),
			regexp.MustCompile(`/Library/MobileSubstrate/MobileSubstrate.dylib`),
			regexp.MustCompile(`/usr/sbin/sshd`),
			regexp.MustCompile(`/etc/apt`),
			regexp.MustCompile(`cydia://`),
			regexp.MustCompile(`/var/lib/cydia`),
			regexp.MustCompile(`/Applications/FakeCarrier.app`),
			regexp.MustCompile(`/Applications/Icy.app`),
			regexp.MustCompile(`/Applications/IntelliScreen.app`),
			regexp.MustCompile(`/Applications/SBSettings.app`),
			regexp.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist`),
			regexp.MustCompile(`/System/Library/LaunchDaemons/com.ikey.bbot.plist`),
			regexp.MustCompile(`/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist`),
			regexp.MustCompile(`/etc/ssh/sshd_config`),
			regexp.MustCompile(`/private/var/tmp/cydia.log`),
			regexp.MustCompile(`/usr/libexec/ssh-keysign`),
			regexp.MustCompile(`/Applications/MxTube.app`),
			regexp.MustCompile(`/Applications/RockApp.app`),
			regexp.MustCompile(`/Applications/WinterBoard.app`),
			regexp.MustCompile(`/Applications/blackra1n.app`),
			regexp.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/Veency.plist`),
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
		},
	}
}
