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

package dart

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewUsageLocalDataWithoutCryptography() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-1",
			Name:        "Usage Local Data Without Cryptography",
			Description: "While useful to speed applications up on the client side, it can be dangerous to store sensitive information this way because the data is not encrypted by default and any script on the page may access it. This rule raises an issue when the SharedPreferences and localstorage API's are used. For more information checkout the OWSAP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SharedPreferences\.getInstance`),
			regexp.MustCompile(`\.(setInt|setDouble|setBool|setString|setStringList)\(.*,.*\)`),
		},
	}
}

func NewNoSendSensitiveInformation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-2",
			Name:        "No Send Sensitive Information in alternative channels (sms, mms, notifications)",
			Description: "Sensitive information should never send for this channels sms, mms, notifications. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(firebase|fb).*\.configure\(`),
			regexp.MustCompile(`onMessage|onResume`),
		},
	}
}

func NewNoUseBiometricsTypeIOS() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:   "HS-DART-3",
			Name: "No use biometrics types face or fingerprint for login in account",
			Description: `If the mobile app uses a feature like TouchID, it suffers from insecure authentication.
Depending on the implementation in the operating system the bioID is just a lock for the traditional 4-digit password.
Basically on Android, you can ask to use the 4-digit password because of "faulty hardware" and this functionality depends on how the application uses this.
There are applications that ask for 6 digit passwords and then ask for the bioID just to "automatically type" the 6 digit password which can cause an easy identification and access to your application is broken.
For more information checkout the OWSAP M4:2016 (https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication) advisory and see this example how implement good authentication (in "C" Language): https://developer.apple.com/library/archive/samplecode/KeychainTouchID/Introduction/Intro.html.`,
			Severity:   severities.Info.ToString(),
			Confidence: confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getAvailableBiometrics`),
			regexp.MustCompile(`(contains\(BiometricType\.face\))|(contains\(BiometricType\.fingerprint\))`),
		},
	}
}

func NewXmlReaderExternalEntityExpansion() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-4",
			Name:        "Xml Reader External Entity Expansion",
			Description: "XML External Entity (XXE) vulnerabilities occur when applications process untrusted XML data without disabling external entities and DTD processing. Processing untrusted XML data with a vulnerable parser can allow attackers to extract data from the server, perform denial of service attacks, and in some cases gain remote code execution. The XmlReaderSettings and XmlTextReader classes are vulnerable to XXE attacks when setting the DtdProcessing property to DtdProcessing.Parse or the ProhibitDtd property to false. To prevent XmlReader XXE attacks, avoid using the deprecated ProhibitDtd property. Set the DtdProcessing property to DtdProcessing.Prohibit. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new File\(\w+`),
			regexp.MustCompile(`XmlDocument\.parse\(`),
			regexp.MustCompile(`readAsStringSync\(`),
		},
	}
}

func NewNoUseConnectionWithoutSSL() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-5",
			Name:        "No use connection without SSL",
			Description: "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.bindSecure\(\n?('|")http:\/\/`),
			regexp.MustCompile(`\.parse\(\n?('|")http:\/\/`),
			regexp.MustCompile(`(.parse\(('|")|.bindSecure\(('|"))(([^h]|h[^t]|ht[^t]|htt[^p])*)(\))`),
		},
	}
}

func NewSendSMS() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-6",
			Name:        "Send SMS",
			Description: "Send SMS. For more information checkout the OWASP-M3 (https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`flutter_sms\.dart`),
			regexp.MustCompile(`sendSMS`),
		},
	}
}

func NewXSSAttack() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-7",
			Name:        "Prevent XSS Attack",
			Description: "A potential Cross-Site Scripting (XSS) was found. The endpoint returns a variable from the client entry that has not been coded. Always encode untrusted input before output, regardless of validation or cleaning performed. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Element\.html\(`),
		},
	}
}

func NewNoLogSensitive() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-8",
			Name:        "No Log Sensitive Information in console",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`print\(.*(\$|%|('|")\s*\+)`),
			regexp.MustCompile(`window\.console.*\(.*(\$|%|('|")\s*\+)`),
			regexp.MustCompile(`log.*\.(finest|finer|fine|config|info|warning|severe|shout|erro).*\(.*(\$|%|('|")\s*\+)`),
		},
	}
}

func NewWeakHashingFunctionMd5OrSha1() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-9",
			Name:        "Weak hashing function md5 or sha1",
			Description: "MD5 or SHA1 have known collision weaknesses and are no longer considered strong hashing algorithms. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severities.Medium.ToString(),
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

func NewNoUseSelfSignedCertificate() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-10",
			Name:        "No Use Self Signed Certificate",
			Description: "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setTrustedCertificates`),
			regexp.MustCompile(`setAllowsAnyHTTPSCertificate`),
		},
	}
}

func NewNoUseBiometricsTypeAndroid() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-11",
			Name:        "No use biometrics types face or fingerprint for login in account",
			Description: "If the mobile app uses a feature like TouchID, it suffers from insecure authentication. For more information checkout the OWSAP M4:2016 (https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`authenticateWithBiometrics`),
		},
	}
}

func NewNoListClipboardChanges() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-12",
			Name:        "No List changes on the clipboard",
			Description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Clipboard\.getData|StreamController.*broadcast\(`),
		},
	}
}

func NewSQLInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-13",
			Name:        "SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(rawQuery|rawDelete|rawUpdate|rawInsert|query).*\(\s*.*(SELECT|UPDATE|DELETE|INSERT).*((\$(\{)?)|(\+))+`),
		},
	}
}

func NewNoUseNSTemporaryDirectory() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-14",
			Name:        "No use NSTemporaryDirectory",
			Description: "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory. For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSTemporaryDirectory\(\)`),
		},
	}
}

func NewNoUseCipherMode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-15",
			Name:        "No Use Cipher mode",
			Description: "This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB and OFB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(AesMode\.ECB)`),
			regexp.MustCompile(`(?i)(AesMode\.OFB)`),
			regexp.MustCompile(`(?i)(AesMode\.CTS)`),
			regexp.MustCompile(`(?i)(AesMode\.CFB)`),
		},
	}
}

func NewCorsAllowOriginWildCard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-16",
			Name:        "Cors Allow Origin Wild Card",
			Description: "Cross-Origin Resource Sharing (CORS) allows a service to disable the browser’s Same-origin policy, which prevents scripts on an attacker-controlled domain from accessing resources and data hosted on a different domain. The CORS Access-Control-Allow-Origin HTTP header specifies the domain with permission to invoke a cross-origin service and view the response data. Configuring the Access-Control-Allow-Origin header with a wildcard (*) can allow code running on an attacker-controlled domain to view responses containing sensitive data. For more information checkout the CWE-942 (https://cwe.mitre.org/data/definitions/942.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Access-Control-Allow-Origin.*\*`),
		},
	}
}

func NewUsingShellInterpreterWhenExecutingOSCommand() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-DART-17",
			Name:        "Using shell interpreter when executing OS commands",
			Description: "Arbitrary OS command injection vulnerabilities are more likely when a shell is spawned rather than a new process, indeed shell meta-chars can be used (when parameters are user-controlled for instance) to inject OS commands. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Process\.run`),
		},
	}
}
