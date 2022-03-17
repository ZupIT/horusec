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

package jvm

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func Rules() []engine.Rule {
	return []engine.Rule{
		// Regular rules
		NewHTTPRequestsConnectionsAndSessions(),
		NewNoUsesSafetyNetAPI(),
		NewNoUsesContentProvider(),
		NewNoUseWithUnsafeBytes(),
		NewNoUseLocalFileIOOperations(),
		NewWebViewComponent(),
		NewEncryptionAPI(),
		NewKeychainAccessAndMatch(),
		NewNoUseProhibitedAPIs(),
		NewApplicationAllowMITMAttacks(),
		NewUIWebViewInApplicationIgnoringErrorsSSL(),
		NewNoListClipboardChanges(),
		NewApplicationUsingSQLite(),
		NewNoUseNSTemporaryDirectory(),
		NewNoCopiesDataToTheClipboard(),
		NewNoLogSensitiveInformation(),

		// And rules
		NewNoDownloadFileUsingAndroidDownloadManager(),
		NewSQLInjectionWithSQLite(),
		NewAndroidKeystore(),
		NewWebViewGETRequest(),
		NewWebViewPOSTRequest(),
		NewAndroidNotifications(),
		NewBase64Decode(),
		NewPotentialAndroidSQLInjection(),
		NewKeychainAccess(),
		// NewWebViewLoadRequest(),
		NewCookieStorage(),
		NewSetReadClipboard(),
		NewUsingLoadHTMLStringCanResultInject(),
		NewNoUseSFAntiPiracyJailbreak(),
		NewNoUseSFAntiPiracyIsPirated(),
		NewWeakMd5HashUsing(),
		NewWeakSha1HashUsing(),
		NewWeakECBEncryptionAlgorithmUsing(),
		NewUsingPtrace(),

		// Or rules
		NewSuperUserPrivileges(),
		NewSendSMS(),
		NewBase64Encode(),
		NewGpsLocation(),
		NewApplicationMayContainJailbreakDetectionMechanisms(),
	}
}

func NewNoLogSensitiveInformation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-1",
			Name:          "No Log Sensitive Information",
			Description:   "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM1,
			UnsafeExample: SampleVulnerableHSJVM1,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Log|log)\.(v|d|i|w|e|f|s)|System\.out\.print|System\.err\.print|println`),
		},
	}
}

func NewHTTPRequestsConnectionsAndSessions() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-2",
			Name:          "HTTP Requests, Connections and Sessions",
			Description:   "For more information checkout the CWE-CVE-2020-13956 (https://www.cvedetails.com/cve/CVE-2020-13956)",
			Severity:      severities.Low.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM2,
			UnsafeExample: SampleVulnerableHSJVM2,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`http\.client\.HttpClient|net\.http\.AndroidHttpClient|http\.impl\.client\.AbstractHttpClient`),
		},
	}
}

func NewNoUsesSafetyNetAPI() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-3",
			Name:          "No uses safety api",
			Description:   "This App uses SafetyNet API",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM3,
			UnsafeExample: SampleVulnerableHSJVM3,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`com.google.android.gms.safetynet.SafetyNetApi`),
		},
	}
}

func NewNoUsesContentProvider() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-4",
			Name:          "No uses Content Provider",
			Description:   "No uses Content Provider",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM4,
			UnsafeExample: SampleVulnerableHSJVM4,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.content.ContentProvider`),
		},
	}
}

func NewNoUseWithUnsafeBytes() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-5",
			Name:          "No Use With Unsafe Bytes",
			Description:   "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer. For more information checkout the CWE-789 (https://cwe.mitre.org/data/definitions/789.html) advisory.",
			Severity:      severities.Low.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM5,
			UnsafeExample: SampleVulnerableHSJVM5,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\w+.withUnsafeBytes\s*{.*`),
		},
	}
}

func NewNoUseLocalFileIOOperations() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-6",
			Name:          "Local File I/O Operations",
			Description:   "Local File I/O Operations. See more details in https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM6,
			UnsafeExample: SampleVulnerableHSJVM6,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete`),
		},
	}
}

func NewWebViewComponent() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-7",
			Name:          "WebView Component",
			Description:   "UIWebview is available since iOS 1 and deprecated in iOS 8. It has many security issues: You can NOT disable Javascript. You can NOT disable Access to files. You can NOT implement the same origin policy for file access. Native application has access to all the requests/response, which is not ideal for sensitive data and external authentication. The rendered content, and the native application shares the same process",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM7,
			UnsafeExample: SampleVulnerableHSJVM7,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIWebView`),
		},
	}
}

func NewEncryptionAPI() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-8",
			Name:          "Encryption API",
			Description:   "Encryption API. For more information checkout the CWE-789 (https://cwe.mitre.org/data/definitions/789.html) advisory",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM8,
			UnsafeExample: SampleVulnerableHSJVM8,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`RNEncryptor|RNDecryptor|AESCrypt`),
		},
	}
}

func NewKeychainAccess() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-9",
			Name:          "Keychain Access",
			Description:   "Keychain Access",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM9,
			UnsafeExample: SampleVulnerableHSJVM9,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`PDKeychainBindings`),
		},
	}
}

func NewNoUseProhibitedAPIs() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-10",
			Name:          "No Use Prohibited APIs",
			Description:   "The application may contain prohibited APIs. These APIs are insecure and should not be used. For more information checkout the CWE-676 (https://cwe.mitre.org/data/definitions/676.html) advisory.",
			Severity:      severities.Critical.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM10,
			UnsafeExample: SampleVulnerableHSJVM10,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(strcpy)|(memcpy)|(strcat)|(strncat)|(strncpy)|(sprintf)|(vsprintf)`),
		},
	}
}

func NewApplicationAllowMITMAttacks() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-11",
			Name:          "Application allow MITM attacks",
			Description:   "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:      severities.Critical.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM11,
			UnsafeExample: SampleVulnerableHSJVM11,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|allowInvalidCertificates\s*=\s*(YES|yes)`),
		},
	}
}

func NewUIWebViewInApplicationIgnoringErrorsSSL() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-12",
			Name:          "UIWebView in application ignoring errors SSL",
			Description:   "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle). For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:      severities.High.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM12,
			UnsafeExample: SampleVulnerableHSJVM12,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`),
		},
	}
}

func NewNoListClipboardChanges() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-13",
			Name:          "No List changes on the clipboard",
			Description:   "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM13,
			UnsafeExample: SampleVulnerableHSJVM13,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboardChangedNotification|generalPasteboard\]\.string`),
		},
	}
}

func NewApplicationUsingSQLite() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-14",
			Name:          "The application is using SQLite. Confidential information must be encrypted.",
			Description:   "The application is using SQLite. Confidential information must be encrypted.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM14,
			UnsafeExample: SampleVulnerableHSJVM14,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sqlite3_exec`),
		},
	}
}

func NewNoUseNSTemporaryDirectory() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-15",
			Name:          "No use NSTemporaryDirectory",
			Description:   "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory. For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM15,
			UnsafeExample: SampleVulnerableHSJVM15,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSTemporaryDirectory\(\)`),
		},
	}
}

func NewNoCopiesDataToTheClipboard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-16",
			Name:          "No copies data to the Clipboard",
			Description:   "The application copies data to the Clipboard. Confidential data must not be copied to the Clipboard, as other applications can access it. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM16,
			UnsafeExample: SampleVulnerableHSJVM16,
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\w+\s*=\s*UIPasteboard)`),
		},
	}
}

func NewNoDownloadFileUsingAndroidDownloadManager() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-17",
			Name:          "No Download File Using Android Download Manager",
			Description:   "This App downloads files using Android Download Manager",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM17,
			UnsafeExample: SampleVulnerableHSJVM17,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getSystemService\(.*DOWNLOAD_SERVICE.*\)`),
			regexp.MustCompile(`android.app.DownloadManager`),
		},
	}
}

func NewAndroidKeystore() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-18",
			Name:          "Android Keystore",
			Description:   "Android Keystore",
			Severity:      severities.Critical.ToString(),
			Confidence:    confidence.Medium.ToString(),
			SafeExample:   SampleSafeHSJVM18,
			UnsafeExample: SampleVulnerableHSJVM18,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)security.KeyStore`),
			regexp.MustCompile(`(?i)Keystore.getInstance\(`),
		},
	}
}

func NewAndroidNotifications() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-19",
			Name:          "Android Notifications",
			Description:   "For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:      severities.Low.ToString(),
			Confidence:    confidence.Medium.ToString(),
			SafeExample:   SampleSafeHSJVM19,
			UnsafeExample: SampleVulnerableHSJVM19,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`app.NotificationManager`),
			regexp.MustCompile(`notify`),
		},
	}
}

func NewPotentialAndroidSQLInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-20",
			Name:          "Potential Android SQL Injection",
			Description:   "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:      severities.High.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM20,
			UnsafeExample: SampleVulnerableHSJVM20,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(select|update|insert|delete)((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
			regexp.MustCompile(`rawQuery\(\w+\,null\)`),
		},
	}
}

func NewSQLInjectionWithSQLite() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-21",
			Name:          "SQL Injection With SQLite",
			Description:   "App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:      severities.High.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM21,
			UnsafeExample: SampleVulnerableHSJVM21,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(select|update|insert|delete)((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
			regexp.MustCompile(`execSQL\(|rawQuery\(`),
			regexp.MustCompile(`android\.database\.sqlite`),
		},
	}
}

func NewWebViewGETRequest() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-22",
			Name:          "WebView GET Request",
			Description:   "WebView GET Request",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM22,
			UnsafeExample: SampleVulnerableHSJVM22,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`WebView`),
			regexp.MustCompile(`loadData\(`),
			regexp.MustCompile(`android.webkit`),
		},
	}
}

func NewWebViewPOSTRequest() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-23",
			Name:          "WebView POST Request",
			Description:   "WebView POST Request",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.High.ToString(),
			SafeExample:   SampleSafeHSJVM23,
			UnsafeExample: SampleVulnerableHSJVM23,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`WebView`),
			regexp.MustCompile(`postUrl`),
			regexp.MustCompile(`android.webkit`),
		},
	}
}

func NewBase64Decode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-24",
			Name:          "Base64 Decode",
			Description:   "Base64 Decode",
			Severity:      severities.Low.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM24,
			UnsafeExample: SampleVulnerableHSJVM24,
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.util.Base64`),
			regexp.MustCompile(`\.decode\(`),
		},
	}
}

func NewKeychainAccessAndMatch() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-25",
			Name:          "WebView Load Request",
			Description:   "WebView Load Request",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM25,
			UnsafeExample: SampleVulnerableHSJVM25,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`webView`),
			regexp.MustCompile(`loadRequest`),
		},
	}
}

// Deprecated: Repeated vulnerability, same as HS-JVM-25
//func NewWebViewLoadRequest() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:            "HS-JVM-26",
//			Name:          "WebView Load Request",
//			Description:   "WebView Load Request",
//			Severity:      severities.Info.ToString(),
//			Confidence:    confidence.Low.ToString(),
//			SafeExample:   SampleSafeHSJVM26,
//			UnsafeExample: SampleVulnerableHSJVM26,
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`webView`),
//			regexp.MustCompile(`loadRequest`),
//		},
//	}
//}

func NewCookieStorage() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-27",
			Name:          "Cookie Storage",
			Description:   "Cookie Storage",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM27,
			UnsafeExample: SampleVulnerableHSJVM27,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSHTTPCookieStorage`),
			regexp.MustCompile(`sharedHTTPCookieStorage`),
		},
	}
}

func NewSetReadClipboard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-28",
			Name:          "Set or Read Clipboard",
			Description:   "Set or Read Clipboard",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM28,
			UnsafeExample: SampleVulnerableHSJVM28,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboard`),
			regexp.MustCompile(`generalPasteboard`),
		},
	}
}

func NewUsingLoadHTMLStringCanResultInject() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-29",
			Name:          "Using LoadHTMLString can result Inject",
			Description:   "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data. For more information checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM29,
			UnsafeExample: SampleVulnerableHSJVM29,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`loadHTMLString`),
			regexp.MustCompile(`webView`),
		},
	}
}

func NewNoUseSFAntiPiracyJailbreak() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-30",
			Name:          "No Use SFAntiPiracy Jailbreak",
			Description:   "Verifications found of type SFAntiPiracy Jailbreak",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM30,
			UnsafeExample: SampleVulnerableHSJVM30,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SFAntiPiracy.h`),
			regexp.MustCompile(`SFAntiPiracy`),
			regexp.MustCompile(`isJailbroken`),
		},
	}
}

func NewNoUseSFAntiPiracyIsPirated() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-31",
			Name:          "No Use SFAntiPiracy IsPirated",
			Description:   "Verifications found of type SFAntiPiracy isPirated",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM31,
			UnsafeExample: SampleVulnerableHSJVM31,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SFAntiPiracy.h`),
			regexp.MustCompile(`SFAntiPiracy`),
			regexp.MustCompile(`isPirated`),
		},
	}
}

func NewWeakMd5HashUsing() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-32",
			Name:          "Weak md5 hash using",
			Description:   "MD5 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:      severities.High.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM32,
			UnsafeExample: SampleVulnerableHSJVM32,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_MD5`),
			regexp.MustCompile(`CommonDigest.h`),
		},
	}
}

func NewWeakSha1HashUsing() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-33",
			Name:          "Weak sha1 hash using",
			Description:   "SHA1 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:      severities.High.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM33,
			UnsafeExample: SampleVulnerableHSJVM33,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_SHA1`),
			regexp.MustCompile(`CommonDigest.h`),
		},
	}
}

func NewWeakECBEncryptionAlgorithmUsing() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-34",
			Name:          "Weak ECB encryption algorithm using",
			Description:   "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM34,
			UnsafeExample: SampleVulnerableHSJVM34,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`kCCOptionECBMode`),
			regexp.MustCompile(`kCCAlgorithmAES`),
		},
	}
}

func NewUsingPtrace() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-35",
			Name:          "The application has anti-debugger using ptrace()",
			Description:   "The application has anti-debugger using ptrace()",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM35,
			UnsafeExample: SampleVulnerableHSJVM35,
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ptrace_ptr`),
			regexp.MustCompile(`PT_DENY_ATTACH`),
		},
	}
}

func NewSuperUserPrivileges() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-36",
			Name:          "Super User Privileges",
			Description:   "This App may request root (Super User) privileges. For more information checkout the CWE-250 (https://cwe.mitre.org/data/definitions/250.html) advisory.",
			Severity:      severities.High.ToString(),
			Confidence:    confidence.Medium.ToString(),
			SafeExample:   SampleSafeHSJVM36,
			UnsafeExample: SampleVulnerableHSJVM36,
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

func NewSendSMS() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-37",
			Name:          "Send SMS",
			Description:   "Send SMS. For more information checkout the OWASP-M3 (https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication) advisory",
			Severity:      severities.Low.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM37,
			UnsafeExample: SampleVulnerableHSJVM37,
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

func NewBase64Encode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-38",
			Name:          "Base64 Encode",
			Description:   "Basic authentication's only means of obfuscation is Base64 encoding. Since Base64 encoding is easily recognized and reversed, it offers only the thinnest veil of protection to your users, and should not be used.",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM38,
			UnsafeExample: SampleVulnerableHSJVM38,
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.util.Base64`),
			regexp.MustCompile(`\.encodeToString\(`),
			regexp.MustCompile(`\.encode\(`),
		},
	}
}

func NewGpsLocation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-39",
			Name:          "GPS Location",
			Description:   "GPS Location",
			Severity:      severities.Medium.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM39,
			UnsafeExample: SampleVulnerableHSJVM39,
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

func NewApplicationMayContainJailbreakDetectionMechanisms() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:            "HS-JVM-40",
			Name:          "The application may contain Jailbreak detection mechanisms",
			Description:   "The application may contain Jailbreak detection mechanisms.",
			Severity:      severities.Info.ToString(),
			Confidence:    confidence.Low.ToString(),
			SafeExample:   SampleSafeHSJVM40,
			UnsafeExample: SampleVulnerableHSJVM40,
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
