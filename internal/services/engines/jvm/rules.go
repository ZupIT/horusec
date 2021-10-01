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
	engine "github.com/ZupIT/horusec-engine"

	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
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
		NewWebViewLoadRequest(),
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

func NewNoLogSensitiveInformation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ef15bf33-7099-4112-9570-a5a337e292df",
			Name:        "No Log Sensitive Information",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Log|log)\.(v|d|i|w|e|f|s)|System\.out\.print|System\.err\.print|println`),
		},
	}
}

func NewHTTPRequestsConnectionsAndSessions() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "eae26917-b455-49df-b21d-769ef9604f56",
			Name:        "HTTP Requests, Connections and Sessions",
			Description: "HTTP Requests, Connections and Sessions",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`http\.client\.HttpClient|net\.http\.AndroidHttpClient|http\.impl\.client\.AbstractHttpClient`),
		},
	}
}

func NewNoUsesSafetyNetAPI() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bcb097bd-8420-49f1-a378-86ece6d19088",
			Name:        "No uses safety api",
			Description: "This App uses SafetyNet API",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`com.google.android.gms.safetynet.SafetyNetApi`),
		},
	}
}

func NewNoUsesContentProvider() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6a35b054-133c-4627-b906-aa1d88ff1139",
			Name:        "No uses Content Provider",
			Description: "No uses Content Provider",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.content.ContentProvider`),
		},
	}
}

func NewNoUseWithUnsafeBytes() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5fb2d840-ba1e-484c-acc9-843c06542b27",
			Name:        "No Use With Unsafe Bytes",
			Description: "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer. For more information checkout the CWE-789 (https://cwe.mitre.org/data/definitions/789.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\w+.withUnsafeBytes\s*{.*`),
		},
	}
}

func NewNoUseLocalFileIOOperations() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4ca5deb2-6e86-4cf5-bf50-fe2901e9191e",
			Name:        "Local File I/O Operations",
			Description: "Local File I/O Operations",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete`),
		},
	}
}

func NewWebViewComponent() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2bc5ee05-1fad-4be6-b7ae-8cd43131d7f5",
			Name:        "WebView Component",
			Description: "WebView Component",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIWebView`),
		},
	}
}

func NewEncryptionAPI() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5e2ef51a-4e2a-40e8-9191-ed0f843985b2",
			Name:        "Encryption API",
			Description: "Encryption API",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`RNEncryptor|RNDecryptor|AESCrypt`),
		},
	}
}

func NewKeychainAccess() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e47ca59c-8b58-4334-91b5-3039a15f42fa",
			Name:        "Keychain Access",
			Description: "Keychain Access",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`PDKeychainBindings`),
		},
	}
}

func NewNoUseProhibitedAPIs() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "60ba6d71-bb7c-4bf7-9ab1-49b2fa62e088",
			Name:        "No Use Prohibited APIs",
			Description: "The application may contain prohibited APIs. These APIs are insecure and should not be used. For more information checkout the CWE-676 (https://cwe.mitre.org/data/definitions/676.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(strcpy)|(memcpy)|(strcat)|(strncat)|(strncpy)|(sprintf)|(vsprintf)`),
		},
	}
}

func NewApplicationAllowMITMAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "284164f9-6549-4cde-9eae-bee29fc0b6b8",
			Name:        "Application allow MITM attacks",
			Description: "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|allowInvalidCertificates\s*=\s*(YES|yes)`),
		},
	}
}

func NewUIWebViewInApplicationIgnoringErrorsSSL() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5d4d9327-8174-4822-bf99-2f36e550286a",
			Name:        "UIWebView in application ignoring errors SSL",
			Description: "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle). For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`),
		},
	}
}

func NewNoListClipboardChanges() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0e89654f-1a6b-4323-a0ae-3fb82dc3a7d3",
			Name:        "No List changes on the clipboard",
			Description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboardChangedNotification|generalPasteboard\]\.string`),
		},
	}
}

func NewApplicationUsingSQLite() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "14cc5f74-278c-4e7c-941b-9aab07ae6b85",
			Name:        "The application is using SQLite. Confidential information must be encrypted.",
			Description: "The application is using SQLite. Confidential information must be encrypted.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sqlite3_exec`),
		},
	}
}

func NewNoUseNSTemporaryDirectory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c96bcd38-ba0f-4afa-aeb6-4becc1775622",
			Name:        "No use NSTemporaryDirectory",
			Description: "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory. For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSTemporaryDirectory\(\),`),
		},
	}
}

func NewNoCopiesDataToTheClipboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3821c9c7-e204-44c6-bb85-820b3245103a",
			Name:        "No copies data to the Clipboard",
			Description: "The application copies data to the Clipboard. Confidential data must not be copied to the Clipboard, as other applications can access it. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\w+\s*=\s*UIPasteboard)`),
		},
	}
}

func NewNoDownloadFileUsingAndroidDownloadManager() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "64093fae-a8bb-4d0a-a430-51ab6d1ab212",
			Name:        "No Download File Using Android Download Manager",
			Description: "This App downloads files using Android Download Manager",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.app.DownloadManager`),
			regexp.MustCompile(`getSystemService\(DOWNLOAD_SERVICE\)`),
		},
	}
}

func NewAndroidKeystore() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c64f7930-53a1-49e2-bada-b67dcfb8b45a",
			Name:        "Android Keystore",
			Description: "Android Keystore",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`security.KeyStore`),
			regexp.MustCompile(`Keystore.getInstance\(`),
		},
	}
}

func NewAndroidNotifications() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fc6dda2b-c8e6-4f18-acb2-2bebff236c9e",
			Name:        "Android Notifications",
			Description: "Android Notifications",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`app.NotificationManager`),
			regexp.MustCompile(`notify`),
		},
	}
}

func NewPotentialAndroidSQLInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1dfaf38a-a9d1-4947-bce1-ee6d06740a76",
			Name:        "Potential Android SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
			regexp.MustCompile(`rawQuery\(\w+\,null\)`),
		},
	}
}

func NewSQLInjectionWithSQLite() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ad56bc23-5259-4b74-89f3-8cc94dc238a4",
			Name:        "SQL Injection With SQLite",
			Description: "App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android\.database\.sqlite`),
			regexp.MustCompile(`execSQL\(|rawQuery\(`),
		},
	}
}

func NewWebViewGETRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2d8fe201-d0ab-43f4-b218-65fe9f6711b9",
			Name:        "WebView GET Request",
			Description: "WebView GET Request",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`WebView`),
			regexp.MustCompile(`loadData\(`),
			regexp.MustCompile(`android.webkit`),
		},
	}
}

func NewWebViewPOSTRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b2399139-ad4a-47df-9ad2-b02c174fd381",
			Name:        "WebView POST Request",
			Description: "WebView POST Request",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`WebView`),
			regexp.MustCompile(`postUrl`),
			regexp.MustCompile(`android.webkit`),
		},
	}
}

func NewBase64Decode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2a6a650f-e5d6-4c58-ab86-9ddb0c7fed02",
			Name:        "Base64 Decode",
			Description: "Base64 Decode",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.util.Base64`),
			regexp.MustCompile(`.decode`),
		},
	}
}

func NewKeychainAccessAndMatch() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3ae76439-24f3-4c8b-83ad-422c68b42b88",
			Name:        "WebView Load Request",
			Description: "WebView Load Request",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`webView`),
			regexp.MustCompile(`loadRequest`),
		},
	}
}

func NewWebViewLoadRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8571c367-b2ee-432e-a90d-a742532266a6",
			Name:        "WebView Load Request",
			Description: "WebView Load Request",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`webView`),
			regexp.MustCompile(`loadRequest`),
		},
	}
}

func NewCookieStorage() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "87de6208-8044-439a-bdbb-e656c04ea1c8",
			Name:        "Cookie Storage",
			Description: "Cookie Storage",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSHTTPCookieStorage`),
			regexp.MustCompile(`sharedHTTPCookieStorage`),
		},
	}
}

func NewSetReadClipboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "51105998-a47e-4b1a-abd4-65fd5d2a8394",
			Name:        "Set or Read Clipboard",
			Description: "Set or Read Clipboard",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboard`),
			regexp.MustCompile(`generalPasteboard`),
		},
	}
}

func NewUsingLoadHTMLStringCanResultInject() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "60889816-9305-4c0b-9aa8-335b32d6ff89",
			Name:        "Using LoadHTMLString can result Inject",
			Description: "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data. For more information checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`loadHTMLString`),
			regexp.MustCompile(`webView`),
		},
	}
}

func NewNoUseSFAntiPiracyJailbreak() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c984fc09-2feb-4a9c-a452-0f558b9b88cd",
			Name:        "No Use SFAntiPiracy Jailbreak",
			Description: "Verifications found of type SFAntiPiracy Jailbreak",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SFAntiPiracy.h`),
			regexp.MustCompile(`SFAntiPiracy`),
			regexp.MustCompile(`isJailbroken`),
		},
	}
}

func NewNoUseSFAntiPiracyIsPirated() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bc7f23e2-a519-4a8a-b0a4-d8e7ad55fed0",
			Name:        "No Use SFAntiPiracy IsPirated",
			Description: "Verifications found of type SFAntiPiracy isPirated",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SFAntiPiracy.h`),
			regexp.MustCompile(`SFAntiPiracy`),
			regexp.MustCompile(`isPirated`),
		},
	}
}

func NewWeakMd5HashUsing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "29383ac6-eb45-469a-8413-9d829a3743b1",
			Name:        "Weak md5 hash using",
			Description: "MD5 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_MD5`),
			regexp.MustCompile(`CommonDigest.h`),
		},
	}
}

func NewWeakSha1HashUsing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "54e4d4de-01be-44f6-9b10-53893a1f998a",
			Name:        "Weak sha1 hash using",
			Description: "SHA1 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_SHA1`),
			regexp.MustCompile(`CommonDigest.h`),
		},
	}
}

func NewWeakECBEncryptionAlgorithmUsing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a6ab0daf-fc7b-48fc-9eda-3ba2ff0a3849",
			Name:        "Weak ECB encryption algorithm using",
			Description: "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`kCCOptionECBMode`),
			regexp.MustCompile(`kCCAlgorithmAES`),
		},
	}
}

func NewUsingPtrace() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a497aed9-7e65-44d4-969d-832e1bbcd34f",
			Name:        "The application has anti-debugger using ptrace()",
			Description: "The application has anti-debugger using ptrace()",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ptrace_ptr`),
			regexp.MustCompile(`PT_DENY_ATTACH`),
		},
	}
}

func NewSuperUserPrivileges() text.TextRule {
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

func NewSendSMS() text.TextRule {
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

func NewBase64Encode() text.TextRule {
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

func NewGpsLocation() text.TextRule {
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

func NewApplicationMayContainJailbreakDetectionMechanisms() text.TextRule {
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
