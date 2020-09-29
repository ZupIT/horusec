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
	"regexp"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

func NewJvmRegularNoLogSensitiveInformation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ef15bf33-7099-4112-9570-a5a337e292df",
			Name:        "No Log Sensitive Information",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Log|log)\.(v|d|i|w|e|f|s)|System\.out\.print|System\.err\.print|println`),
		},
	}
}

func NewJvmRegularHTTPRequestsConnectionsAndSessions() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "eae26917-b455-49df-b21d-769ef9604f56",
			Name:        "HTTP Requests, Connections and Sessions",
			Description: "HTTP Requests, Connections and Sessions",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`http\.client\.HttpClient|net\.http\.AndroidHttpClient|http\.impl\.client\.AbstractHttpClient`),
		},
	}
}

func NewJvmRegularNoUsesSafetyNetAPI() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bcb097bd-8420-49f1-a378-86ece6d19088",
			Name:        "No uses safety api",
			Description: "This App uses SafetyNet API",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`com.google.android.gms.safetynet.SafetyNetApi`),
		},
	}
}

func NewJvmRegularNoUsesContentProvider() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6a35b054-133c-4627-b906-aa1d88ff1139",
			Name:        "No uses Content Provider",
			Description: "No uses Content Provider",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.content.ContentProvider`),
		},
	}
}

func NewJvmRegularNoUseWithUnsafeBytes() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5fb2d840-ba1e-484c-acc9-843c06542b27",
			Name:        "No Use With Unsafe Bytes",
			Description: "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer. For more information checkout the CWE-789 (https://cwe.mitre.org/data/definitions/789.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\w+.withUnsafeBytes\s*{.*`),
		},
	}
}

func NewJvmRegularNoUseLocalFileIOOperations() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4ca5deb2-6e86-4cf5-bf50-fe2901e9191e",
			Name:        "Local File I/O Operations",
			Description: "Local File I/O Operations",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete`),
		},
	}
}

func NewJvmRegularWebViewComponent() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2bc5ee05-1fad-4be6-b7ae-8cd43131d7f5",
			Name:        "WebView Component",
			Description: "WebView Component",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIWebView`),
		},
	}
}

func NewJvmRegularEncryptionAPI() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5e2ef51a-4e2a-40e8-9191-ed0f843985b2",
			Name:        "Encryption API",
			Description: "Encryption API",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`RNEncryptor|RNDecryptor|AESCrypt`),
		},
	}
}

func NewJvmRegularKeychainAccess() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e47ca59c-8b58-4334-91b5-3039a15f42fa",
			Name:        "Keychain Access",
			Description: "Keychain Access",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`PDKeychainBindings`),
		},
	}
}

func NewJvmRegularNoUseProhibitedAPIs() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "60ba6d71-bb7c-4bf7-9ab1-49b2fa62e088",
			Name:        "No Use Prohibited APIs",
			Description: "The application may contain prohibited APIs. These APIs are insecure and should not be used. For more information checkout the CWE-676 (https://cwe.mitre.org/data/definitions/676.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(strcpy)|(memcpy)|(strcat)|(strncat)|(strncpy)|(sprintf)|(vsprintf)`),
		},
	}
}

func NewJvmRegularApplicationAllowMITMAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "284164f9-6549-4cde-9eae-bee29fc0b6b8",
			Name:        "Application allow MITM attacks",
			Description: "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|allowInvalidCertificates\s*=\s*(YES|yes)`),
		},
	}
}

func NewJvmRegularUIWebViewInApplicationIgnoringErrorsSSL() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5d4d9327-8174-4822-bf99-2f36e550286a",
			Name:        "UIWebView in application ignoring errors SSL",
			Description: "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle). For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`),
		},
	}
}

func NewJvmRegularNoListClipboardChanges() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0e89654f-1a6b-4323-a0ae-3fb82dc3a7d3",
			Name:        "No List changes on the clipboard",
			Description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboardChangedNotification|generalPasteboard\]\.string`),
		},
	}
}

func NewJvmRegularApplicationUsingSQLite() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "14cc5f74-278c-4e7c-941b-9aab07ae6b85",
			Name:        "The application is using SQLite. Confidential information must be encrypted.",
			Description: "The application is using SQLite. Confidential information must be encrypted.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sqlite3_exec`),
		},
	}
}

func NewJvmRegularNoUseNSTemporaryDirectory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c96bcd38-ba0f-4afa-aeb6-4becc1775622",
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

func NewJvmRegularNoCopiesDataToTheClipboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3821c9c7-e204-44c6-bb85-820b3245103a",
			Name:        "No copies data to the Clipboard",
			Description: "The application copies data to the Clipboard. Confidential data must not be copied to the Clipboard, as other applications can access it. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\w+\s*=\s*UIPasteboard)`),
		},
	}
}
