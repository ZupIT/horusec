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
package and

import (
	"regexp"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

func NewJvmAndNoDownloadFileUsingAndroidDownloadManager() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "64093fae-a8bb-4d0a-a430-51ab6d1ab212",
			Name:        "No Download File Using Android Download Manager",
			Description: "This App downloads files using Android Download Manager",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.app.DownloadManager`),
			regexp.MustCompile(`getSystemService\(DOWNLOAD_SERVICE\)`),
		},
	}
}

func NewJvmAndAndroidKeystore() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c64f7930-53a1-49e2-bada-b67dcfb8b45a",
			Name:        "Android Keystore",
			Description: "Android Keystore",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`security.KeyStore`),
			regexp.MustCompile(`Keystore.getInstance\(`),
		},
	}
}

func NewJvmAndAndroidNotifications() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fc6dda2b-c8e6-4f18-acb2-2bebff236c9e",
			Name:        "Android Notifications",
			Description: "Android Notifications",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`app.NotificationManager`),
			regexp.MustCompile(`notify`),
		},
	}
}

func NewJvmAndPotentialAndroidSQLInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1dfaf38a-a9d1-4947-bce1-ee6d06740a76",
			Name:        "Potential Android SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
			regexp.MustCompile(`rawQuery\(\w+\,null\)`),
		},
	}
}

func NewJvmAndSQLInjectionWithSQLite() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ad56bc23-5259-4b74-89f3-8cc94dc238a4",
			Name:        "SQL Injection With SQLite",
			Description: "App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android\.database\.sqlite`),
			regexp.MustCompile(`execSQL\(|rawQuery\(`),
		},
	}
}

func NewJvmAndWebViewGETRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2d8fe201-d0ab-43f4-b218-65fe9f6711b9",
			Name:        "WebView GET Request",
			Description: "WebView GET Request",
			Severity:    severity.Medium.ToString(),
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

func NewJvmAndWebViewPOSTRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b2399139-ad4a-47df-9ad2-b02c174fd381",
			Name:        "WebView POST Request",
			Description: "WebView POST Request",
			Severity:    severity.Medium.ToString(),
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

func NewJvmAndBase64Decode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2a6a650f-e5d6-4c58-ab86-9ddb0c7fed02",
			Name:        "Base64 Decode",
			Description: "Base64 Decode",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`android.util.Base64`),
			regexp.MustCompile(`.decode`),
		},
	}
}

func NewJvmAndKeychainAccess() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3ae76439-24f3-4c8b-83ad-422c68b42b88",
			Name:        "WebView Load Request",
			Description: "WebView Load Request",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`webView`),
			regexp.MustCompile(`loadRequest`),
		},
	}
}

func NewJvmAndWebViewLoadRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8571c367-b2ee-432e-a90d-a742532266a6",
			Name:        "WebView Load Request",
			Description: "WebView Load Request",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`webView`),
			regexp.MustCompile(`loadRequest`),
		},
	}
}

func NewJvmAndCookieStorage() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "87de6208-8044-439a-bdbb-e656c04ea1c8",
			Name:        "Cookie Storage",
			Description: "Cookie Storage",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NSHTTPCookieStorage`),
			regexp.MustCompile(`sharedHTTPCookieStorage`),
		},
	}
}

func NewJvmAndSetReadClipboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "51105998-a47e-4b1a-abd4-65fd5d2a8394",
			Name:        "Set or Read Clipboard",
			Description: "Set or Read Clipboard",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboard`),
			regexp.MustCompile(`generalPasteboard`),
		},
	}
}

func NewJvmAndUsingLoadHTMLStringCanResultInject() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "60889816-9305-4c0b-9aa8-335b32d6ff89",
			Name:        "Using LoadHTMLString can result Inject",
			Description: "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data. For more information checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`loadHTMLString`),
			regexp.MustCompile(`webView`),
		},
	}
}

func NewJvmAndNoUseSFAntiPiracyJailbreak() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c984fc09-2feb-4a9c-a452-0f558b9b88cd",
			Name:        "No Use SFAntiPiracy Jailbreak",
			Description: "Verifications found of type SFAntiPiracy Jailbreak",
			Severity:    severity.Info.ToString(),
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

func NewJvmAndNoUseSFAntiPiracyIsPirated() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bc7f23e2-a519-4a8a-b0a4-d8e7ad55fed0",
			Name:        "No Use SFAntiPiracy IsPirated",
			Description: "Verifications found of type SFAntiPiracy isPirated",
			Severity:    severity.Info.ToString(),
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

func NewJvmAndWeakMd5HashUsing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "29383ac6-eb45-469a-8413-9d829a3743b1",
			Name:        "Weak md5 hash using",
			Description: "MD5 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_MD5`),
			regexp.MustCompile(`CommonDigest.h`),
		},
	}
}

func NewJvmAndWeakSha1HashUsing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "54e4d4de-01be-44f6-9b10-53893a1f998a",
			Name:        "Weak sha1 hash using",
			Description: "SHA1 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_SHA1`),
			regexp.MustCompile(`CommonDigest.h`),
		},
	}
}

func NewJvmAndWeakECBEncryptionAlgorithmUsing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a6ab0daf-fc7b-48fc-9eda-3ba2ff0a3849",
			Name:        "Weak ECB encryption algorithm using",
			Description: "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`kCCOptionECBMode`),
			regexp.MustCompile(`kCCAlgorithmAES`),
		},
	}
}

func NewJvmAndUsingPtrace() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a497aed9-7e65-44d4-969d-832e1bbcd34f",
			Name:        "The application has anti-debugger using ptrace()",
			Description: "The application has anti-debugger using ptrace()",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ptrace_ptr`),
			regexp.MustCompile(`PT_DENY_ATTACH`),
		},
	}
}
