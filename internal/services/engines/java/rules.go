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

package java

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewXMLParsingVulnerableToXXE() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1356db4d-4f0c-43dc-afeb-8208fe2c9a87",
			Name:        "XML parsing vulnerable to XXE",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`XMLReaderFactory\.createXMLReader\(`),
			regexp.MustCompile(`\.parse\(`),
			// regexp.MustCompile(`\.setFeature\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithXMLInputFactory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c5240964-ac24-4a73-9842-2ae716071b65",
			Name:        "XML parsing vulnerable to XXE With XMLInputFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`XMLInputFactory\.newInstance\(`),
			// regexp.MustCompile(`\.setProperty\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithDocumentBuilder() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "37a302cd-0d9c-4e59-8a96-e78bcd38103a",
			Name:        "XML parsing vulnerable to XXE With DocumentBuilder",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`DocumentBuilderFactory\.newInstance\(`),
			regexp.MustCompile(`\.parse\(`),
			// regexp.MustCompile(`\.setFeature\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithSAXParserFactory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9b54f113-9315-415a-87b0-0dfd5dd205fb",
			Name:        "XML parsing vulnerable to XXE With SAXParserFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SAXParserFactory\.newInstance\(`),
			regexp.MustCompile(`\.parse\(`),
			// regexp.MustCompile(`\.setProperty\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithTransformerFactory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3714cbfe-0178-4375-8f02-dec3851d069e",
			Name:        "XML parsing vulnerable to XXE With TransformerFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`javax\.xml\.transform\.TransformerFactory\.newInstance\(`),
			// regexp.MustCompile(`\.setAttribute\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithSchemaFactory() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e88880c4-af9a-4ac3-96f7-87ee02427eca",
			Name:        "XML parsing vulnerable to XXE With TransformerFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SchemaFactory\.newInstance\(`),
			// regexp.MustCompile(`\.setProperty\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithDom4j() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "47bce37c-953c-45b8-adbe-029c045e52fa",
			Name:        "XML parsing vulnerable to XXE With Dom4j",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSAXReader\(\)`),
			// regexp.MustCompile(`\.setProperty\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewXMLParsingVulnerableToXXEWithJdom2() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b8ba1c3f-9431-42c6-a1a9-496a099f9aa9",
			Name:        "XML parsing vulnerable to XXE With Jdom2",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSAXBuilder\(\)`),
			// regexp.MustCompile(`\.setProperty\(`), // Commented because is necessary run this regex with not condition
		},
	}
}

func NewInsecureImplementationOfSSL() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "25fabaf2-8071-40c3-91f5-ecf9da38c0e8",
			Name:        "Insecure Implementation of SSL",
			Description: "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`javax\.net\.ssl`),
			regexp.MustCompile(`TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\(`),
		},
	}
}

func NewMessageDigestIsCustom() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d34c6b79-4051-4f73-bf8e-37db9becc896",
			Name:        "Message digest is custom",
			Description: "Implementing a custom MessageDigest is error-prone. NIST recommends the use of SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, or SHA-512/256. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`extends\sMessageDigest`),
			regexp.MustCompile(`@Override`),
			regexp.MustCompile(`protected\sbyte\[\]\sengineDigest\(\)`),
		},
	}
}

func NewTrustManagerThatAcceptAnyCertificatesClient() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f917cb33-f4d4-4522-a8f2-6d86e4fdaf34",
			Name:        "TrustManager that accept any certificates Client",
			Description: "Empty TrustManager implementations are often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`implements\sX509TrustManager`),
			regexp.MustCompile(`(implements\sX509TrustManager)((.*|\n)*)(\@Override.*\n.*getAcceptedIssuers)`),
			regexp.MustCompile(`public\svoid\scheckClientTrusted`),
		},
	}
}

func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ef41938f-916a-4dc1-bac0-faace8310234",
			Name:        "Server hostnames should be verified during SSL/TLS connections",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SSLContext\.getInstance\(.*TLS.*\)((.*|\n)*)(\@Override.*\n.*verify\()(.*\n.*return\strue)`),
			regexp.MustCompile(`checkClientTrusted\(`),
			regexp.MustCompile(`checkServerTrusted\(`),
			regexp.MustCompile(`getAcceptedIssuers\(`),
		},
	}
}

func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b879cde8-0e6e-431a-b766-ffce317b8f99",
			Name:        "Server hostnames should be verified during SSL/TLS connections With SimpleEmail",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sSimpleEmail\(\))(([^s]|s[^e]|se[^t]|set[^S]|setS[^S]|setSS[^L]|setSSL[^C]|setSSLC[^h]|setSSLCh[^e]|setSSLChe[^c]|setSSLChec[^k]|setSSLCheck[^S]|setSSLCheckS[^e]|setSSLCheckSe[^r]|setSSLCheckSer[^v]|setSSLCheckServ[^e]|setSSLCheckServe[^r]|setSSLCheckServer[^I]|setSSLCheckServerI[^d]|setSSLCheckServerId[^e]|setSSLCheckServerIde[^n]|setSSLCheckServerIden[^t]|setSSLCheckServerIdent[^i]|setSSLCheckServerIdenti[^t]|setSSLCheckServerIdentit[^y])*)(\.send\(\))`),
			regexp.MustCompile(`setSSLOnConnect\(true\)`),
		},
	}
}

//Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "90ee28f2-d622-4a5e-9d9d-13fb53ea5ca7",
			Name:        "Server hostnames should be verified during SSL/TLS connections With Mail's",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new Properties\()(([^c]|c[^h]|ch[^e]|che[^c]|chec[^k]|check[^s]|checks[^e]|checkse[^r]|checkser[^v]|checkserv[^e]|checkserve[^r]|checkserver[^i]|checkserveri[^d]|checkserverid[^e]|checkserveride[^n]|checkserveriden[^t]|checkserverident[^i]|checkserveridenti[^t]|checkserveridentit[^y])*?)(new\sjavax\.mail\.Authenticator\()`),
			regexp.MustCompile(`put\(.*mail.smtp`),
		},
	}
}

func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithJakartaMail() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a6a2ae16-8ca5-46e1-bed4-822068a41a01",
			Name:        "Server hostnames should be verified during SSL/TLS connections With Mail's",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new Properties\()(([^c]|c[^h]|ch[^e]|che[^c]|chec[^k]|check[^s]|checks[^e]|checkse[^r]|checkser[^v]|checkserv[^e]|checkserve[^r]|checkserver[^i]|checkserveri[^d]|checkserverid[^e]|checkserveride[^n]|checkserveriden[^t]|checkserverident[^i]|checkserveridenti[^t]|checkserveridentit[^y])*?)(new\sjakarta\.mail\.Authenticator\()`),
			regexp.MustCompile(`put\(.*mail.smtp`),
		},
	}
}

func NewTrustManagerThatAcceptAnyCertificatesServer() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "82b5193f-9d4a-4d41-a994-8673c35d8059",
			Name:        "TrustManager that accept any certificates Server",
			Description: "Empty TrustManager implementations are often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`implements\sX509TrustManager`),
			regexp.MustCompile(`@Override`),
			regexp.MustCompile(`public\svoid\scheckServerTrusted`),
		},
	}
}

func NewTrustManagerThatAcceptAnyCertificatesIssuers() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a2d527dc-7e17-459a-90d4-52c2b2dee39c",
			Name:        "TrustManager that accept any certificates Issuers",
			Description: "Empty TrustManager implementations are often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`implements\sX509TrustManager`),
			regexp.MustCompile(`@Override`),
			regexp.MustCompile(`public\sX509Certificate\[\]\sgetAcceptedIssuers`),
		},
	}
}

func NewWebViewLoadFilesFromExternalStorage() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a575a379-7f71-45f7-a33f-0764bcbc7aae",
			Name:        "WebView Load Files From External Storage",
			Description: "WebView load files from external storage. Files in external storage can be modified by any application. For more information checkout the CWE-919 (https://cwe.mitre.org/data/definitions/919.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.loadUrl\(.*getExternalStorageDirectory\(`),
			regexp.MustCompile(`webkit\.WebView`),
		},
	}
}

func NewInsecureWebViewImplementation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "267a6553-c375-4293-906f-929c6d70e698",
			Name:        "Insecure Web View Implementation",
			Description: "Insecure WebView Implementation. Execution of user controlled code in WebView is a critical Security Hole. For more information checkout the CWE-749 (https://cwe.mitre.org/data/definitions/749.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setScriptEnabled\(true\)`),
			regexp.MustCompile(`.addscriptInterface\(`),
		},
	}
}

func NewNoUseSQLCipherAndMatch() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f06f8a53-311a-45d1-9047-ae243c2a313d",
			Name:        "No Use SQL Cipher",
			Description: "This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite database files",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SQLiteDatabase.loadLibs\(`),
			regexp.MustCompile(`net.sqlcipher`),
		},
	}
}

func NewNoUseRealmDatabaseWithEncryptionKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "47b35134-a487-4dee-8104-c7c36eddd342",
			Name:        "No Use Realm Database With Encryption Key",
			Description: "This App use Realm Database with encryption",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`io.realm.Realm`),
			regexp.MustCompile(`.encryptionKey\(`),
		},
	}
}

func NewNoUseWebviewDebuggingEnable() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6dd9a190-9697-4aec-a5d6-c6f865938510",
			Name:        "No Use Webview Debugging Enable",
			Description: "Remote WebView debugging is enabled. For more information checkout the CWE-215 (https://cwe.mitre.org/data/definitions/215.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.setWebContentsDebuggingEnabled\(true\)`),
			regexp.MustCompile(`WebView`),
		},
	}
}

func NewNoListenToClipboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7b4a855b-a32a-4631-80df-90445d8cd27b",
			Name:        "No Listen To Clipboard",
			Description: "This app listens to Clipboard changes. Some malwares also listen to Clipboard changes.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`content.ClipboardManager`),
			regexp.MustCompile(`OnPrimaryClipChangedListener`),
		},
	}
}

func NewNoCopyContentToClipboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "65162a79-2364-4c5a-a6d7-33f958c2720f",
			Name:        "No copy content to clipboard",
			Description: "This App copies data to clipboard. Sensitive data should not be copied to clipboard as other applications can access it.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`content.ClipboardManager`),
			regexp.MustCompile(`setPrimaryClip\(`),
		},
	}
}

func NewNoUseWebviewIgnoringSSL() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "73e7547e-0fcc-40ef-b856-3af428792fe6",
			Name:        "No Use Webview Ignoring SSL",
			Description: "Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`onReceivedSslError\(WebView`),
			regexp.MustCompile(`.proceed\(\);`),
		},
	}
}

func NewSQLInjectionWithSqlUtil() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1e9fc0cc-cc21-451a-b355-d3215330a2d1",
			Name:        "SQL Injection With SqlUtil",
			Description: "The method identified is susceptible to injection. The input should be validated and properly escaped. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SqlUtil\.execQuery\(`),
		},
	}
}

func NewNoUseFridaServer() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3e0df0b8-8c07-4956-8981-593fe7f78bcd",
			Name:        "No Use Frida Server",
			Description: "This App detects frida server.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`fridaserver`),
			regexp.MustCompile(`27047|LIBFRIDA`),
		},
	}
}

func NewNoUseSSLPinningLib() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "69010f00-8e9e-4c49-940e-d8c0b7ce1cfc",
			Name:        "No Use SSL Pinning Lib",
			Description: "This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to prevent MITM attacks in secure communication channel.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`org.thoughtcrime.ssl.pinning`),
			regexp.MustCompile(`PinningHelper.getPinnedHttpsURLConnection|PinningHelper.getPinnedHttpClient|PinningSSLSocketFactory\(`),
		},
	}
}

func NewNoUseDexGuardAppDebuggable() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "96bc6ee0-dc41-4e9d-a77c-4a7cc07cfdd9",
			Name:        "DexGuard Debug Detection",
			Description: "DexGuard Debug Detection code to detect wheather an App is debuggable or not is identified.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`DebugDetector.isDebuggable`),
		},
	}
}

func NewNoUseDexGuardDebuggerConnected() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5ddf6f89-6037-49b2-a5cb-e9e4dad93f6a",
			Name:        "No Use DexGuard Debugger Connected",
			Description: "DexGuard Debugger Detection code is identified.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`DebugDetector.isDebuggerConnected`),
		},
	}
}

func NewNoUseDexGuardEmulatorDetection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7273f8a8-a1f6-4637-a320-0c5c937a89dc",
			Name:        "No Use DexGuard Emulator Detection",
			Description: "DexGuard Emulator Detection code is identified.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`EmulatorDetector.isRunningInEmulator`),
		},
	}
}

func NewNoUseDexGuardWithDebugKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e939eb2c-97e2-434d-94a0-0caf77217a53",
			Name:        "No Use DexGuard With Debug Key",
			Description: "DexGuard code to detect wheather the App is signed with a debug key or not is identified.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`DebugDetector.isSignedWithDebugKey`),
		},
	}
}

func NewNoUseDexGuardRoot() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "51529a88-f321-4b9c-bba6-9975fe28cb81",
			Name:        "No Use DexGuard Root",
			Description: "DexGuard Root Detection code is identified",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`RootDetector.isDeviceRooted`),
		},
	}
}

func NewNoUseDexGuard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "cd2817af-398e-4d07-b528-cc87c0078576",
			Name:        "No Use DexGuard",
			Description: "DexGuard App Tamper Detection code is identified",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`TamperDetector.checkApk`),
		},
	}
}

func NewNoUseDexGuardInSigner() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d3e01b9c-1a3c-4229-8b89-f4aedb5e5a02",
			Name:        "No Use DexGuard in signer",
			Description: "DexGuard Signer Certificate Tamper Detection code is identified",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import dexguard.util`),
			regexp.MustCompile(`TCertificateChecker.checkCertificate`),
		},
	}
}

func NewNoUsePackageWithTamperDetection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d688b4eb-5fd6-47a6-865c-a560a847ffb7",
			Name:        "No use package with tamper detection.",
			Description: "The App may use package signature for tamper detection.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`PackageManager.GET_SIGNATURES`),
			regexp.MustCompile(`getPackageName\(`),
		},
	}
}

func NewLoadAndManipulateDexFiles() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6e5c863b-e649-44f7-a660-e468aceaa0b4",
			Name:        "Load and Manipulate Dex Files",
			Description: "Load and Manipulate Dex Files",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`dalvik\.system\.PathClassLoader|dalvik\.system\.DexFile|dalvik\.system\.DexPathList`),
			regexp.MustCompile(`loadDex|loadClass|DexClassLoader|loadDexFile`),
		},
	}
}

func NewObfuscation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6643135e-dcd5-47d4-9aed-de6874ccb04e",
			Name:        "Obfuscation",
			Description: "Obfuscation",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`utils.AESObfuscator`),
			regexp.MustCompile(`getObfuscator`),
		},
	}
}

func NewExecuteOSCommand() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e3cb1f0b-5e53-483c-b4b7-84cdafa86c20",
			Name:        "Execute OS Command",
			Description: "Execute OS Command. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getRuntime\(\).exec\(`),
			regexp.MustCompile(`getRuntime\(`),
			regexp.MustCompile(`(public|private|protected|\{)([^E]|E[^S]|ES[^A]|ESA[^P]|ESAP[^I])*getRuntime\(\)\.exec\(`),
		},
	}
}

func NewTCPServerSocket() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3fcdfb34-987d-45bf-b8bb-766294d7c72b",
			Name:        "TCP Server Socket",
			Description: "TCP Server Socket",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sServerSocket\(`),
			regexp.MustCompile(`net.ServerSocket`),
		},
	}
}

func NewTCPSocket() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "57e60e4a-aa8c-498d-b216-bdae01682d0a",
			Name:        "TCP Socket",
			Description: "TCP Socket",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSocket\(`),
			regexp.MustCompile(`net.Socket`),
		},
	}
}

func NewUDPDatagramPacket() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7dfbb123-e9c3-493f-9ceb-0e601c44cba0",
			Name:        "UDP Datagram Packet",
			Description: "UDP Datagram Packet",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`DatagramPacket`),
			regexp.MustCompile(`net.DatagramPacket`),
		},
	}
}

func NewUDPDatagramSocket() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ade5f894-7e29-4a6e-8ad0-cc7feb6be380",
			Name:        "UDP Datagram Socket",
			Description: "UDP Datagram Socket",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`DatagramSocket`),
			regexp.MustCompile(`net.DatagramSocket`),
		},
	}
}

func NewWebViewScriptInterface() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ba2f4ac8-e5fa-4bd9-b124-d08aeedbe60d",
			Name:        "WebView Script Interface",
			Description: "WebView Script Interface",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`addscriptInterface`),
			regexp.MustCompile(`WebView`),
		},
	}
}

func NewGetCellInformation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "06ee3440-03e1-4bb7-9146-67f0a383f40a",
			Name:        "Get Cell Information",
			Description: "Get Cell Information",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getAllCellInfo`),
		},
	}
}

func NewGetCellLocation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "652f45f6-b60a-4cce-b079-fc719346c74d",
			Name:        "Get Cell Location",
			Description: "Get Cell Location",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getCellLocation`),
		},
	}
}

func NewGetSubscriberID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "02d785d6-dfb9-4304-8513-6f21b55e15fe",
			Name:        "Get Subscriber ID",
			Description: "Get Subscriber ID",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getSubscriberId`),
		},
	}
}

func NewGetDeviceID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7d976361-bf8b-4bf4-948d-0dcd5afb5f22",
			Name:        "Get Device ID",
			Description: "Get Device ID",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getDeviceId`),
		},
	}
}

func NewGetSoftwareVersion() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9fc57ddc-88b4-42a5-8234-cb0fc0ee4341",
			Name:        "Get Software Version, IMEI/SV etc",
			Description: "Get Software Version, IMEI/SV etc",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getDeviceSoftwareVersion`),
		},
	}
}

func NewGetSIMSerialNumber() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e24d6c27-6fd5-43bc-9c34-9e60dba334af",
			Name:        "Get SIM Serial Number",
			Description: "Get SIM Serial Number",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getSimSerialNumber`),
		},
	}
}

func NewGetSIMProviderDetails() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "949e7382-baeb-4518-8c95-a1d65d72ec26",
			Name:        "Get SIM Provider Details",
			Description: "Get SIM Provider Details",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getSimOperator`),
		},
	}
}

func NewGetSIMOperatorName() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e376decc-cbea-4422-afe4-4ac619295530",
			Name:        "Get SIM Operator Name",
			Description: "Get SIM Operator Name",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`telephony.TelephonyManager`),
			regexp.MustCompile(`getSimOperatorName`),
		},
	}
}

func NewQueryDatabaseOfSMSContacts() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0fcd7ae6-7396-4724-b122-242986626129",
			Name:        "Query Database of SMS, Contacts etc.",
			Description: "Query Database of SMS, Contacts etc.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`content.ContentResolver`),
			regexp.MustCompile(`query`),
		},
	}
}

//Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewPotentialPathTraversal() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8b8acafb-b4e5-45d2-aa8a-2a297c2c7856",
			Name:        "Potential Path Traversal (file read)",
			Description: "A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read. This rule identifies potential path traversal vulnerabilities. Please consider use this example: \"new File(\"resources/images/\", FilenameUtils.getName(value_received_in_params))\". For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(.*\@javax\.ws\.rs\.PathParam\(['|"]?\w+[[:print:]]['|"]?\).*)`),
			regexp.MustCompile(`(.*new File\(['|"]?.*,\s?\w+\).*)`),
		},
	}
}

func NewJakartaAndPotentialPathTraversal() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2ed3def4-780f-4076-9cbc-d1943cd9adc2",
			Name:        "Potential Path Traversal (file read)",
			Description: "A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read. This rule identifies potential path traversal vulnerabilities. Please consider use this example: \"new File(\"resources/images/\", FilenameUtils.getName(value_received_in_params))\". For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(.*\@jakarta\.ws\.rs\.PathParam\(['|"]?\w+[[:print:]]['|"]?\).*)`),
			regexp.MustCompile(`(.*new File\(['|"]?.*,\s?\w+\).*)`),
		},
	}
}

func NewPotentialPathTraversalUsingScalaAPI() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d822c866-2aeb-4c81-a69c-aac0f9e735c8",
			Name:        "Potential Path Traversal Using scala API (file read)",
			Description: "A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read. Please consider use this example: \"val result = Source.fromFile(\"public/lists/\" + FilenameUtils.getName(value_received_in_params)).getLines().mkString\". For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`([^org\.apache\.commons\.io\.FilenameUtils])(Source\.fromFile\(.*\).getLines\(\)\.mkString)`),
		},
	}
}

func NewSMTPHeaderInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bda37076-b175-43bf-b10f-0f1611e5e4b0",
			Name:        "SMTP Header Injection",
			Description: "If user input is place in a header line, the application should remove or replace new line characters (CR / LF). For more information checkout the CWE-93 (https://cwe.mitre.org/data/definitions/93.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(setText\(|setSubject\(|setRecipients\(|setFrom\()`),
			regexp.MustCompile(`request.getParameter\(`),
			regexp.MustCompile(`Transport.send\(`),
		},
	}
}

func NewInsecureSMTPSSLConnection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "abecb9d2-ed29-11ea-adc1-0242ac120002",
			Name:        "Insecure SMTP SSL connection",
			Description: "Some email libraries that enable SSL connections do not verify the server certificate by default. This is equivalent to trusting all certificates. For more information checkout the CWE-297 (https://cwe.mitre.org/data/definitions/297.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setSSLOnConnect\(true\)`),
			regexp.MustCompile(`setSSLCheckServerIdentity\(false\)`),
		},
	}
}

func NewPersistentCookieUsage() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "cb480d6f-8287-4549-b010-e80ee728a884",
			Name:        "Persistent Cookie Usage",
			Description: "Storing sensitive data in a persistent cookie for an extended period can lead to a breach of confidentiality or account compromise. For more information checkout the CWE-539 (https://cwe.mitre.org/data/definitions/539.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new Cookie`),
			regexp.MustCompile(`setMaxAge`),
		},
	}
}

func NewAnonymousLDAPBind() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "02137214-b1af-41f0-9c5b-b4fd3c7b7ccf",
			Name:        "Anonymous LDAP bind",
			Description: "All LDAP queries executed against the context will be performed without authentication and access control. For more information checkout the (https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`put\(Context.SECURITY_AUTHENTICATION, "none"\)`),
			regexp.MustCompile(`new InitialDirContext(.*)`),
		},
	}
}

func NewLDAPEntryPoisoning() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4b089244-6fbf-4341-a786-10c62fe0bae7",
			Name:        "LDAP Entry Poisoning",
			Description: "If certain attributes are presented, the deserialization of object will be made in the application querying the directory. Object deserialization should be consider a risky operation that can lead to remote code execution. For more information checkout the (https://blog.trendmicro.com/trendlabs-security-intelligence/new-headaches-how-the-pawn-storm-zero-day-evaded-javas-click-to-play-protection) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new InitialDirContext\(\)`),
			regexp.MustCompile(`.*.search\(.*, .*, new SearchControls\(.*, .*, .*, .*, true, .*\)\);`),
		},
	}
}

func NewIgnoringXMLCommentsInSAML() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "009d6057-c351-4f05-93ad-ef172c3d15be",
			Name:        "Ignoring XML comments in SAML",
			Description: "Security Assertion Markup Language (SAML) is a single sign-on protocol that that used XML. The SAMLResponse message include statements that describe the authenticated user. If a user manage to place XML comments (<!-- -->), it may caused issue in the way the parser extract literal value. For more information checkout the (https://spring.io/blog/2018/03/01/spring-security-saml-and-this-week-s-saml-vulnerability) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new BasicParserPool\(\)`),
			regexp.MustCompile(`setIgnoreComments\(false\)`),
		},
	}
}

func NewInformationExposureThroughAnErrorMessage() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "77dcf4ea-068b-4f99-9cde-5b6b3d708dc3",
			Name:        "Information Exposure Through An Error Message",
			Description: "The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more deadly attacks. For more information checkout the CWE-209 (https://cwe.mitre.org/data/definitions/209.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`catch \(Exception .*\)`),
			regexp.MustCompile(`printStackTrace\(.*\)`),
		},
	}
}

func NewHTTPParameterPollution() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "96864660-9c6c-45ee-9027-acd3575745fa",
			Name:        "HTTP Parameter Pollution",
			Description: "Concatenating unvalidated user input into a URL can allow an attacker to override the value of a request parameter. For more information checkout the CAPEC-460 (https://capec.mitre.org/data/definitions/460.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`request.getParameter\(.*\)`),
			regexp.MustCompile(`setQueryString\(.*\)`),
		},
	}
}

func NewAWSQueryInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5604b1e8-138a-42f7-9dac-15e7e19926bf",
			Name:        "AWS Query Injection",
			Description: "Constructing SimpleDB queries containing user input can allow an attacker to view unauthorized records. For more information checkout the CWE-943 (https://cwe.mitre.org/data/definitions/943.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`request.getParameter\(.*\)`),
			regexp.MustCompile(`new AmazonSimpleDBClient\(.*\)`),
			regexp.MustCompile(`select | from | where | query`),
			regexp.MustCompile(`new SelectRequest\(query\)`),
		},
	}
}

func NewPotentialTemplateInjectionPebble() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4d0e7c37-3fa0-4a88-b21b-a6b42c081db0",
			Name:        "Potential template injection with Pebble ",
			Description: "A malicious user in control of a template can run malicious code on the server-side. Freemarker templates should be seen as scripts. For more information checkout the (https://portswigger.net/research/server-side-template-injection) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`PebbleTemplate`),
			regexp.MustCompile(`engine.getLiteralTemplate\(.*\)`),
			regexp.MustCompile(`evaluate\(.*\)`),
		},
	}
}

func NewPotentialTemplateInjectionFreemarker() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9e6db86e-b461-47e7-a558-3d48bced66e8",
			Name:        "Potential template injection with Freemarker ",
			Description: "A malicious user in control of a template can run malicious code on the server-side. Freemarker templates should be seen as scripts. For more information checkout the (https://portswigger.net/research/server-side-template-injection) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Template`),
			regexp.MustCompile(`.getTemplate\(.*\)`),
			regexp.MustCompile(`.process\(.*\)`),
		},
	}
}

func NewRequestDispatcherFileDisclosure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f05f724c-9436-42a4-a270-3d835c704004",
			Name:        "Request Dispatcher File Disclosure",
			Description: "Constructing a server-side redirect path with user input could allow an attacker to download application binaries (including application classes or jar files) or view arbitrary files within protected directories. For more information checkout the CWE-552 (https://cwe.mitre.org/data/definitions/552.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`request.getParameter\(.*\)`),
			regexp.MustCompile(`request.getRequestDispatcher\(.*\).include\(.*\)`),
		},
	}
}

func NewSpringFileDisclosure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b1bfc6bd-0548-4a3e-83fa-aa376ce18509",
			Name:        "Spring File Disclosure ",
			Description: "Constructing a server-side redirect path with user input could allow an attacker to download application binaries (including application classes or jar files) or view arbitrary files within protected directories. For more information checkout the CWE-552 (https://cwe.mitre.org/data/definitions/552.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`request.getParameter\(.*\)`),
			regexp.MustCompile(`ModelAndView\(.*\)`),
		},
	}
}

func NewPotentialCodeScriptInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "22ceb2bf-a073-45e3-a50c-13594ee24379",
			Name:        "Potential code injection when using Script Engine",
			Description: "Dynamic code is being evaluate. A careful analysis of the code construction should be made. Malicious code execution could lead to data leakage or operating system compromised. For more information checkout the CWE-94 (https://cwe.mitre.org/data/definitions/94.html) advisory and checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new.ScriptEngineManager\(`),
			regexp.MustCompile(`factory\.getEngineByName\(`),
			regexp.MustCompile(`\.eval\(`),
		},
	}
}

func NewStrutsFileDisclosure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2488cf37-4337-46ad-b10a-cda7eefa0ff1",
			Name:        "Struts File Disclosure ",
			Description: "Constructing a server-side redirect path with user input could allow an attacker to download application binaries (including application classes or jar files) or view arbitrary files within protected directories. For more information checkout the CWE-552 (https://cwe.mitre.org/data/definitions/552.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`request.getParameter\(.*\)`),
			regexp.MustCompile(`new ActionForward\(.*\)`),
		},
	}
}

func NewUnsafeJacksonDeserializationConfiguration() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8f091815-f05e-4782-945b-a7b4fd8cf5ae",
			Name:        "Unsafe Jackson deserialization configuration ",
			Description: "When the Jackson databind library is used incorrectly the deserialization of untrusted data can lead to remote code execution, if there is a class in classpath that allows the trigger of malicious operation.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ObjectMapper\(\)`),
			regexp.MustCompile(`enableDefaultTyping\(\)`),
			regexp.MustCompile(`readValue\(.*\)`),
		},
	}
}

func NewObjectDeserializationUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fb22c2a8-1bdf-4a24-b18e-1d1528f554c1",
			Name:        "Object deserialization is used",
			Description: "Object deserialization of untrusted data can lead to remote code execution, if there is a class in classpath that allows the trigger of malicious operation. For more information checkout the CWE-502 (https://cwe.mitre.org/data/definitions/502.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(public|private|protected)`),
			regexp.MustCompile(`ObjectInputStream\(.*\)`),
			regexp.MustCompile(`readObject\(\)`),
			regexp.MustCompile(`(\(InputStream \w+)\)`),
		},
	}
}
func NewPotentialCodeScriptInjectionWithSpringExpression() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "da8118cb-44d4-450d-8e30-ed9778d3003c",
			Name:        "Potential code injection when using Spring Expression",
			Description: "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation. For more information checkout the CWE-94 (https://cwe.mitre.org/data/definitions/94.html) advisory and checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new.SpelExpressionParser\(`),
			regexp.MustCompile(`\.parseExpression\(`),
		},
	}
}

func NewCookieWithoutTheHttpOnlyFlag() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "67dfe348-5a8b-4fd3-a66e-8234a60278a3",
			Name:        "Cookie without the HttpOnly flag ",
			Description: "A new cookie is created without the HttpOnly flag set. For more information checkout the (https://owasp.org/www-community/HttpOnly) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Cookie\(.*\)`),
			regexp.MustCompile(`setSecure\(false\)|setHttpOnly\(false\)`),
		},
	}
}

func NewWebViewWithGeolocationActivated() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e5ec77a9-8f43-4022-90b6-0667cfddf401",
			Name:        "WebView with geolocation activated",
			Description: "It is suggested to ask the user for a confirmation about obtaining its geolocation.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setWebChromeClient\(new WebChromeClient\(\)`),
			regexp.MustCompile(`@Override`),
			regexp.MustCompile(`onGeolocationPermissionsShowPrompt\(.*, GeolocationPermissions.Callback callback\)`),
		},
	}
}

func NewUseOfESAPIEncryptor() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "38061285-d4c2-4a7f-80d4-d53e4d862a8f",
			Name:        "Use of ESAPI Encryptor",
			Description: "The ESAPI has a small history of vulnerabilities within the cryptography component. Here is a quick validation list to make sure the Authenticated Encryption is working as expected. For more information checkout the CWE-310 (https://cwe.mitre.org/data/definitions/310.html) advisory",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Encryptor.CipherText.useMAC=false`),
			regexp.MustCompile(`Encryptor.EncryptionAlgorithm=AES`),
			regexp.MustCompile(`Encryptor.CipherTransformation=AES/CBC/PKCS5Padding`),
			regexp.MustCompile(`Encryptor.cipher_modes.additional_allowed=CBC`),
		},
	}
}

func NewStaticIV() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6145b691-da4f-4210-bf05-414cccc6b8e1",
			Name:        "Static IV",
			Description: "Initialization vector must be regenerated for each message to be encrypted. For more information checkout the CWE-329 (https://cwe.mitre.org/data/definitions/329.html) advisory",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new byte\[.*\]`),
			regexp.MustCompile(`IvParameterSpec\(.*\)`),
		},
	}
}

func NewXMLDecoderUsage() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bf09c7be-035b-4e1b-b1ad-1924d4e87f9b",
			Name:        "XML Decoder usage",
			Description: "XMLDecoder should not be used to parse untrusted data. Deserializing user input can lead to arbitrary code execution. For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`XMLDecoder\(.*\)`),
			regexp.MustCompile(`readObject\(\)`),
		},
	}
}

func NewPotentialXSSInServlet() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4d43695d-a3f4-4f11-9a30-705ceb128d63",
			Name:        "Potential XSS in Servlet",
			Description: "A potential XSS was found. It could be used to execute unwanted Script in a client's browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getParameter\(.*\)`),
			regexp.MustCompile(`getWriter\(\).write`),
			regexp.MustCompile(`HttpServletRequest|HttpServletResponse`),
		},
	}
}

func NewEscapingOfSpecialXMLCharactersIsDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8b195c27-6bea-471e-95df-dde5a7442c43",
			Name:        "Escaping of special XML characters is disabled",
			Description: "A potential XSS was found. It could be used to execute unwanted Script in a client's browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`<%@ taglib prefix=".*" uri=".*" %>`),
			regexp.MustCompile(`<c:out value=".*" escapeXml="false"/>`),
		},
	}
}

func NewDynamicVariableInSpringExpression() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f1d40c63-a6e3-45f7-9331-6eac65e0bed0",
			Name:        "Dynamic variable in Spring expression",
			Description: "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation. For more information checkout the CWE-95 (https://cwe.mitre.org/data/definitions/95.html) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`<%@ taglib prefix=".*" uri=".*" %>`),
			regexp.MustCompile(`<spring:eval expression="\${.*}" var=".*" />`),
		},
	}
}

func NewRSAUsageWithShortKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2af457e2-5fc6-429f-8c6f-eb15685595c3",
			Name:        "RSA usage with short key",
			Description: "The NIST recommends the use of 2048 bits and higher keys for the RSA algorithm. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`KeyPairGenerator.getInstance\(.*\)`),
			regexp.MustCompile(`(initialize\()(\)|[0-9][^\d]|[0-9]{2}[^\d]|[0-9]{3}[^\d]|[0-1][0-9]{3}[^\d]|20[0-3][0-9]|204[0-7])`),
		},
	}
}

func NewBlowfishUsageWithShortKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a5b7dc4f-81b3-406c-8c2e-5586a7ad4a40",
			Name:        "Blowfish usage with short key",
			Description: "The Blowfish cipher supports key sizes from 32 bits to 448 bits. A small key size makes the ciphertext vulnerable to brute force attacks. At least 128 bits of entropy should be used when generating the key if use of Blowfish is required. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`KeyGenerator.getInstance\(['|"]Blowfish['|"]\)`),
			regexp.MustCompile(`(init\()(\)|[0-9][^\d]|[0-9]{2}[^\d]|[0-1][0-2][0-7])`),
		},
	}
}

func NewClassesShouldNotBeLoadedDynamically() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "de9f63c5-598d-4830-8986-299941b02104",
			Name:        "Classes should not be loaded dynamically",
			Description: "Dynamically loaded classes could contain malicious code executed by a static class initializer. I.E. you wouldn't even have to instantiate or explicitly invoke methods on such classes to be vulnerable to an attack. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`System.getProperty\(.*\)`),
			regexp.MustCompile(`Class.forName\(.*\)`),
		},
	}
}

func NewHostnameVerifierVerifyShouldNotAlwaysReturnTrue() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "54420eaa-5300-49b2-a9aa-4a902d3327ac",
			Name:        "HostnameVerifier.verify should not always return true",
			Description: "To prevent URL spoofing, HostnameVerifier.verify() methods should do more than simply return true. Doing so may get you quickly past an exception, but that comes at the cost of opening a security hole in your application. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`@Override`),
			regexp.MustCompile(`public boolean verify\(String requestedHost, SSLSession remoteServerSession\)`),
			regexp.MustCompile(`return true`),
		},
	}
}

func NewXPathExpressionsShouldNotBeVulnerableToInjectionAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "dcfc2105-4d7c-4ed1-91e7-8911f649fea3",
			Name:        "XPath expressions should not be vulnerable to injection attacks",
			Description: "User provided data, such as URL parameters, should always be considered untrusted and tainted. Constructing XPath expressions directly from tainted data enables attackers to inject specially crafted values that changes the initial meaning of the expression itself. Successful XPath injection attacks can read sensitive information from XML documents. For more information checkout the CWE-643 (https://cwe.mitre.org/data/definitions/643.html) advisory",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`=\s?\".*?\@.*?\+`),
			regexp.MustCompile(`\.evaluate\(`),
		},
	}
}

func NewExceptionsShouldNotBeThrownFromServletMethods() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0ae9df9f-99d8-4b80-a92a-48957db57422",
			Name:        "Exceptions should not be thrown from servlet methods",
			Description: "Even though the signatures for methods in a servlet include throws IOException, ServletException, it's a bad idea to let such exceptions be thrown. Failure to catch exceptions in a servlet could leave a system in a vulnerable state. For more information checkout the CWE-600 (https://cwe.mitre.org/data/definitions/600.html) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\(HttpServletRequest .*, HttpServletResponse .*\)`),
			regexp.MustCompile(`ServletException`),
			regexp.MustCompile(`throws UnknownHostException`),
		},
	}
}

func NewFunctionCallsShouldNotBeVulnerableToPathInjectionAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "86c82b8e-2a04-4729-99c5-cc88c9d3f0fe",
			Name:        "I/O function calls should not be vulnerable to path injection attacks",
			Description: "User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Constructing file system paths directly from tainted data could enable an attacker to inject specially crafted values, such as '../', that change the initial path and, when accessed, resolve to a path on the filesystem where the user should normally not have access.\n\nA successful attack might give an attacker the ability to read, modify, or delete sensitive information from the file system and sometimes even execute arbitrary operating system commands. This is often referred to as a \"path traversal\" or \"directory traversal\" attack. For more information checkout the CWE-99 (https://cwe.mitre.org/data/definitions/99.html) advisory and checkout the (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.forceDelete\(`),
			regexp.MustCompile(`new\sFile`),
			regexp.MustCompile(`new\sFile\(([^d]|d[^i]|di[^r]|dir[^e]|dire[^c]|direc[^t]|direct[^o]|directo[^r]|director[^y]|directory[^C]|directoryC[^o]|directoryCo[^n]|directoryCon[^t]|directoryCont[^a]|directoryConta[^i]|directoryContai[^n]|directoryContain[^s])*\.forceDelete`),
		},
	}
}

func NewActiveMQConnectionFactoryVulnerableToMaliciousCodeDeserialization() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e883edb5-2fa3-429f-97c0-9d5d1da06627",
			Name:        "ActiveMQConnectionFactory should not be vulnerable to malicious code deserialization",
			Description: "Internally, ActiveMQ relies on  serialization mechanism for marshaling/unmashaling of the message payload. Deserialization based on data supplied by the user could lead to remote code execution attacks, where the structure of the serialized data is changed to modify the behavior of the object being unserialized. For more information checkout the CWE-502 (https://cwe.mitre.org/data/definitions/502.html) advisory",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ActiveMQConnectionFactory\(.*\)`),
			regexp.MustCompile(`(setTrustAllPackages\(true\)|ActiveMQConnectionFactory([^f]|f[^a]|fa[^c]|fac[^t]|fact[^o]|facto[^r]|factor[^y]|factory[^.]|factory.[^s]|factory.s[^e]|factory.se[^t]|factory.set[^T]|factory.setT[^r]|factory.setTr[^u]|factory.setTru[^s]|factory.setTrus[^t]|factory.setTrust[^A]|factory.setTrustA[^l]|factory.setTrustAl[^l]|factory.setTrustAll[^P]|factory.setTrustAllP[^a]|factory.setTrustAllPa[^c]|factory.setTrustAllPac[^k]|factory.setTrustAllPack[^a]|factory.setTrustAllPacka[^g]|factory.setTrustAllPackag[^e]factory.setTrustAllPackage[^s])*})`),
		},
	}
}

func NewHTTPResponseHeadersShouldNotBeVulnerableToInjectionAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4fd66672-8fc8-462e-bd02-3b4f19ab4e2a",
			Name:        "HTTP response headers should not be vulnerable to injection attacks",
			Description: "User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Applications constructing HTTP response headers based on tainted data could allow attackers to change security sensitive headers like Cross-Origin Resource Sharing headers. This could, for example, enable Cross-Site Scripting (XSS) attacks. Web application frameworks and servers might also allow attackers to inject new line characters in headers to craft malformed HTTP response. In this case the application would be vulnerable to a larger range of attacks like HTTP Response Splitting/Smuggling. Most of the time this type of attack is mitigated by default modern web application frameworks but there might be rare cases where older versions are still vulnerable. As a best practice, applications that use user provided data to construct the response header should always validate the data first. Validation should be based on a whitelist. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory and checkout (https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_(XSS)).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`req.getParameter`),
			regexp.MustCompile(`resp.addHeader\(["|']`),
			regexp.MustCompile(`\.getParameter\(["|']([^i]|i[^f]|if\s?\([^!])*\.addHeader\(['|"].*["|'].*[^"]\)`),
		},
	}
}

func NewOpenSAML2ShouldBeConfiguredToPreventAuthenticationBypass() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "827ed743-5a6a-4758-adcd-6c1534555422",
			Name:        "OpenSAML2 should be configured to prevent authentication bypass",
			Description: "From a specially crafted <SAMLResponse> file, an attacker having already access to the SAML system with his own account can bypass the authentication mechanism and be authenticated as another user. This is due to the fact that SAML protocol rely on XML format and how the underlying XML parser interprets XML comments. If an attacker manage to change the <NameID> field identifying the authenticated user with XML comments, he can exploit the vulnerability. For more information checkout the OWASP (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication) advisory",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(import org.opensaml.xml.parse.BasicParserPool|import org.opensaml.xml.parse.StaticBasicParserPool)`),
			regexp.MustCompile(`setIgnoreComments\(false\)`),
		},
	}
}

//Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewHttpServletRequestGetRequestedSessionIdShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fa0ccc8d-f6bd-4be2-8764-f38194fd9185",
			Name:        "HttpServletRequest.getRequestedSessionId should not be used",
			Description: "Due to the ability of the end-user to manually change the value, the session ID in the request should only be used by a servlet container (E.G. Tomcat or Jetty) to see if the value matches the ID of an an existing session. If it does not, the user should be considered unauthenticated. Moreover, this session ID should never be logged to prevent hijacking of active sessions. For more information checkout the CWE-807 (https://cwe.mitre.org/data/definitions/807) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import javax.servlet.http.HttpServletRequest`),
			regexp.MustCompile(`getRequestedSessionId\(\)`),
		},
	}
}

func NewJakartaAndHttpServletRequestGetRequestedSessionIdShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2e301a1e-d2eb-4505-9dff-26341e159bdf",
			Name:        "HttpServletRequest.getRequestedSessionId should not be used",
			Description: "Due to the ability of the end-user to manually change the value, the session ID in the request should only be used by a servlet container (E.G. Tomcat or Jetty) to see if the value matches the ID of an an existing session. If it does not, the user should be considered unauthenticated. Moreover, this session ID should never be logged to prevent hijacking of active sessions. For more information checkout the CWE-807 (https://cwe.mitre.org/data/definitions/807) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import jakarta.servlet.http.HttpServletRequest`),
			regexp.MustCompile(`getRequestedSessionId\(\)`),
		},
	}
}
func NewLDAPAuthenticatedAnalyzeYourCode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "89a63033-d7e4-4f74-b162-6e9a5fd81f91",
			Name:        "LDAP authenticated Analyze your code",
			Description: "An LDAP client authenticates to an LDAP server with a \"bind request\" which provides, among other, a simple authentication method. Anonymous binds and unauthenticated binds allow access to information in the LDAP directory without providing a password, their use is therefore strongly discouraged. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory and checkout (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sHashtable`),
			regexp.MustCompile(`put\(Context\.SECURITY_AUTHENTICATION, ["|']none["|']\)`),
		},
	}
}

//Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewWebApplicationsShouldHotHaveAMainMethod() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3b02a174-58a8-47da-b732-444899361a24",
			Name:        "Web applications should not have a main method",
			Description: "Having a main method in a web application opens a door to the application logic that an attacker may never be able to reach (but watch out if one does!), but it is a sloppy practice and indicates that other problems may be present. For more information checkout the CWE-489 (https://cwe.mitre.org/data/definitions/489.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import javax.servlet.*`),
			regexp.MustCompile(`public static void main\(String\[\] args\)`),
		},
	}
}

func NewJakartaAndWebApplicationsShouldHotHaveAMainMethod() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "84f60119-53e7-4ca2-beca-504891712b80",
			Name:        "Web applications should not have a main method",
			Description: "Having a main method in a web application opens a door to the application logic that an attacker may never be able to reach (but watch out if one does!), but it is a sloppy practice and indicates that other problems may be present. For more information checkout the CWE-489 (https://cwe.mitre.org/data/definitions/489.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`import jakarta.servlet.*`),
			regexp.MustCompile(`public static void main\(String\[\] args\)`),
		},
	}
}

func NewSecureRandomSeedsShouldNotBePredictable() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c801646c-d221-4a8b-9ec1-306a1003d13a",
			Name:        "\"SecureRandom\" seeds should not be predictable",
			Description: "The java.security.SecureRandom class provides a strong random number generator (RNG) appropriate for cryptography. However, seeding it with a constant or another predictable value will weaken it significantly. In general, it is much safer to rely on the seed provided by the SecureRandom implementation. For more information checkout the CWE-330 (https://cwe.mitre.org/data/definitions/330.html) advisory and checkout (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSecureRandom`),
			regexp.MustCompile(`\.setSeed\(`),
		},
	}
}

func NewFileIsWorldReadable() text.TextRule {
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

func NewFileIsWorldWritable() text.TextRule {
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

func NewNoWriteExternalContent() text.TextRule {
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

func NewNoUseIVsWeak() text.TextRule {
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

func NewRootDetectionCapabilities() text.TextRule {
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

func NewJARURLConnection() text.TextRule {
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

func NewSetOrReadClipboardData() text.TextRule {
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

func NewMessageDigest() text.TextRule {
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

func NewOverlyPermissiveFilePermission() text.TextRule {
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

func NewCipherGetInstanceInsecure() text.TextRule {
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

func NewHiddenElements() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c3e26bb3-a07b-4e1d-881d-0d194f813105",
			Name:        "Hidden elements",
			Description: "Hidden elements in view can be used to hide data from user. But this data can be leaked. For more information checkout the CWE-919 (https://cwe.mitre.org/data/definitions/919.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)`),
		},
	}
}

func NewWeakCypherBlockMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "cbf823d8-13f7-45d1-9ab6-b6accfd2414d",
			Name:        "Weak block mode for Cryptographic Hash Function",
			Description: "A weak ECB, (a.k.a 'block mode') was found in one of your Ciphers. Always use a strong, high entropy hash, for example the SHA-512 with salt options. For more information check CWE-327 (https://cwe.mitre.org/data/definitions/327.html), CWE-719 (https://cwe.mitre.org/data/definitions/719.html), CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-780 (https://cwe.mitre.org/data/definitions/780.html) for deeper details on how to fix it.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Cipher\.getInstance\(\s*\".+/ECB/.+\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\"AES.+\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\".+/GCM/.+\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\".+\/CBC\/.*\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\"RSA/.+/NoPadding`),
		},
	}
}

func NewWeakHash() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "de9be233-8f65-4e2a-bb6e-8acbc2a4dff3",
			Name:        "Weak Cryptographic Hash Function used",
			Description: "Using a weak CHF pose a threat to your application security since it can be vulnerable to a number of attacks that could lead to data leaking, improper access of features and resources of your infrastructure and even rogue sessions. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getInstance("md4")|getInstance("rc2")|getInstance("rc4")|getInstance("RC4")|getInstance("RC2")|getInstance("MD4")`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*MD5["|']*\)|MessageDigest\.getInstance\(["|']*md5["|']*\)|DigestUtils\.md5\(`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*SHA-?1["|']*\)|MessageDigest\.getInstance\(["|']*sha-?1["|']*\)|DigestUtils\.sha\(|DigestUtils\.getSha1Digest\(`),
			regexp.MustCompile(`getInstance\(["|']rc4["|']\)|getInstance\(["|']RC4["|']\)|getInstance\(["|']RC2["|']\)|getInstance\(["|']rc2["|']\)`),
			regexp.MustCompile(`getInstance\(["|']md4["|']\)|getInstance\(["|']MD4["|']\)|getInstance\(["|']md2["|']\)|getInstance\(["|']MD2["|']\)`),
		},
	}
}

func NewPossibleFileWithVulnerabilityWhenOpen() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fe722822-2c24-4701-9e16-faf848b13aa8",
			Name:        "Possible  File With Vulnerability When Open",
			Description: "The file is World Readable and Writable. Any App can read/write to the file. For more information checkout the CWE-276  (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*3\s*\)`),
		},
	}
}

func NewSensitiveInformationNotEncrypted() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "14b76559-d0b1-4b41-8408-cf28e6f75e0d",
			Name:        "Sensitive Information Not Encrypted",
			Description: "App can write to App Directory. Sensitive Information should be encrypted. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`MODE_PRIVATE|Context\.MODE_PRIVATE`),
		},
	}
}

func NewInsecureRandomNumberGenerator() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1079260f-aea3-4d10-9b14-1a96d7043dad",
			Name:        "Insecure Random Number Generator",
			Description: "The App uses an insecure Random Number Generator. For more information checkout the CWE-330 (https://cwe.mitre.org/data/definitions/330.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`java\.util\.Random`),
			regexp.MustCompile(`scala\.util\.Random`),
		},
	}
}

func NewNoDefaultHash() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a77029ba-1863-4ffd-b2d6-3caf5461ccf6",
			Name:        "No Default  Hash",
			Description: "This App uses  Hash Code. It\"s a weak hash function and should never be used in Secure Crypto Implementation. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.hashCode()`),
		},
	}
}

func NewLayoutParamsFlagSecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bd76384c-9540-4f1f-ba8e-a24e16e21864",
			Name:        "Layout Params Flag Secure",
			Description: "These activities prevent screenshot when they go to background.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`LayoutParams.FLAG_SECURE`),
		},
	}
}

func NewNoUseSQLCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c2e4cd9f-aea9-45e9-8e7a-7f7e893dd9e0",
			Name:        "No use SQL Cipher",
			Description: "This App uses SQL Cipher. But the secret may be hardcoded. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SQLiteOpenHelper.getWritableDatabase\(`),
		},
	}
}

func NewPreventTapJackingAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "43a692bf-d23b-4137-b652-90c38fd7aca2",
			Name:        "Prevent Tap Jacking Attacks",
			Description: "This app has capabilities to prevent tapjacking attacks. For more information checkout the CWE-1021 (https://cwe.mitre.org/data/definitions/1021.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setFilterTouchesWhenObscured\(true\)`),
		},
	}
}

func NewPreventWriteSensitiveInformationInTmpFile() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2a3f6aef-4fa3-4d40-89c3-a249a28cb17b",
			Name:        "Prevent Write sensitive information in tmp file",
			Description: "App creates temp file. Sensitive information should never be written into a temp file. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.createTempFile\(`),
		},
	}
}

func NewGetWindowFlagSecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d34b3ba5-b988-4a0f-9344-467274cd98be",
			Name:        "Get Window Flag Secure",
			Description: "This App has capabilities to prevent against Screenshots from Recent Task History/Now On Tap etc.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getWindow\(.*\)\.(set|add)Flags\(.*\.FLAG_SECURE`),
		},
	}
}

func NewLoadingNativeCode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d0253f59-ae24-4825-bacf-372fd75f1154",
			Name:        "Loading Native Code",
			Description: "Loading Native Code (Shared Library)",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`System\.loadLibrary\(|System\.load\(`),
		},
	}
}

func NewDynamicClassAndDexloading() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a80e1c26-101e-4382-b3af-0d617e4e366f",
			Name:        "Dynamic Class and Dexloading",
			Description: "Dynamic Class and Dexloading",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`dalvik\.system\.DexClassLoader|java\.security\.ClassLoader|java\.net\.URLClassLoader|java\.security\.SecureClassLoader`),
		},
	}
}

func NewCryptoImport() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e647f537-fb3b-40f0-8bbb-f35a414443e0",
			Name:        " Crypto import",
			Description: " Crypto import",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`javax\.crypto|kalium\.crypto|bouncycastle\.crypto`),
		},
	}
}

func NewStartingService() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "378cfa72-43bf-4e81-ab86-996238fb49c7",
			Name:        "Starting Service",
			Description: "Starting Service",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`startService\(|bindService\(`),
		},
	}
}

func NewSendingBroadcast() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5e6f4999-3461-482b-9047-1b24cf28b9fa",
			Name:        "Sending Broadcast",
			Description: "Sending Broadcast",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(`),
		},
	}
}

func NewLocalFileOperations() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c28d5ca9-5d6a-46ce-9a72-4ed6ba042884",
			Name:        "Local File I/O Operations",
			Description: "Local File I/O Operations",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`OpenFileOutput|getSharedPreferences|SharedPreferences.Editor|getCacheDir|getExternalStorageState|openOrCreateDatabase`),
		},
	}
}

func NewInterProcessCommunication() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7e0001c3-d89d-4da7-8cd3-25dddc6d4157",
			Name:        "Inter Process Communication",
			Description: "Inter Process Communication",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`IRemoteService|IRemoteService\.Stub|IBinder`),
		},
	}
}

func NewDefaultHttpClient() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4455e6d5-4533-49e4-8edc-6efda9fce9c3",
			Name:        "DefaultHttpClient with default constructor is not compatible with TLS 1.2",
			Description: "Upgrade your implementation to use one of the recommended constructs and configure https.protocols JVM option to include TLSv1.2. Use SystemDefaultHttpClient instead. For more information checkout (https://blogs.oracle.com/java-platform-group/diagnosing-tls,-ssl,-and-https)",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSystemDefaultHttpClient\(\)`),
		},
	}
}

func NewWeakSSLContext() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0cc60028-b33b-45e3-9c62-44a0c60ae517",
			Name:        "Weak SSLContext",
			Description: "Upgrade your implementation to the following, and configure https.protocols JVM option to include TLSv1.2:. Use SSLContext.getInstance(\"TLS\"). For more information checkout (https://blogs.oracle.com/java-platform-group/diagnosing-tls,-ssl,-and-https)",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SSLContext\.getInstance\(["|']SSL.*["|']\)`),
		},
	}
}

func NewHostnameVerifierThatAcceptAnySignedCertificates() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5bc8ba32-9022-4ff4-963a-a08ae4a5cae9",
			Name:        "HostnameVerifier that accept any signed certificates",
			Description: "A HostnameVerifier that accept any host are often use because of certificate reuse on many hosts. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`implements\sHostnameVerifier`),
		},
	}
}

func NewURLRewritingMethod() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8c29a16a-8e94-43a9-aa27-4e32a6f0594e",
			Name:        "URL rewriting method",
			Description: "URL rewriting has significant security risks. Since session ID appears in the URL, it may be easily seen by third parties. Session ID in the URL can be disclosed in many ways. For more information checkout the (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.*out.println\(.*(res.encodeURL\(HttpUtils.getRequestURL\(.*\).toString\(\)).*\)`),
		},
	}
}

func NewDisablingHTMLEscaping() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a4df3c73-70bf-4594-ba37-43aed3df8509",
			Name:        "Disabling HTML escaping",
			Description: "Disabling HTML escaping put the application at risk for Cross-Site Scripting (XSS). For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`add\(new Label\(.*\).setEscapeModelStrings\(false\)\)`),
		},
	}
}

func NewOverlyPermissiveCORSPolicy() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8f10b6ba-065d-4e14-b3b9-ec231884b086",
			Name:        "Overly permissive CORS policy",
			Description: "A web server defines which other domains are allowed to access its domain using cross-origin requests. However, caution should be taken when defining the header because an overly permissive CORS policy will allow a malicious application to communicate with the victim application in an inappropriate way, leading to spoofing, data theft, relay and other attacks. For more information checkout the (https://fetch.spec.whatwg.org/) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.addHeader\("Access-Control-Allow-Origin", "\*"\)`),
		},
	}
}

func NewSQLInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "22e307e8-af07-4397-a9bf-232bad45fa52",
			Name:        "SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createQuery\(.?((.*|\n)*)?)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
			// regexp.MustCompile(`\.encodeForSQL\(`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewSQLInjectionWithTurbine() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8192e0eb-d9c7-4718-a80d-40bf2ebbcfab",
			Name:        "SQL Injection With Turbine",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Turbine API provide a DSL to build query with  code. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(BasePeer\.)?(executeQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.encodeForSQL\(`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewSQLInjectionWithHibernate() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "99ce8a42-71aa-43f6-b247-28891f862c9d",
			Name:        "SQL Injection With Hibernate",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, Hibernate Criteria can be used. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory and checkout the CWE-564 (https://cwe.mitre.org/data/definitions/564.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(openSession\(\))?(\.)(createQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setString|\.setInteger`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewSQLInjectionWithJDO() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6d93be06-de01-4522-91b5-648d5d11fcad",
			Name:        "SQL Injection With JDO",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(getPM\(\))?(\.)(newQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.declareParameters`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewSQLInjectionWithJPA() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "477f2d07-8b1a-4b14-971d-e476ebcb9002",
			Name:        "SQL Injection With JPA",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(getEM\(\))?(\.)(createQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setParameter`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewSQLInjectionWithSpringJDBC() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "772b4a13-5fb1-4deb-8fcc-4cb39bfb3e9f",
			Name:        "SQL Injection Spring JDBC",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(JdbcTemplate\(\))?(\.)(queryForObject\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setParameter`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewSQLInjectionWithJDBC() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bfa5c53d-2ea2-4499-bf82-daaf4cca4400",
			Name:        "SQL Injection JDBC",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createStatement\(\))?(\.)(executeQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setParameter`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewLDAPInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2820379a-5322-4131-9f2d-7e3ad1d4aed8",
			Name:        "Potential LDAP Injection",
			Description: "Just like SQL, all inputs passed to an LDAP query need to be passed in safely. Unfortunately, LDAP doesn't have prepared statement interfaces like SQL. Therefore, the primary defense against LDAP injection is strong input validation of any untrusted data before including it in an LDAP query. For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(search\(["|'](((.*|\n))*)(\+.*\+.*)["|']\))|(search\(.*,.*,.*,new SearchControls\()`),
		},
	}
}

func NewPotentialExternalControl() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "357b9de7-6d22-4e5f-9bd6-cfe69431f319",
			Name:        "Potential external control of configuration",
			Description: "Allowing external control of system settings can disrupt service or cause an application to behave in unexpected, and potentially malicious ways. An attacker could cause an error by providing a nonexistent catalog name or connect to an unauthorized portion of the database. For more information checkout the CWE-15 (https://cwe.mitre.org/data/definitions/15.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setCatalog\(.*\.getParameter`),
		},
	}
}

func NewBadHexadecimalConcatenation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e6bfb8da-3680-497e-9652-63d6913b791d",
			Name:        "Bad hexadecimal concatenation",
			Description: "When converting a byte array containing a hash signature to a human readable string, a conversion mistake can be made if the array is read byte by byte. The following sample illustrates the use of the method Integer.toHexString() which will trim any leading zeroes from each byte of the computed hash value. For more information checkout the CWE-704 (https://cwe.mitre.org/data/definitions/704.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`&\s[0xFF]`),
		},
	}
}

func NewNullCipherInsecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1c11c767-15d9-4030-935b-0905b7607f37",
			Name:        "NullCipher is insecure",
			Description: "The NullCipher is rarely used intentionally in production applications. It implements the Cipher interface by returning ciphertext identical to the supplied plaintext. In a few contexts, such as testing, a NullCipher may be appropriate. For more information checkout the CWE-704 (https://cwe.mitre.org/data/definitions/704.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NullCipher\(`),
		},
	}
}

func NewUnsafeHashEquals() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4dad1120-f1bd-4b26-8561-699a7d61af84",
			Name:        "Unsafe hash equals",
			Description: "An attacker might be able to detect the value of the secret hash due to the exposure of comparison timing. When the functions Arrays.equals() or String.equals() are called, they will exit earlier if fewer bytes are matched. For more information checkout the CWE-704 (https://cwe.mitre.org/data/definitions/704.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\.equals\()(.*)(hash|Hash)`),
		},
	}
}

func NewUnvalidatedRedirect() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "869b7ff4-54b6-414f-9524-3eb4d5700801",
			Name:        "Unvalidated Redirect",
			Description: "Unvalidated redirects occur when an application redirects a user to a destination URL specified by a user supplied parameter that is not validated. Such vulnerabilities can be used to facilitate phishing attacks. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sendRedirect\(.*.getParameter\(.*\)\)`),
		},
	}
}

func NewRequestMappingMethodsNotPublic() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c6418f44-3424-44fd-b49e-6af5dd0dc219",
			Name:        "@RequestMapping methods should be public",
			Description: "A method with a @RequestMapping annotation part of a class annotated with @Controller (directly or indirectly through a meta annotation - @RestController from Spring Boot is a good example) will be called to handle matching web requests. That will happen even if the method is private, because Spring invokes such methods via reflection, without checking visibility. For more information checkout the OWASAP:A6 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration) advisory",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`RequestMapping\((.*\n)(.*)private`),
		},
	}
}

func NewLDAPDeserializationNotDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "73072f1e-fd29-424c-938a-f233e589d23d",
			Name:        "LDAP deserialization should be disabled",
			Description: "JNDI supports the deserialization of objects from LDAP directories, which is fundamentally insecure and can lead to remote code execution. This rule raises an issue when an LDAP search query is executed with SearchControls configured to allow deserialization. For more information checkout the CWE-502 (https://cwe.mitre.org/data/definitions/502.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SearchControls\(((.*|\n)*)true((.*|\n)*)\)`),
		},
	}
}

func NewDatabasesPasswordNotProtected() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "71dd0c28-bed7-4c34-ac50-94a9ac3b8b5b",
			Name:        "Databases should be password-protected",
			Description: "Databases should always be password protected. The use of a database connection with an empty password is a clear indication of a database that is not protected. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.getConnection\(['|"]jdbc`),
		},
	}
}
