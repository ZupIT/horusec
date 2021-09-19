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
package and

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewJavaAndXMLParsingVulnerableToXXE() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithXMLInputFactory() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithDocumentBuilder() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithSAXParserFactory() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithTransformerFactory() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithSchemaFactory() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithDom4j() text.TextRule {
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

func NewJavaAndXMLParsingVulnerableToXXEWithJdom2() text.TextRule {
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

func NewJavaAndInsecureImplementationOfSSL() text.TextRule {
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

func NewJavaAndMessageDigestIsCustom() text.TextRule {
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

func NewJavaAndTrustManagerThatAcceptAnyCertificatesClient() text.TextRule {
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

func NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnections() text.TextRule {
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

func NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail() text.TextRule {
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

//Deprecated the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithJavaMail() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "90ee28f2-d622-4a5e-9d9d-13fb53ea5ca7",
			Name:        "Server hostnames should be verified during SSL/TLS connections With JavaMail's",
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

func NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithJakartaMail() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "90ee28f2-d622-4a5e-9d9d-13fb53ea5ca7",
			Name:        "Server hostnames should be verified during SSL/TLS connections With JavaMail's",
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

func NewJavaAndTrustManagerThatAcceptAnyCertificatesServer() text.TextRule {
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

func NewJavaAndTrustManagerThatAcceptAnyCertificatesIssuers() text.TextRule {
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

func NewJavaAndWebViewLoadFilesFromExternalStorage() text.TextRule {
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

func NewJavaAndInsecureWebViewImplementation() text.TextRule {
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
			regexp.MustCompile(`setJavaScriptEnabled\(true\)`),
			regexp.MustCompile(`.addJavascriptInterface\(`),
		},
	}
}

func NewJavaAndNoUseSQLCipher() text.TextRule {
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

func NewJavaAndNoUseRealmDatabaseWithEncryptionKey() text.TextRule {
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

func NewJavaAndNoUseWebviewDebuggingEnable() text.TextRule {
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

func NewJavaAndNoListenToClipboard() text.TextRule {
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

func NewJavaAndNoCopyContentToClipboard() text.TextRule {
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

func NewJavaAndNoUseWebviewIgnoringSSL() text.TextRule {
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

func NewJavaAndSQLInjectionWithSqlUtil() text.TextRule {
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

func NewJavaAndNoUseFridaServer() text.TextRule {
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

func NewJavaAndNoUseSSLPinningLib() text.TextRule {
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

func NewJavaAndNoUseDexGuardAppDebuggable() text.TextRule {
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

func NewJavaAndNoUseDexGuardDebuggerConnected() text.TextRule {
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

func NewJavaAndNoUseDexGuardEmulatorDetection() text.TextRule {
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

func NewJavaAndNoUseDexGuardWithDebugKey() text.TextRule {
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

func NewJavaAndNoUseDexGuardRoot() text.TextRule {
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

func NewJavaAndNoUseDexGuard() text.TextRule {
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

func NewJavaAndNoUseDexGuardInSigner() text.TextRule {
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

func NewJavaAndNoUsePackageWithTamperDetection() text.TextRule {
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

func NewJavaAndLoadAndManipulateDexFiles() text.TextRule {
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

func NewJavaAndObfuscation() text.TextRule {
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

func NewJavaAndExecuteOSCommand() text.TextRule {
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

func NewJavaAndTCPServerSocket() text.TextRule {
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

func NewJavaAndTCPSocket() text.TextRule {
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

func NewJavaAndUDPDatagramPacket() text.TextRule {
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

func NewJavaAndUDPDatagramSocket() text.TextRule {
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

func NewJavaAndWebViewJavaScriptInterface() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ba2f4ac8-e5fa-4bd9-b124-d08aeedbe60d",
			Name:        "WebView JavaScript Interface",
			Description: "WebView JavaScript Interface",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`addJavascriptInterface`),
			regexp.MustCompile(`WebView`),
		},
	}
}

func NewJavaAndGetCellInformation() text.TextRule {
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

func NewJavaAndGetCellLocation() text.TextRule {
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

func NewJavaAndGetSubscriberID() text.TextRule {
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

func NewJavaAndGetDeviceID() text.TextRule {
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

func NewJavaAndGetSoftwareVersion() text.TextRule {
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

func NewJavaAndGetSIMSerialNumber() text.TextRule {
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

func NewJavaAndGetSIMProviderDetails() text.TextRule {
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

func NewJavaAndGetSIMOperatorName() text.TextRule {
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

func NewJavaAndQueryDatabaseOfSMSContacts() text.TextRule {
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

//Deprecated the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewJavaAndPotentialPathTraversal() text.TextRule {
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

func NewJavaAndPotentialPathTraversalUsingScalaAPI() text.TextRule {
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

func NewJavaAndSMTPHeaderInjection() text.TextRule {
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

func NewJavaAndInsecureSMTPSSLConnection() text.TextRule {
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

func NewJavaAndPersistentCookieUsage() text.TextRule {
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

func NewJavaAndAnonymousLDAPBind() text.TextRule {
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

func NewJavaAndLDAPEntryPoisoning() text.TextRule {
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

func NewJavaAndIgnoringXMLCommentsInSAML() text.TextRule {
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

func NewJavaAndInformationExposureThroughAnErrorMessage() text.TextRule {
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

func NewJavaAndHTTPParameterPollution() text.TextRule {
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

func NewJavaAndAWSQueryInjection() text.TextRule {
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

func NewJavaAndPotentialTemplateInjectionPebble() text.TextRule {
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

func NewJavaAndPotentialTemplateInjectionFreemarker() text.TextRule {
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

func NewJavaAndRequestDispatcherFileDisclosure() text.TextRule {
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

func NewJavaAndSpringFileDisclosure() text.TextRule {
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

func NewJavaAndPotentialCodeScriptInjection() text.TextRule {
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

func NewJavaAndStrutsFileDisclosure() text.TextRule {
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

func NewJavaAndUnsafeJacksonDeserializationConfiguration() text.TextRule {
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

func NewJavaAndObjectDeserializationUsed() text.TextRule {
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
func NewJavaAndPotentialCodeScriptInjectionWithSpringExpression() text.TextRule {
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

func NewJavaAndCookieWithoutTheHttpOnlyFlag() text.TextRule {
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

func NewJavaAndWebViewWithGeolocationActivated() text.TextRule {
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

func NewJavaAndUseOfESAPIEncryptor() text.TextRule {
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

func NewJavaAndStaticIV() text.TextRule {
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

func NewJavaAndXMLDecoderUsage() text.TextRule {
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

func NewJavaAndPotentialXSSInServlet() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4d43695d-a3f4-4f11-9a30-705ceb128d63",
			Name:        "Potential XSS in Servlet",
			Description: "A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory",
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

func NewJavaAndEscapingOfSpecialXMLCharactersIsDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8b195c27-6bea-471e-95df-dde5a7442c43",
			Name:        "Escaping of special XML characters is disabled",
			Description: "A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory",
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

func NewJavaAndDynamicVariableInSpringExpression() text.TextRule {
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

func NewJavaAndRSAUsageWithShortKey() text.TextRule {
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

func NewJavaAndBlowfishUsageWithShortKey() text.TextRule {
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

func NewJavaAndClassesShouldNotBeLoadedDynamically() text.TextRule {
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

func NewJavaAndHostnameVerifierVerifyShouldNotAlwaysReturnTrue() text.TextRule {
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

func NewJavaAndXPathExpressionsShouldNotBeVulnerableToInjectionAttacks() text.TextRule {
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

func NewJavaAndExceptionsShouldNotBeThrownFromServletMethods() text.TextRule {
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

func NewJavaAndFunctionCallsShouldNotBeVulnerableToPathInjectionAttacks() text.TextRule {
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

func NewJavaAndActiveMQConnectionFactoryVulnerableToMaliciousCodeDeserialization() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e883edb5-2fa3-429f-97c0-9d5d1da06627",
			Name:        "ActiveMQConnectionFactory should not be vulnerable to malicious code deserialization",
			Description: "Internally, ActiveMQ relies on Java serialization mechanism for marshaling/unmashaling of the message payload. Deserialization based on data supplied by the user could lead to remote code execution attacks, where the structure of the serialized data is changed to modify the behavior of the object being unserialized. For more information checkout the CWE-502 (https://cwe.mitre.org/data/definitions/502.html) advisory",
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

func NewJavaAndHTTPResponseHeadersShouldNotBeVulnerableToInjectionAttacks() text.TextRule {
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

func NewJavaAndOpenSAML2ShouldBeConfiguredToPreventAuthenticationBypass() text.TextRule {
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
func NewJavaAndHttpServletRequestGetRequestedSessionIdShouldNotBeUsed() text.TextRule {
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
func NewJavaAndLDAPAuthenticatedAnalyzeYourCode() text.TextRule {
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

func NewJavaAndWebApplicationsShouldHotHaveAMainMethod() text.TextRule {
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

func NewJavaAndSecureRandomSeedsShouldNotBePredictable() text.TextRule {
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
