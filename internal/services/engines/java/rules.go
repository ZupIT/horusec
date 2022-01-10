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

func NewXMLParsingVulnerableToXXE() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-1",
			Name:        "XML parsing vulnerable to XXE",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`XMLReaderFactory\.createXMLReader\(`),
			regexp.MustCompile(`\.parse\(`),
			regexp.MustCompile(`(XMLReaderFactory\.createXMLReader\(\))(([^s]|s[^e]|se[^t]|set[^F]|setF[^e]|setFe[^a]|setFea[^t]|setFeat[^u]|setFeatu[^r]|setFeatur[^e])*)(\.parse\(.*\))`),
		},
	}
}

func NewXMLParsingVulnerableToXXEWithXMLInputFactory() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-2",
			Name:        "XML parsing vulnerable to XXE With XMLInputFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`XMLInputFactory\.newFactory\(`),
			regexp.MustCompile(`(XMLInputFactory\.newFactory\(\))(([^s]|s[^e]|se[^t]|set[^P]|setP[^r]|setPr[^o]|setPro[^p]|setProp[^e]|setPrope[^r]|setProper[^t]|setPropert[^y])*)(\.createXMLStreamReader\(.*\))`),
		},
	}
}

func NewXMLParsingVulnerableToXXEWithDocumentBuilder() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-3",
			Name:        "XML parsing vulnerable to XXE With DocumentBuilder",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`DocumentBuilderFactory\.newInstance\(`),
			regexp.MustCompile(`\.parse\(`),
			regexp.MustCompile(`(DocumentBuilderFactory\.newInstance\(\))(([^s]|s[^e]|se[^t]|set[^F]|setF[^e]|setFe[^a]|setFea[^t]|setFeat[^u]|setFeatu[^r]|setFeatur[^e])*)(\.parse\(.*\))`),
		},
	}
}

func NewXMLParsingVulnerableToXXEWithSAXParserFactory() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-4",
			Name:        "XML parsing vulnerable to XXE With SAXParserFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SAXParserFactory\.newInstance\(`),
			regexp.MustCompile(`\.parse\(`),
			regexp.MustCompile(`(SAXParserFactory\.newInstance\(\))(([^s]|s[^e]|se[^t]|set[^F]|setF[^e]|setFe[^a]|setFea[^t]|setFeat[^u]|setFeatu[^r]|setFeatur[^e])*)(\.parse\(.*\))`),
		},
	}
}

func NewXMLParsingVulnerableToXXEWithTransformerFactory() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-5",
			Name:        "XML parsing vulnerable to XXE With TransformerFactory",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(TransformerFactory\.newInstance\(\))(([^s]|s[^e]|se[^t]|set[^O]|setO[^u]|setOu[^t]|setOut[^p]|setOutp[^u]|setOutpu[^t]|setOutput[^P]|setOutputP[^r]|setOutputPr[^o]|setOutputPro[^p]|setOutputProp[^e]|setOutputPrope[^r]|setOutputProper[^t]|setPropertyPropert[^y])*)(\.transform\(.*\))`),
			regexp.MustCompile(`(TransformerFactory\.newInstance\(\))(([^s]|s[^e]|se[^t]|set[^F]|setF[^e]|setFe[^a]|setFea[^t]|setFeat[^u]|setFeatu[^r]|setFeatur[^e])*)(\.transform\(.*\))`),
			regexp.MustCompile(`(TransformerFactory\.newInstance\(\))(([^s]|s[^e]|se[^t]|set[^A]|setA[^t]|setAt[^t]|setAtt[^r]setAttr[^i]setAttri[^b]setAttrib[^u]|setAttribu[^^t]setAttribut[^e])*)(\.transform\(.*\))`),
		},
	}
}

// Deprecated: Repeated vulnerability, same as HS-JAVA-5
//
//func NewXMLParsingVulnerableToXXEWithSchemaFactory() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-6",
//			Name:        "XML parsing vulnerable to XXE With TransformerFactory",
//			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
//			Severity:    severities.Medium.ToString(),
//			Confidence:  confidence.Low.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`SchemaFactory\.newInstance\(`),
//		},
//	}
//}

func NewXMLParsingVulnerableToXXEWithDom4j() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-7",
			Name:        "XML parsing vulnerable to XXE With Dom4j",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSAXReader\(\)`),
			regexp.MustCompile(`(new\sSAXReader\(\))(([^s]|s[^e]|se[^t]|set[^F]|setF[^e]|setFe[^a]|setFea[^t]|setFeat[^u]|setFeatu[^r]|setFeatur[^e])*)(read\(.*\))`),
		},
	}
}

func NewXMLParsingVulnerableToXXEWithJdom2() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-8",
			Name:        "XML parsing vulnerable to XXE With Jdom2",
			Description: "XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSAXBuilder\(\)`),
			regexp.MustCompile(`(new\sSAXBuilder\(\))(([^s]|s[^e]|se[^t]|set[^P]|setP[^r]|setPr[^o]|setPro[^p]|setProp[^e]|setPrope[^r]|setProper[^t]|setPropert[^y])*)(\.build\(.*\))`),
		},
	}
}

func NewInsecureImplementationOfSSL() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-9",
			Name:        "Insecure Implementation of SSL",
			Description: "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\(`),
			regexp.MustCompile(`javax\.net\.ssl`),
		},
	}
}

func NewMessageDigestIsCustom() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-10",
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

func NewTrustManagerThatAcceptAnyCertificatesClient() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-11",
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

func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-12",
			Name:        "Server hostnames should be verified during SSL/TLS connections",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(verify\(String.*, SSLSession.*\).*\n.*return\strue)`),
			regexp.MustCompile(`(\@Override.*\n.*verify\(String.*, SSLSession .*\).*\n.*return\strue)`),
			regexp.MustCompile(`setHostnameVerifier\(new HostnameVerifier\(\)`),
		},
	}
}

func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-13",
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

func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-14",
			Name:        "Server hostnames should be verified during SSL/TLS connections With Mail's",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`put\("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory"\);`),
			regexp.MustCompile(`(new Properties\()(([^c]|c[^h]|ch[^e]|che[^c]|chec[^k]|check[^s]|checks[^e]|checkse[^r]|checkser[^v]|checkserv[^e]|checkserve[^r]|checkserver[^i]|checkserveri[^d]|checkserverid[^e]|checkserveride[^n]|checkserveriden[^t]|checkserverident[^i]|checkserveridenti[^t]|checkserveridentit[^y])*?)(new\s(javax|jakarta)\.mail\.Authenticator\()`),
			regexp.MustCompile(`put\(.*mail.smtp`),
		},
	}
}

// Deprecated: Repeated vulnerability, same as HS-JAVA-14
//
//func NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithJakartaMail() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-15",
//			Name:        "Server hostnames should be verified during SSL/TLS connections With Mail's",
//			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
//			Severity:    severities.High.ToString(),
//			Confidence:  confidence.Low.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`(new Properties\()(([^c]|c[^h]|ch[^e]|che[^c]|chec[^k]|check[^s]|checks[^e]|checkse[^r]|checkser[^v]|checkserv[^e]|checkserve[^r]|checkserver[^i]|checkserveri[^d]|checkserverid[^e]|checkserveride[^n]|checkserveriden[^t]|checkserverident[^i]|checkserveridenti[^t]|checkserveridentit[^y])*?)(new\sjakarta\.mail\.Authenticator\()`),
//			regexp.MustCompile(`put\(.*mail.smtp`),
//		},
//	}
//}

// Deprecated: Repeated vulnerability, same as HS-JAVA-11
//
//func NewTrustManagerThatAcceptAnyCertificatesServer() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-16",
//			Name:        "TrustManager that accept any certificates Server",
//			Description: "Empty TrustManager implementations are often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
//			Severity:    severities.Critical.ToString(),
//			Confidence:  confidence.High.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`implements\sX509TrustManager`),
//			regexp.MustCompile(`@Override`),
//			regexp.MustCompile(`public\svoid\scheckServerTrusted`),
//		},
//	}
//}

// Deprecated: Repeated vulnerability, same as HS-JAVA-11
//
//func NewTrustManagerThatAcceptAnyCertificatesIssuers() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-17",
//			Name:        "TrustManager that accept any certificates Issuers",
//			Description: "Empty TrustManager implementations are often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
//			Severity:    severities.Critical.ToString(),
//			Confidence:  confidence.High.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`implements\sX509TrustManager`),
//			regexp.MustCompile(`@Override`),
//			regexp.MustCompile(`public\sX509Certificate\[\]\sgetAcceptedIssuers`),
//		},
//	}
//}

func NewWebViewLoadFilesFromExternalStorage() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-18",
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

func NewInsecureWebViewImplementation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-19",
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

// Deprecated: Simply using SQL Cipher does not appear to be a vulnerability, to this becomes a vulnerability will
// depend on what is stored, how it was stored and the sql cipher version, removed to avoid false positives.
// reference: https://www.zetetic.net/blog/2019/08/14/defcon-sqlite-attacks/
//
//func NewNoUseSQLCipherAndMatch() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-20",
//			Name:        "No Use SQL Cipher",
//			Description: "This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite database files",
//			Severity:    severities.Medium.ToString(),
//			Confidence:  confidence.High.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`SQLiteDatabase.loadLibs\(`),
//			regexp.MustCompile(`net.sqlcipher`),
//		},
//	}
//}

// Deprecated: This vulnerability should search for a hardcoded secret, the actual implemented way
// will only lead to false positives, leaks engine already does a search for hardcoded credentials.
// reference: https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-6301?search=realm
//
//func NewNoUseRealmDatabaseWithEncryptionKey() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-21",
//			Name:        "No Use Realm Database With Encryption Key",
//			Description: "This App use Realm Database with encryption",
//			Severity:    severities.Medium.ToString(),
//			Confidence:  confidence.Medium.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`io.realm.Realm`),
//			regexp.MustCompile(`.encryptionKey\(`),
//		},
//	}
//}

func NewNoUseWebviewDebuggingEnable() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-22",
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

func NewNoListenToClipboard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-23",
			Name:        "No Listen To Clipboard",
			Description: "ClipboardManager is a system service that allows you to register a listener for when the clipboard changes and some malwares also listen to Clipboard changes.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`OnPrimaryClipChangedListener`),
			regexp.MustCompile(`content.ClipboardManager`),
		},
	}
}

func NewNoCopyContentToClipboard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-24",
			Name:        "No copy content to clipboard",
			Description: "This App copies data to clipboard. Sensitive data should not be copied to clipboard as other applications can access it.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setPrimaryClip\(`),
			regexp.MustCompile(`content.ClipboardManager`),
		},
	}
}

func NewNoUseWebviewIgnoringSSL() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-25",
			Name:        "No Use Webview Ignoring SSL",
			Description: "Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`onReceivedSslError\(WebView`),
			regexp.MustCompile(`@Override\n.*onReceivedSslError\(WebView`),
			regexp.MustCompile(`.proceed\(\);`),
		},
	}
}

func NewSQLInjectionWithSqlUtil() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-26",
			Name:        "SQL Injection With SqlUtil",
			Description: "The method identified is susceptible to injection. The input should be validated and properly escaped. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SqlUtil\.execQuery\(.*\+`),
		},
	}
}

// NewNoUseFridaServer Frida seems to be a pentest tool. I couldn't find an example similar to what our rule is looking for, so it's remains without tests.
func NewNoUseFridaServer() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-27",
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

// NewNoUseSSLPinningLib not really sure about this vulnerability, needs to be revised in the future.
func NewNoUseSSLPinningLib() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-28",
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

func NewNoUseDexGuardAppDebuggable() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-29",
			Name:        "DexGuard Debug Detection",
			Description: "DexGuard Debug Detection code to detect whatever an App is debuggable or not is identified.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`DebugDetector.isDebuggable`),
			regexp.MustCompile(`dexguard.util`),
		},
	}
}

func NewNoUseDexGuardDebuggerConnected() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-30",
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

func NewNoUseDexGuardEmulatorDetection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-31",
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

func NewNoUseDexGuardWithDebugKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-32",
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

func NewNoUseDexGuardRoot() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-33",
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

func NewNoUseDexGuard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-34",
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

func NewNoUseDexGuardInSigner() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-35",
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

func NewNoUsePackageWithTamperDetection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-36",
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

func NewLoadAndManipulateDexFiles() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-37",
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

func NewObfuscation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-38",
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

func NewExecuteOSCommand() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-39",
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

func NewTCPServerSocket() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-40",
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

func NewTCPSocket() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-41",
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

func NewUDPDatagramPacket() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-42",
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

func NewUDPDatagramSocket() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-43",
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

func NewWebViewScriptInterface() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-44",
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

func NewGetCellInformation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-45",
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

func NewGetCellLocation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-46",
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

func NewGetSubscriberID() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-47",
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

func NewGetDeviceID() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-48",
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

func NewGetSoftwareVersion() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-49",
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

func NewGetSIMSerialNumber() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-50",
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

func NewGetSIMProviderDetails() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-51",
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

func NewGetSIMOperatorName() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-52",
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

func NewQueryDatabaseOfSMSContacts() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-53",
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

// Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewPotentialPathTraversal() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-54",
			Name:        "Potential Path Traversal (file read)",
			Description: `A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read. This rule identifies potential path traversal vulnerabilities. Please consider use this example: "new File("resources/images/", FilenameUtils.getName(value_received_in_params))". For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.`,
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

func NewJakartaAndPotentialPathTraversal() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-55",
			Name:        "Potential Path Traversal (file read)",
			Description: `A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read. This rule identifies potential path traversal vulnerabilities. Please consider use this example: "new File("resources/images/", FilenameUtils.getName(value_received_in_params))". For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.`,
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

func NewPotentialPathTraversalUsingScalaAPI() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-56",
			Name:        "Potential Path Traversal Using scala API (file read)",
			Description: `A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read. Please consider use this example: "val result = Source.fromFile("public/lists/" + FilenameUtils.getName(value_received_in_params)).getLines().mkString". For more information checkout the CWE-22 (https://cwe.mitre.org/data/definitions/22.html) advisory.`,
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`([^org\.apache\.commons\.io\.FilenameUtils])(Source\.fromFile\(.*\).getLines\(\)\.mkString)`),
		},
	}
}

func NewSMTPHeaderInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-57",
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

func NewInsecureSMTPSSLConnection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-58",
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

func NewPersistentCookieUsage() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-59",
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

func NewAnonymousLDAPBind() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-60",
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

func NewLDAPEntryPoisoning() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-61",
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

func NewIgnoringXMLCommentsInSAML() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-62",
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

func NewInformationExposureThroughAnErrorMessage() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-63",
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

func NewHTTPParameterPollution() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-64",
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

func NewAWSQueryInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-65",
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

func NewPotentialTemplateInjectionPebble() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-66",
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

func NewPotentialTemplateInjectionFreemarker() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-67",
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

func NewRequestDispatcherFileDisclosure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-68",
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

func NewSpringFileDisclosure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-69",
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

func NewPotentialCodeScriptInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-70",
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

func NewStrutsFileDisclosure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-71",
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

func NewUnsafeJacksonDeserializationConfiguration() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-72",
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

func NewObjectDeserializationUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-73",
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

func NewPotentialCodeScriptInjectionWithSpringExpression() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-74",
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

func NewCookieWithoutTheHttpOnlyFlag() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-75",
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

func NewWebViewWithGeolocationActivated() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-76",
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

func NewUseOfESAPIEncryptor() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-77",
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

func NewStaticIV() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-78",
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

func NewXMLDecoderUsage() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-79",
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

func NewPotentialXSSInServlet() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-80",
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

func NewEscapingOfSpecialXMLCharactersIsDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-81",
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

func NewDynamicVariableInSpringExpression() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-82",
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

func NewRSAUsageWithShortKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-83",
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

func NewBlowfishUsageWithShortKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-84",
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

func NewClassesShouldNotBeLoadedDynamically() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-85",
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

// Deprecated: Repeated vulnerability, same as HS-JAVA-12
//
//func NewHostnameVerifierVerifyShouldNotAlwaysReturnTrue() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-86",
//			Name:        "HostnameVerifier.verify should not always return true",
//			Description: "To prevent URL spoofing, HostnameVerifier.verify() methods should do more than simply return true. Doing so may get you quickly past an exception, but that comes at the cost of opening a security hole in your application. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory",
//			Severity:    severities.High.ToString(),
//			Confidence:  confidence.Low.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`@Override`),
//			regexp.MustCompile(`public boolean verify\(String requestedHost, SSLSession remoteServerSession\)`),
//			regexp.MustCompile(`return true`),
//		},
//	}
//}

func NewXPathExpressionsShouldNotBeVulnerableToInjectionAttacks() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-87",
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

func NewExceptionsShouldNotBeThrownFromServletMethods() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-88",
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

func NewFunctionCallsShouldNotBeVulnerableToPathInjectionAttacks() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:   "HS-JAVA-89",
			Name: "I/O function calls should not be vulnerable to path injection attacks",
			Description: `User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Constructing file system paths directly from tainted data could enable an attacker to inject specially crafted values, such as '../', that change the initial path and, when accessed, resolve to a path on the filesystem where the user should normally not have access.

A successful attack might give an attacker the ability to read, modify, or delete sensitive information from the file system and sometimes even execute arbitrary operating system commands. This is often referred to as a "path traversal" or "directory traversal" attack. For more information checkout the CWE-99 (https://cwe.mitre.org/data/definitions/99.html) advisory and checkout the (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)`,
			Severity:   severities.Medium.ToString(),
			Confidence: confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.forceDelete\(`),
			regexp.MustCompile(`new\sFile`),
			regexp.MustCompile(`new\sFile\(([^d]|d[^i]|di[^r]|dir[^e]|dire[^c]|direc[^t]|direct[^o]|directo[^r]|director[^y]|directory[^C]|directoryC[^o]|directoryCo[^n]|directoryCon[^t]|directoryCont[^a]|directoryConta[^i]|directoryContai[^n]|directoryContain[^s])*\.forceDelete`),
		},
	}
}

func NewActiveMQConnectionFactoryVulnerableToMaliciousCodeDeserialization() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-90",
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

func NewHTTPResponseHeadersShouldNotBeVulnerableToInjectionAttacks() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-91",
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

func NewOpenSAML2ShouldBeConfiguredToPreventAuthenticationBypass() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-92",
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

// Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewHttpServletRequestGetRequestedSessionIdShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-93",
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

func NewJakartaAndHttpServletRequestGetRequestedSessionIdShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-94",
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

func NewLDAPAuthenticatedAnalyzeYourCode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-95",
			Name:        "LDAP authenticated Analyze your code",
			Description: `An LDAP client authenticates to an LDAP server with a "bind request" which provides, among other, a simple authentication method. Anonymous binds and unauthenticated binds allow access to information in the LDAP directory without providing a password, their use is therefore strongly discouraged. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory and checkout (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication).`,
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

// Deprecated: the javax package is deprecated in the Jakarta EE newest version. We'll use jakarta package.
func NewWebApplicationsShouldHotHaveAMainMethod() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-96",
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

func NewJakartaAndWebApplicationsShouldHotHaveAMainMethod() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-97",
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

func NewSecureRandomSeedsShouldNotBePredictable() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-98",
			Name:        "SecureRandom seeds should not be predictable",
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

func NewFileIsWorldReadable() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-99",
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

func NewFileIsWorldWritable() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-100",
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

func NewNoWriteExternalContent() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-101",
			Name:        "No Write External Content",
			Description: "App can read/write to External Storage. Any App can read data written to External Storage. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.getExternalStorage\(`),
			regexp.MustCompile(`.getExternalFilesDir\(`),
		},
	}
}

func NewNoUseIVsWeak() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-102",
			Name:        "No use IVs weak",
			Description: `The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or "0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the resulting ciphertext much more predictable and susceptible to a dictionary attack. For more information checkout the CWE-329 (https://cwe.mitre.org/data/definitions/329.html) advisory.`,
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

func NewRootDetectionCapabilities() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-103",
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

func NewJARURLConnection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-104",
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

// Deprecated: Repeated vulnerability, same as HS-JAVA-23
//
//func NewSetOrReadClipboardData() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:          "HS-JAVA-105",
//			Name:        "Set or Read Clipboard data",
//			Description: "Set or Read Clipboard data",
//			Severity:    severities.Low.ToString(),
//			Confidence:  confidence.Low.ToString(),
//		},
//		Type: text.OrMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`content.ClipboardManager`),
//			regexp.MustCompile(`CLIPBOARD_SERVICE`),
//			regexp.MustCompile(`ClipboardManager`),
//		},
//	}
//}

// Deprecated: Repeated vulnerability, same as HS-JAVA-111
//
//func NewMessageDigest() *text.Rule {
//	return &text.Rule{
//		Metadata: engine.Metadata{
//			ID:   "HS-JAVA-106",
//			Name: "Message Digest",
//			Description: `The MD5 algorithm and its successor, SHA-1, are no longer considered secure, because it is too easy to create hash collisions with them. That is, it takes too little computational effort to come up with a different input that produces the same MD5 or SHA-1 hash, and using the new, same-hash value gives an attacker the same access as if he had the originally-hashed value. This applies as well to the other Message-Digest algorithms: MD2, MD4, MD6, HAVAL-128, HMAC-MD5, DSA (which uses SHA-1), RIPEMD, RIPEMD-128, RIPEMD-160, HMACRIPEMD160.`,
//			Severity:   severities.Medium.ToString(),
//			Confidence: confidence.Low.ToString(),
//		},
//		Type: text.AndMatch,
//		Expressions: []*regexp.Regexp{
//			regexp.MustCompile(`java.security.MessageDigest`),
//			regexp.MustCompile(`MessageDigestSpi`),
//			regexp.MustCompile(`MessageDigest`),
//		},
//	}
//}

func NewOverlyPermissiveFilePermission() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-107",
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

func NewCipherGetInstanceInsecure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-108",
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

func NewHiddenElements() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-109",
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

func NewWeakCypherBlockMode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-110",
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

func NewWeakHash() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-111",
			Name:        "Weak Cryptographic Hash Function used",
			Description: "Using a weak CHF pose a threat to your application security since it can be vulnerable to a number of attacks that could lead to data leaking, improper access of features and resources of your infrastructure and even rogue sessions. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getInstance("md4")|getInstance("rc2")|getInstance("rc4")|getInstance("RC4")|getInstance("RC2")|getInstance("MD4")`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*MD5["|']*\)|MessageDigest\.getInstance\(["|']*md5["|']*\)|DigestUtils\.md5\(|DigestUtils\.getMd5Digest\(`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*SHA-?1["|']*\)|MessageDigest\.getInstance\(["|']*sha-?1["|']*\)|DigestUtils\.sha\(|DigestUtils\.getSha1Digest\(`),
			regexp.MustCompile(`getInstance\(["|']rc4["|']\)|getInstance\(["|']RC4["|']\)|getInstance\(["|']RC2["|']\)|getInstance\(["|']rc2["|']\)`),
			regexp.MustCompile(`getInstance\(["|']md4["|']\)|getInstance\(["|']MD4["|']\)|getInstance\(["|']md2["|']\)|getInstance\(["|']MD2["|']\)`),
		},
	}
}

func NewPossibleFileWithVulnerabilityWhenOpen() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-112",
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

func NewSensitiveInformationNotEncrypted() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-113",
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

func NewInsecureRandomNumberGenerator() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-114",
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

func NewNoDefaultHash() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-115",
			Name:        "No Default  Hash",
			Description: `This App uses  Hash Code. It"s a weak hash function and should never be used in Secure Crypto Implementation. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.`,
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.hashCode()`),
		},
	}
}

func NewLayoutParamsFlagSecure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-116",
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

func NewNoUseSQLCipher() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-117",
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

func NewPreventTapJackingAttacks() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-118",
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

func NewPreventWriteSensitiveInformationInTmpFile() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-119",
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

func NewGetWindowFlagSecure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-120",
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

func NewLoadingNativeCode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-121",
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

func NewDynamicClassAndDexloading() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-122",
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

func NewCryptoImport() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-123",
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

func NewStartingService() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-124",
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

func NewSendingBroadcast() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-125",
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

func NewLocalFileOperations() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-126",
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

func NewInterProcessCommunication() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-127",
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

func NewDefaultHttpClient() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-128",
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

func NewWeakSSLContext() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-129",
			Name:        "Weak SSLContext",
			Description: `Upgrade your implementation to the following, and configure https.protocols JVM option to include TLSv1.2:. Use SSLContext.getInstance("TLS"). For more information checkout (https://blogs.oracle.com/java-platform-group/diagnosing-tls,-ssl,-and-https)`,
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SSLContext\.getInstance\(["|']SSL.*["|']\)`),
		},
	}
}

func NewHostnameVerifierThatAcceptAnySignedCertificates() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-130",
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

func NewURLRewritingMethod() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-131",
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

func NewDisablingHTMLEscaping() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-132",
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

func NewOverlyPermissiveCORSPolicy() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-133",
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

func NewSQLInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-134",
			Name:        "SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createQuery\(.?((.*|\n)*)?)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
		},
	}
}

func NewSQLInjectionWithTurbine() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-135",
			Name:        "SQL Injection With Turbine",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Turbine API provide a DSL to build query with  code. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(BasePeer\.)?(executeQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
		},
	}
}

func NewSQLInjectionWithHibernate() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-136",
			Name:        "SQL Injection With Hibernate",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, Hibernate Criteria can be used. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory and checkout the CWE-564 (https://cwe.mitre.org/data/definitions/564.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(openSession\(\))?(\.)(createQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
		},
	}
}

func NewSQLInjectionWithJDO() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-137",
			Name:        "SQL Injection With JDO",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(getPM\(\))?(\.)(newQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
		},
	}
}

func NewSQLInjectionWithJPA() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-138",
			Name:        "SQL Injection With JPA",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(getEM\(\))?(\.)(createQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
		},
	}
}

func NewSQLInjectionWithSpringJDBC() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-139",
			Name:        "SQL Injection Spring JDBC",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(JdbcTemplate\(\))?(\.)(queryForObject\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
		},
	}
}

func NewSQLInjectionWithJDBC() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-140",
			Name:        "SQL Injection JDBC",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createStatement\(\))?(\.)(executeQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
		},
	}
}

func NewLDAPInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-141",
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

func NewPotentialExternalControl() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-142",
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

func NewBadHexadecimalConcatenation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-143",
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

func NewNullCipherInsecure() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-144",
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

func NewUnsafeHashEquals() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-145",
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

func NewUnvalidatedRedirect() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-146",
			Name:        "Unvalidated Redirect",
			Description: "Unvalidated redirects occur when an application redirects a user to a destination URL specified by a user supplied parameter that is not validated. Such vulnerabilities can be used to facilitate phishing attacks. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.sendRedirect\(.*\.getParameter\(.*\)\)`),
		},
	}
}

func NewRequestMappingMethodsNotPublic() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-147",
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

func NewLDAPDeserializationNotDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-148",
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

func NewDatabasesPasswordNotProtected() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-149",
			Name:        "Databases should be password-protected",
			Description: "Databases should always be password protected. The use of a database connection with an empty password is a clear indication of a database that is not protected. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.getConnection\("jdbc:derby:memory:.*;create=true".*, ""\);`),
		},
	}
}

func NewVulnerableRemoteCodeInjectionApacheLog4j() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVA-150",
			Name:        "Remote code injection Apache Log4j",
			Description: "Log4j versions prior to 2.17.1 are subject to a remote code execution vulnerability via the ldap JNDI parser, uncontrolled recursion from self-referential lookups and some other vulnerabilities. For more information checkout the CVE-2021-44228 (https://nvd.nist.gov/vuln/detail/CVE-2021-44228), CVE-2021-45046 (https://nvd.nist.gov/vuln/detail/CVE-2021-45046), CVE-2021-45105 (https://nvd.nist.gov/vuln/detail/CVE-2021-45105) and CVE-2021-44832 (https://nvd.nist.gov/vuln/detail/CVE-2021-44832) advisories.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`compile.*group:.*org\.apache\.logging\.log4j.*name:.*log4j.*version:.*(('|")(2\.([0-9]\.|1[0-6]|17\.0))|([0-1]\.[0-9]+\.[0-9]+)).*('|")`),
			regexp.MustCompile(`compile.*log4j.*(:((2\.([0-9]\.|1[0-6]|17\.0))|([0-1]\.[0-9]+\.[0-9]+))).*('|")`),
			regexp.MustCompile(`<groupId>(.*|\n).*org\.apache\.logging\.log4j.*(.*|\n).*<artifactId>.*log4j.*</artifactId>(.*|\n)*(version>((2\.([0-9]\.|1[0-6]|17\.0))|([0-1]\.[0-9]+\.[0-9]+)))(.*|\n)*</version>`),
			regexp.MustCompile(`<dependency.*org.*org\.apache\.logging\.log4j.*name.*log4j.*rev.*(2\.([0-9]\.|1[0-6]|17\.0))|([0-1]\.[0-9]+\.[0-9]+).*/>`),
			regexp.MustCompile(`<(log4j2|log4j)\.version>.*(2\.([0-9]\.|1[0-6]|17\.0))|([0-1]\.[0-9]+\.[0-9]+).*</(log4j2|log4j)\.version>`),
		},
	}
}
