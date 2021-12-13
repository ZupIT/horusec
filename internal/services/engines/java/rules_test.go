// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package java

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-JAVA-1",
			Rule: NewXMLParsingVulnerableToXXE(),
			Src:  SampleVulnerableHSJAVA1,
			Findings: []engine.Finding{
				{
					CodeSample: `XMLReader reader = XMLReaderFactory.createXMLReader();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 21,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-2",
			Rule: NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
			Src:  SampleVulnerableHSJAVA2,
			Findings: []engine.Finding{
				{
					CodeSample: `XMLInputFactory factory = XMLInputFactory.newFactory();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 28,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-3",
			Rule: NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
			Src:  SampleVulnerableHSJAVA3,
			Findings: []engine.Finding{
				{
					CodeSample: `DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 23,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-4",
			Rule: NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
			Src:  SampleVulnerableHSJAVA4,
			Findings: []engine.Finding{
				{
					CodeSample: `SAXParser parser = SAXParserFactory.newInstance().newSAXParser();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 21,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-5",
			Rule: NewXMLParsingVulnerableToXXEWithTransformerFactory(),
			Src:  SampleVulnerableHSJAVA5,
			Findings: []engine.Finding{
				{
					CodeSample: `Transformer transformer = TransformerFactory.newInstance().newTransformer();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 28,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-7",
			Rule: NewXMLParsingVulnerableToXXEWithDom4j(),
			Src:  SampleVulnerableHSJAVA7,
			Findings: []engine.Finding{
				{
					CodeSample: `SAXReader xmlReader = new SAXReader();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 24,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-8",
			Rule: NewXMLParsingVulnerableToXXEWithJdom2(),
			Src:  SampleVulnerableHSJAVA8,
			Findings: []engine.Finding{
				{
					CodeSample: "SAXBuilder builder = new SAXBuilder();",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 23,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-9",
			Rule: NewInsecureImplementationOfSSL(),
			Src:  SampleVulnerableHSJAVA9,
			Findings: []engine.Finding{
				{
					CodeSample: "sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);",
					SourceLocation: engine.Location{
						Line:   11,
						Column: 43,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-10",
			Rule: NewMessageDigestIsCustom(),
			Src:  SampleVulnerableHSJAVA10,
			Findings: []engine.Finding{
				{
					CodeSample: "MyProprietaryMessageDigest extends MessageDigest {",
					SourceLocation: engine.Location{
						Line:   2,
						Column: 27,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-11",
			Rule: NewTrustManagerThatAcceptAnyCertificatesClient(),
			Src:  SampleVulnerableHSJAVA11,
			Findings: []engine.Finding{
				{
					CodeSample: "class TrustAllManager implements X509TrustManager {",
					SourceLocation: engine.Location{
						Line:   2,
						Column: 22,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-12",
			Rule: NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections(),
			Src:  SampleVulnerableHSJAVA12,
			Findings: []engine.Finding{
				{
					CodeSample: "public boolean verify(String requestedHost, SSLSession remoteServerSession) {",
					SourceLocation: engine.Location{
						Line:   8,
						Column: 19,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-13",
			Rule: NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail(),
			Src:  SampleVulnerableHSJAVA13,
			Findings: []engine.Finding{
				{
					CodeSample: "Email email = new SimpleEmail();",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 16,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-14",
			Rule: NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail(),
			Src:  SampleVulnerableHSJAVA14,
			Findings: []engine.Finding{
				{
					CodeSample: "props.put(\"mail.smtp.socketFactory.class\", \"javax.net.ssl.SSLSocketFactory\");",
					SourceLocation: engine.Location{
						Line:   7,
						Column: 8,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-18",
			Rule: NewWebViewLoadFilesFromExternalStorage(),
			Src:  SampleVulnerableHSJAVA18,
			Findings: []engine.Finding{
				{
					CodeSample: "WebView.loadUrl(\"file://\"+Environment.getExternalStorageDirectory().getAbsolutePath()+\"dangerZone.html\");",
					SourceLocation: engine.Location{
						Line:   6,
						Column: 9,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-19",
			Rule: NewInsecureWebViewImplementation(),
			Src:  SampleVulnerableHSJAVA19,
			Findings: []engine.Finding{
				{
					CodeSample: "webSettings.setJavaScriptEnabled(true);",
					SourceLocation: engine.Location{
						Line:   16,
						Column: 14,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-22",
			Rule: NewNoUseWebviewDebuggingEnable(),
			Src:  SampleVulnerableHSJAVA22,
			Findings: []engine.Finding{
				{
					CodeSample: "this.setWebContentsDebuggingEnabled(true);",
					SourceLocation: engine.Location{
						Line:   7,
						Column: 7,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-23",
			Rule: NewNoListenToClipboard(),
			Src:  SampleVulnerableHSJAVA23,
			Findings: []engine.Finding{
				{
					CodeSample: "private ClipboardManager.OnPrimaryClipChangedListener listener = new ClipboardManager.OnPrimaryClipChangedListener() {",
					SourceLocation: engine.Location{
						Line:   18,
						Column: 29,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-24",
			Rule: NewNoCopyContentToClipboard(),
			Src:  SampleVulnerableHSJAVA24,
			Findings: []engine.Finding{
				{
					CodeSample: "clipboardManager.setPrimaryClip(clip);",
					SourceLocation: engine.Location{
						Line:   12,
						Column: 29,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-25",
			Rule: NewNoUseWebviewIgnoringSSL(),
			Src:  SampleVulnerableHSJAVA25,
			Findings: []engine.Finding{
				{
					CodeSample: "public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 15,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-26",
			Rule: NewSQLInjectionWithSqlUtil(),
			Src:  SampleVulnerableHSJAVA26,
			Findings: []engine.Finding{
				{
					CodeSample: "SqlUtil.execQuery(\"select * from UserEntity where id = \" + parameterInput);",
					SourceLocation: engine.Location{
						Line:   3,
						Column: 4,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-28",
			Rule: NewNoUseSSLPinningLib(),
			Src:  SampleVulnerableHSJAVA28,
			Findings: []engine.Finding{
				{
					CodeSample: "package org.thoughtcrime.ssl.pinning;",
					SourceLocation: engine.Location{
						Line:   2,
						Column: 8,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  SampleVulnerableHSJAVA111,
			Findings: []engine.Finding{
				{
					CodeSample: "MessageDigest md5Digest = MessageDigest.getInstance(\"MD5\");",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 28,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  Sample2VulnerableHSJAVA111,
			Findings: []engine.Finding{
				{
					CodeSample: "byte[] hashValue = DigestUtils.getMd5Digest().digest(password.getBytes());",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 21,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  Sample3VulnerableHSJAVA111,
			Findings: []engine.Finding{
				{
					CodeSample: "MessageDigest sha1Digest = MessageDigest.getInstance(\"SHA1\");",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 29,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  Sample4VulnerableHSJAVA111,
			Findings: []engine.Finding{
				{
					CodeSample: "byte[] hashValue = DigestUtils.getSha1Digest().digest(password.getBytes());",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 21,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-134",
			Rule: NewSQLInjection(),
			Src:  SampleVulnerableHSJAVA134,
			Findings: []engine.Finding{
				{
					CodeSample: "var pstmt = con.prepareStatement(\"select * from mytable where field01 = '\" + field01 + \"'\");",
					SourceLocation: engine.Location{
						Line:   14,
						Column: 50,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-144",
			Rule: NewNullCipherInsecure(),
			Src:  SampleVulnerableHSJAVA144,
			Findings: []engine.Finding{
				{
					CodeSample: "Cipher doNothingCihper = new NullCipher();",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 31,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-145",
			Rule: NewUnsafeHashEquals(),
			Src:  SampleVulnerableHSJAVA145,
			Findings: []engine.Finding{
				{
					CodeSample: "if(userInput.equals(actualHash)) {",
					SourceLocation: engine.Location{
						Line:   6,
						Column: 14,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-146",
			Rule: NewUnvalidatedRedirect(),
			Src:  SampleVulnerableHSJAVA146,
			Findings: []engine.Finding{
				{
					CodeSample: "resp.sendRedirect(req.getParameter(\"url\"));",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 7,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-147",
			Rule: NewRequestMappingMethodsNotPublic(),
			Src:  SampleVulnerableHSJAVA147,
			Findings: []engine.Finding{
				{
					CodeSample: "@RequestMapping(\"/test\")",
					SourceLocation: engine.Location{
						Line:   3,
						Column: 5,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-148",
			Rule: NewLDAPDeserializationNotDisabled(),
			Src:  SampleVulnerableHSJAVA148,
			Findings: []engine.Finding{
				{
					CodeSample: "ctx.search(query, filter,new SearchControls(scope, countLimit, timeLimit, attributes,true, deref));",
					SourceLocation: engine.Location{
						Line:   6,
						Column: 31,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-149",
			Rule: NewDatabasesPasswordNotProtected(),
			Src:  SampleVulnerableHSJAVA149,
			Findings: []engine.Finding{
				{
					CodeSample: "Connection conn = DriverManager.getConnection(\"jdbc:derby:memory:myDB;create=true\", \"login\", \"\");",
					SourceLocation: engine.Location{
						Line:   4,
						Column: 33,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  SampleMavenVulnerableHSJAVA150,
			Findings: []engine.Finding{
				{
					CodeSample: "<groupId>org.apache.logging.log4j</groupId>",
					SourceLocation: engine.Location{
						Line:   11,
						Column: 12,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample2GradleVulnerableHSJAVA150,
			Findings: []engine.Finding{
				{
					CodeSample: "compile group: 'org.apache.logging.log4j', name: 'log4j-api', version: '2.11.0'",
					SourceLocation: engine.Location{
						Line:   16,
						Column: 4,
					},
				},
				{
					CodeSample: "compile group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.11.0'",
					SourceLocation: engine.Location{
						Line:   17,
						Column: 4,
					},
				},
				{
					CodeSample: "compile group: 'org.apache.logging.log4j', name: 'log4j-slf4j-impl', version: '2.11.0'",
					SourceLocation: engine.Location{
						Line:   18,
						Column: 4,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample3GradleVulnerableHSJAVA150,
			Findings: []engine.Finding{
				{
					CodeSample: "compile 'org.slf4j:slf4j-log4j12:1.7.26'",
					SourceLocation: engine.Location{
						Line:   23,
						Column: 4,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample4IvyVulnerableHSJAVA150,
			Findings: []engine.Finding{
				{
					CodeSample: "<dependency org=\"org.apache.logging.log4j\" name=\"log4j-api\" rev=\"2.11.0\" />",
					SourceLocation: engine.Location{
						Line:   15,
						Column: 4,
					},
				},
				{
					CodeSample: "<dependency org=\"org.apache.logging.log4j\" name=\"log4j-core\" rev=\"2.14.1\" />",
					SourceLocation: engine.Location{
						Line:   16,
						Column: 4,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample5MavenVulnerableHSJAVA150,
			Findings: []engine.Finding{
				{
					CodeSample: "<log4j2.version>2.8.2</log4j2.version>",
					SourceLocation: engine.Location{
						Line:   16,
						Column: 8,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-JAVA-1",
			Rule: NewXMLParsingVulnerableToXXE(),
			Src:  SampleSafeHSJAVA1,
		},
		{
			Name: "HS-JAVA-1",
			Rule: NewXMLParsingVulnerableToXXE(),
			Src:  Sample2SafeHSJAVA1,
		},
		{
			Name: "HS-JAVA-2",
			Rule: NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
			Src:  SampleSafeHSJAVA2,
		},
		{
			Name: "HS-JAVA-2",
			Rule: NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
			Src:  Sample2SafeHSJAVA2,
		},
		{
			Name: "HS-JAVA-3",
			Rule: NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
			Src:  SampleSafeHSJAVA3,
		},
		{
			Name: "HS-JAVA-3",
			Rule: NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
			Src:  Sample2SafeHSJAVA3,
		},
		{
			Name: "HS-JAVA-4",
			Rule: NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
			Src:  SampleSafeHSJAVA4,
		},
		{
			Name: "HS-JAVA-4",
			Rule: NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
			Src:  Sample2SafeHSJAVA4,
		},
		{
			Name: "HS-JAVA-5",
			Rule: NewXMLParsingVulnerableToXXEWithTransformerFactory(),
			Src:  SampleSafeHSJAVA5,
		},
		{
			Name: "HS-JAVA-5",
			Rule: NewXMLParsingVulnerableToXXEWithTransformerFactory(),
			Src:  Sample2SafeHSJAVA5,
		},
		{
			Name: "HS-JAVA-7",
			Rule: NewXMLParsingVulnerableToXXEWithDom4j(),
			Src:  SampleSafeHSJAVA7,
		},
		{
			Name: "HS-JAVA-8",
			Rule: NewXMLParsingVulnerableToXXEWithJdom2(),
			Src:  SampleSafeHSJAVA8,
		},
		{
			Name: "HS-JAVA-9",
			Rule: NewInsecureImplementationOfSSL(),
			Src:  SampleSafeHSJAVA9,
		},
		{
			Name: "HS-JAVA-10",
			Rule: NewMessageDigestIsCustom(),
			Src:  SampleSafeHSJAVA10,
		},
		{
			Name: "HS-JAVA-11",
			Rule: NewTrustManagerThatAcceptAnyCertificatesClient(),
			Src:  SampleSafeHSJAVA11,
		},
		{
			Name: "HS-JAVA-12",
			Rule: NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections(),
			Src:  SampleSafeHSJAVA12,
		},
		{
			Name: "HS-JAVA-13",
			Rule: NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail(),
			Src:  SampleSafeHSJAVA13,
		},
		{
			Name: "HS-JAVA-14",
			Rule: NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail(),
			Src:  SampleSafeHSJAVA14,
		},
		{
			Name: "HS-JAVA-18",
			Rule: NewWebViewLoadFilesFromExternalStorage(),
			Src:  SampleSafeHSJAVA18,
		},
		{
			Name: "HS-JAVA-19",
			Rule: NewInsecureWebViewImplementation(),
			Src:  SampleSafeHSJAVA19,
		},
		{
			Name: "HS-JAVA-22",
			Rule: NewNoUseWebviewDebuggingEnable(),
			Src:  SampleSafeHSJAVA22,
		},
		{
			Name: "HS-JAVA-23",
			Rule: NewNoListenToClipboard(),
			Src:  SampleSafeHSJAVA23,
		},
		{
			Name: "HS-JAVA-24",
			Rule: NewNoCopyContentToClipboard(),
			Src:  SampleSafeHSJAVA24,
		},
		{
			Name: "HS-JAVA-25",
			Rule: NewNoUseWebviewIgnoringSSL(),
			Src:  SampleSafeHSJAVA25,
		},
		{
			Name: "HS-JAVA-26",
			Rule: NewSQLInjectionWithSqlUtil(),
			Src:  SampleSafeHSJAVA26,
		},
		{
			Name: "HS-JAVA-28",
			Rule: NewNoUseSSLPinningLib(),
			Src:  SampleSafeHSJAVA28,
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  SampleSafeHSJAVA111,
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  Sample2SafeHSJAVA111,
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  Sample3SafeHSJAVA111,
		},
		{
			Name: "HS-JAVA-111",
			Rule: NewWeakHash(),
			Src:  Sample4SafeHSJAVA111,
		},
		{
			Name: "HS-JAVA-134",
			Rule: NewSQLInjection(),
			Src:  SampleSafeHSJAVA134,
		},
		{
			Name: "HS-JAVA-145",
			Rule: NewUnsafeHashEquals(),
			Src:  SampleSafeHSJAVA145,
		},
		{
			Name: "HS-JAVA-146",
			Rule: NewUnvalidatedRedirect(),
			Src:  SampleSafeHSJAVA146,
		},
		{
			Name: "HS-JAVA-147",
			Rule: NewRequestMappingMethodsNotPublic(),
			Src:  SampleSafeHSJAVA147,
		},
		{
			Name: "HS-JAVA-148",
			Rule: NewLDAPDeserializationNotDisabled(),
			Src:  SampleSafeHSJAVA148,
		},
		{
			Name: "HS-JAVA-149",
			Rule: NewDatabasesPasswordNotProtected(),
			Src:  SampleSafeHSJAVA149,
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  SampleMavenSafeHSJAVA150,
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample2GradleSafeHSJAVA150,
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample3GradleSafeHSJAVA150,
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample4IvySafeHSJAVA150,
		},
		{
			Name: "HS-JAVA-150",
			Rule: NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:  Sample5MavenSafeHSJAVA150,
		},
	}
	testutil.TestSafeCode(t, testcases)
}
