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
	"fmt"
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-JAVA-1",
			Rule:     NewXMLParsingVulnerableToXXE(),
			Src:      SampleVulnerableHSJAVA1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-1", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `XMLReader reader = XMLReaderFactory.createXMLReader();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-1", ".test")),
						Line:     4,
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-2",
			Rule:     NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
			Src:      SampleVulnerableHSJAVA2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `XMLInputFactory factory = XMLInputFactory.newFactory();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-2", ".test")),
						Line:     4,
						Column:   28,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-3",
			Rule:     NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
			Src:      SampleVulnerableHSJAVA3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-3", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-3", ".test")),
						Line:     4,
						Column:   23,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-4",
			Rule:     NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
			Src:      SampleVulnerableHSJAVA4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-4", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `SAXParser parser = SAXParserFactory.newInstance().newSAXParser();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-4", ".test")),
						Line:     4,
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-5",
			Rule:     NewXMLParsingVulnerableToXXEWithTransformerFactory(),
			Src:      SampleVulnerableHSJAVA5,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-5", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `Transformer transformer = TransformerFactory.newInstance().newTransformer();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-5", ".test")),
						Line:     4,
						Column:   28,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-7",
			Rule:     NewXMLParsingVulnerableToXXEWithDom4j(),
			Src:      SampleVulnerableHSJAVA7,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-7", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `SAXReader xmlReader = new SAXReader();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-7", ".test")),
						Line:     4,
						Column:   24,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-8",
			Rule:     NewXMLParsingVulnerableToXXEWithJdom2(),
			Src:      SampleVulnerableHSJAVA8,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-8", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "SAXBuilder builder = new SAXBuilder();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-8", ".test")),
						Line:     4,
						Column:   23,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-9",
			Rule:     NewInsecureImplementationOfSSL(),
			Src:      SampleVulnerableHSJAVA9,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-9", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-9", ".test")),
						Line:     11,
						Column:   43,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-10",
			Rule:     NewMessageDigestIsCustom(),
			Src:      SampleVulnerableHSJAVA10,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-10", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "MyProprietaryMessageDigest extends MessageDigest {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-10", ".test")),
						Line:     2,
						Column:   27,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-11",
			Rule:     NewTrustManagerThatAcceptAnyCertificatesClient(),
			Src:      SampleVulnerableHSJAVA11,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-11", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "class TrustAllManager implements X509TrustManager {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-11", ".test")),
						Line:     2,
						Column:   22,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-12",
			Rule:     NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections(),
			Src:      SampleVulnerableHSJAVA12,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-12", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "public boolean verify(String requestedHost, SSLSession remoteServerSession) {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-12", ".test")),
						Line:     8,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-13",
			Rule:     NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail(),
			Src:      SampleVulnerableHSJAVA13,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-13", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "Email email = new SimpleEmail();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-13", ".test")),
						Line:     4,
						Column:   16,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-14",
			Rule:     NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail(),
			Src:      SampleVulnerableHSJAVA14,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-14", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "props.put(\"mail.smtp.socketFactory.class\", \"javax.net.ssl.SSLSocketFactory\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-14", ".test")),
						Line:     7,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-18",
			Rule:     NewWebViewLoadFilesFromExternalStorage(),
			Src:      SampleVulnerableHSJAVA18,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-18", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "WebView.loadUrl(\"file://\"+Environment.getExternalStorageDirectory().getAbsolutePath()+\"dangerZone.html\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-18", ".test")),
						Line:     6,
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-19",
			Rule:     NewInsecureWebViewImplementation(),
			Src:      SampleVulnerableHSJAVA19,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-19", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "webSettings.setJavaScriptEnabled(true);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-19", ".test")),
						Line:     16,
						Column:   14,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-22",
			Rule:     NewNoUseWebviewDebuggingEnable(),
			Src:      SampleVulnerableHSJAVA22,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-22", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "this.setWebContentsDebuggingEnabled(true);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-22", ".test")),
						Line:     7,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-23",
			Rule:     NewNoListenToClipboard(),
			Src:      SampleVulnerableHSJAVA23,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-23", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "private ClipboardManager.OnPrimaryClipChangedListener listener = new ClipboardManager.OnPrimaryClipChangedListener() {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-23", ".test")),
						Line:     18,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-24",
			Rule:     NewNoCopyContentToClipboard(),
			Src:      SampleVulnerableHSJAVA24,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-24", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "clipboardManager.setPrimaryClip(clip);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-24", ".test")),
						Line:     12,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-25",
			Rule:     NewNoUseWebviewIgnoringSSL(),
			Src:      SampleVulnerableHSJAVA25,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-25", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-25", ".test")),
						Line:     4,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-26",
			Rule:     NewSQLInjectionWithSqlUtil(),
			Src:      SampleVulnerableHSJAVA26,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-26", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "SqlUtil.execQuery(\"select * from UserEntity where id = \" + parameterInput);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-26", ".test")),
						Line:     3,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-28",
			Rule:     NewNoUseSSLPinningLib(),
			Src:      SampleVulnerableHSJAVA28,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-28", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "package org.thoughtcrime.ssl.pinning;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-28", ".test")),
						Line:     2,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      SampleVulnerableHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "MessageDigest md5Digest = MessageDigest.getInstance(\"MD5\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111", ".test")),
						Line:     4,
						Column:   28,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      Sample2VulnerableHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111.2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "byte[] hashValue = DigestUtils.getMd5Digest().digest(password.getBytes());",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111.2", ".test")),
						Line:     4,
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      Sample3VulnerableHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111.3", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "MessageDigest sha1Digest = MessageDigest.getInstance(\"SHA1\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111.3", ".test")),
						Line:     4,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      Sample4VulnerableHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111.4", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "byte[] hashValue = DigestUtils.getSha1Digest().digest(password.getBytes());",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111.4", ".test")),
						Line:     4,
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-134",
			Rule:     NewSQLInjection(),
			Src:      SampleVulnerableHSJAVA134,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-134", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "var pstmt = con.prepareStatement(\"select * from mytable where field01 = '\" + field01 + \"'\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-134", ".test")),
						Line:     14,
						Column:   50,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-144",
			Rule:     NewNullCipherInsecure(),
			Src:      SampleVulnerableHSJAVA144,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-144", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "Cipher doNothingCihper = new NullCipher();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-144", ".test")),
						Line:     4,
						Column:   31,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-145",
			Rule:     NewUnsafeHashEquals(),
			Src:      SampleVulnerableHSJAVA145,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-145", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "if(userInput.equals(actualHash)) {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-145", ".test")),
						Line:     6,
						Column:   14,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-146",
			Rule:     NewUnvalidatedRedirect(),
			Src:      SampleVulnerableHSJAVA146,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-146", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "resp.sendRedirect(req.getParameter(\"url\"));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-146", ".test")),
						Line:     4,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-147",
			Rule:     NewRequestMappingMethodsNotPublic(),
			Src:      SampleVulnerableHSJAVA147,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-147", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "@RequestMapping(\"/test\")",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-147", ".test")),
						Line:     3,
						Column:   5,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-148",
			Rule:     NewLDAPDeserializationNotDisabled(),
			Src:      SampleVulnerableHSJAVA148,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-148", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "ctx.search(query, filter,new SearchControls(scope, countLimit, timeLimit, attributes,true, deref));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-148", ".test")),
						Line:     6,
						Column:   31,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-149",
			Rule:     NewDatabasesPasswordNotProtected(),
			Src:      SampleVulnerableHSJAVA149,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-149", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "Connection conn = DriverManager.getConnection(\"jdbc:derby:memory:myDB;create=true\", \"login\", \"\");",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-149", ".test")),
						Line:     4,
						Column:   33,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      SampleMavenVulnerableHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "<groupId>org.apache.logging.log4j</groupId>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
						Line:     11,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample2GradleVulnerableHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "compile group: 'org.apache.logging.log4j', name: 'log4j-api', version: '2.11.0'",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.2", ".test")),
						Line:     16,
						Column:   4,
					},
				},
				{
					CodeSample: "compile group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.11.0'",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.2", ".test")),
						Line:     17,
						Column:   4,
					},
				},
				{
					CodeSample: "compile group: 'org.apache.logging.log4j', name: 'log4j-slf4j-impl', version: '2.11.0'",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.2", ".test")),
						Line:     18,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample3GradleVulnerableHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.3", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "compile 'org.slf4j:slf4j-log4j12:1.7.26'",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.3", ".test")),
						Line:     23,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample4IvyVulnerableHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.4", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "<dependency org=\"org.apache.logging.log4j\" name=\"log4j-api\" rev=\"2.11.0\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.4", ".test")),
						Line:     15,
						Column:   4,
					},
				},
				{
					CodeSample: "<dependency org=\"org.apache.logging.log4j\" name=\"log4j-core\" rev=\"2.14.1\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.4", ".test")),
						Line:     16,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample5MavenVulnerableHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.5", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "<log4j2.version>2.8.2</log4j2.version>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150.5", ".test")),
						Line:     16,
						Column:   8,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-JAVA-1",
			Rule:     NewXMLParsingVulnerableToXXE(),
			Src:      SampleSafeHSJAVA1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-1", ".test")),
		},
		{
			Name:     "HS-JAVA-1",
			Rule:     NewXMLParsingVulnerableToXXE(),
			Src:      Sample2SafeHSJAVA1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-1", ".test")),
		},
		{
			Name:     "HS-JAVA-2",
			Rule:     NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
			Src:      SampleSafeHSJAVA2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-2", ".test")),
		},
		{
			Name:     "HS-JAVA-2",
			Rule:     NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
			Src:      Sample2SafeHSJAVA2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-2", ".test")),
		},
		{
			Name:     "HS-JAVA-3",
			Rule:     NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
			Src:      SampleSafeHSJAVA3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-3", ".test")),
		},
		{
			Name:     "HS-JAVA-3",
			Rule:     NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
			Src:      Sample2SafeHSJAVA3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-3", ".test")),
		},
		{
			Name:     "HS-JAVA-4",
			Rule:     NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
			Src:      SampleSafeHSJAVA4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-4", ".test")),
		},
		{
			Name:     "HS-JAVA-4",
			Rule:     NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
			Src:      Sample2SafeHSJAVA4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-4", ".test")),
		},
		{
			Name:     "HS-JAVA-5",
			Rule:     NewXMLParsingVulnerableToXXEWithTransformerFactory(),
			Src:      SampleSafeHSJAVA5,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-5", ".test")),
		},
		{
			Name:     "HS-JAVA-5",
			Rule:     NewXMLParsingVulnerableToXXEWithTransformerFactory(),
			Src:      Sample2SafeHSJAVA5,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-5", ".test")),
		},
		{
			Name:     "HS-JAVA-7",
			Rule:     NewXMLParsingVulnerableToXXEWithDom4j(),
			Src:      SampleSafeHSJAVA7,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-7", ".test")),
		},
		{
			Name:     "HS-JAVA-8",
			Rule:     NewXMLParsingVulnerableToXXEWithJdom2(),
			Src:      SampleSafeHSJAVA8,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-8", ".test")),
		},
		{
			Name:     "HS-JAVA-9",
			Rule:     NewInsecureImplementationOfSSL(),
			Src:      SampleSafeHSJAVA9,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-9", ".test")),
		},
		{
			Name:     "HS-JAVA-10",
			Rule:     NewMessageDigestIsCustom(),
			Src:      SampleSafeHSJAVA10,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-10", ".test")),
		},
		{
			Name:     "HS-JAVA-11",
			Rule:     NewTrustManagerThatAcceptAnyCertificatesClient(),
			Src:      SampleSafeHSJAVA11,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-11", ".test")),
		},
		{
			Name:     "HS-JAVA-12",
			Rule:     NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections(),
			Src:      SampleSafeHSJAVA12,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-12", ".test")),
		},
		{
			Name:     "HS-JAVA-13",
			Rule:     NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail(),
			Src:      SampleSafeHSJAVA13,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-13", ".test")),
		},
		{
			Name:     "HS-JAVA-14",
			Rule:     NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail(),
			Src:      SampleSafeHSJAVA14,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-14", ".test")),
		},
		{
			Name:     "HS-JAVA-18",
			Rule:     NewWebViewLoadFilesFromExternalStorage(),
			Src:      SampleSafeHSJAVA18,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-18", ".test")),
		},
		{
			Name:     "HS-JAVA-19",
			Rule:     NewInsecureWebViewImplementation(),
			Src:      SampleSafeHSJAVA19,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-19", ".test")),
		},
		{
			Name:     "HS-JAVA-22",
			Rule:     NewNoUseWebviewDebuggingEnable(),
			Src:      SampleSafeHSJAVA22,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-22", ".test")),
		},
		{
			Name:     "HS-JAVA-23",
			Rule:     NewNoListenToClipboard(),
			Src:      SampleSafeHSJAVA23,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-23", ".test")),
		},
		{
			Name:     "HS-JAVA-24",
			Rule:     NewNoCopyContentToClipboard(),
			Src:      SampleSafeHSJAVA24,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-24", ".test")),
		},
		{
			Name:     "HS-JAVA-25",
			Rule:     NewNoUseWebviewIgnoringSSL(),
			Src:      SampleSafeHSJAVA25,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-25", ".test")),
		},
		{
			Name:     "HS-JAVA-26",
			Rule:     NewSQLInjectionWithSqlUtil(),
			Src:      SampleSafeHSJAVA26,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-26", ".test")),
		},
		{
			Name:     "HS-JAVA-28",
			Rule:     NewNoUseSSLPinningLib(),
			Src:      SampleSafeHSJAVA28,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-28", ".test")),
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      SampleSafeHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111", ".test")),
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      Sample2SafeHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111", ".test")),
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      Sample3SafeHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111", ".test")),
		},
		{
			Name:     "HS-JAVA-111",
			Rule:     NewWeakHash(),
			Src:      Sample4SafeHSJAVA111,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-111", ".test")),
		},
		{
			Name:     "HS-JAVA-134",
			Rule:     NewSQLInjection(),
			Src:      SampleSafeHSJAVA134,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-134", ".test")),
		},
		{
			Name:     "HS-JAVA-145",
			Rule:     NewUnsafeHashEquals(),
			Src:      SampleSafeHSJAVA145,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-145", ".test")),
		},
		{
			Name:     "HS-JAVA-146",
			Rule:     NewUnvalidatedRedirect(),
			Src:      SampleSafeHSJAVA146,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-146", ".test")),
		},
		{
			Name:     "HS-JAVA-147",
			Rule:     NewRequestMappingMethodsNotPublic(),
			Src:      SampleSafeHSJAVA147,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-147", ".test")),
		},
		{
			Name:     "HS-JAVA-148",
			Rule:     NewLDAPDeserializationNotDisabled(),
			Src:      SampleSafeHSJAVA148,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-148", ".test")),
		},
		{
			Name:     "HS-JAVA-149",
			Rule:     NewDatabasesPasswordNotProtected(),
			Src:      SampleSafeHSJAVA149,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-149", ".test")),
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      SampleMavenSafeHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample2GradleSafeHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample3GradleSafeHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample4IvySafeHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
		},
		{
			Name:     "HS-JAVA-150",
			Rule:     NewVulnerableRemoteCodeInjectionApacheLog4j(),
			Src:      Sample5MavenSafeHSJAVA150,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVA-150", ".test")),
		},
	}
	testutil.TestSafeCode(t, testcases)
}
