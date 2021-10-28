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
	}
	testutil.TestSafeCode(t, testcases)
}
