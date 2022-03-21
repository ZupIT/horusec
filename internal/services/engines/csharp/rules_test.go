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

package csharp

import (
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-CSHARP-1",
			Rule:     NewCommandInjection(),
			Src:      SampleVulnerableHSCSHARP1,
			Filename: filepath.Join(tempDir, "HS-CSHARP-1.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var p = new Process();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-1.test"),
						Line:     2,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-2",
			Rule:     NewXPathInjection(),
			Src:      SampleVulnerableHSCSHARP2,
			Filename: filepath.Join(tempDir, "HS-CSHARP-2.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var doc = new XmlDocument {XmlResolver = null};",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-2.test"),
						Line:     2,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-3",
			Rule:     NewExternalEntityInjection(),
			Src:      SampleVulnerableHSCSHARP3,
			Filename: filepath.Join(tempDir, "HS-CSHARP-3.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "XmlReaderSettings settings = new XmlReaderSettings();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-3.test"),
						Line:     2,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-4",
			Rule:     NewPathTraversal(),
			Src:      SampleVulnerableHSCSHARP4,
			Filename: filepath.Join(tempDir, "HS-CSHARP-4.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "public ActionResult Download(string fileName)",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-4.test"),
						Line:     3,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-5",
			Rule:     NewSQLInjectionWebControls(),
			Src:      SampleVulnerableHSCSHARP5,
			Filename: filepath.Join(tempDir, "HS-CSHARP-5.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var cmd = \"SELECT * FROM Users WHERE username = '\" + input + \"' and role='user'\";",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-5.test"),
						Line:     2,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-6",
			Rule:     NewWeakCipherOrCBCOrECBMode(),
			Src:      SampleVulnerableHSCSHARP6,
			Filename: filepath.Join(tempDir, "HS-CSHARP-6.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "using (var aes = new AesManaged {",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-6.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-7",
			Rule:     NewFormsAuthenticationCookielessMode(),
			Src:      SampleVulnerableHSCSHARP7,
			Filename: filepath.Join(tempDir, "HS-CSHARP-7.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<forms path=\"/\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-7.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-8",
			Rule:     NewFormsAuthenticationCrossAppRedirects(),
			Src:      SampleVulnerableHSCSHARP8,
			Filename: filepath.Join(tempDir, "HS-CSHARP-8.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<authentication mode=\"Forms\">",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-8.test"),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-9",
			Rule:     NewFormsAuthenticationWeakCookieProtection(),
			Src:      SampleVulnerableHSCSHARP9,
			Filename: filepath.Join(tempDir, "HS-CSHARP-9.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<authentication mode=\"Forms\">",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-9.test"),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-10",
			Rule:     NewFormsAuthenticationWeakTimeout(),
			Src:      SampleVulnerableHSCSHARP10,
			Filename: filepath.Join(tempDir, "HS-CSHARP-10.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<authentication mode=\"Forms\">",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-10.test"),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-11",
			Rule:     NewHeaderCheckingDisabled(),
			Src:      SampleVulnerableHSCSHARP11,
			Filename: filepath.Join(tempDir, "HS-CSHARP-11.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<httpRuntime enableHeaderChecking=\"false\"/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-11.test"),
						Line:     2,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-12",
			Rule:     NewVersionHeaderEnabled(),
			Src:      SampleVulnerableHSCSHARP12,
			Filename: filepath.Join(tempDir, "HS-CSHARP-12.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<httpRuntime enableVersionHeader=\"true\"/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-12.test"),
						Line:     2,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-13",
			Rule:     NewEventValidationDisabled(),
			Src:      SampleVulnerableHSCSHARP13,
			Filename: filepath.Join(tempDir, "HS-CSHARP-13.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<pages enableEventValidation=\"false\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-13.test"),
						Line:     2,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-14",
			Rule:     NewWeakSessionTimeout(),
			Src:      SampleVulnerableHSCSHARP14,
			Filename: filepath.Join(tempDir, "HS-CSHARP-14.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<sessionState timeout=\"30\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-14.test"),
						Line:     2,
						Column:   14,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-15",
			Rule:     NewStateServerMode(),
			Src:      SampleVulnerableHSCSHARP15,
			Filename: filepath.Join(tempDir, "HS-CSHARP-15.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<sessionState mode=\"StateServer\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-15.test"),
						Line:     2,
						Column:   14,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-16",
			Rule:     NewJwtSignatureValidationDisabled(),
			Src:      SampleVulnerableHSCSHARP16,
			Filename: filepath.Join(tempDir, "HS-CSHARP-16.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-16.test"),
						Line:     2,
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-17",
			Rule:     NewInsecureHttpCookieTransport(),
			Src:      SampleVulnerableHSCSHARP17,
			Filename: filepath.Join(tempDir, "HS-CSHARP-17.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "Secure = false,",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-17.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-18",
			Rule:     NewHttpCookieAccessibleViaScript(),
			Src:      SampleVulnerableHSCSHARP18,
			Filename: filepath.Join(tempDir, "HS-CSHARP-18.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "HttpOnly = false,",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-18.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-19",
			Rule:     NewDirectoryListingEnabled(),
			Src:      SampleVulnerableHSCSHARP19,
			Filename: filepath.Join(tempDir, "HS-CSHARP-19.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<directoryBrowse enabled=\"true\"/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-19.test"),
						Line:     3,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-20",
			Rule:     NewLdapAuthenticationDisabled(),
			Src:      SampleVulnerableHSCSHARP20,
			Filename: filepath.Join(tempDir, "HS-CSHARP-20.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "entry.AuthenticationType = AuthenticationTypes.Anonymous;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-20.test"),
						Line:     3,
						Column:   27,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-21",
			Rule:     NewCertificateValidationDisabledAndMatch(),
			Src:      SampleVulnerableHSCSHARP21,
			Filename: filepath.Join(tempDir, "HS-CSHARP-21.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "handler.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-21.test"),
						Line:     4,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-22",
			Rule:     NewActionRequestValidationDisabled(),
			Src:      SampleVulnerableHSCSHARP22,
			Filename: filepath.Join(tempDir, "HS-CSHARP-22.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "[ValidateInput(false)]",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-22.test"),
						Line:     3,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-23",
			Rule:     NewXmlDocumentExternalEntityExpansion(),
			Src:      SampleVulnerableHSCSHARP23,
			Filename: filepath.Join(tempDir, "HS-CSHARP-23.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "xmlDoc.XmlResolver = resolver;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-23.test"),
						Line:     6,
						Column:   6,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-24",
			Rule:     NewLdapInjectionFilterAssignment(),
			Src:      SampleVulnerableHSCSHARP24,
			Filename: filepath.Join(tempDir, "HS-CSHARP-24.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "searcher.Filter = string.Format(\"(name={0})\", model.UserName);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-24.test"),
						Line:     5,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-25",
			Rule:     NewSqlInjectionDynamicNHibernateQuery(),
			Src:      SampleVulnerableHSCSHARP25,
			Filename: filepath.Join(tempDir, "HS-CSHARP-25.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "string q = \"SELECT * FROM Items WHERE ProductCode = '\" + model.ProductCode + \"'\";",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-25.test"),
						Line:     2,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-26",
			Rule:     NewLdapInjectionDirectorySearcher(),
			Src:      SampleVulnerableHSCSHARP26,
			Filename: filepath.Join(tempDir, "HS-CSHARP-26.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "DirectorySearcher searcher = new DirectorySearcher(entry, string.Format(\"(name={0})\", model.UserName);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-26.test"),
						Line:     3,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-27",
			Rule:     NewLdapInjectionPathAssignment(),
			Src:      SampleVulnerableHSCSHARP27,
			Filename: filepath.Join(tempDir, "HS-CSHARP-27.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "entry.Path = string.Format(\"LDAP://DC={0},DC=COM,CN=Users\", model.Domain);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-27.test"),
						Line:     3,
						Column:   5,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-28",
			Rule:     NewLDAPInjection(),
			Src:      SampleVulnerableHSCSHARP28,
			Filename: filepath.Join(tempDir, "HS-CSHARP-28.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "searcher.Filter = \"(cn=\" + input + \")\";",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-28.test"),
						Line:     3,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-29",
			Rule:     NewSQLInjectionLinq(),
			Src:      SampleVulnerableHSCSHARP29,
			Filename: filepath.Join(tempDir, "HS-CSHARP-29.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var cmd = \"SELECT * FROM Users WHERE username = '\" + input + \"' and role='user'\";",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-29.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-30",
			Rule:     NewInsecureDeserialization(),
			Src:      SampleVulnerableHSCSHARP30,
			Filename: filepath.Join(tempDir, "HS-CSHARP-30.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var mySerializer = new JavaScriptSerializer(new SimpleTypeResolver());",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-30.test"),
						Line:     4,
						Column:   23,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-31",
			Rule:     NewSQLInjectionEnterpriseLibraryData(),
			Src:      SampleVulnerableHSCSHARP31,
			Filename: filepath.Join(tempDir, "HS-CSHARP-31.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "DbCommand dbCommand = db.GetSqlStringCommand(\"select * from v_Comments WITH(NOLOCK)   where CommentsID=\" + CommentsID);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-31.test"),
						Line:     6,
						Column:   37,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-32",
			Rule:     NewCQLInjectionCassandra(),
			Src:      SampleVulnerableHSCSHARP32,
			Filename: filepath.Join(tempDir, "HS-CSHARP-32.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "PreparedStatement ps = session.prepare(\"SELECT * FROM users WHERE uname=\"+filter);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-32.test"),
						Line:     3,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-33",
			Rule:     NewPasswordComplexityDefault(),
			Src:      SampleVulnerableHSCSHARP33,
			Filename: filepath.Join(tempDir, "HS-CSHARP-33.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "manager.PasswordValidator = new PasswordValidator();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-33.test"),
						Line:     9,
						Column:   28,
					},
				},
				{
					CodeSample: "manager.PasswordValidator = new PasswordValidator",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-33.test"),
						Line:     2,
						Column:   28,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-34",
			Rule:     NewCookieWithoutSSLFlag(),
			Src:      SampleVulnerableHSCSHARP34,
			Filename: filepath.Join(tempDir, "HS-CSHARP-34.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<httpCookies requireSSL=\"false\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-34.test"),
						Line:     4,
						Column:   17,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-35",
			Rule:     NewCookieWithoutHttpOnlyFlag(),
			Src:      SampleVulnerableHSCSHARP35,
			Filename: filepath.Join(tempDir, "HS-CSHARP-35.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<httpCookies httpOnlyCookies=\"false\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-35.test"),
						Line:     4,
						Column:   17,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-36",
			Rule:     NewNoInputVariable(),
			Src:      SampleVulnerableHSCSHARP36,
			Filename: filepath.Join(tempDir, "HS-CSHARP-36.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "element.innerHTML = executableXss",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-36.test"),
						Line:     4,
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-37",
			Rule:     NewIdentityWeakPasswordComplexity(),
			Src:      SampleVulnerableHSCSHARP37,
			Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "RequiredLength = 6",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
						Line:     4,
						Column:   4,
					},
				},
				{
					CodeSample: "manager.PasswordValidator = new PasswordValidator",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
						Line:     2,
						Column:   28,
					},
				},
				{
					CodeSample: "manager.PasswordValidator = new PasswordValidator",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
						Line:     2,
						Column:   28,
					},
				},
				{
					CodeSample: "manager.PasswordValidator = new PasswordValidator",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
						Line:     2,
						Column:   28,
					},
				},
				{
					CodeSample: "manager.PasswordValidator = new PasswordValidator",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
						Line:     2,
						Column:   28,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-38",
			Rule:     NewNoLogSensitiveInformationInConsole(),
			Src:      SampleVulnerableHSCSHARP38,
			Filename: filepath.Join(tempDir, "HS-CSHARP-38.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "Console.WriteLine(\"The user logged is: \" + user);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-38.test"),
						Line:     4,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-39",
			Rule:     NewOutputCacheConflict(),
			Src:      SampleVulnerableHSCSHARP39,
			Filename: filepath.Join(tempDir, "HS-CSHARP-39.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "[Authorize]",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-39.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-40",
			Rule:     NewOpenRedirect(),
			Src:      SampleVulnerableHSCSHARP40,
			Filename: filepath.Join(tempDir, "HS-CSHARP-40.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "if (!String.IsNullOrEmpty(returnUrl))",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-40.test"),
						Line:     10,
						Column:   17,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-41",
			Rule:     NewRequestValidationDisabledAttribute(),
			Src:      SampleVulnerableHSCSHARP41,
			Filename: filepath.Join(tempDir, "HS-CSHARP-41.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "[ValidateInput(false)]",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-41.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-42",
			Rule:     NewSQLInjectionOLEDB(),
			Src:      SampleVulnerableHSCSHARP42,
			Filename: filepath.Join(tempDir, "HS-CSHARP-42.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "OleDbConnection oconnection = new OleDbConnection(ModGloVariable.RasmusConn);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-42.test"),
						Line:     3,
						Column:   50,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-43",
			Rule:     NewRequestValidationDisabledConfigurationFile(),
			Src:      SampleVulnerableHSCSHARP43,
			Filename: filepath.Join(tempDir, "HS-CSHARP-43.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<pages validateRequest=\"false\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-43.test"),
						Line:     4,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-44",
			Rule:     NewSQLInjectionMsSQLDataProvider(),
			Src:      SampleVulnerableHSCSHARP44,
			Filename: filepath.Join(tempDir, "HS-CSHARP-44.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "SqlCommand cmd = new SqlCommand(\"Select * from GridViewDynamicData where Field1= '\" + txtSearch.Text +\"'\", conn);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-44.test"),
						Line:     4,
						Column:   18,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-45",
			Rule:     NewRequestValidationIsEnabledOnlyForPages(),
			Src:      SampleVulnerableHSCSHARP45,
			Filename: filepath.Join(tempDir, "HS-CSHARP-45.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<httpRuntime [..] requestValidationMode=\"2.0\" [..]/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-45.test"),
						Line:     4,
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-46",
			Rule:     NewSQLInjectionEntityFramework(),
			Src:      SampleVulnerableHSCSHARP46,
			Filename: filepath.Join(tempDir, "HS-CSHARP-46.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "ctx.Database.ExecuteSqlCommand(",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-46.test"),
						Line:     3,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-47",
			Rule:     NewViewStateNotEncrypted(),
			Src:      SampleVulnerableHSCSHARP47,
			Filename: filepath.Join(tempDir, "HS-CSHARP-47.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<pages [..] viewStateEncryptionMode=\"Auto\" [..]/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-47.test"),
						Line:     4,
						Column:   15,
					},
				},
				{
					CodeSample: "<pages [..] viewStateEncryptionMode=\"Never\" [..]/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-47.test"),
						Line:     13,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-48",
			Rule:     NewSQLInjectionNhibernate(),
			Src:      SampleVulnerableHSCSHARP48,
			Filename: filepath.Join(tempDir, "HS-CSHARP-48.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var query = session.CreateSqlQuery(q);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-48.test"),
						Line:     8,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-49",
			Rule:     NewViewStateMacDisabled(),
			Src:      SampleVulnerableHSCSHARP49,
			Filename: filepath.Join(tempDir, "HS-CSHARP-49.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<pages enableViewStateMac=\"false\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-49.test"),
						Line:     4,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-50",
			Rule:     NewSQLInjectionNpgsql(),
			Src:      SampleVulnerableHSCSHARP50,
			Filename: filepath.Join(tempDir, "HS-CSHARP-50.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "using (var cmd = new NpgsqlCommand(",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-50.test"),
						Line:     14,
						Column:   41,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-51",
			Rule:     NewCertificateValidationDisabled(),
			Src:      SampleVulnerableHSCSHARP51,
			Filename: filepath.Join(tempDir, "HS-CSHARP-51.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "handler.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-51.test"),
						Line:     4,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-52",
			Rule:     NewWeakCipherAlgorithm(),
			Src:      SampleVulnerableHSCSHARP52,
			Filename: filepath.Join(tempDir, "HS-CSHARP-52.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "DES DESalg = DES.Create();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-52.test"),
						Line:     2,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-53",
			Rule:     NewNoUseHtmlRaw(),
			Src:      SampleVulnerableHSCSHARP53,
			Filename: filepath.Join(tempDir, "HS-CSHARP-53.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "@Html.Raw(string.Format(\"Welcome <span class=\\\"bold\\\">{0}</span>!\", Model.UserName))",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-53.test"),
						Line:     3,
						Column:   5,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-54",
			Rule:     NewNoLogSensitiveInformation(),
			Src:      SampleVulnerableHSCSHARP54,
			Filename: filepath.Join(tempDir, "HS-CSHARP-54.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<customErrors mode=\"Off\" defaultRedirect=\"/home/error\"/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-54.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-55",
			Rule:     NewNoReturnStringConcatInController(),
			Src:      SampleVulnerableHSCSHARP55,
			Filename: filepath.Join(tempDir, "HS-CSHARP-55.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "public class AdminController : Controller",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-55.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-56",
			Rule:     NewSQLInjectionOdbcCommand(),
			Src:      SampleVulnerableHSCSHARP56,
			Filename: filepath.Join(tempDir, "HS-CSHARP-56.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "OdbcCommand cmd = new OdbcCommand(\"SELECT a.id, a.image FROM auspiciante a Where a.name = \" + name, con);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-56.test"),
						Line:     9,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-57",
			Rule:     NewWeakHashingFunctionMd5OrSha1(),
			Src:      SampleVulnerableHSCSHARP57,
			Filename: filepath.Join(tempDir, "HS-CSHARP-57.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "HashAlgorithm hash = new SHA1CryptoServiceProvider();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-57.test"),
						Line:     2,
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-58",
			Rule:     NewWeakHashingFunctionDESCrypto(),
			Src:      SampleVulnerableHSCSHARP58,
			Filename: filepath.Join(tempDir, "HS-CSHARP-58.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "SymmetricAlgorithm alg = new DESCryptoServiceProvider();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-58.test"),
						Line:     7,
						Column:   29,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-59",
			Rule:     NewNoUseCipherMode(),
			Src:      SampleVulnerableHSCSHARP59,
			Filename: filepath.Join(tempDir, "HS-CSHARP-59.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "alg.Mode = CipherMode.ECB;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-59.test"),
						Line:     8,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-60",
			Rule:     NewDebugBuildEnabled(),
			Src:      SampleVulnerableHSCSHARP60,
			Filename: filepath.Join(tempDir, "HS-CSHARP-60.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<compilation debug=\"true\" targetFramework=\"4.5\"/>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-60.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-61",
			Rule:     NewVulnerablePackageReference(),
			Src:      SampleVulnerableHSCSHARP61,
			Filename: filepath.Join(tempDir, "HS-CSHARP-61.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<package id=\"bootstrap\" version=\"3.0.0\" targetFramework=\"net462\" />",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-61.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-62",
			Rule:     NewCorsAllowOriginWildCard(),
			Src:      SampleVulnerableHSCSHARP62,
			Filename: filepath.Join(tempDir, "HS-CSHARP-62.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "app.UseCors(builder => builder.AllowAnyOrigin());",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-62.test"),
						Line:     5,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-63",
			Rule:     NewMissingAntiForgeryTokenAttribute(),
			Src:      SampleVulnerableHSCSHARP63,
			Filename: filepath.Join(tempDir, "HS-CSHARP-63.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "[HttpPost]",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-63.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-64",
			Rule:     NewUnvalidatedWebFormsRedirect(),
			Src:      SampleVulnerableHSCSHARP64,
			Filename: filepath.Join(tempDir, "HS-CSHARP-64.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "Response.Redirect(Request.QueryString[\"ReturnUrl\"]);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-64.test"),
						Line:     5,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-65",
			Rule:     NewIdentityPasswordLockoutDisabled(),
			Src:      SampleVulnerableHSCSHARP65,
			Filename: filepath.Join(tempDir, "HS-CSHARP-65.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-65.test"),
						Line:     6,
						Column:   38,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-66",
			Rule:     NewRawInlineExpression(),
			Src:      SampleVulnerableHSCSHARP66,
			Filename: filepath.Join(tempDir, "HS-CSHARP-66.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "Welcome <%= Request[\"UserName\"].ToString() %>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-66.test"),
						Line:     3,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-67",
			Rule:     NewRawBindingExpression(),
			Src:      SampleVulnerableHSCSHARP67,
			Filename: filepath.Join(tempDir, "HS-CSHARP-67.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "<%# Item.ProductName %>",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-67.test"),
						Line:     6,
						Column:   16,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-68",
			Rule:     NewRawWriteLiteralMethod(),
			Src:      SampleVulnerableHSCSHARP68,
			Filename: filepath.Join(tempDir, "HS-CSHARP-68.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "WriteLiteral(string.Format(\"Welcome <span class=\\\"bold\\\">{0}</span>!\", Model.UserName));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-68.test"),
						Line:     4,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-69",
			Rule:     NewUnencodedWebFormsProperty(),
			Src:      SampleVulnerableHSCSHARP69,
			Filename: filepath.Join(tempDir, "HS-CSHARP-69.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "litDetails.Text = product.ProductDescription;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-69.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-70",
			Rule:     NewUnencodedLabelText(),
			Src:      SampleVulnerableHSCSHARP70,
			Filename: filepath.Join(tempDir, "HS-CSHARP-70.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "lblDetails.Text = product.ProductDescription;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-70.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-71",
			Rule:     NewWeakRandomNumberGenerator(),
			Src:      SampleVulnerableHSCSHARP71,
			Filename: filepath.Join(tempDir, "HS-CSHARP-71.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "var random = new Random();",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-71.test"),
						Line:     4,
						Column:   17,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-72",
			Rule:     NewWeakRsaKeyLength(),
			Src:      SampleVulnerableHSCSHARP72,
			Filename: filepath.Join(tempDir, "HS-CSHARP-72.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "RSACryptoServiceProvider alg = new RSACryptoServiceProvider(1024);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-72.test"),
						Line:     2,
						Column:   31,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-73",
			Rule:     NewXmlReaderExternalEntityExpansion(),
			Src:      SampleVulnerableHSCSHARP73,
			Filename: filepath.Join(tempDir, "HS-CSHARP-73.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "XmlReaderSettings rs = new XmlReaderSettings",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-73.test"),
						Line:     2,
						Column:   23,
					},
				},
			},
		},
		{
			Name:     "HS-CSHARP-74",
			Rule:     NewLdapInjectionDirectoryEntry(),
			Src:      SampleVulnerableHSCSHARP74,
			Filename: filepath.Join(tempDir, "HS-CSHARP-74.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "DirectoryEntry entry = new DirectoryEntry(string.Format(\"LDAP://DC={0}, DC=COM/\", model.Domain));",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-CSHARP-74.test"),
						Line:     2,
						Column:   23,
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
			Name:     "HS-CSHARP-1",
			Rule:     NewCommandInjection(),
			Src:      SampleSafeHSCSHARP1,
			Filename: filepath.Join(tempDir, "HS-CSHARP11.test"),
		},
		{
			Name:     "HS-CSHARP-2",
			Rule:     NewXPathInjection(),
			Src:      SampleSafeHSCSHARP2,
			Filename: filepath.Join(tempDir, "HS-CSHARP22.test"),
		},
		{
			Name:     "HS-CSHARP-3",
			Rule:     NewExternalEntityInjection(),
			Src:      SampleSafeHSCSHARP3,
			Filename: filepath.Join(tempDir, "HS-CSHARP32.test"),
		},
		{
			Name:     "HS-CSHARP-4",
			Rule:     NewPathTraversal(),
			Src:      SampleSafeHSCSHARP4,
			Filename: filepath.Join(tempDir, "HS-CSHARP42.test"),
		},
		{
			Name:     "HS-CSHARP-5",
			Rule:     NewSQLInjectionWebControls(),
			Src:      SampleSafeHSCSHARP5,
			Filename: filepath.Join(tempDir, "HS-CSHARP52.test"),
		},
		{
			Name:     "HS-CSHARP-6",
			Rule:     NewWeakCipherOrCBCOrECBMode(),
			Src:      SampleSafeHSCSHARP6,
			Filename: filepath.Join(tempDir, "HS-CSHARP62.test"),
		},
		{
			Name:     "HS-CSHARP-7",
			Rule:     NewFormsAuthenticationCookielessMode(),
			Src:      SampleSafeHSCSHARP7,
			Filename: filepath.Join(tempDir, "HS-CSHARP72.test"),
		},
		{
			Name:     "HS-CSHARP-8",
			Rule:     NewFormsAuthenticationCrossAppRedirects(),
			Src:      SampleSafeHSCSHARP8,
			Filename: filepath.Join(tempDir, "HS-CSHARP82.test"),
		},
		{
			Name:     "HS-CSHARP-9",
			Rule:     NewFormsAuthenticationWeakCookieProtection(),
			Src:      SampleSafeHSCSHARP9,
			Filename: filepath.Join(tempDir, "HS-CSHARP92.test"),
		},
		{
			Name:     "HS-CSHARP-10",
			Rule:     NewFormsAuthenticationWeakTimeout(),
			Src:      SampleSafeHSCSHARP10,
			Filename: filepath.Join(tempDir, "HS-CSHARP-10.test"),
		},
		{
			Name:     "HS-CSHARP-11",
			Rule:     NewHeaderCheckingDisabled(),
			Src:      SampleSafeHSCSHARP11,
			Filename: filepath.Join(tempDir, "HS-CSHARP-11.test"),
		},
		{
			Name:     "HS-CSHARP-12",
			Rule:     NewVersionHeaderEnabled(),
			Src:      SampleSafeHSCSHARP12,
			Filename: filepath.Join(tempDir, "HS-CSHARP-12.test"),
		},
		{
			Name:     "HS-CSHARP-13",
			Rule:     NewEventValidationDisabled(),
			Src:      SampleSafeHSCSHARP13,
			Filename: filepath.Join(tempDir, "HS-CSHARP-13.test"),
		},
		{
			Name:     "HS-CSHARP-14",
			Rule:     NewWeakSessionTimeout(),
			Src:      SampleSafeHSCSHARP14,
			Filename: filepath.Join(tempDir, "HS-CSHARP-14.test"),
		},
		{
			Name:     "HS-CSHARP-15",
			Rule:     NewStateServerMode(),
			Src:      SampleSafeHSCSHARP15,
			Filename: filepath.Join(tempDir, "HS-CSHARP-15.test"),
		},
		{
			Name:     "HS-CSHARP-16",
			Rule:     NewJwtSignatureValidationDisabled(),
			Src:      SampleSafeHSCSHARP16,
			Filename: filepath.Join(tempDir, "HS-CSHARP-16.test"),
		},
		{
			Name:     "HS-CSHARP-17",
			Rule:     NewInsecureHttpCookieTransport(),
			Src:      SampleSafeHSCSHARP17,
			Filename: filepath.Join(tempDir, "HS-CSHARP-17.test"),
		},
		{
			Name:     "HS-CSHARP-18",
			Rule:     NewHttpCookieAccessibleViaScript(),
			Src:      SampleSafeHSCSHARP18,
			Filename: filepath.Join(tempDir, "HS-CSHARP-18.test"),
		},
		{
			Name:     "HS-CSHARP-19",
			Rule:     NewDirectoryListingEnabled(),
			Src:      SampleSafeHSCSHARP19,
			Filename: filepath.Join(tempDir, "HS-CSHARP-19.test"),
		},
		{
			Name:     "HS-CSHARP-20",
			Rule:     NewLdapAuthenticationDisabled(),
			Src:      SampleSafeHSCSHARP20,
			Filename: filepath.Join(tempDir, "HS-CSHARP-20.test"),
		},
		{
			Name:     "HS-CSHARP-21",
			Rule:     NewCertificateValidationDisabledAndMatch(),
			Src:      SampleSafeHSCSHARP21,
			Filename: filepath.Join(tempDir, "HS-CSHARP-21.test"),
		},
		{
			Name:     "HS-CSHARP-22",
			Rule:     NewActionRequestValidationDisabled(),
			Src:      SampleSafeHSCSHARP22,
			Filename: filepath.Join(tempDir, "HS-CSHARP-22.test"),
		},
		{
			Name:     "HS-CSHARP-23",
			Rule:     NewXmlDocumentExternalEntityExpansion(),
			Src:      SampleSafeHSCSHARP23,
			Filename: filepath.Join(tempDir, "HS-CSHARP-23.test"),
		},
		{
			Name:     "HS-CSHARP-24",
			Rule:     NewLdapInjectionFilterAssignment(),
			Src:      SampleSafeHSCSHARP24,
			Filename: filepath.Join(tempDir, "HS-CSHARP-24.test"),
		},
		{
			Name:     "HS-CSHARP-25",
			Rule:     NewSqlInjectionDynamicNHibernateQuery(),
			Src:      SampleSafeHSCSHARP25,
			Filename: filepath.Join(tempDir, "HS-CSHARP-25.test"),
		},
		{
			Name:     "HS-CSHARP-26",
			Rule:     NewLdapInjectionDirectorySearcher(),
			Src:      SampleSafeHSCSHARP26,
			Filename: filepath.Join(tempDir, "HS-CSHARP-26.test"),
		},
		{
			Name:     "HS-CSHARP-27",
			Rule:     NewLdapInjectionPathAssignment(),
			Src:      SampleSafeHSCSHARP27,
			Filename: filepath.Join(tempDir, "HS-CSHARP-27.test"),
		},
		{
			Name:     "HS-CSHARP-28",
			Rule:     NewLDAPInjection(),
			Src:      SampleSafeHSCSHARP28,
			Filename: filepath.Join(tempDir, "HS-CSHARP-28.test"),
		},
		{
			Name:     "HS-CSHARP-29",
			Rule:     NewSQLInjectionLinq(),
			Src:      SampleSafeHSCSHARP29,
			Filename: filepath.Join(tempDir, "HS-CSHARP-29.test"),
		},
		{
			Name:     "HS-CSHARP-30",
			Rule:     NewInsecureDeserialization(),
			Src:      SampleSafeHSCSHARP30,
			Filename: filepath.Join(tempDir, "HS-CSHARP-30.test"),
		},
		{
			Name:     "HS-CSHARP-31",
			Rule:     NewSQLInjectionEnterpriseLibraryData(),
			Src:      SampleSafeHSCSHARP31,
			Filename: filepath.Join(tempDir, "HS-CSHARP-31.test"),
		},
		{
			Name:     "HS-CSHARP-32",
			Rule:     NewCQLInjectionCassandra(),
			Src:      SampleSafeHSCSHARP32,
			Filename: filepath.Join(tempDir, "HS-CSHARP-32.test"),
		},
		{
			Name:     "HS-CSHARP-33",
			Rule:     NewPasswordComplexityDefault(),
			Src:      SampleSafeHSCSHARP33,
			Filename: filepath.Join(tempDir, "HS-CSHARP-33.test"),
		},
		{
			Name:     "HS-CSHARP-34",
			Rule:     NewCookieWithoutSSLFlag(),
			Src:      SampleSafeHSCSHARP34,
			Filename: filepath.Join(tempDir, "HS-CSHARP-34.test"),
		},
		{
			Name:     "HS-CSHARP-35",
			Rule:     NewCookieWithoutHttpOnlyFlag(),
			Src:      SampleSafeHSCSHARP35,
			Filename: filepath.Join(tempDir, "HS-CSHARP-35.test"),
		},
		{
			Name:     "HS-CSHARP-36",
			Rule:     NewNoInputVariable(),
			Src:      SampleSafeHSCSHARP36,
			Filename: filepath.Join(tempDir, "HS-CSHARP-36.test"),
		},
		{
			Name:     "HS-CSHARP-37",
			Rule:     NewIdentityWeakPasswordComplexity(),
			Src:      SampleSafeHSCSHARP37,
			Filename: filepath.Join(tempDir, "HS-CSHARP-37.test"),
		},
		{
			Name:     "HS-CSHARP-38",
			Rule:     NewNoLogSensitiveInformationInConsole(),
			Src:      SampleSafeHSCSHARP38,
			Filename: filepath.Join(tempDir, "HS-CSHARP-38.test"),
		},
		{
			Name:     "HS-CSHARP-39",
			Rule:     NewOutputCacheConflict(),
			Src:      SampleSafeHSCSHARP39,
			Filename: filepath.Join(tempDir, "HS-CSHARP-39.test"),
		},
		{
			Name:     "HS-CSHARP-40",
			Rule:     NewOpenRedirect(),
			Src:      SampleSafeHSCSHARP40,
			Filename: filepath.Join(tempDir, "HS-CSHARP-40.test"),
		},
		{
			Name:     "HS-CSHARP-41",
			Rule:     NewRequestValidationDisabledAttribute(),
			Src:      SampleSafeHSCSHARP41,
			Filename: filepath.Join(tempDir, "HS-CSHARP-41.test"),
		},
		{
			Name:     "HS-CSHARP-42",
			Rule:     NewSQLInjectionOLEDB(),
			Src:      SampleSafeHSCSHARP42,
			Filename: filepath.Join(tempDir, "HS-CSHARP-42.test"),
		},
		{
			Name:     "HS-CSHARP-43",
			Rule:     NewRequestValidationDisabledConfigurationFile(),
			Src:      SampleSafeHSCSHARP43,
			Filename: filepath.Join(tempDir, "HS-CSHARP-43.test"),
		},
		{
			Name:     "HS-CSHARP-44",
			Rule:     NewSQLInjectionMsSQLDataProvider(),
			Src:      SampleSafeHSCSHARP44,
			Filename: filepath.Join(tempDir, "HS-CSHARP-44.test"),
		},
		{
			Name:     "HS-CSHARP-45",
			Rule:     NewRequestValidationIsEnabledOnlyForPages(),
			Src:      SampleSafeHSCSHARP45,
			Filename: filepath.Join(tempDir, "HS-CSHARP-45.test"),
		},
		{
			Name:     "HS-CSHARP-46",
			Rule:     NewSQLInjectionEntityFramework(),
			Src:      SampleSafeHSCSHARP46,
			Filename: filepath.Join(tempDir, "HS-CSHARP-46.test"),
		},
		{
			Name:     "HS-CSHARP-47",
			Rule:     NewViewStateNotEncrypted(),
			Src:      SampleSafeHSCSHARP47,
			Filename: filepath.Join(tempDir, "HS-CSHARP-47.test"),
		},
		{
			Name:     "HS-CSHARP-48",
			Rule:     NewSQLInjectionNhibernate(),
			Src:      SampleSafeHSCSHARP48,
			Filename: filepath.Join(tempDir, "HS-CSHARP-48.test"),
		},
		{
			Name:     "HS-CSHARP-49",
			Rule:     NewViewStateMacDisabled(),
			Src:      SampleSafeHSCSHARP49,
			Filename: filepath.Join(tempDir, "HS-CSHARP-49.test"),
		},
		{
			Name:     "HS-CSHARP-50",
			Rule:     NewSQLInjectionNpgsql(),
			Src:      SampleSafeHSCSHARP50,
			Filename: filepath.Join(tempDir, "HS-CSHARP-50.test"),
		},
		{
			Name:     "HS-CSHARP-51",
			Rule:     NewCertificateValidationDisabled(),
			Src:      SampleSafeHSCSHARP51,
			Filename: filepath.Join(tempDir, "HS-CSHARP-51.test"),
		},
		{
			Name:     "HS-CSHARP-52",
			Rule:     NewWeakCipherAlgorithm(),
			Src:      SampleSafeHSCSHARP52,
			Filename: filepath.Join(tempDir, "HS-CSHARP-52.test"),
		},
		{
			Name:     "HS-CSHARP-53",
			Rule:     NewNoUseHtmlRaw(),
			Src:      SampleSafeHSCSHARP53,
			Filename: filepath.Join(tempDir, "HS-CSHARP-53.test"),
		},
		{
			Name:     "HS-CSHARP-54",
			Rule:     NewNoLogSensitiveInformation(),
			Src:      SampleSafeHSCSHARP54,
			Filename: filepath.Join(tempDir, "HS-CSHARP-54.test"),
		},
		{
			Name:     "HS-CSHARP-55",
			Rule:     NewNoReturnStringConcatInController(),
			Src:      SampleSafeHSCSHARP55,
			Filename: filepath.Join(tempDir, "HS-CSHARP-55.test"),
		},
		{
			Name:     "HS-CSHARP-56",
			Rule:     NewSQLInjectionOdbcCommand(),
			Src:      SampleSafeHSCSHARP56,
			Filename: filepath.Join(tempDir, "HS-CSHARP-56.test"),
		},
		{
			Name:     "HS-CSHARP-57",
			Rule:     NewWeakHashingFunctionMd5OrSha1(),
			Src:      SampleSafeHSCSHARP57,
			Filename: filepath.Join(tempDir, "HS-CSHARP-57.test"),
		},
		{
			Name:     "HS-CSHARP-58",
			Rule:     NewWeakHashingFunctionDESCrypto(),
			Src:      SampleSafeHSCSHARP58,
			Filename: filepath.Join(tempDir, "HS-CSHARP-58.test"),
		},
		{
			Name:     "HS-CSHARP-59",
			Rule:     NewNoUseCipherMode(),
			Src:      SampleSafeHSCSHARP59,
			Filename: filepath.Join(tempDir, "HS-CSHARP-59.test"),
		},
		{
			Name:     "HS-CSHARP-60",
			Rule:     NewDebugBuildEnabled(),
			Src:      SampleSafeHSCSHARP60,
			Filename: filepath.Join(tempDir, "HS-CSHARP-60.test"),
		},
		{
			Name:     "HS-CSHARP-61",
			Rule:     NewVulnerablePackageReference(),
			Src:      SampleSafeHSCSHARP61,
			Filename: filepath.Join(tempDir, "HS-CSHARP-61.test"),
		},
		{
			Name:     "HS-CSHARP-62",
			Rule:     NewCorsAllowOriginWildCard(),
			Src:      SampleSafeHSCSHARP62,
			Filename: filepath.Join(tempDir, "HS-CSHARP-62.test"),
		},
		{
			Name:     "HS-CSHARP-63",
			Rule:     NewMissingAntiForgeryTokenAttribute(),
			Src:      SampleSafeHSCSHARP63,
			Filename: filepath.Join(tempDir, "HS-CSHARP-63.test"),
		},
		{
			Name:     "HS-CSHARP-64",
			Rule:     NewUnvalidatedWebFormsRedirect(),
			Src:      SampleSafeHSCSHARP64,
			Filename: filepath.Join(tempDir, "HS-CSHARP-64.test"),
		},
		{
			Name:     "HS-CSHARP-65",
			Rule:     NewIdentityPasswordLockoutDisabled(),
			Src:      SampleSafeHSCSHARP65,
			Filename: filepath.Join(tempDir, "HS-CSHARP-65.test"),
		},
		{
			Name:     "HS-CSHARP-66",
			Rule:     NewRawInlineExpression(),
			Src:      SampleSafeHSCSHARP66,
			Filename: filepath.Join(tempDir, "HS-CSHARP-66.test"),
		},
		{
			Name:     "HS-CSHARP-67",
			Rule:     NewRawBindingExpression(),
			Src:      SampleSafeHSCSHARP67,
			Filename: filepath.Join(tempDir, "HS-CSHARP-67.test"),
		},
		{
			Name:     "HS-CSHARP-68",
			Rule:     NewRawWriteLiteralMethod(),
			Src:      SampleSafeHSCSHARP68,
			Filename: filepath.Join(tempDir, "HS-CSHARP-68.test"),
		},
		{
			Name:     "HS-CSHARP-69",
			Rule:     NewUnencodedWebFormsProperty(),
			Src:      SampleSafeHSCSHARP69,
			Filename: filepath.Join(tempDir, "HS-CSHARP-69.test"),
		},
		{
			Name:     "HS-CSHARP-70",
			Rule:     NewUnencodedLabelText(),
			Src:      SampleSafeHSCSHARP70,
			Filename: filepath.Join(tempDir, "HS-CSHARP-70.test"),
		},
		{
			Name:     "HS-CSHARP-71",
			Rule:     NewWeakRandomNumberGenerator(),
			Src:      SampleSafeHSCSHARP71,
			Filename: filepath.Join(tempDir, "HS-CSHARP-71.test"),
		},
		{
			Name:     "HS-CSHARP-72",
			Rule:     NewWeakRsaKeyLength(),
			Src:      SampleSafeHSCSHARP72,
			Filename: filepath.Join(tempDir, "HS-CSHARP-72.test"),
		},
		{
			Name:     "HS-CSHARP-73",
			Rule:     NewXmlReaderExternalEntityExpansion(),
			Src:      SampleSafeHSCSHARP73,
			Filename: filepath.Join(tempDir, "HS-CSHARP-73.test"),
		},
		{
			Name:     "HS-CSHARP-74",
			Rule:     NewLdapInjectionDirectoryEntry(),
			Src:      SampleSafeHSCSHARP74,
			Filename: filepath.Join(tempDir, "HS-CSHARP-74.test"),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
