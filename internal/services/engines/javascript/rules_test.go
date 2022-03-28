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

package javascript

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
			Name:     "HS-JAVASCRIPT-1",
			Rule:     NewNoLogSensitiveInformationInConsole(),
			Src:      SampleVulnerableHSJAVASCRIPT1,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-1.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `console.log("user email: ", email)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-1.test"),
						Line:     2,
						Column:   0,
					},
				},
				{
					CodeSample: `console.debug("user password: ", pwd)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-1.test"),
						Line:     3,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-2",
			Rule:     NewNoUseEval(),
			Src:      SampleVulnerableHSJAVASCRIPT2,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-2.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `eval(foo);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-2.test"),
						Line:     3,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-3",
			Rule:     NewNoDisableTlsRejectUnauthorized(),
			Src:      SampleVulnerableHSJAVASCRIPT3,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-3.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-3.test"),
						Line:     2,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-4",
			Rule:     NewNoUseMD5Hashing(),
			Src:      SampleVulnerableHSJAVASCRIPT4,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-4.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const hash = crypto.createHash('md5')`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-4.test"),
						Line:     2,
						Column:   20,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-5",
			Rule:     NewNoUseSHA1Hashing(),
			Src:      SampleVulnerableHSJAVASCRIPT5,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-5.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const hash = crypto.createHash('sha1')`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-5.test"),
						Line:     2,
						Column:   20,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-6",
			Rule:     NewNoUseWeakRandom(),
			Src:      SampleVulnerableHSJAVASCRIPT6,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-6.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return Math.random();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-6.test"),
						Line:     3,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-7",
			Rule:     NewNoReadFileUsingDataFromRequest(),
			Src:      SampleVulnerableHSJAVASCRIPT7,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-7.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return fs.readFileSync(req.body, 'utf8')`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-7.test"),
						Line:     3,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-8",
			Rule:     NewNoCreateReadStreamUsingDataFromRequest(),
			Src:      SampleVulnerableHSJAVASCRIPT8,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-8.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return fs.createReadStream(req.body)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-8.test"),
						Line:     3,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-9",
			Rule:     NewSQLInjectionUsingParams(),
			Src:      SampleVulnerableHSJAVASCRIPT9,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-9.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `Model.find({ where: { foo: req.body}});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-9.test"),
						Line:     3,
						Column:   6,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-10",
			Rule:     NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
			Src:      SampleVulnerableHSJAVASCRIPT10,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-10.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var xmlDoc = libxml.parseXmlString(xml, {});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-10.test"),
						Line:     4,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-11",
			Rule:     NewOriginsNotVerified(),
			Src:      SampleVulnerableHSJAVASCRIPT11,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-11.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `popup.postMessage("message", "https://foo.bar", "*");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-11.test"),
						Line:     4,
						Column:   6,
					},
				},
				{
					CodeSample: `window.addEventListener("message", (event) => {});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-11.test"),
						Line:     8,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-12",
			Rule:     NewWeakSSLTLSProtocolsShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT12,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-12.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `secureProtocol: 'TLSv1_method'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-12.test"),
						Line:     4,
						Column:   19,
					},
				},
				{
					CodeSample: `secureProtocol: 'TLSv1.1'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-12.test"),
						Line:     10,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-13",
			Rule:     NewWebSQLDatabasesShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT13,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-13.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const db = window.openDatabase();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-13.test"),
						Line:     2,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-14",
			Rule:     NewLocalStorageShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT14,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-14.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `localStorage.setItem("foo", "bar");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-14.test"),
						Line:     3,
						Column:   1,
					},
				},
				{
					CodeSample: `sessionStorage.setItem("foo", "bar");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-14.test"),
						Line:     7,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-15",
			Rule:     NewDebuggerStatementsShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT15,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-15.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `debugger;`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-15.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-16",
			Rule:     NewAlertStatementsShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT16,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-16.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `alert("testing");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-16.test"),
						Line:     3,
						Column:   1,
					},
				},
				{
					CodeSample: `confirm("testing");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-16.test"),
						Line:     7,
						Column:   1,
					},
				},
				{
					CodeSample: `prompt("testing");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-16.test"),
						Line:     11,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-17",
			Rule:     NewStaticallyServingHiddenFilesIsSecuritySensitive(),
			Src:      SampleVulnerableHSJAVASCRIPT17,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-17.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `dotfiles : 'allow'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-17.test"),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-18",
			Rule:     NewUsingIntrusivePermissionsWithGeolocation(),
			Src:      SampleVulnerableHSJAVASCRIPT18,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-18.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `navigator.geolocation.getCurrentPosition(success, error, {});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-18.test"),
						Line:     10,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-19",
			Rule:     NewHavingAPermissiveCrossOriginResourceSharingPolicy(),
			Src:      SampleVulnerableHSJAVASCRIPT19,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-19.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `res.header("Access-Control-Allow-Origin", "*");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-19.test"),
						Line:     7,
						Column:   14,
					},
				},
				{
					CodeSample: `app.get('/products/:id', cors(), function (req, res, next) {`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-19.test"),
						Line:     6,
						Column:   25,
					},
				},
				{
					CodeSample: `origin: '*',`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-19.test"),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-20",
			Rule:     NewReadingTheStandardInput(),
			Src:      SampleVulnerableHSJAVASCRIPT20,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-20.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var input = process.stdin.read();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-20.test"),
						Line:     3,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-21",
			Rule:     NewUsingCommandLineArguments(),
			Src:      SampleVulnerableHSJAVASCRIPT21,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-21.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `console.exec(process.argv[0])`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-21.test"),
						Line:     3,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-22",
			Rule:     NewRedirectToUnknownPath(),
			Src:      SampleVulnerableHSJAVASCRIPT22,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-22.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `redirect(path);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-22.test"),
						Line:     4,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-23",
			Rule:     NewNoRenderContentFromRequest(),
			Src:      SampleVulnerableHSJAVASCRIPT23,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-23.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return response.render(req.body.data);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-23.test"),
						Line:     3,
						Column:   16,
					},
				},
				{
					CodeSample: `return response.send(req.body.content);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-23.test"),
						Line:     7,
						Column:   16,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-24",
			Rule:     NewNoWriteOnDocumentContentFromRequest(),
			Src:      SampleVulnerableHSJAVASCRIPT24,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-24.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return document.write(req.body.data);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-24.test"),
						Line:     3,
						Column:   8,
					},
				},
				{
					CodeSample: `return body.write(req.body.content);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-24.test"),
						Line:     7,
						Column:   8,
					},
				},
				{
					CodeSample: `return element.write(req.body.content);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-24.test"),
						Line:     12,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-25",
			Rule:     NewNoExposeStackTrace(),
			Src:      SampleVulnerableHSJAVASCRIPT25,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-25.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return res.send(err.stack);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-25.test"),
						Line:     7,
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-26",
			Rule:     NewInsecureDownload(),
			Src:      SampleVulnerableHSJAVASCRIPT26,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-26.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const badBinary = axios.get('http://insecureDomain.com/program.bin');`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-26.test"),
						Line:     3,
						Column:   25,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-27",
			Rule:     NewNoUseRequestMethodUsingDataFromRequestOfUserInput(),
			Src:      SampleVulnerableHSJAVASCRIPT27,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-27.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import request from 'request';`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-27.test"),
						Line:     2,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-28",
			Rule:     NewNoUseGetMethodUsingDataFromRequestOfUserInput(),
			Src:      SampleVulnerableHSJAVASCRIPT28,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-28.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const res = request.get(req.body);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-28.test"),
						Line:     4,
						Column:   20,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-29",
			Rule:     NewCryptographicRsaShouldBeRobust(),
			Src:      SampleVulnerableHSJAVASCRIPT29,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-29.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `modulusLength: 1024`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-29.test"),
						Line:     4,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-30",
			Rule:     NewCryptographicEcShouldBeRobust(),
			Src:      SampleVulnerableHSJAVASCRIPT30,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-30.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `namedCurve: 'secp102k1'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-30.test"),
						Line:     4,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-31",
			Rule:     NewJWTNeedStrongCipherAlgorithms(),
			Src:      SampleVulnerableHSJAVASCRIPT31,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-31.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256'});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-31.test"),
						Line:     4,
						Column:   52,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-32",
			Rule:     NewServerHostnameNotVerified(),
			Src:      SampleVulnerableHSJAVASCRIPT32,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-32.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `checkServerIdentity: () => myCustomVerification()`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-32.test"),
						Line:     4,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-33",
			Rule:     NewServerCertificatesNotVerified(),
			Src:      SampleVulnerableHSJAVASCRIPT33,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-33.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `rejectUnauthorized: false`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-33.test"),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-34",
			Rule:     NewUntrustedContentShouldNotBeIncluded(),
			Src:      SampleVulnerableHSJAVASCRIPT34,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-34.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `element.setAttribute('src', req.body.data)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-34.test"),
						Line:     3,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-35",
			Rule:     NewMysqlHardCodedCredentialsSecuritySensitive(),
			Src:      SampleVulnerableHSJAVASCRIPT35,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-35.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `password: "root",`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-35.test"),
						Line:     5,
						Column:   3,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-36",
			Rule:     NewUsingShellInterpreterWhenExecutingOSCommands(),
			Src:      SampleVulnerableHSJAVASCRIPT36,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-36.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `exec('chmod 666 /home/dev', { shell: true })`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-36.test"),
						Line:     3,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-37",
			Rule:     NewForwardingClientIPAddress(),
			Src:      SampleVulnerableHSJAVASCRIPT37,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-37.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `xfwd: true`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-37.test"),
						Line:     5,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-38",
			Rule:     NewAllowingConfidentialInformationToBeLoggedWithSignale(),
			Src:      SampleVulnerableHSJAVASCRIPT38,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-38.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const logger = new Signale({ secrets: [] });`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-38.test"),
						Line:     3,
						Column:   30,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-39",
			Rule:     NewAllowingBrowsersToPerformDNSPrefetching(),
			Src:      SampleVulnerableHSJAVASCRIPT39,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-39.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `dnsPrefetchControl:{ allow: true }`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-39.test"),
						Line:     5,
						Column:   25,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-40",
			Rule:     NewDisablingCertificateTransparencyMonitoring(),
			Src:      SampleVulnerableHSJAVASCRIPT40,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-40.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `expectCt: false`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-40.test"),
						Line:     5,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-41",
			Rule:     NewDisablingStrictHTTPNoReferrerPolicy(),
			Src:      SampleVulnerableHSJAVASCRIPT41,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-41.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `referrerPolicy: { policy: 'no-referrer-when-downgrade' }`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-41.test"),
						Line:     7,
						Column:   22,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-42",
			Rule:     NewAllowingBrowsersToSniffMIMETypes(),
			Src:      SampleVulnerableHSJAVASCRIPT42,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-42.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `noSniff: false`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-42.test"),
						Line:     7,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-43",
			Rule:     NewDisablingContentSecurityPolicyFrameAncestorsDirective(),
			Src:      SampleVulnerableHSJAVASCRIPT43,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-43.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `frameAncestors: ["'none'"],`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-43.test"),
						Line:     8,
						Column:   6,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-44",
			Rule:     NewAllowingMixedContent(),
			Src:      SampleVulnerableHSJAVASCRIPT44,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-44.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `directives: {`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-44.test"),
						Line:     7,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-45",
			Rule:     NewDisablingContentSecurityPolicyFetchDirectives(),
			Src:      SampleVulnerableHSJAVASCRIPT45,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-45.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `contentSecurityPolicy: false`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-45.test"),
						Line:     7,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-46",
			Rule:     NewCreatingCookiesWithoutTheHttpOnlyFlag(),
			Src:      SampleVulnerableHSJAVASCRIPT46,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-46.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `httpOnly: false`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-46.test"),
						Line:     7,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-47",
			Rule:     NewCreatingCookiesWithoutTheSecureFlag(),
			Src:      SampleVulnerableHSJAVASCRIPT47,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-47.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `secure: false`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-47.test"),
						Line:     7,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-48",
			Rule:     NewNoUseSocketManually(),
			Src:      SampleVulnerableHSJAVASCRIPT48,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-48.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const socket = new net.Socket();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-48.test"),
						Line:     3,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-49",
			Rule:     NewEncryptionAlgorithmsWeak(),
			Src:      SampleVulnerableHSJAVASCRIPT49,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-49.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `let cipher = crypto.createCipheriv('RC4', key, iv);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-49.test"),
						Line:     6,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-50",
			Rule:     NewFileUploadsShouldBeRestricted(),
			Src:      SampleVulnerableHSJAVASCRIPT50,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-50.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const form = new Formidable();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-50.test"),
						Line:     3,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-51",
			Rule:     NewAllowingRequestsWithExcessiveContentLengthSecurity(),
			Src:      SampleVulnerableHSJAVASCRIPT51,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-51.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const form = new Formidable();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-51.test"),
						Line:     3,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-52",
			Rule:     NewNoDisableSanitizeHtml(),
			Src:      SampleVulnerableHSJAVASCRIPT52,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-52.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `Mustache.escape = function(text) {return text;};`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-52.test"),
						Line:     4,
						Column:   1,
					},
				},
				{
					CodeSample: `const markdownIt = require('markdown-it');`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-52.test"),
						Line:     9,
						Column:   6,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-53",
			Rule:     NewSQLInjection(),
			Src:      SampleVulnerableHSJAVASCRIPT53,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-53.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `db.query("SELECT * FROM USERS WHERE EMAIL = " + name);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-53.test"),
						Line:     4,
						Column:   3,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-54",
			Rule:     NewMongoDbHardCodedCredentialsSecuritySensitive(),
			Src:      SampleVulnerableHSJAVASCRIPT54,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-54.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `MongoClient.connect("mongodb://localhost:27017/mydb", function(err, db) {`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-54.test"),
						Line:     3,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-55",
			Rule:     NewPostgresqlHardCodedCredentialsSecuritySensitive(),
			Src:      SampleVulnerableHSJAVASCRIPT55,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-55.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `password: 'root',`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-55.test"),
						Line:     4,
						Column:   1,
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
			Name:     "HS-JAVASCRIPT-1",
			Rule:     NewNoLogSensitiveInformationInConsole(),
			Src:      SampleSafeHSJAVASCRIPT1,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-1.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-2",
			Rule:     NewNoUseEval(),
			Src:      SampleSafeHSJAVASCRIPT2,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-2.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-3",
			Rule:     NewNoDisableTlsRejectUnauthorized(),
			Src:      SampleSafeHSJAVASCRIPT3,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-3.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-4",
			Rule:     NewNoUseMD5Hashing(),
			Src:      SampleSafeHSJAVASCRIPT4,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-4.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-5",
			Rule:     NewNoUseSHA1Hashing(),
			Src:      SampleSafeHSJAVASCRIPT5,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-5.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-6",
			Rule:     NewNoUseWeakRandom(),
			Src:      SampleSafeHSJAVASCRIPT6,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-6.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-7",
			Rule:     NewNoReadFileUsingDataFromRequest(),
			Src:      SampleSafeHSJAVASCRIPT7,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-7.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-9",
			Rule:     NewSQLInjectionUsingParams(),
			Src:      SampleSafeHSJAVASCRIPT9,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-9.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-10",
			Rule:     NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
			Src:      SampleSafeHSJAVASCRIPT10,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-10.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-11",
			Rule:     NewOriginsNotVerified(),
			Src:      SampleSafeHSJAVASCRIPT11,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-11.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-12",
			Rule:     NewWeakSSLTLSProtocolsShouldNotBeUsed(),
			Src:      SampleSafeHSJAVASCRIPT12,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-12.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-16",
			Rule:     NewAlertStatementsShouldNotBeUsed(),
			Src:      SampleSafeHSJAVASCRIPT16,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-16.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-17",
			Rule:     NewStaticallyServingHiddenFilesIsSecuritySensitive(),
			Src:      SampleSafeHSJAVASCRIPT17,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-17.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-19",
			Rule:     NewHavingAPermissiveCrossOriginResourceSharingPolicy(),
			Src:      SampleSafeHSJAVASCRIPT19,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-19.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-21",
			Rule:     NewUsingCommandLineArguments(),
			Src:      SampleSafeHSJAVASCRIPT21,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-21.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-22",
			Rule:     NewRedirectToUnknownPath(),
			Src:      SampleSafeHSJAVASCRIPT22,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-22.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-23",
			Rule:     NewNoRenderContentFromRequest(),
			Src:      SampleSafeHSJAVASCRIPT23,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-23.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-24",
			Rule:     NewNoWriteOnDocumentContentFromRequest(),
			Src:      SampleSafeHSJAVASCRIPT24,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-24.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-25",
			Rule:     NewNoExposeStackTrace(),
			Src:      SampleSafeHSJAVASCRIPT25,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-25.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-26",
			Rule:     NewInsecureDownload(),
			Src:      SampleSafeHSJAVASCRIPT26,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-26.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-27",
			Rule:     NewNoUseRequestMethodUsingDataFromRequestOfUserInput(),
			Src:      SampleSafeHSJAVASCRIPT27,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-27.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-29",
			Rule:     NewCryptographicRsaShouldBeRobust(),
			Src:      SampleSafeHSJAVASCRIPT29,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-29.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-30",
			Rule:     NewCryptographicEcShouldBeRobust(),
			Src:      SampleSafeHSJAVASCRIPT30,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-30.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-31",
			Rule:     NewJWTNeedStrongCipherAlgorithms(),
			Src:      SampleSafeHSJAVASCRIPT31,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-31.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-32",
			Rule:     NewServerHostnameNotVerified(),
			Src:      SampleSafeHSJAVASCRIPT32,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-32.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-33",
			Rule:     NewServerCertificatesNotVerified(),
			Src:      SampleSafeHSJAVASCRIPT33,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-33.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-35",
			Rule:     NewMysqlHardCodedCredentialsSecuritySensitive(),
			Src:      SampleSafeHSJAVASCRIPT35,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-35.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-37",
			Rule:     NewForwardingClientIPAddress(),
			Src:      SampleSafeHSJAVASCRIPT37,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-37.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-38",
			Rule:     NewAllowingConfidentialInformationToBeLoggedWithSignale(),
			Src:      SampleSafeHSJAVASCRIPT38,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-38.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-39",
			Rule:     NewAllowingBrowsersToPerformDNSPrefetching(),
			Src:      SampleSafeHSJAVASCRIPT39,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-39.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-40",
			Rule:     NewDisablingCertificateTransparencyMonitoring(),
			Src:      SampleSafeHSJAVASCRIPT40,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-40.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-41",
			Rule:     NewDisablingStrictHTTPNoReferrerPolicy(),
			Src:      SampleSafeHSJAVASCRIPT41,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-41.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-42",
			Rule:     NewAllowingBrowsersToSniffMIMETypes(),
			Src:      SampleSafeHSJAVASCRIPT42,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-42.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-43",
			Rule:     NewDisablingContentSecurityPolicyFrameAncestorsDirective(),
			Src:      SampleSafeHSJAVASCRIPT43,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-43.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-44",
			Rule:     NewAllowingMixedContent(),
			Src:      SampleSafeHSJAVASCRIPT44,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-44.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-45",
			Rule:     NewDisablingContentSecurityPolicyFetchDirectives(),
			Src:      SampleSafeHSJAVASCRIPT45,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-45.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-46",
			Rule:     NewCreatingCookiesWithoutTheHttpOnlyFlag(),
			Src:      SampleSafeHSJAVASCRIPT46,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-46.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-47",
			Rule:     NewCreatingCookiesWithoutTheSecureFlag(),
			Src:      SampleSafeHSJAVASCRIPT47,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-47.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-48",
			Rule:     NewNoUseSocketManually(),
			Src:      SampleSafeHSJAVASCRIPT48,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-48.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-49",
			Rule:     NewEncryptionAlgorithmsWeak(),
			Src:      SampleSafeHSJAVASCRIPT49,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-49.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-50",
			Rule:     NewFileUploadsShouldBeRestricted(),
			Src:      SampleSafeHSJAVASCRIPT50,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-50.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-51",
			Rule:     NewAllowingRequestsWithExcessiveContentLengthSecurity(),
			Src:      SampleSafeHSJAVASCRIPT51,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-51.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-52",
			Rule:     NewNoDisableSanitizeHtml(),
			Src:      SampleSafeHSJAVASCRIPT52,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-52.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-53",
			Rule:     NewSQLInjection(),
			Src:      SampleSafeHSJAVASCRIPT53,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-53.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-54",
			Rule:     NewMongoDbHardCodedCredentialsSecuritySensitive(),
			Src:      SampleSafeHSJAVASCRIPT54,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-54.test"),
		},
		{
			Name:     "HS-JAVASCRIPT-55",
			Rule:     NewPostgresqlHardCodedCredentialsSecuritySensitive(),
			Src:      SampleSafeHSJAVASCRIPT55,
			Filename: filepath.Join(tempDir, "HS-JAVASCRIPT-55.test"),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
