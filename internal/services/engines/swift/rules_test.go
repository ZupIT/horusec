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

package swift

import (
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tmpDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-SWIFT-2",
			Rule:     NewCoreDataDatabase(),
			Src:      SampleVulnerableHSSWIFT2,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-2.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var mainContext: NSManagedObjectContext {`,
					SourceLocation: engine.Location{
						Line:     13,
						Column:   21,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-2.test"),
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-3",
			Rule:     NewDTLS12NotUsed(),
			Src:      SampleVulnerableHSSWIFT3,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-3.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.DTLSv11`,
					SourceLocation: engine.Location{
						Line:     3,
						Column:   40,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-3.test"),
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-4",
			Rule:     NewTLS13NotUsed(),
			Src:      SampleVulnerableHSSWIFT4,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-4.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.TLSv11`,
					SourceLocation: engine.Location{
						Line:     3,
						Column:   40,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-4.test"),
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-5",
			Rule:     NewReverseEngineering(),
			Src:      SampleVulnerableHSSWIFT5,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-5.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `.library(name: "FridaGadget", targets: ["FridaGadget"]),`,
					SourceLocation: engine.Location{
						Line:     8,
						Column:   25,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-5.test"),
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-6",
			Rule:     NewWeakMD5CryptoCipher(),
			Src:      SampleVulnerableHSSWIFT6,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-6.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import CryptoSwift`,
					SourceLocation: engine.Location{
						Line:     1,
						Column:   0,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-6.test"),
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-7",
			Rule:     NewWeakCommonDesCryptoCipher(),
			Src:      SampleVulnerableHSSWIFT7,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-7.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import CommonCrypto`,
					SourceLocation: engine.Location{
						Line:     2,
						Column:   0,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-7.test"),
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-8",
			Rule:     NewWeakIDZDesCryptoCipher(),
			Src:      SampleVulnerableHSSWIFT8,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-8.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import IDZSwiftCommonCrypto`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-8.test"),
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-9",
			Rule:     NewWeakBlowfishCryptoCipher(),
			Src:      SampleVulnerableHSSWIFT9,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-9.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import CryptoSwift`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-9.test"),
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-10",
			Rule:     NewMD6Collision(),
			Src:      SampleVulnerableHSSWIFT10,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-10.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `MD6( cStr, strlen(cStr), result );`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-10.test"),
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-11",
			Rule:     NewMD5Collision(),
			Src:      SampleVulnerableHSSWIFT11,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-11.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `MD5( cStr, strlen(cStr), result );`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-11.test"),
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-12",
			Rule:     NewSha1Collision(),
			Src:      SampleVulnerableHSSWIFT12,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-12.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `let digest = Insecure.SHA1.hash(data: data)`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-12.test"),
						Column:   21,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-13",
			Rule:     NewJailbreakDetect(),
			Src:      SampleVulnerableHSSWIFT13,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-13.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `if(fm.fileExists(atPath: "/private/var/lib/apt")) || (fm.fileExists(atPath: "/Applications/Cydia.app")) {`,
					SourceLocation: engine.Location{
						Line:     3,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-13.test"),
						Column:   78,
					},
				},
				{
					CodeSample: `if(fm.fileExists(atPath: "/private/var/lib/apt")) || (fm.fileExists(atPath: "/Applications/Cydia.app")) {`,
					SourceLocation: engine.Location{
						Line:     3,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-13.test"),
						Column:   27,
					},
				},
				{
					CodeSample: `if(fm.fileExists(atPath: "/private/var/lib/apt")) || (fm.fileExists(atPath: "/Applications/Cydia.app")) {`,
					SourceLocation: engine.Location{
						Line:     3,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-13.test"),
						Column:   35,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-14",
			Rule:     NewLoadHTMLString(),
			Src:      SampleVulnerableHSSWIFT14,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-14.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `webView1.loadHTMLString("<html><body><p>"+content+"</p></body></html>", baseURL: nil)`,
					SourceLocation: engine.Location{
						Line:     4,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-14.test"),
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-15",
			Rule:     NewWeakDesCryptoCipher(),
			Src:      SampleVulnerableHSSWIFT15,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-15.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `crypt.CryptAlgorithm = "3des"`,
					SourceLocation: engine.Location{
						Line:     5,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-15.test"),
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-16",
			Rule:     NewRealmDatabase(),
			Src:      SampleVulnerableHSSWIFT16,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-16.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `try! realm.write {`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-16.test"),
						Column:   5,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-17",
			Rule:     NewTLSMinimum(),
			Src:      SampleVulnerableHSSWIFT17,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-17.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `config.tlsMinimumSupportedProtocol = .tlsProtocol12`,
					SourceLocation: engine.Location{
						Line:     3,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-17.test"),
						Column:   6,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-18",
			Rule:     NewUIPasteboard(),
			Src:      SampleVulnerableHSSWIFT18,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-18.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `let content = UIPasteboard.general.string`,
					SourceLocation: engine.Location{
						Line:     3,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-18.test"),
						Column:   14,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-19",
			Rule:     NewFileProtection(),
			Src:      SampleVulnerableHSSWIFT19,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-19.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `try data?.write(to: documentURL, options: .noFileProtection)`,
					SourceLocation: engine.Location{
						Line:     3,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-19.test"),
						Column:   50,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-20",
			Rule:     NewWebViewSafari(),
			Src:      SampleVulnerableHSSWIFT20,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-20.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `let config = SFSafariViewController.Configuration()`,
					SourceLocation: engine.Location{
						Line:     4,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-20.test"),
						Column:   14,
					},
				},
				{
					CodeSample: `let vc = SFSafariViewController(url: url, configuration: config)`,
					SourceLocation: engine.Location{
						Line:     7,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-20.test"),
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-21",
			Rule:     NewKeyboardCache(),
			Src:      SampleVulnerableHSSWIFT21,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-21.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `textField.autocorrectionType = .no`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-21.test"),
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-22",
			Rule:     NewMD4Collision(),
			Src:      SampleVulnerableHSSWIFT22,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-22.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `CC_MD4( cStr, strlen(cStr), result );`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-22.test"),
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-23",
			Rule:     NewMD2Collision(),
			Src:      SampleVulnerableHSSWIFT23,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-23.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `CC_MD2( cStr, strlen(cStr), result );`,
					SourceLocation: engine.Location{
						Line:     2,
						Filename: filepath.Join(tmpDir, "HS-SWIFT-23.test"),
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-24",
			Src:      SampleVulnerableHSSWIFT24,
			Rule:     NewSQLInjection(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-24.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `let err = SD.executeChange("SELECT * FROM User where user="+ valuesFromInput) {`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tmpDir, "HS-SWIFT-24.test"),
						Line:     2,
						Column:   13,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tmpDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-SWIFT-2",
			Rule:     NewCoreDataDatabase(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-2.test"),
			Src:      SampleSafeHSSWIFT2,
		},
		{
			Name:     "HS-SWIFT-3",
			Rule:     NewDTLS12NotUsed(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-3.test"),
			Src:      SampleSafeHSSWIFT3,
		},
		{
			Name:     "HS-SWIFT-4",
			Rule:     NewTLS13NotUsed(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-4.test"),
			Src:      SampleSafeHSSWIFT4,
		},
		{
			Name:     "HS-SWIFT-5",
			Rule:     NewReverseEngineering(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-5.test"),
			Src:      SampleSafeHSSWIFT5,
		},
		{
			Name:     "HS-SWIFT-6",
			Rule:     NewWeakMD5CryptoCipher(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-6.test"),
			Src:      SampleSafeHSSWIFT6,
		},
		{
			Name:     "HS-SWIFT-7",
			Rule:     NewWeakCommonDesCryptoCipher(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-7.test"),
			Src:      SampleSafeHSSWIFT7,
		},
		{
			Name:     "HS-SWIFT-8",
			Rule:     NewWeakIDZDesCryptoCipher(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-8.test"),
			Src:      SampleSafeHSSWIFT8,
		},
		{
			Name:     "HS-SWIFT-9",
			Rule:     NewWeakBlowfishCryptoCipher(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-9.test"),
			Src:      SampleSafeHSSWIFT9,
		},
		{
			Name:     "HS-SWIFT-10",
			Rule:     NewMD6Collision(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-10.test"),
			Src:      SampleSafeHSSWIFT10,
		},
		{
			Name:     "HS-SWIFT-11",
			Rule:     NewMD5Collision(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-11.test"),
			Src:      SampleSafeHSSWIFT11,
		},
		{
			Name:     "HS-SWIFT-12",
			Rule:     NewSha1Collision(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-12.test"),
			Src:      SampleSafeHSSWIFT12,
		},
		{
			Name:     "HS-SWIFT-13",
			Rule:     NewJailbreakDetect(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-13.test"),
			Src:      SampleSafeHSSWIFT13,
		},
		{
			Name:     "HS-SWIFT-14",
			Rule:     NewLoadHTMLString(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-14.test"),
			Src:      SampleSafeHSSWIFT14,
		},
		{
			Name:     "HS-SWIFT-15",
			Rule:     NewWeakDesCryptoCipher(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-15.test"),
			Src:      SampleSafeHSSWIFT15,
		},
		{
			Name:     "HS-SWIFT-16",
			Rule:     NewRealmDatabase(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-16.test"),
			Src:      SampleSafeHSSWIFT16,
		},
		{
			Name:     "HS-SWIFT-17",
			Rule:     NewTLSMinimum(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-17.test"),
			Src:      SampleSafeHSSWIFT17,
		},
		{
			Name:     "HS-SWIFT-18",
			Rule:     NewUIPasteboard(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-18.test"),
			Src:      SampleSafeHSSWIFT18,
		},
		{
			Name:     "HS-SWIFT-19",
			Rule:     NewFileProtection(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-19.test"),
			Src:      SampleSafeHSSWIFT19,
		},
		{
			Name:     "HS-SWIFT-20",
			Rule:     NewWebViewSafari(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-20.test"),
			Src:      SampleSafeHSSWIFT20,
		},
		{
			Name:     "HS-SWIFT-21",
			Rule:     NewKeyboardCache(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-21.test"),
			Src:      SampleSafeHSSWIFT21,
		},
		{
			Name:     "HS-SWIFT-22",
			Rule:     NewMD4Collision(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-22.test"),
			Src:      SampleSafeHSSWIFT22,
		},
		{
			Name:     "HS-SWIFT-23",
			Rule:     NewMD2Collision(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-23.test"),
			Src:      SampleSafeHSSWIFT23,
		},
		{
			Name:     "HS-SWIFT-24",
			Src:      SampleSafeHSSWIFT24,
			Rule:     NewSQLInjection(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-24.test"),
		},
		{
			Name:     "HS-SWIFT-24",
			Src:      Sample2SafeHSSWIFT24,
			Rule:     NewSQLInjection(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-2.test"),
		},
	}
	testutil.TestSafeCode(t, testcases)
}
