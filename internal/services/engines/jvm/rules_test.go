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

package jvm

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
			Name:     "HS-JVM-1",
			Rule:     NewNoLogSensitiveInformation(),
			Src:      SampleVulnerableHSJVM1,
			Filename: filepath.Join(tempDir, "HS-JVM-1.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "log.info(\"the user requested is: \" + user);",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-1.test"),
						Line:     7,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-2",
			Rule:     NewHTTPRequestsConnectionsAndSessions(),
			Src:      SampleVulnerableHSJVM2,
			Filename: filepath.Join(tempDir, "HS-JVM-2.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import http.client.HttpClient;`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-2.test"),
						Line:     2,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-3",
			Rule:     NewNoUsesSafetyNetAPI(),
			Src:      SampleVulnerableHSJVM3,
			Filename: filepath.Join(tempDir, "HS-JVM-3.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "compile 'com.google.android.gms.safetynet.SafetyNetApi:11.0.4'",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-3.test"),
						Line:     3,
						Column:   13,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-4",
			Rule:     NewNoUsesContentProvider(),
			Src:      SampleVulnerableHSJVM4,
			Filename: filepath.Join(tempDir, "HS-JVM-4.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import android.content.ContentProvider;`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-4.test"),
						Line:     2,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-5",
			Rule:     NewNoUseWithUnsafeBytes(),
			Src:      SampleVulnerableHSJVM5,
			Filename: filepath.Join(tempDir, "HS-JVM-5.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `messageData.withUnsafeBytes {messageBytes in`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-5.test"),
						Line:     3,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-6",
			Rule:     NewNoUseLocalFileIOOperations(),
			Src:      SampleVulnerableHSJVM6,
			Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `Keychain`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
						Line:     3,
						Column:   0,
					},
				},
				{
					CodeSample: `kSecAttrAccessibleWhenUnlocked`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
						Line:     5,
						Column:   0,
					},
				},
				{
					CodeSample: `kSecAttrAccessibleAfterFirstUnlock`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
						Line:     7,
						Column:   0,
					},
				},
				{
					CodeSample: `SecItemAdd`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
						Line:     9,
						Column:   0,
					},
				},
				{
					CodeSample: `SecItemUpdate`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
						Line:     11,
						Column:   0,
					},
				},
				{
					CodeSample: `NSDataWritingFileProtectionComplete`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
						Line:     13,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-7",
			Rule:     NewWebViewComponent(),
			Src:      SampleVulnerableHSJVM7,
			Filename: filepath.Join(tempDir, "HS-JVM-7.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `UIWebView`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-7.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-8",
			Rule:     NewEncryptionAPI(),
			Src:      SampleVulnerableHSJVM8,
			Filename: filepath.Join(tempDir, "HS-JVM-8.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `return AESCrypt.encrypt(passPhrase, value);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-8.test"),
						Line:     4,
						Column:   9,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-9",
			Rule:     NewKeychainAccess(),
			Src:      SampleVulnerableHSJVM9,
			Filename: filepath.Join(tempDir, "HS-JVM-9.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `PDKeychainBindings`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-9.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-10",
			Rule:     NewNoUseProhibitedAPIs(),
			Src:      SampleVulnerableHSJVM10,
			Filename: filepath.Join(tempDir, "HS-JVM-10.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `strncat(dest, src, strlen(dest));`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-10.test"),
						Line:     3,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-11",
			Rule:     NewApplicationAllowMITMAttacks(),
			Src:      SampleVulnerableHSJVM11,
			Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `request.validatesSecureCertificate = NO;`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     2,
						Column:   8,
					},
				},
				{
					CodeSample: `allowInvalidCertificates = YES;`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     4,
						Column:   0,
					},
				},
				{
					CodeSample: `canAuthenticateAgainstProtectionSpace`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     6,
						Column:   0,
					},
				},
				{
					CodeSample: `continueWithoutCredentialForAuthenticationChallenge`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     8,
						Column:   0,
					},
				},
				{
					CodeSample: `kCFStreamSSLAllowsExpiredCertificates`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     10,
						Column:   0,
					},
				},
				{
					CodeSample: `kCFStreamSSLAllowsAnyRoot`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     12,
						Column:   0,
					},
				},
				{
					CodeSample: `kCFStreamSSLAllowsExpiredRoots`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
						Line:     14,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-12",
			Rule:     NewUIWebViewInApplicationIgnoringErrorsSSL(),
			Src:      SampleVulnerableHSJVM12,
			Filename: filepath.Join(tempDir, "HS-JVM-12.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `setAllowsAnyHTTPSCertificate: YES`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-12.test"),
						Line:     2,
						Column:   0,
					},
				},
				{
					CodeSample: `allowsAnyHTTPSCertificateForHost`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-12.test"),
						Line:     4,
						Column:   0,
					},
				},
				{
					CodeSample: `loadingUnvalidatedHTTPSPage = yes`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-12.test"),
						Line:     6,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-13",
			Rule:     NewNoListClipboardChanges(),
			Src:      SampleVulnerableHSJVM13,
			Filename: filepath.Join(tempDir, "HS-JVM-13.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `[[NSNotificationCenter defaultCenter] postNotificationName:UIPasteboardChangedNotification object:[UIPasteboard generalPasteboard]];`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-13.test"),
						Line:     2,
						Column:   59,
					},
				},
				{
					CodeSample: `[UIPasteboard generalPasteboard].string = @"your string";`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-13.test"),
						Line:     4,
						Column:   14,
					},
				},
				{
					CodeSample: `NSString *str =  [UIPasteboard generalPasteboard].string];`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-13.test"),
						Line:     5,
						Column:   31,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-14",
			Rule:     NewApplicationUsingSQLite(),
			Src:      SampleVulnerableHSJVM14,
			Filename: filepath.Join(tempDir, "HS-JVM-14.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `sqlite3_exec(...)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-14.test"),
						Line:     2,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-15",
			Rule:     NewNoUseNSTemporaryDirectory(),
			Src:      SampleVulnerableHSJVM15,
			Filename: filepath.Join(tempDir, "HS-JVM-15.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `const tempDirectory NSTemporaryDirectory = new NSTemporaryDirectory()`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-15.test"),
						Line:     2,
						Column:   47,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-16",
			Rule:     NewNoCopiesDataToTheClipboard(),
			Src:      SampleVulnerableHSJVM16,
			Filename: filepath.Join(tempDir, "HS-JVM-16.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var clipboard = UIPasteboard()`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-16.test"),
						Line:     2,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-17",
			Rule:     NewNoDownloadFileUsingAndroidDownloadManager(),
			Src:      SampleVulnerableHSJVM17,
			Filename: filepath.Join(tempDir, "HS-JVM-17.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `var foo = mContext.getSystemService(Context.DOWNLOAD_SERVICE);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-17.test"),
						Line:     5,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-18",
			Rule:     NewAndroidKeystore(),
			Src:      SampleVulnerableHSJVM18,
			Filename: filepath.Join(tempDir, "HS-JVM-18.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import security.KeyStore`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-18.test"),
						Line:     2,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-19",
			Rule:     NewAndroidNotifications(),
			Src:      SampleVulnerableHSJVM19,
			Filename: filepath.Join(tempDir, "HS-JVM-19.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `import android.app.NotificationManager`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-19.test"),
						Line:     2,
						Column:   15,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-20",
			Rule:     NewPotentialAndroidSQLInjection(),
			Src:      SampleVulnerableHSJVM20,
			Filename: filepath.Join(tempDir, "HS-JVM-20.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "String query = \"SELECT * FROM  messages WHERE uid= '\"+userInput+\"'\" ;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-20.test"),
						Line:     2,
						Column:   16,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-21",
			Rule:     NewSQLInjectionWithSQLite(),
			Src:      SampleVulnerableHSJVM21,
			Filename: filepath.Join(tempDir, "HS-JVM-21.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "String query = \"SELECT * FROM  messages WHERE uid= '\"+userInput+\"'\" ;",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-21.test"),
						Line:     5,
						Column:   16,
					},
				},
			},
		},
		//{
		//	Name:     "HS-JVM-22",
		//	Rule:     NewWebViewGETRequest(),
		//	Src:      SampleVulnerableHSJVM22,
		//	Filename: filepath.Join(tempDir, "HS-JVM-22.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-22.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-23",
		//	Rule:     NewWebViewPOSTRequest(),
		//	Src:      SampleVulnerableHSJVM23,
		//	Filename: filepath.Join(tempDir, "HS-JVM-23.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-23.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-24",
		//	Rule:     NewBase64Decode(),
		//	Src:      SampleVulnerableHSJVM24,
		//	Filename: filepath.Join(tempDir, "HS-JVM-24.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-24.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-25",
		//	Rule:     NewKeychainAccessAndMatch(),
		//	Src:      SampleVulnerableHSJVM25,
		//	Filename: filepath.Join(tempDir, "HS-JVM-25.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-25.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-27",
		//	Rule:     NewCookieStorage(),
		//	Src:      SampleVulnerableHSJVM27,
		//	Filename: filepath.Join(tempDir, "HS-JVM-27.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-27.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-28",
		//	Rule:     NewSetReadClipboard(),
		//	Src:      SampleVulnerableHSJVM28,
		//	Filename: filepath.Join(tempDir, "HS-JVM-28.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-28.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-29",
		//	Rule:     NewUsingLoadHTMLStringCanResultInject(),
		//	Src:      SampleVulnerableHSJVM29,
		//	Filename: filepath.Join(tempDir, "HS-JVM-29.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-29.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-30",
		//	Rule:     NewNoUseSFAntiPiracyJailbreak(),
		//	Src:      SampleVulnerableHSJVM30,
		//	Filename: filepath.Join(tempDir, "HS-JVM-30.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-30.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-31",
		//	Rule:     NewNoUseSFAntiPiracyIsPirated(),
		//	Src:      SampleVulnerableHSJVM31,
		//	Filename: filepath.Join(tempDir, "HS-JVM-31.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-31.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-32",
		//	Rule:     NewWeakMd5HashUsing(),
		//	Src:      SampleVulnerableHSJVM32,
		//	Filename: filepath.Join(tempDir, "HS-JVM-32.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-32.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-33",
		//	Rule:     NewWeakSha1HashUsing(),
		//	Src:      SampleVulnerableHSJVM33,
		//	Filename: filepath.Join(tempDir, "HS-JVM-33.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-33.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-34",
		//	Rule:     NewWeakECBEncryptionAlgorithmUsing(),
		//	Src:      SampleVulnerableHSJVM34,
		//	Filename: filepath.Join(tempDir, "HS-JVM-34.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-34.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-35",
		//	Rule:     NewUsingPtrace(),
		//	Src:      SampleVulnerableHSJVM35,
		//	Filename: filepath.Join(tempDir, "HS-JVM-35.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-35.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-36",
		//	Rule:     NewSuperUserPrivileges(),
		//	Src:      SampleVulnerableHSJVM36,
		//	Filename: filepath.Join(tempDir, "HS-JVM-36.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-36.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-37",
		//	Rule:     NewSendSMS(),
		//	Src:      SampleVulnerableHSJVM37,
		//	Filename: filepath.Join(tempDir, "HS-JVM-37.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-37.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-38",
		//	Rule:     NewBase64Encode(),
		//	Src:      SampleVulnerableHSJVM38,
		//	Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `Base64.getEncoder().encodeToString(input.getBytes());`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		//				Line:     5,
		//				Column:   21,
		//			},
		//		},
		//		{
		//			CodeSample: `String encodedString = new String(base64.encode(input.getBytes()));`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		//				Line:     8,
		//				Column:   42,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-39",
		//	Rule:     NewGpsLocation(),
		//	Src:      SampleVulnerableHSJVM39,
		//	Filename: filepath.Join(tempDir, "HS-JVM-39.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-39.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name:     "HS-JVM-40",
		//	Rule:     NewApplicationMayContainJailbreakDetectionMechanisms(),
		//	Src:      SampleVulnerableHSJVM40,
		//	Filename: filepath.Join(tempDir, "HS-JVM-40.test"),
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
		//			SourceLocation: engine.Location{
		//				Filename: filepath.Join(tempDir, "HS-JVM-40.test"),
		//				Line:     4,
		//				Column:   43,
		//			},
		//		},
		//	},
		//},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-JVM-1",
			Rule:     NewNoLogSensitiveInformation(),
			Src:      SampleSafeHSJVM1,
			Filename: filepath.Join(tempDir, "HS-JVM-1.test"),
		},
		{
			Name:     "HS-JVM-2",
			Rule:     NewHTTPRequestsConnectionsAndSessions(),
			Src:      SampleSafeHSJVM2,
			Filename: filepath.Join(tempDir, "HS-JVM-2.test"),
		},
		{
			Name:     "HS-JVM-3",
			Rule:     NewNoUsesSafetyNetAPI(),
			Src:      SampleSafeHSJVM3,
			Filename: filepath.Join(tempDir, "HS-JVM-3.test"),
		},
		{
			Name:     "HS-JVM-4",
			Rule:     NewNoUsesContentProvider(),
			Src:      SampleSafeHSJVM4,
			Filename: filepath.Join(tempDir, "HS-JVM-4.test"),
		},
		{
			Name:     "HS-JVM-5",
			Rule:     NewNoUseWithUnsafeBytes(),
			Src:      SampleSafeHSJVM5,
			Filename: filepath.Join(tempDir, "HS-JVM-5.test"),
		},
		{
			Name:     "HS-JVM-6",
			Rule:     NewNoUseLocalFileIOOperations(),
			Src:      SampleSafeHSJVM6,
			Filename: filepath.Join(tempDir, "HS-JVM-6.test"),
		},
		{
			Name:     "HS-JVM-7",
			Rule:     NewWebViewComponent(),
			Src:      SampleSafeHSJVM7,
			Filename: filepath.Join(tempDir, "HS-JVM-7.test"),
		},
		{
			Name:     "HS-JVM-8",
			Rule:     NewEncryptionAPI(),
			Src:      SampleSafeHSJVM8,
			Filename: filepath.Join(tempDir, "HS-JVM-8.test"),
		},
		{
			Name:     "HS-JVM-9",
			Rule:     NewKeychainAccess(),
			Src:      SampleSafeHSJVM9,
			Filename: filepath.Join(tempDir, "HS-JVM-9.test"),
		},
		{
			Name:     "HS-JVM-10",
			Rule:     NewNoUseProhibitedAPIs(),
			Src:      SampleSafeHSJVM10,
			Filename: filepath.Join(tempDir, "HS-JVM-10.test"),
		},
		{
			Name:     "HS-JVM-11",
			Rule:     NewApplicationAllowMITMAttacks(),
			Src:      SampleSafeHSJVM11,
			Filename: filepath.Join(tempDir, "HS-JVM-11.test"),
		},
		{
			Name:     "HS-JVM-12",
			Rule:     NewUIWebViewInApplicationIgnoringErrorsSSL(),
			Src:      SampleSafeHSJVM12,
			Filename: filepath.Join(tempDir, "HS-JVM-12.test"),
		},
		{
			Name:     "HS-JVM-13",
			Rule:     NewNoListClipboardChanges(),
			Src:      SampleSafeHSJVM13,
			Filename: filepath.Join(tempDir, "HS-JVM-13.test"),
		},
		{
			Name:     "HS-JVM-14",
			Rule:     NewApplicationUsingSQLite(),
			Src:      SampleSafeHSJVM14,
			Filename: filepath.Join(tempDir, "HS-JVM-14.test"),
		},
		{
			Name:     "HS-JVM-15",
			Rule:     NewNoUseNSTemporaryDirectory(),
			Src:      SampleSafeHSJVM15,
			Filename: filepath.Join(tempDir, "HS-JVM-15.test"),
		},
		{
			Name:     "HS-JVM-16",
			Rule:     NewNoCopiesDataToTheClipboard(),
			Src:      SampleSafeHSJVM16,
			Filename: filepath.Join(tempDir, "HS-JVM-16.test"),
		},
		{
			Name:     "HS-JVM-17",
			Rule:     NewNoDownloadFileUsingAndroidDownloadManager(),
			Src:      SampleSafeHSJVM17,
			Filename: filepath.Join(tempDir, "HS-JVM-17.test"),
		},
		{
			Name:     "HS-JVM-18",
			Rule:     NewAndroidKeystore(),
			Src:      SampleSafeHSJVM18,
			Filename: filepath.Join(tempDir, "HS-JVM-18.test"),
		},
		{
			Name:     "HS-JVM-19",
			Rule:     NewAndroidNotifications(),
			Src:      SampleSafeHSJVM19,
			Filename: filepath.Join(tempDir, "HS-JVM-19.test"),
		},
		{
			Name:     "HS-JVM-20",
			Rule:     NewPotentialAndroidSQLInjection(),
			Src:      SampleSafeHSJVM20,
			Filename: filepath.Join(tempDir, "HS-JVM-20.test"),
		},
		{
			Name:     "HS-JVM-21",
			Rule:     NewSQLInjectionWithSQLite(),
			Src:      SampleSafeHSJVM21,
			Filename: filepath.Join(tempDir, "HS-JVM-21.test"),
		},
		//{
		//	Name:     "HS-JVM-22",
		//	Rule:     NewWebViewGETRequest(),
		//	Src:      SampleSafeHSJVM22,
		//	Filename: filepath.Join(tempDir, "HS-JVM-22.test"),
		//},
		//{
		//	Name:     "HS-JVM-23",
		//	Rule:     NewWebViewPOSTRequest(),
		//	Src:      SampleSafeHSJVM23,
		//	Filename: filepath.Join(tempDir, "HS-JVM-23.test"),
		//},
		//{
		//	Name:     "HS-JVM-24",
		//	Rule:     NewBase64Decode(),
		//	Src:      SampleSafeHSJVM24,
		//	Filename: filepath.Join(tempDir, "HS-JVM-24.test"),
		//},
		//{
		//	Name:     "HS-JVM-25",
		//	Rule:     NewKeychainAccessAndMatch(),
		//	Src:      SampleSafeHSJVM25,
		//	Filename: filepath.Join(tempDir, "HS-JVM-25.test"),
		//},
		//{
		//	Name:     "HS-JVM-27",
		//	Rule:     NewCookieStorage(),
		//	Src:      SampleSafeHSJVM27,
		//	Filename: filepath.Join(tempDir, "HS-JVM-27.test"),
		//},
		//{
		//	Name:     "HS-JVM-28",
		//	Rule:     NewSetReadClipboard(),
		//	Src:      SampleSafeHSJVM28,
		//	Filename: filepath.Join(tempDir, "HS-JVM-28.test"),
		//},
		//{
		//	Name:     "HS-JVM-29",
		//	Rule:     NewUsingLoadHTMLStringCanResultInject(),
		//	Src:      SampleSafeHSJVM29,
		//	Filename: filepath.Join(tempDir, "HS-JVM-29.test"),
		//},
		//{
		//	Name:     "HS-JVM-30",
		//	Rule:     NewNoUseSFAntiPiracyJailbreak(),
		//	Src:      SampleSafeHSJVM30,
		//	Filename: filepath.Join(tempDir, "HS-JVM-30.test"),
		//},
		//{
		//	Name:     "HS-JVM-31",
		//	Rule:     NewNoUseSFAntiPiracyIsPirated(),
		//	Src:      SampleSafeHSJVM31,
		//	Filename: filepath.Join(tempDir, "HS-JVM-31.test"),
		//},
		//{
		//	Name:     "HS-JVM-32",
		//	Rule:     NewWeakMd5HashUsing(),
		//	Src:      SampleSafeHSJVM32,
		//	Filename: filepath.Join(tempDir, "HS-JVM-32.test"),
		//},
		//{
		//	Name:     "HS-JVM-33",
		//	Rule:     NewWeakSha1HashUsing(),
		//	Src:      SampleSafeHSJVM33,
		//	Filename: filepath.Join(tempDir, "HS-JVM-33.test"),
		//},
		//{
		//	Name:     "HS-JVM-34",
		//	Rule:     NewWeakECBEncryptionAlgorithmUsing(),
		//	Src:      SampleSafeHSJVM34,
		//	Filename: filepath.Join(tempDir, "HS-JVM-34.test"),
		//},
		//{
		//	Name:     "HS-JVM-35",
		//	Rule:     NewUsingPtrace(),
		//	Src:      SampleSafeHSJVM35,
		//	Filename: filepath.Join(tempDir, "HS-JVM-35.test"),
		//},
		//{
		//	Name:     "HS-JVM-36",
		//	Rule:     NewSuperUserPrivileges(),
		//	Src:      SampleSafeHSJVM36,
		//	Filename: filepath.Join(tempDir, "HS-JVM-36.test"),
		//},
		//{
		//	Name:     "HS-JVM-37",
		//	Rule:     NewSendSMS(),
		//	Src:      SampleSafeHSJVM37,
		//	Filename: filepath.Join(tempDir, "HS-JVM-37.test"),
		//},
		//{
		//	Name:     "HS-JVM-38",
		//	Rule:     NewBase64Encode(),
		//	Src:      SampleSafeHSJVM38,
		//	Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		//},
		//{
		//	Name:     "HS-JVM-38",
		//	Rule:     NewBase64Encode(),
		//	Src:      Sample2SafeHSJVM38,
		//	Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		//},
		//{
		//	Name:     "HS-JVM-39",
		//	Rule:     NewGpsLocation(),
		//	Src:      SampleSafeHSJVM39,
		//	Filename: filepath.Join(tempDir, "HS-JVM-39.test"),
		//},
		//{
		//	Name:     "HS-JVM-40",
		//	Rule:     NewApplicationMayContainJailbreakDetectionMechanisms(),
		//	Src:      SampleSafeHSJVM40,
		//	Filename: filepath.Join(tempDir, "HS-JVM-40.test"),
		//},
	}

	testutil.TestSafeCode(t, testcases)
}
