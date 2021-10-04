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

package engines_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	enginesenum "github.com/ZupIT/horusec/internal/enums/engines"
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/csharp"
	"github.com/ZupIT/horusec/internal/services/engines/dart"
	"github.com/ZupIT/horusec/internal/services/engines/java"
	"github.com/ZupIT/horusec/internal/services/engines/kotlin"
	"github.com/ZupIT/horusec/internal/services/engines/kubernetes"
	"github.com/ZupIT/horusec/internal/services/engines/leaks"
	"github.com/ZupIT/horusec/internal/services/engines/nginx"
	"github.com/ZupIT/horusec/internal/services/engines/nodejs"
	"github.com/ZupIT/horusec/internal/services/engines/swift"
)

type testcase struct {
	name     string
	src      string
	rule     text.TextRule
	findings []engine.Finding
}

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []testcase{
		{
			name: "Leaks-HS-LEAKS-1",
			rule: leaks.NewAWSManagerID(),
			src:  SampleVulnerableLeaksRegularAWSManagerID,
			findings: []engine.Finding{
				{
					CodeSample: "ACCESS_KEY: 'AKIAJSIE27KKMHXI3BJQ'",
					SourceLocation: engine.Location{
						Line:   7,
						Column: 18,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-2",
			rule: leaks.NewAWSSecretKey(),
			src:  SampleVulnerableLeaksRegularAWSSecretKey,
			findings: []engine.Finding{
				{
					CodeSample: `AWS_SECRET_KEY: 'doc5eRXFpsWllGC5yKJV/Ymm5KwF+IRZo95EudOm'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-3",
			rule: leaks.NewAWSMWSKey(),
			src:  SampleVulnerableLeaksRegularAWSMWSKey,
			findings: []engine.Finding{
				{
					CodeSample: `AWS_WMS_KEY: 'amzn.mws.986478f0-9775-eabc-2af4-e499a8496828'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 20,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-4",
			rule: leaks.NewFacebookSecretKey(),
			src:  SampleVulnerableLeaksRegularFacebookSecretKey,
			findings: []engine.Finding{
				{
					CodeSample: `FB_SECRET_KEY: 'cb6f53505911332d30867f44a1c1b9b5'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-5",
			rule: leaks.NewFacebookClientID(),
			src:  SampleVulnerableLeaksRegularFacebookClientID,
			findings: []engine.Finding{
				{
					CodeSample: `FB_CLIENT_ID: '148695999071979'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-7",
			rule: leaks.NewTwitterClientID(),
			src:  SampleVulnerableLeaksRegularTwitterClientID,
			findings: []engine.Finding{
				{
					CodeSample: `TWITTER_CLIENT_ID: '1h6433fsvygnyre5a40'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-LEAKS-6",
			rule: leaks.NewTwitterSecretKey(),
			src:  SampleVulnerableLeaksRegularTwitterSecretKey,
			findings: []engine.Finding{
				{
					CodeSample: `TWITTER_SECRET_KEY: 'ej64cqk9k8px9ae3e47ip89l7if58tqhpxi1r'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-8",
			rule: leaks.NewGithub(),
			src:  SampleVulnerableLeaksRegularGithub,
			findings: []engine.Finding{
				{
					CodeSample: `GITHUB_SECRET_KEY: 'edzvPbU3SYUc7pFc9le20lzIRErTOaxCABQ1'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-9",
			rule: leaks.NewLinkedInClientID(),
			src:  SampleVulnerableLeaksRegularLinkedInClientID,
			findings: []engine.Finding{
				{
					CodeSample: `LINKEDIN_CLIENT_ID: 'g309xttlaw25'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-LEAKS-10",
			rule: leaks.NewLinkedInSecretKey(),
			src:  SampleVulnerableLeaksRegularLinkedInSecretKey,
			findings: []engine.Finding{
				{
					CodeSample: `LINKEDIN_SECRET_KEY: '0d16kcnjyfzmcmjp'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-LEAKS-11",
			rule: leaks.NewSlack(),
			src:  SampleVulnerableLeaksRegularSlack,
			findings: []engine.Finding{
				{
					CodeSample: `SLACK_WEBHOOK: 'https://hooks.slack.com/services/TNeqvYPeO/BncTJ74Hf/NlvFFKKAKPkd6h7FlQCz1Blu'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 22,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-12",
			rule: leaks.NewAsymmetricPrivateKey(),
			src:  SampleVulnerableLeaksRegularAsymmetricPrivateKey,
			findings: []engine.Finding{
				{
					CodeSample: `SSH_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anGcmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYDVQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD...bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEFBQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdhz3P668YfhUbKdRF6S42Cg6zn-----END PRIVATE KEY-----'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 24,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-13",
			rule: leaks.NewGoogleAPIKey(),
			src:  SampleVulnerableLeaksRegularGoogleAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `GCP_API_KEY: 'AIzaMPZHYiu1RdzE1nG2SaVyOoz244TuacQIR6m'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 20,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-14",
			rule: leaks.NewGoogleGCPServiceAccount(),
			src:  SampleVulnerableLeaksRegularGoogleGCPServiceAccount,
			findings: []engine.Finding{
				{
					CodeSample: `GCP_SERVICE_ACCOUNT: '18256698220617903267772185514630273595-oy8_uzouz8tyy46y84ckrwei9_6rq_pb.apps.googleusercontent.com'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-15",
			rule: leaks.NewHerokuAPIKey(),
			src:  SampleVulnerableLeaksRegularHerokuAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `HEROKU_API_KEY: '3623f8e9-2d05-c9bb-2209082d6b5c'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-16",
			rule: leaks.NewMailChimpAPIKey(),
			src:  SampleVulnerableLeaksRegularMailChimpAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `MAILCHIMP_API_KEY: 'f7e9c13c10d0b19c3bb003a9f635d488-us72'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-17",
			rule: leaks.NewMailgunAPIKey(),
			src:  SampleVulnerableLeaksRegularMailgunAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `MAILGUN_API_KEY: 'key-xke9nbc2i5po5cjw3ngyxiz450zxpapu'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-18",
			rule: leaks.NewPayPalBraintreeAccessToken(),
			src:  SampleVulnerableLeaksRegularPayPalBraintreeAccessToken,
			findings: []engine.Finding{
				{
					CodeSample: `PAY_PAL_ACCESS_TOKEN: 'access_token$production$mk0sech2v7qqsol3$db651af2221c22b4ca2f0f583798135e'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 29,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-19",
			rule: leaks.NewPicaticAPIKey(),
			src:  SampleVulnerableLeaksRegularPicaticAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `PICATIC_API_KEY: 'sk_live_voy1p9k7r9g9j8ezmif488nk2p8310nl'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 24,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-20",
			rule: leaks.NewSendGridAPIKey(),
			src:  SampleVulnerableLeaksRegularSendGridAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `SEND_GRID_API_KEY: 'SG.44b7kq3FurdH0bSHBGjPSWhE8vJ.1evu4Un0TXFIb1_6zW4YOdjTMeE'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 26,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-21",
			rule: leaks.NewStripeAPIKey(),
			src:  SampleVulnerableLeaksRegularStripeAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `STRIPE_API_KEY: 'rk_live_8qSZpoI9t0BOGkOLVzvesc6K'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-22",
			rule: leaks.NewSquareAccessToken(),
			src:  SampleVulnerableLeaksRegularSquareAccessToken,
			findings: []engine.Finding{
				{
					CodeSample: `SQUARE_ACCESS_TOKEN: 'sq0atp-clYRBSht6oefa7w_2R56ra'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 28,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-23",
			rule: leaks.NewSquareOAuthSecret(),
			src:  SampleVulnerableLeaksRegularSquareOAuthSecret,
			findings: []engine.Finding{
				{
					CodeSample: `SQUARE_SECRET: 'sq0csp-LsEBYQNja]OgT3hRxjJV5cWX^XjpT12n3QkRY_vep2z'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 22,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-24",
			rule: leaks.NewTwilioAPIKey(),
			src:  SampleVulnerableLeaksRegularTwilioAPIKey,
			findings: []engine.Finding{
				{
					CodeSample: `TWILIO_API_KEY: '^SK9ae6bd84ccd091eb6bfad8e2a474af95'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 6,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-25",
			rule: leaks.NewHardCodedCredentialGeneric(),
			src:  SampleVulnerableLeaksRegularHardCodedCredentialGeneric,
			findings: []engine.Finding{
				{
					CodeSample: `POSTGRES_DBPASSWD: 'Ch@ng3m3'`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 15,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-26",
			rule: leaks.NewHardCodedPassword(),
			src:  SampleVulnerableLeaksRegularHardCodedPassword,
			findings: []engine.Finding{
				{
					CodeSample: `DB_PASSWORD="gorm"`,
					SourceLocation: engine.Location{
						Line:   12,
						Column: 4,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-27",
			rule: leaks.NewPasswordExposedInHardcodedURL(),
			src:  SampleVulnerableLeaksRegularPasswordExposedInHardcodedURL,
			findings: []engine.Finding{
				{
					CodeSample: `dsn := "postgresql://gorm:gorm@127.0.0.1:5432/gorm?sslmode=disable"`,
					SourceLocation: engine.Location{
						Line:   10,
						Column: 9,
					},
				},
			},
		},
		{
			name: "Leaks-HS-LEAKS-28",
			rule: leaks.NewWPConfig(),
			src:  SampleVulnerableLeaksRegularWPConfig,
			findings: []engine.Finding{
				{
					CodeSample: `define('AUTH_KEY', 'put your unique phrase here');`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 0,
					},
				},
				{
					CodeSample: `define('DB_PASSWORD', 'wen0221!');`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 0,
					},
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			findings := executeRule(t, tt)
			assert.Len(t, findings, len(tt.findings), "Expected equal issues on vulnerable code")
			for idx, finding := range findings {
				expected := tt.findings[idx]
				assert.Equal(t, expected.CodeSample, finding.CodeSample)
				assert.Equal(t, expected.SourceLocation, finding.SourceLocation)
				assert.Equal(t, tt.rule.ID, finding.ID)
				assert.Equal(t, tt.rule.Name, finding.Name)
				assert.Equal(t, tt.rule.Severity, finding.Severity)
				assert.Equal(t, tt.rule.Confidence, finding.Confidence)
				assert.Equal(t, tt.rule.Description, finding.Description)
			}
		})
	}
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []testcase{
		{
			name: "Leaks-HS-LEAKS-1",
			rule: leaks.NewAWSManagerID(),
			src:  SampleSafeLeaksRegularAWSManagerID,
		},
		{
			name: "Leaks-HS-LEAKS-2",
			rule: leaks.NewAWSSecretKey(),
			src:  SampleSafeLeaksRegularAWSSecretKey,
		},
		{
			name: "Leaks-HS-LEAKS-3",
			rule: leaks.NewAWSMWSKey(),
			src:  SampleSafeLeaksRegularAWSMWSKey,
		},
		{
			name: "Leaks-HS-LEAKS-4",
			rule: leaks.NewFacebookSecretKey(),
			src:  SampleSafeLeaksRegularFacebookSecretKey,
		},
		{
			name: "Leaks-HS-LEAKS-5",
			rule: leaks.NewFacebookClientID(),
			src:  SampleSafeLeaksRegularFacebookClientID,
		},
		{
			name: "Leaks-HS-LEAKS-7",
			rule: leaks.NewTwitterClientID(),
			src:  SampleSafeLeaksRegularTwitterClientID,
		},
		{
			name: "Leaks-LEAKS-6",
			rule: leaks.NewTwitterSecretKey(),
			src:  SampleSafeLeaksRegularTwitterSecretKey,
		},
		{
			name: "Leaks-HS-LEAKS-8",
			rule: leaks.NewGithub(),
			src:  SampleSafeLeaksRegularGithub,
		},
		{
			name: "Leaks-HS-LEAKS-9",
			rule: leaks.NewLinkedInClientID(),
			src:  SampleSafeLeaksRegularLinkedInClientID,
		},
		{
			name: "Leaks-LEAKS-10",
			rule: leaks.NewLinkedInSecretKey(),
			src:  SampleSafeLeaksRegularLinkedInSecretKey,
		},
		{
			name: "Leaks-LEAKS-11",
			rule: leaks.NewSlack(),
			src:  SampleSafeLeaksRegularSlack,
		},
		{
			name: "Leaks-HS-LEAKS-12",
			rule: leaks.NewAsymmetricPrivateKey(),
			src:  SampleSafeLeaksRegularAsymmetricPrivateKey,
		},
		{
			name: "Leaks-HS-LEAKS-13",
			rule: leaks.NewGoogleAPIKey(),
			src:  SampleSafeLeaksRegularGoogleAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-14",
			rule: leaks.NewGoogleGCPServiceAccount(),
			src:  SampleSafeLeaksRegularGoogleGCPServiceAccount,
		},
		{
			name: "Leaks-HS-LEAKS-15",
			rule: leaks.NewHerokuAPIKey(),
			src:  SampleSafeLeaksRegularHerokuAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-16",
			rule: leaks.NewMailChimpAPIKey(),
			src:  SampleSafeLeaksRegularMailChimpAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-17",
			rule: leaks.NewMailgunAPIKey(),
			src:  SampleSafeLeaksRegularMailgunAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-18",
			rule: leaks.NewPayPalBraintreeAccessToken(),
			src:  SampleSafeLeaksRegularPayPalBraintreeAccessToken,
		},
		{
			name: "Leaks-HS-LEAKS-19",
			rule: leaks.NewPicaticAPIKey(),
			src:  SampleSafeLeaksRegularPicaticAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-20",
			rule: leaks.NewSendGridAPIKey(),
			src:  SampleSafeLeaksRegularSendGridAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-21",
			rule: leaks.NewStripeAPIKey(),
			src:  SampleSafeLeaksRegularStripeAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-22",
			rule: leaks.NewSquareAccessToken(),
			src:  SampleSafeLeaksRegularSquareAccessToken,
		},
		{
			name: "Leaks-HS-LEAKS-23",
			rule: leaks.NewSquareOAuthSecret(),
			src:  SampleSafeLeaksRegularSquareOAuthSecret,
		},
		{
			name: "Leaks-HS-LEAKS-24",
			rule: leaks.NewTwilioAPIKey(),
			src:  SampleSafeLeaksRegularTwilioAPIKey,
		},
		{
			name: "Leaks-HS-LEAKS-25",
			rule: leaks.NewHardCodedCredentialGeneric(),
			src:  SampleSafeLeaksRegularHardCodedCredentialGeneric,
		},
		{
			name: "Leaks-HS-LEAKS-26",
			rule: leaks.NewHardCodedPassword(),
			src:  SampleSafeLeaksRegularHardCodedPassword,
		},
		{
			name: "Leaks-HS-LEAKS-27",
			rule: leaks.NewPasswordExposedInHardcodedURL(),
			src:  SampleSafeLeaksRegularPasswordExposedInHardcodedURL,
		},
		{
			name: "Leaks-HS-LEAKS-28",
			rule: leaks.NewWPConfig(),
			src:  SampleSafeLeaksRegularWPConfig,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			findings := executeRule(t, tt)
			assert.Empty(t, findings, "Expected not issues on safe code to rule %s", tt.name)
		})
	}
}

func TestGetRules(t *testing.T) {
	testcases := []struct {
		engine             string
		manager            *engines.RuleManager
		expectedTotalRules int
	}{
		{
			engine:             "Nodejs",
			manager:            nodejs.NewRules(),
			expectedTotalRules: 53,
		},
		{
			engine:             "Nginx",
			manager:            nginx.NewRules(),
			expectedTotalRules: 4,
		},
		{
			engine:             "Leaks",
			manager:            leaks.NewRules(),
			expectedTotalRules: 28,
		},
		{
			engine:             "Kubernetes",
			manager:            kubernetes.NewRules(),
			expectedTotalRules: 9,
		},
		{
			engine:             "Kotlin",
			manager:            kotlin.NewRules(),
			expectedTotalRules: 40,
		},
		{
			engine:             "Java",
			manager:            java.NewRules(),
			expectedTotalRules: 189,
		},
		{
			engine:             "Dart",
			manager:            dart.NewRules(),
			expectedTotalRules: 17,
		},
		{
			engine:             "Csharp",
			manager:            csharp.NewRules(),
			expectedTotalRules: 74,
		},
		{
			engine:             "Swift",
			manager:            swift.NewRules(),
			expectedTotalRules: 23,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.engine, func(t *testing.T) {
			rules := tt.manager.GetAllRules()
			expressions := 0
			rulesID := map[string]bool{}

			for _, rule := range rules {
				r, ok := rule.(text.TextRule)
				require.True(t, ok, "Expected rule type of text.TextRule, got %T", rule)
				expressions += len(r.Expressions)

				if rulesID[r.ID] == true {
					t.Errorf(
						"Rule in %s is duplicated ID(%s) => Name: %s, Description: %s, Type: %v", tt.engine, r.ID, r.Name, r.Description, r.Type,
					)
				} else {
					// Record this element as an encountered element.
					rulesID[r.ID] = true
				}

			}

			assert.Greater(t, len(rules), 0)
			assert.Greater(t, expressions, 0)

			assert.Equal(t, len(rules), tt.expectedTotalRules, "Total rules is not equal the expected")
			assert.Equal(t, len(rulesID), tt.expectedTotalRules, "Rules ID is not equal the expected")
		})
	}
}

func executeRule(tb testing.TB, tt testcase) []engine.Finding {
	textFile, err := text.NewTextFile("", []byte(tt.src))
	require.Nil(tb, err, "Expected nil error to create text file")

	unit := text.TextUnit{
		Files: []text.TextFile{
			textFile,
		},
	}

	return engine.RunMaxUnitsByAnalysis(
		[]engine.Unit{unit}, []engine.Rule{tt.rule}, enginesenum.DefaultMaxUnitsPerAnalysis,
	)

}
