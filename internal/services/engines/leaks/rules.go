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

package leaks

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewAWSManagerID() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-1",
			Name:        "AWS Manager ID",
			Description: "When use AWS Manager ID is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		},
	}
}

func NewAWSSecretKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-2",
			Name:        "AWS Secret Key",
			Description: "When use AWS Secret Key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]`),
			regexp.MustCompile(`AAAA(?:[0-9A-Za-z+/])+={0,3}(?:.+@.+)`),
		},
	}
}

func NewAWSMWSKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-3",
			Name:        "AWS MWS key",
			Description: "When use AWS MWS key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		},
	}
}

func NewFacebookSecretKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-4",
			Name:        "Facebook Secret Key",
			Description: "When use Facebook Secret Key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]`),
		},
	}
}

func NewFacebookClientID() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-5",
			Name:        "Facebook Client ID",
			Description: "When use Facebook Client ID is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]`),
		},
	}
}

func NewTwitterSecretKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-6",
			Name:        "Twitter Secret Key",
			Description: "When use Twitter Secret Key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)twitter(.{0,20})?[0-9a-z]{35,44}`),
		},
	}
}

func NewTwitterClientID() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-7",
			Name:        "Twitter Client ID",
			Description: "When use Twitter Client ID is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)twitter(.{0,20})?[0-9a-z]{18,25}`),
		},
	}
}

func NewGithub() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-8",
			Name:        "Github",
			Description: "A GitHub access token was found. This pose a critical threat against your organization since it can give access not only to the platform itself and all the members of your (perhaps private) organization to feed more accurate spear phishing attacks but also to actual source code from your applications. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)github(.{0,20})?(?-i)[0-9a-zA-Z]{35,40}`),
		},
	}
}

func NewLinkedInClientID() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-9",
			Name:        "LinkedIn Client ID",
			Description: "When use LinkedIn Client ID is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)linkedin(.{0,20})?(?-i)[0-9a-z]{12}`),
		},
	}
}

func NewLinkedInSecretKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-10",
			Name:        "LinkedIn Secret Key",
			Description: "When use LinkedIn Secret Key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)linkedin(.{0,20})?[0-9a-z]{16}`),
		},
	}
}

func NewSlack() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-11",
			Name:        "Slack",
			Description: "A hardcoded credential for your company's Slack can pose a huge threat to the safety and image of your company, since, in the wrong hands, this could lead to data leaking, a high chance of a successful spear phishing attacks and even access to logs and other development related conversations that could leverage a more critical attack. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})?`),
			regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
		},
	}
}

func NewAsymmetricPrivateKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-12",
			Name:        "Asymmetric Private Key",
			Description: "Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
			regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
		},
	}
}

func NewGoogleAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-13",
			Name:        "Google API key",
			Description: "When use Google API key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
			regexp.MustCompile(`ya29\\.[0-9A-Za-z\\-_]+`),
		},
	}
}

func NewGoogleGCPServiceAccount() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-14",
			Name:        "Google (GCP) Service Account",
			Description: "When use Google (GCP) Service Account is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`"type": "service_account"`),
			regexp.MustCompile(`(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]`),
			regexp.MustCompile(`(?i)(google|gcp|auth)(.{0,20})?['\"][0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com['\"]`),
		},
	}
}

func NewHerokuAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-15",
			Name:        "Heroku API key",
			Description: "Hardcoded credentials pose a huge threat to your cloud provider account since you can lose control over who can access some resources, which can lead not only to data access violation but also to improper usage of resources leading to a financial loss. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		},
	}
}

func NewMailChimpAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-16",
			Name:        "MailChimp API key",
			Description: "Mail and/or SMS providers are a huge entrypoint for more sophisticated attacks or even attacks focused on damaging a brand's reputation. Leaving them in your source code will lead your team to lost track of who can access and personificate your company or application. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(mailchimp|mc)(.{0,20})?[0-9a-f]{32}-us[0-9]{1,2}`),
		},
	}
}

func NewMailgunAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-17",
			Name:        "Mailgun API key",
			Description: "Mail and/or SMS providers are a huge entrypoint for more sophisticated attacks or even attacks focused on damaging a brand's reputation. Leaving them in your source code will lead your team to lost track of who can access and personificate your company or application. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`((?i)(mailgun|mg)(.{0,20})?)?key-[0-9a-z]{32}`),
		},
	}
}

func NewPayPalBraintreeAccessToken() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-18",
			Name:        "PayPal Braintree access token",
			Description: "Payment providers are the barebones of your companies monetization so it is a absolutely disaster if any of this tokens fall in wrong hands since they can provide access to crucial information about your company, and in worst case scenarios even lead to big financial loss. It's important to keep this kind of info in some form of secret manager, e.g Hashicorp's Vault. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
		},
	}
}

func NewPicaticAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-19",
			Name:        "Picatic API key",
			Description: "When use Picatic API key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sk_live_[0-9a-z]{32}`),
		},
	}
}

func NewSendGridAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-20",
			Name:        "SendGrid API Key",
			Description: "When use SendGrid API Key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SG\.[\w_]{16,32}\.[\w_]{16,64}`),
		},
	}
}

func NewStripeAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-21",
			Name:        "Stripe API key",
			Description: "When use Stripe API key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)stripe(.{0,20})?[sr]k_live_[0-9a-zA-Z]{24}`),
		},
	}
}

func NewSquareAccessToken() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-22",
			Name:        "Square access token",
			Description: "When use Square access token is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`),
		},
	}
}

func NewSquareOAuthSecret() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-23",
			Name:        "Square OAuth secret",
			Description: "When use Square OAuth secret is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sq0csp-[0-9A-Za-z\\-_]{43}`),
		},
	}
}

func NewTwilioAPIKey() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-24",
			Name:        "Twilio API key",
			Description: "When use Twilio API key is recommended use vault or environment variable encrypted for the best security. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)twilio(.{0,20})?SK[0-9a-f]{32}`),
		},
	}
}

func NewHardCodedCredentialGeneric() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-25",
			Name:        "Potential Hard-coded credential",
			Description: "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(dbpasswd|dbuser|dbname|dbhost|api_key|apikey|client_secret|clientsecret|access_key|accesskey|secret_key|secretkey)(.{0,20})?['|"]([0-9a-zA-Z-_\/+!{}/=:@#%\*]{4,120})['|"]`),
		},
	}
}

func NewHardCodedPassword() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-26",
			Name:        "Hard-coded password",
			Description: "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(set)?password\s*(.?=.?|\()\s*['|\"]\w+[[:print:]]*['|\"]`),
			regexp.MustCompile(`(?i)(set)?pass\s*(.?=.?|\()\s*['|\"]\w+[[:print:]]*['|\"]`),
			regexp.MustCompile(`(?i)(set)?pwd\s*(.?=.?|\()\s*['|\"]\w+[[:print:]]*['|\"]`),
			regexp.MustCompile(`(?i)(set)?passwd\s*(.?=.?|\()\s*['|\"]\w+[[:print:]]*['|\"]`),
			regexp.MustCompile(`(?i)(set)?senha\s*(.?=.?|\()\s*['|\"]\w+[[:print:]]*['|\"]`),
		},
	}
}

func NewPasswordExposedInHardcodedURL() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-27",
			Name:        "Password found in a hardcoded URL",
			Description: "A password was found in a hardcoded URL, this can lead to not only the leak of this password but also a failure point to some more sophisticated CSRF and SSRF attacks. Check CWE-352 (https://cwe.mitre.org/data/definitions/352.html) and CWE-918 (https://cwe.mitre.org/data/definitions/918.html) for more details.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}/?.?`),
		},
	}
}

func NewWPConfig() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-LEAKS-28",
			Name:        "Wordpress configuration file disclosure",
			Description: "Wordpress configuration file exposed, this can lead to the leak of admin passwords, database credentials and a lot of sensitive data about the system. Check CWE-200 (https://cwe.mitre.org/data/definitions/200.html) for more details.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER).*,\s*['|"].{6,120}['|"]`),
		},
	}
}
