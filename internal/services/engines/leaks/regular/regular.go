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
package regular

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewLeaksRegularAWSManagerID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "18332543-1ec3-47c7-b064-2a159359bc73",
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

func NewLeaksRegularAWSSecretKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ea46d798-5042-45f7-8909-4af5a1e5a2e7",
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

func NewLeaksRegularAWSMWSKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0dc1ba76-3d27-400d-9d2f-b9f29e1f5bfb",
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

func NewLeaksRegularFacebookSecretKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d2f7d0ba-3924-465f-ab3b-cc982716be28",
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

func NewLeaksRegularFacebookClientID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "14b76fce-787e-4455-b0fe-07b1f7439e44",
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

func NewLeaksRegularTwitterSecretKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f385deb6-61de-4469-92e1-53a587022dd3",
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

func NewLeaksRegularTwitterClientID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1519a250-9e23-4b4e-941e-a0bfd2386e19",
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

func NewLeaksRegularGithub() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "894980a0-808a-4e6b-871a-6afe40f43005",
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

func NewLeaksRegularLinkedInClientID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6d71ebbc-4d52-4a7b-a4fb-d09145c2abdd",
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

func NewLeaksRegularLinkedInSecretKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "78556a58-0ff6-420f-8e42-63e6330cc76e",
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

func NewLeaksRegularSlack() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3122329f-91f9-4e95-a3aa-045e3cc73932",
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

func NewLeaksRegularAsymmetricPrivateKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "51d26605-42bc-4700-9f7e-8017b7fe5927",
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

func NewLeaksRegularGoogleAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e793da8a-20b4-4295-b1e7-761031441dbc",
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

func NewLeaksRegularGoogleGCPServiceAccount() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1ca0e0e6-da90-460a-abe3-46a829a7cc7b",
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

func NewLeaksRegularHerokuAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "87255d86-a271-45ea-8fc5-88cb47957563",
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

func NewLeaksRegularMailChimpAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8d52c328-d955-4d4d-bbc4-d495176d5aa2",
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

func NewLeaksRegularMailgunAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3c806272-b40a-4e74-8b79-8ea0b1d8e580",
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

func NewLeaksRegularPayPalBraintreeAccessToken() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "574dbf14-1f08-46a7-8ea6-93a38c884620",
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

func NewLeaksRegularPicaticAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9bbd94af-2c25-4184-a03c-9fa4b5199210",
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

func NewLeaksRegularSendGridAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "65c6903a-3020-42e7-b472-b2278410a438",
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

func NewLeaksRegularStripeAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "646ce9f8-3081-4df8-b175-1f0c2c754ccd",
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

func NewLeaksRegularSquareAccessToken() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b6cb61aa-fc61-41eb-9859-780e3b059f10",
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

func NewLeaksRegularSquareOAuthSecret() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0ce81561-6e85-4c11-a2fd-a133e752e946",
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

func NewLeaksRegularTwilioAPIKey() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "81dd9f27-d333-4f49-be07-11823b8876db",
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

func NewLeaksRegularHardCodedCredentialGeneric() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "00db8b1e-a9ef-4533-803e-66514dabdf28",
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

func NewLeaksRegularHardCodedPassword() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3dfb3624-e218-4e2b-a7e9-814b64aaa43e",
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

func NewLeaksRegularPasswordExposedInHardcodedURL() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b4c300cd-1cdd-4039-9b19-8163acd91bac",
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

func NewLeaksRegularWPConfig() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5332204a-0d3d-4fe3-a73b-29525101afa0",
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
