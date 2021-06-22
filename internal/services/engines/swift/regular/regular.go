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

package regular

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewSwiftRegularRealmDatabase() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4bbe89c6-c2dc-11eb-a035-13ab0aa767e8",
			Name:        "Realm Database",
			Description: "App uses Realm Database. Sensitive Information should be encrypted.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`realm\.write`),
		},
	}
}

func NewSwiftRegularTLSMinimum() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "26aa8e92-c240-11eb-a035-13ab0aa767e8",
			Name:        "Deperected tls property",
			Description: "Use of deprecated property tlsMinimumSupportedProtocol. To avoid potential security risks, use tlsMinimumSupportedProtocolVersion",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.tlsMinimumSupportedProtocol`),
		},
	}
}

func NewSwiftRegularUIPasteboard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "65ae22c4-c23c-11eb-a035-13ab0aa767e8",
			Name:        "UIPasteboard",
			Description: "This application uses UIPasteboard, improper use of this class can lead to security issues.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIPasteboard`),
		},
	}
}

func NewSwiftRegularFileProtection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "37870fe6-c23c-11eb-a035-13ab0aa767e8",
			Name:        "File protection",
			Description: "The file has no special protections associated with it.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\.noFileProtection`),
		},
	}
}

func NewSwiftRegularWebViewSafari() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "88c1786e-c238-11eb-a035-13ab0aa767e8",
			Name:        "WebView Safari",
			Description: "It is recommended to use WKWebView instead of SFSafariViewController or UIWebView to prevent navigating to arbitrary URLs.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`UIWebView|SFSafariViewController`),
		},
	}
}

func NewSwiftRegularKeyboardCache() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5efb173e-c237-11eb-a035-13ab0aa767e8",
			Name:        "Keyboard cache",
			Description: "Keyboard cache should be disabled for all sensitive data inputs.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.autocorrectionType = .no`),
		},
	}
}

func NewSwiftRegularMD4Collision() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "32d631d6-c235-11eb-a035-13ab0aa767e8",
			Name:        "Weak MD4 hash using",
			Description: "MD4 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_MD4\(`),
		},
	}
}

func NewSwiftRegularMD2Collision() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "363a5186-c235-11eb-a035-13ab0aa767e8",
			Name:        "Weak MD2 hash using",
			Description: "MD2 is a weak hash, which can generate repeated hashes. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CC_MD2\(`),
		},
	}
}
