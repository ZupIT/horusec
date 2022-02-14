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

//nolint:lll multiple regex is not possible broken lines
package nginx

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewIncludeXFrameOptionsHeader() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-NGINX-1",
			Name:        "Improper Restriction of Rendered UI Layers or Frames",
			Description: "Your Nginx file must include the X-Frame-Options header. A web application is expected to place restrictions on whether it is allowed to be rendered within frames, iframes, objects, embed or applet elements. Without the restrictions, users can be tricked into interacting with the application when they were not intending to. For more information checkout the CWE-1021 (https://cwe.mitre.org/data/definitions/1021.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.NotMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`add_header X-Frame-Options (?i)(sameorigin|"sameorigin"|deny|"deny");`),
		},
	}
}

func NewIncludeXContentTypeOptionsHeader() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-NGINX-2",
			Name:        "Missing X-Content-Type-Options header",
			Description: "Setting this header will prevent the browser from interpreting files as a different MIME type to what is specified in the Content-Type HTTP header (e.g. treating text/plain as text/css). For more information checkout https://owasp.org/www-project-secure-headers/#x-content-type-options",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.NotMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`add_header X-Content-Type-Options (?i)(nosniff|"nosniff");`),
		},
	}
}

func NewIncludeContentSecurityPolicyHeader() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-NGINX-3",
			Name:        "Missing Content-Security-Policy header",
			Description: "A Content Security Policy (also named CSP) requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browsers render pages (e.g., inline JavaScript is disabled by default and must be explicitly allowed in the policy). CSP prevents a wide range of attacks, including cross-site scripting and other cross-site injections. For more information checkout https://owasp.org/www-project-secure-headers/#content-security-policy",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.NotMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`add_header Content-Security-Policy (.*);`),
		},
	}
}

func NewIncludeServerTokensOff() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-NGINX-4",
			Name:        "Exposure of Sensitive Information",
			Description: "Your Nginx file must include 'server_tokens off;' configuration. There are many different kinds of mistakes that introduce information exposures. The severities of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. For more information checkout the CWE-200 (https://cwe.mitre.org/data/definitions/200.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.NotMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`server_tokens off;`),
		},
	}
}
