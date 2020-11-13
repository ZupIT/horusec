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
package regular

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewCsharpRegularCrossSiteScripting() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "899e67a9-72b6-413f-9743-b9a9a7a742c1",
			Name:        "Cross-Site Scripting (XSS)",
			Description: "A potential XSS was found. The endpoint returns a variable from the client input that has not been encoded. To protect against stored XSS attacks, make sure any dynamic content coming from user or data store cannot be used to inject JavaScript on a page. Most modern frameworks will escape dynamic content by default automatically (Razor for example) or by using special syntax (<%: content %>, <%= HttpUtility.HtmlEncode(content) %>). For more information access: (https://security-code-scan.github.io/#SCS0029).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[HttpGet\(.*\)\]|\[HttpPost\(.*\)\]|\[HttpPut\(.*\)\]|\[HttpDelete\(.*\)\])(([^H]|H[^t]|Ht[^t]|Htt[^p]|Http[^U]|HttpU[^t]|HttpUt[^i]|HttpUti[^l]|HttpUtil[^i]|HttpUtili[^t]|HttpUtilit[^y]|HttpUtility[^.]|HttpUtility\.H[^t]|HttpUtility\.Ht[^m]|HttpUtility\.Htm[^l]|HttpUtility\.Html[^E]|HttpUtility\.HtmlE[^n]|HttpUtility\.HtmlEn[^c]|HttpUtility\.HtmlEnc[^o]|HttpUtility\.HtmlEnco[^d]|HttpUtility\.HtmlEncod[^e])*)(})`),
		},
	}
}

func NewCsharpRegularOutputCacheConflict() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5fc0eefc-31b3-4d07-8d97-37834aff963e",
			Name:        "OutputCache Conflict",
			Description: "Having the annotation [OutputCache] will disable the annotation [Authorize] for the requests following the first one. For more information access: (https://security-code-scan.github.io/#SCS0019).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[Authorize\])(.*|\n)*(\[OutputCache\])`),
		},
	}
}

func NewCsharpRegularOpenRedirect() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7fefbb75-2c16-4651-ab8f-3bff4d4e1b78",
			Name:        "Open Redirect",
			Description: "Your site may be used in phishing attacks. An attacker may craft a trustworthy looking link to your site redirecting a victim to a similar looking malicious site: 'http://yourdomain.com?redirect=https://urdomain.com/login'. For more information access: (https://security-code-scan.github.io/#SCS0027).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`String.IsNullOrEmpty.*\n?.*{?\n?.*return\sRedirect\(.*\);`),
		},
	}
}
