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
package not

import (
	"regexp"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

func NewNginxNotIncludeXFrameOptionsHeader() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "87cc1073-05e2-4d91-90a6-2bd22e239b54",
			Name:        "Improper Restriction of Rendered UI Layers or Frames",
			Description: "Your Nginx file must include the X-Frame-Options header. A web application is expected to place restrictions on whether it is allowed to be rendered within frames, iframes, objects, embed or applet elements. Without the restrictions, users can be tricked into interacting with the application when they were not intending to. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/1021.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.NotMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`add_header X-Frame-Options .*(?i)(sameorigin|"sameorigin"|deny|"deny");`),
		},
	}
}

func NewNginxNotIncludeServerTokensOff() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "840f50dd-0ceb-4f66-b425-bafc2d1c042c",
			Name:        "Exposure of Sensitive Information",
			Description: "Your Nginx file must include 'server_tokens off;' configuration. There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/1021.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.NotMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`server_tokens off;`),
		},
	}
}
