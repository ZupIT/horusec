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
package and

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewCsharpAndCommandInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "782ad071-1cf3-4230-936f-b7a1e794828d",
			Name:        "Command Injection",
			Description: "If a malicious user controls either the FileName or Arguments, he might be able to execute unwanted commands or add unwanted argument. This behavior would not be possible if input parameter are validate against a white-list of characters. For more information access: (https://security-code-scan.github.io/#SCS0001).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new Process\(\)`),
			regexp.MustCompile(`StartInfo.FileName`),
			regexp.MustCompile(`StartInfo.Arguments`),
		},
	}
}

func NewCsharpAndXPathInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "010a99b2-9f35-4cb3-9209-248bacba07f8",
			Name:        "XPath Injection",
			Description: "If the user input is not properly filtered, a malicious user could extend the XPath query. For more information access: (https://security-code-scan.github.io/#SCS0003).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new XmlDocument {XmlResolver = null}`),
			regexp.MustCompile(`Load\(.*\)`),
			regexp.MustCompile(`SelectNodes\(.*\)`),
		},
	}
}

func NewCsharpAndExternalEntityInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f3390c7e-8151-4f8a-8bc4-433841569153",
			Name:        "XML eXternal Entity Injection (XXE)",
			Description: "The XML parser is configured incorrectly. The operation could be vulnerable to XML eXternal Entity (XXE) processing. For more information access: (https://security-code-scan.github.io/#SCS0007).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new XmlReaderSettings\(\)`),
			regexp.MustCompile(`XmlReader.Create\(.*\)`),
			regexp.MustCompile(`new XmlDocument\(.*\)`),
			regexp.MustCompile(`Load\(.*\)`),
			regexp.MustCompile(`ProhibitDtd = false`),
			regexp.MustCompile(`(new XmlReaderSettings\(\))(([^P]|P[^r]|Pr[^o]|Pro[^h]|Proh[^i]|Prohi[^b]|Prohib[^i]|Prohibi[^t]|Prohibit[^D]|ProhibitD[^t]|ProhibitDt[^d])*)(\.Load\(.*\))`),
		},
	}
}

func NewCsharpAndPathTraversal() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3b905eb5-5af7-41db-a234-38c934f675b2",
			Name:        "Path Traversal",
			Description: "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the expected directory.By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. For more information access: (https://security-code-scan.github.io/#SCS0018).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ActionResult`),
			regexp.MustCompile(`System.IO.File.ReadAllBytes\(Server.MapPath\(.*\) \+ .*\)`),
			regexp.MustCompile(`File\(.*, System.Net.Mime.MediaTypeNames.Application.Octet, .*\)`),
		},
	}
}

func NewCsharpAndSQLInjectionWebControls() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b6f82b7c-f321-4651-8ad3-87fbf5e0412b",
			Name:        "SQL Injection WebControls",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0014).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`"Select .* From .* where .*" & .*`),
			regexp.MustCompile(`System\.Web\.UI\.WebControls\.SqlDataSource | System\.Web\.UI\.WebControls\.SqlDataSourceView | Microsoft\.Whos\.Framework\.Data\.SqlUtility`),
		},
	}
}
