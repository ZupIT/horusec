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

package javascript

import (
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/semantic"
	"github.com/ZupIT/horusec-engine/semantic/analysis/call"
	"github.com/ZupIT/horusec-engine/semantic/analysis/value"
)

func NewSemanticCryptographicallyWeakPseudoRandomNumberGenerator() engine.Rule {
	return &semantic.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-SEMANTIC-JAVASCRIPT-6",
			Name:        "No use weak random number generator",
			Description: "When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information. As the Math.random() function relies on a weak pseudorandom number generator, this function should not be used for security-critical applications or for protecting sensitive data. In such context, a cryptographically strong pseudorandom number generator (CSPRNG) should be used instead. For more information checkout the CWE-338 (https://cwe.mitre.org/data/definitions/338.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Language: languages.Javascript,
		Analyzer: &call.Analyzer{
			Name:      "Math.Random",
			ArgsIndex: call.NoArguments,
		},
	}
}

func NewSemanticFilePathTraversal() engine.Rule {
	return &semantic.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-SEMANTIC-JAVASCRIPT-7",
			Name:        "No read file using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Language: languages.Javascript,
		Analyzer: &call.Analyzer{
			Name:      "fs.readFile",
			ArgsIndex: 1,
			ArgValue:  value.IsConst,
		},
	}
}

func NewSemanticArgumentInjection() engine.Rule {
	return &semantic.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-SEMANTIC-JAVASCRIPT-21",
			Name:        "Using command line arguments",
			Description: "Command line arguments can be dangerous just like any other user input. They should never be used without being first validated and sanitized. Remember also that any user can retrieve the list of processes running on a system, which makes the arguments provided to them visible. Thus passing sensitive information via command line arguments should be considered as insecure. This rule raises an issue when on every program entry points (main methods) when command line arguments are used. The goal is to guide security code reviews. Sanitize all command line arguments before using them. For more information checkout the CWE-88 (https://cwe.mitre.org/data/definitions/88.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Language: languages.Javascript,
		Analyzer: &call.Analyzer{
			Name:      "child_process.spawn",
			ArgsIndex: 1,
			ArgValue:  value.IsConst,
		},
	}
}

func NewSemanticBrokenCryptographicAlgorithm() engine.Rule {
	// TODO(matheus): Fill Metadata
	return &semantic.Rule{
		Language: languages.Javascript,
		Analyzer: &call.Analyzer{
			Name:      "crypto.createHash",
			ArgsIndex: 1,
			ArgValue: value.Contains{
				Values: []string{"sha512", "sha256"},
			},
		},
	}
}

func NewSemanticCodeInjection() engine.Rule {
	return &semantic.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-SEMANTIC-JAVASCRIPT-2",
			Name:        "No use eval",
			Description: "The eval function is extremely dangerous. Because if any user input is not handled correctly and passed to it, it will be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion). For more information checkout the CWE-94 (https://cwe.mitre.org/data/definitions/94.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Language: languages.Javascript,
		Analyzer: &call.Analyzer{
			Name:      "eval",
			ArgsIndex: 1,
			ArgValue:  value.IsConst,
		},
	}
}
