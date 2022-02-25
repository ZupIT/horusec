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

package vulnhash

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/crypto"
)

// Bind create a sha256 hash of the vulnerability using the vulnerability code, line and file. The file path should
// be relative to avoid generating different hashes between environments. The Vulnerability.VulnHash field is set
// automatically with the generated hash. Some hashes that are deprecated but still valid are also defined in the
// Vulnerability.DeprecatedHashes field, as of v2.10.0 is released, these hashes will no longer be considered and
// this field will be removed.
//
// nolint:funlen
func Bind(vuln *vulnerability.Vulnerability) *vulnerability.Vulnerability {
	vuln.VulnHash = crypto.GenerateSHA256(
		toOneLine(vuln.Code),
		vuln.Line,
		vuln.File,
	)

	// TODO: DeprecatedHashes will be removed after the release v2.10.0 be released.
	vuln.DeprecatedHashes = append(vuln.DeprecatedHashes,
		// Generates a hash in an old format containing the rule id, description and commit email.
		crypto.GenerateSHA256(
			toOneLine(vuln.Code),
			vuln.Line,
			fmt.Sprintf("%s: %s", vuln.RuleID, vuln.Details),
			vuln.File,
			vuln.CommitEmail,
		),

		// Generates a hash in an old format containing the description and commit email.
		crypto.GenerateSHA256(
			toOneLine(vuln.Code),
			vuln.Line,
			vuln.Details,
			vuln.File,
			vuln.CommitEmail,
		),
	)

	return vuln
}

func toOneLine(code string) string {
	re := regexp.MustCompile(`\r?\n?\t`)
	// remove line break
	oneLineCode := re.ReplaceAllString(code, " ")
	// remove white space
	oneLineCode = strings.ReplaceAll(oneLineCode, " ", "")

	return oneLineCode
}

func HashRuleID(desc string) string {
	return crypto.GenerateSHA256(desc)[0:8]
}
