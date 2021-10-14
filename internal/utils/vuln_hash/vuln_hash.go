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

// Bind generate and set the vulnerability hash on vuln. Note that Bind
// generate the valid and invalid vulnerability hashes.
//
// nolint:funlen
func Bind(vuln *vulnerability.Vulnerability) *vulnerability.Vulnerability {
	vuln.VulnHash = crypto.GenerateSHA256(
		toOneLine(vuln.Code),
		vuln.Line,
		vuln.Details,
		vuln.File,
		vuln.CommitEmail,
	)

	// See vulnerability.Vulnerability.VulnHashInvalid docs for more info.
	vuln.VulnHashInvalid = crypto.GenerateSHA256(
		toOneLine(vuln.Code),
		vuln.Line,
		fmt.Sprintf("%s: %s", vuln.RuleID, vuln.Details),
		vuln.File,
		vuln.CommitEmail,
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
