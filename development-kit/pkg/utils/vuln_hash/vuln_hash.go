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
	"regexp"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/hash"
)

func Bind(vuln *horusec.Vulnerability) *horusec.Vulnerability {
	vulnHash, _ := hash.GenerateSHA1(
		toOneLine(vuln.Code),
		vuln.Line,
		vuln.Details,
		vuln.File,
	)

	vuln.VulnHash = vulnHash

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
