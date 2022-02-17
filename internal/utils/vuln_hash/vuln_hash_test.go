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
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/stretchr/testify/assert"
)

func TestBind(t *testing.T) {
	vuln := vulnerability.Vulnerability{
		Code:        `fmt.Println("testing")`,
		Line:        "10",
		Details:     "testing",
		File:        "main.go",
		CommitEmail: "foo@bar",
	}

	Bind(&vuln)

	assert.Equal(t, "468865c64851037b2f8b9a8954de9d884d08cdf14e6f841072b85f7ac03ecc5e", vuln.VulnHash)
	assert.Equal(t, "751cf1c4e4f0fbf59777eea1d14c062b913a57fd3c0e457400ec134577c89686", vuln.DeprecatedHashes[0])
	assert.Equal(t, "278facfff87828631a37b27d76d1a926bed37466b05cab7d365d7f5c7345ac6d", vuln.DeprecatedHashes[1])
}

func TestToOneLine(t *testing.T) {
	t.Run("should compress an string to a one line string wihtout whitespaces", func(t *testing.T) {
		str := "func() {" +
			"    return true" +
			"}"
		expected := "func(){returntrue}"

		oneLineStr := toOneLine(str)

		assert.Equal(t, expected, oneLineStr)
	})
}
