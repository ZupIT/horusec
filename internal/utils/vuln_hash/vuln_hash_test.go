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

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/crypto"
)

func TestBind(t *testing.T) {
	t.Run("should bind the vuln hash in VulnHash field", func(t *testing.T) {
		vuln := &vulnerability.Vulnerability{
			Code: "test",
			File: "test.go",
		}

		vuln = Bind(vuln)
		assert.NotEmpty(t, vuln.VulnHash)
	})

	t.Run("should generate the hash from Code and File attrs", func(t *testing.T) {
		expected := crypto.GenerateSHA256("test", "test.go")
		vuln := &vulnerability.Vulnerability{
			Code: "test",
			File: "test.go",
		}

		vuln = Bind(vuln)
		assert.Equal(t, expected, vuln.VulnHash)
	})
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
