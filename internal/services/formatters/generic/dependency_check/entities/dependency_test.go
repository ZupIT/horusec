// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVulnerability(t *testing.T) {
	t.Run("should success get vulnerability without cwe", func(t *testing.T) {
		dependency := &Dependency{
			FileName: "test",
			FilePath: "test",
			Vulnerabilities: []*Vulnerability{
				{
					Description: "test",
					Severity:    "test",
					Name:        "test",
				},
			},
		}

		assert.NotNil(t, dependency.GetVulnerability())
	})

	t.Run("should success get vulnerability with cwe", func(t *testing.T) {
		dependency := &Dependency{
			FileName: "test",
			FilePath: "test",
			Vulnerabilities: []*Vulnerability{
				{
					Description: "test",
					Severity:    "test",
					Name:        "CWE test",
				},
			},
		}

		assert.NotNil(t, dependency.GetVulnerability())
	})

	t.Run("should return nil when do not contains vulnerability", func(t *testing.T) {
		dependency := &Dependency{}

		assert.Nil(t, dependency.GetVulnerability())
	})
}

func TestGetFile(t *testing.T) {
	t.Run("should success get file", func(t *testing.T) {
		dependency := &Dependency{
			FilePath: "test?test",
		}

		file := dependency.GetFile()
		assert.NotEmpty(t, file)
		assert.Equal(t, "test", file)
	})

	t.Run("should success get file", func(t *testing.T) {
		dependency := &Dependency{
			FilePath: "test2",
		}

		file := dependency.GetFile()
		assert.NotEmpty(t, file)
		assert.Equal(t, "test2", file)
	})
}
