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

package dotnetcli

import (
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/stretchr/testify/assert"
)

func TestSetName(t *testing.T) {
	t.Run("should success set name", func(t *testing.T) {
		dependency := &dotnetDependency{}

		dependency.setName("test")
		assert.Equal(t, "test", dependency.Name)
	})
}

func TestSetVersion(t *testing.T) {
	t.Run("should success set version", func(t *testing.T) {
		dependency := &dotnetDependency{}

		dependency.setVersion("test")
		assert.Equal(t, "test", dependency.Version)
	})
}

func TestSetDescription(t *testing.T) {
	t.Run("should success set description", func(t *testing.T) {
		dependency := &dotnetDependency{}

		dependency.setDescription("test")
		assert.Equal(t, "test", dependency.Description)
	})
}

func TestSetSeverity(t *testing.T) {
	t.Run("should success set severity", func(t *testing.T) {
		dependency := &dotnetDependency{}

		dependency.setSeverity("test")
		assert.Equal(t, "test", dependency.Severity)

		dependency.setSeverity("\u001B[31m   Critical")
		assert.Equal(t, "Critical", dependency.Severity)

		dependency.setSeverity("\u001B[33m   Moderate")
		assert.Equal(t, "Moderate", dependency.Severity)
	})
}

func TestGetSeverity(t *testing.T) {
	t.Run("should success get severity", func(t *testing.T) {
		dependency := &dotnetDependency{}

		dependency.Severity = "Critical"
		assert.Equal(t, severities.Critical, dependency.getSeverity())

		dependency.Severity = "High"
		assert.Equal(t, severities.High, dependency.getSeverity())

		dependency.Severity = "Moderate"
		assert.Equal(t, severities.Medium, dependency.getSeverity())

		dependency.Severity = "Low"
		assert.Equal(t, severities.Low, dependency.getSeverity())

		dependency.Severity = "Test"
		assert.Equal(t, severities.Unknown, dependency.getSeverity())
	})
}
