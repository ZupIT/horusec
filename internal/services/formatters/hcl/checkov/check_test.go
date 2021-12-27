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

package checkov

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func checkMock() *checkovCheck {
	guideline := "test"
	return &checkovCheck{
		CheckID:       "CKV_AWS_41",
		CheckName:     "test",
		Guideline:     &guideline,
		FileAbsPath:   "test",
		FileLineRange: [2]int{1, 1},
	}
}

func TestGetDetails(t *testing.T) {
	t.Run("should success get result details", func(t *testing.T) {
		assert.NotEmpty(t, checkMock().getDetails())
	})
}

func TestGetStartLine(t *testing.T) {
	t.Run("should success get start line", func(t *testing.T) {
		assert.NotEmpty(t, checkMock().getStartLine())
	})
}

func TestGetCode(t *testing.T) {
	t.Run("should success get code", func(t *testing.T) {
		assert.NotEmpty(t, checkMock().getCode())
	})
}
