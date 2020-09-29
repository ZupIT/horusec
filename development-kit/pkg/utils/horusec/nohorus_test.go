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

package horusec

import (
	"testing"

	enumSeverity "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/stretchr/testify/assert"
)

func TestGetSeverityOrNoSec(t *testing.T) {
	t.Run("should return no sec severity", func(t *testing.T) {
		response := GetSeverityOrNoSec(enumSeverity.Low, "test //nohorus")
		assert.Equal(t, enumSeverity.NoSec, response)
	})

	t.Run("should return low severity when no-horusec was not found", func(t *testing.T) {
		response := GetSeverityOrNoSec(enumSeverity.Low, "test")
		assert.Equal(t, enumSeverity.Low, response)
	})
}
