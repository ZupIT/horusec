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

package broker

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetUp(t *testing.T) {
	t.Run("Should return panics when setup broker", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_BROKER_USERNAME", "other_username")
		_ = os.Setenv("HORUSEC_BROKER_PASSWORD", "other_password")
		assert.Panics(t, func() {
			SetUp(&relational.MockRead{})
		})
	})

	t.Run("Should not return panics when setup broker", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_BROKER_USERNAME", "guest")
		_ = os.Setenv("HORUSEC_BROKER_PASSWORD", "guest")
		assert.NotPanics(t, func() {
			SetUp(&relational.MockRead{})
		})
	})
}
