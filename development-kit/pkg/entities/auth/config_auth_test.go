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

package auth

import (
	"github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestParseInterfaceToConfigAuth(t *testing.T) {
	t.Run("Check if parse content correctly to Config auth", func(t *testing.T) {
		configAuth := ConfigAuth{
			ApplicationAdminEnable: true,
			AuthType:               auth.Horusec,
		}
		response, err := ParseInterfaceToConfigAuth(configAuth)
		assert.NoError(t, err)
		assert.True(t, response.ApplicationAdminEnable)
		assert.Equal(t, auth.Horusec, response.AuthType)
	})
	t.Run("Check if receive string and try parse return error", func(t *testing.T) {
		response, err := ParseInterfaceToConfigAuth(`{"applicationAdminEnable": "true", "authType": "horusec"}`)
		assert.Error(t, err)
		assert.Empty(t, response)
	})
	t.Run("Check if receive NaN and try marshal return error", func(t *testing.T) {
		response, err := ParseInterfaceToConfigAuth(math.NaN())
		assert.Error(t, err)
		assert.Empty(t, response)
	})
}
