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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateCredentials(t *testing.T) {
	t.Run("should return no error when valid data", func(t *testing.T) {
		credentials := &Credentials{
			Username: "horus@test.com",
			Password: "UltraSafePass",
		}

		assert.NoError(t, credentials.Validate())
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		credentials := &Credentials{}

		assert.Error(t, credentials.Validate())
	})

	t.Run("Should not empty when marshal", func(t *testing.T) {
		credentials := &Credentials{
			Username: "horus@test.com",
			Password: "UltraSafePass",
		}
		assert.NotEmpty(t, credentials.ToBytes())
	})
}
