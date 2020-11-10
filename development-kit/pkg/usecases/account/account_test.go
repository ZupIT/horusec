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

package account

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestNewLoginFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to login data", func(t *testing.T) {
		bytes, _ := json.Marshal(&dto.LoginData{
			Email:    "test@test.com",
			Password: "test",
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		loginData, err := useCases.NewLoginFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, loginData)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAccountUseCases()
		_, err := useCases.NewLoginFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestValidateResetPasswordCode(t *testing.T) {
	t.Run("should return no error when valid code", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := useCases.ValidateResetPasswordCode([]byte("test"), "test")
		assert.NoError(t, err)
	})

	t.Run("should return error when invalid code", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := useCases.ValidateResetPasswordCode([]byte("test"), "123456")
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorInvalidResetPasswordCode, err)
	})
}

func TestValidateEmail(t *testing.T) {
	t.Run("should return no error when valid email", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := useCases.ValidateEmail("test@test.com")
		assert.NoError(t, err)
	})

	t.Run("should return no error when invalid email", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := useCases.ValidateEmail("")
		assert.Error(t, err)
	})
}
