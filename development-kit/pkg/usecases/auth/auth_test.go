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
	"encoding/json"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestNewCredentialsFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to credentials", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Credentials{
			Username: "test",
			Password: "test",
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		credentials, err := useCases.NewCredentialsFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, credentials)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAuthUseCases()
		_, err := useCases.NewCredentialsFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewAuthorizationDataFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to authorization data", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.AuthorizationData{
			Token:  "test",
			Groups: []string{"admin"},
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		credentials, err := useCases.NewAuthorizationDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, credentials)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAuthUseCases()
		_, err := useCases.NewAuthorizationDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestIsInvalidAuthType(t *testing.T) {
	t.Run("should return true when invalid type", func(t *testing.T) {
		useCases := NewAuthUseCases()
		isInvalid := useCases.IsInvalidAuthType(authEnums.Keycloak)
		assert.Error(t, isInvalid)

		isInvalid = useCases.IsInvalidAuthType(authEnums.Ldap)
		assert.Error(t, isInvalid)

		isInvalid = useCases.IsInvalidAuthType("test")
		assert.Error(t, isInvalid)
	})

	t.Run("should false when valid", func(t *testing.T) {
		useCases := NewAuthUseCases()
		isInvalid := useCases.IsInvalidAuthType(authEnums.Horusec)
		assert.NoError(t, isInvalid)
	})
}
