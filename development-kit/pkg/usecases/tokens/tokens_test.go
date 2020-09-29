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

package tokenusecases

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenFromRequestBodyBindingURLParamRepositoryID(t *testing.T) {
	repositoryID := uuid.New()
	data := api.Token{
		RepositoryID: &repositoryID,
		CompanyID:    uuid.New(),
		Description:  "test",
	}

	t.Run("should return reset code data from read closer", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", data.RepositoryID.String())
		ctx.URLParams.Add("companyID", data.CompanyID.String())
		r, _ := http.NewRequest(http.MethodOptions, "api/account", readCloser)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		useCases := NewTokenUseCases()
		token, err := useCases.ValidateTokenRepository(r)
		assert.NoError(t, err)
		assert.Equal(t, data.RepositoryID, token.RepositoryID)
		assert.Equal(t, data.Description, token.Description)
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))

		r, _ := http.NewRequest(http.MethodOptions, "api/account", readCloser)

		useCases := NewTokenUseCases()
		_, err := useCases.ValidateTokenRepository(r)
		assert.Error(t, err)
	})

	t.Run("should return error when invalid company id", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", data.RepositoryID.String())
		r, _ := http.NewRequest(http.MethodOptions, "api/account", readCloser)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		useCases := NewTokenUseCases()
		_, err := useCases.ValidateTokenRepository(r)
		assert.Error(t, err)
	})

	t.Run("should return error when invalid repository id", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		ctx := chi.NewRouteContext()
		r, _ := http.NewRequest(http.MethodOptions, "api/account", readCloser)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		useCases := NewTokenUseCases()
		_, err := useCases.ValidateTokenRepository(r)
		assert.Error(t, err)
	})
}
