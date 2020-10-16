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

package router

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	"github.com/go-chi/cors"
	"github.com/stretchr/testify/assert"
)

func TestNewRouter(t *testing.T) {
	t.Run("should success create a new router", func(t *testing.T) {
		router := NewRouter(server.NewServerConfig("8000", &cors.Options{}))
		assert.NotNil(t, router)
	})
}

func TestGetRouter(t *testing.T) {
	t.Run("should success set router configs", func(t *testing.T) {
		router := NewRouter(server.NewServerConfig("8000", &cors.Options{}))
		assert.NotNil(t, router)

		mux := router.GetRouter()
		assert.NotNil(t, mux)
	})
}
