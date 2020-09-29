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

package server

import (
	"compress/flate"
	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewServerConfig(t *testing.T) {
	t.Run("should return a new server server", func(t *testing.T) {
		assert.NotNil(t, NewServerConfig("8000", &cors.Options{}))
	})
}

func TestCors(t *testing.T) {
	t.Run("should return a new http handler", func(t *testing.T) {
		server := NewServerConfig("8000", &cors.Options{})
		assert.NotNil(t, server)
		assert.NotNil(t, server.Cors(&chi.Mux{}))
	})
}

func TestSetTimeout(t *testing.T) {
	t.Run("should success set timeout", func(t *testing.T) {
		server := NewServerConfig("8000", &cors.Options{})
		assert.NotNil(t, server)
		assert.Equal(t, server.Timeout(20).timeout, time.Duration(20)*time.Second)
	})
}

func TestGetTimeout(t *testing.T) {
	t.Run("should success get timeout", func(t *testing.T) {
		server := NewServerConfig("8000", &cors.Options{})
		assert.NotNil(t, server)

		server.Timeout(10)
		assert.Equal(t, server.GetTimeout(), time.Duration(10)*time.Second)
	})
}

func TestGetCompression(t *testing.T) {
	t.Run("should get compression", func(t *testing.T) {
		server := NewServerConfig("8000", &cors.Options{})
		assert.NotNil(t, server)
		assert.Equal(t, server.GetCompression(), flate.BestCompression)
	})
}

func TestGetPort(t *testing.T) {
	t.Run("should return http server port", func(t *testing.T) {
		server := NewServerConfig("8000", &cors.Options{})
		assert.NotNil(t, server)
		assert.Equal(t, ":8000", server.GetPort())
	})
}
