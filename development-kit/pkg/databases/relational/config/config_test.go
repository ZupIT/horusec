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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	t.Run("Should return default data corretly", func(t *testing.T) {
		c := NewConfig()
		assert.Equal(t, c.LogMode, false)
		assert.Equal(t, c.Dialect, "postgres")
		assert.Equal(t, c.URI, "postgresql://root:root@localhost:5432/horusec_db?sslmode=disable")
	})
	t.Run("Should return start corretly when set GORM configs", func(t *testing.T) {
		dbLogModeString := "true"
		dbURIString := "some other url"
		dbDialectString := "some other dialect"

		err := os.Setenv(EnvRelationalURI, dbURIString)
		assert.NoError(t, err)
		err = os.Setenv(EnvRelationalDialect, dbDialectString)
		assert.NoError(t, err)
		err = os.Setenv(EnvRelationalLogMode, dbLogModeString)
		assert.NoError(t, err)

		c := NewConfig()
		assert.Equal(t, c.URI, dbURIString)
		assert.Equal(t, c.Dialect, dbDialectString)
		assert.Equal(t, c.LogMode, true)
	})
}
