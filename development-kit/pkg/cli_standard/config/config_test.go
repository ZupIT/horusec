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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewConfig(t *testing.T) {
	t.Run("Should return default values", func(t *testing.T) {
		configs := NewConfig()
		assert.Equal(t, configs.GetOutputFilePath(), "output.json")
		assert.Equal(t, configs.GetProjectPath(), "./")
		assert.Equal(t, configs.GetLogLevel(), "info")
	})
	t.Run("Should return new values", func(t *testing.T) {
		configs := NewConfig()
		configs.SetOutputFilePath("tmp.json")
		configs.SetProjectPath("../")
		configs.SetLogLevel("error")
		assert.NotEqual(t, configs.GetOutputFilePath(), "output.json")
		assert.NotEqual(t, configs.GetProjectPath(), "./")
		assert.NotEqual(t, configs.GetLogLevel(), "info")
	})
}
