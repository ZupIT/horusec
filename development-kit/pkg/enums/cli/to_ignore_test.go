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

package cli

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetDefaultFoldersToIgnore(t *testing.T) {
	t.Run("should success get 7 default files to ignore", func(t *testing.T) {
		assert.Equal(t, len(GetDefaultFoldersToIgnore()), 9)
	})
}

func TestGetDefaultExtensionsToIgnore(t *testing.T) {
	t.Run("should success get 32 extensions to ignore", func(t *testing.T) {
		assert.Len(t, GetDefaultExtensionsToIgnore(), 32)
	})
}
