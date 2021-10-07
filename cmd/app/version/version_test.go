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

package version

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestVersionCommand_Execute(t *testing.T) {
	t.Run("should not panic when creating the version command", func(t *testing.T) {
		assert.NotPanics(t, func() {
			CreateCobraCmd()
		})
	})

	t.Run("should success execute the version command without errors", func(t *testing.T) {
		assert.NoError(t, CreateCobraCmd().RunE(&cobra.Command{}, []string{}))
	})
}
