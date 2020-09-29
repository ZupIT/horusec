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

package copy

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestCopy(t *testing.T) {
	t.Run("Should success copy dir", func(t *testing.T) {
		srcPath, err := filepath.Abs("../../../../assets")
		assert.NoError(t, err)

		dstPath, err := filepath.Abs(".")
		assert.NoError(t, err)

		dstPath = fmt.Sprintf(dstPath+"%s", "/test")

		err = Copy(srcPath, dstPath, func(src string) bool { return false })
		assert.NoError(t, err)

		err = os.RemoveAll(dstPath)
		assert.NoError(t, err)
	})
}
