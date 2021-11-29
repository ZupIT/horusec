// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package testutil

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec/internal/utils/copy"
)

// NormalizePathToAssert Returns path spaced to be compatible with Windows in e2e tests asserts.
func NormalizePathToAssert(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}

// NormalizePathToAssertInJSON Returns path spaced to be compatible with Windows in e2e tests when assert is a JSON.
func NormalizePathToAssertInJSON(path string) string {
	return strings.ReplaceAll(path, `\`, `\\\\`)
}

// CreateHorusecAnalysisDirectory create a .horusec directory to be analyzed using the
// analysis.ID as suffix on path and copy paths the created directory.
//
// The value returned will be a project path that contains the .horusec directory inside.
func CreateHorusecAnalysisDirectory(tb testing.TB, analysiss *analysis.Analysis, paths ...string) string {
	projectPath := tb.TempDir()

	horusecPath := filepath.Join(projectPath, ".horusec", analysiss.ID.String())

	for _, src := range paths {
		err := copy.Copy(src, horusecPath, func(src string) bool { return false })
		require.NoError(tb, err, "Exepected no error to copy files from %s to %s", src, projectPath)
	}

	return projectPath
}
