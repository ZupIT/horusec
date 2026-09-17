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

package csharp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A good number of the C# rules are written against ASP.NET configuration XML
// rather than against source: HS-CSHARP-43 is named "Request Validation Disabled
// (Configuration File)", and others match <httpRuntime>, <sessionState> and
// <pages>. Those elements live in Web.config and App.config, so without the
// extension the engine never opens the only files those rules can match.
func TestExtensionsIncludeDotConfig(t *testing.T) {
	assert.Contains(t, extensions(), ".config")
}

func TestExtensionsAreAllDotPrefixed(t *testing.T) {
	// getValidFilePaths compares against filepath.Ext, which always returns a
	// leading dot, so an entry without one can never match anything.
	for _, ext := range extensions() {
		assert.Equal(t, ".", string(ext[0]), "extension %q cannot match filepath.Ext output", ext)
	}
}
