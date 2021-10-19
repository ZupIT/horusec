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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var (
	// RootPath represents the root directory of horusec repository.
	RootPath = findRootDirectory()

	// ExamplesPath represents the entire examples directory.
	ExamplesPath = filepath.Join(RootPath, "examples")

	// CsharpExample represents the entire C# examples directory.
	CsharpExample  = filepath.Join(ExamplesPath, "csharp")
	CsharpExample1 = filepath.Join(CsharpExample, "example1")
	CsharpExample2 = filepath.Join(CsharpExample, "example2")

	// DartExample represents the entire Dart examples directory.
	DartExample  = filepath.Join(ExamplesPath, "dart")
	DartExample1 = filepath.Join(DartExample, "example1")

	// ElfExample represents the entire elf examples directory.
	ElfExample  = filepath.Join(ExamplesPath, "elf")
	ElfExample1 = filepath.Join(ElfExample, "example1")

	// ElixirExample represents the entire Elixir examples directory.
	ElixirExample  = filepath.Join(ExamplesPath, "elixir")
	ElixirExample1 = filepath.Join(ElixirExample, "example1")

	// GoExample represents the entire Go examples directory.
	GoExample  = filepath.Join(ExamplesPath, "go")
	GoExample1 = filepath.Join(GoExample, "example1")
	GoExample2 = filepath.Join(GoExample, "example2")

	// HclExample represents the entire Go examples directory.
	HclExample = filepath.Join(ExamplesPath, "hcl")
	Hclxample1 = filepath.Join(HclExample, "example1")

	// JavaExample represents the entire Java examples directory.
	JavaExample  = filepath.Join(ExamplesPath, "java")
	JavaExample1 = filepath.Join(JavaExample, "example1")

	// JavaScriptExample represents the entire JavaScript examples directory.
	JavaScriptExample  = filepath.Join(ExamplesPath, "javascript")
	JavaScriptExample1 = filepath.Join(JavaScriptExample, "example1")
	JavaScriptExample2 = filepath.Join(JavaScriptExample, "example2")
	JavaScriptExample3 = filepath.Join(JavaScriptExample, "example3")
	JavaScriptExample4 = filepath.Join(JavaScriptExample, "example4")

	// KotlinExample represents the entire Kotlin examples directory.
	KotlinExample  = filepath.Join(ExamplesPath, "kotlin")
	KotlinExample1 = filepath.Join(KotlinExample, "example1")

	// LeaksExample represents the entire Leaks examples directory.
	LeaksExample  = filepath.Join(ExamplesPath, "leaks")
	LeaksExample1 = filepath.Join(LeaksExample, "example1")
	LeaksExample2 = filepath.Join(LeaksExample, "example2")

	// NginxExample represents the entire Nginx examples directory.
	NginxExample  = filepath.Join(ExamplesPath, "nginx")
	NginxExample1 = filepath.Join(NginxExample, "example1")

	// PeExample represents the entire pe examples directory.
	PeExample  = filepath.Join(ExamplesPath, "pe")
	PeExample1 = filepath.Join(PeExample, "example1")

	// PerfExample represents the entire perf examples directory.
	PerfExample  = filepath.Join(ExamplesPath, "perf")
	PerfExample1 = filepath.Join(PerfExample, "example1")

	// PHPExample represents the entire PHP examples directory.
	PHPExample  = filepath.Join(ExamplesPath, "php")
	PHPExample1 = filepath.Join(PHPExample, "example1")

	// PythonExample represents the entire Python examples directory.
	PythonExample  = filepath.Join(ExamplesPath, "python")
	PythonExample1 = filepath.Join(PythonExample, "example1")
	PythonExample2 = filepath.Join(PythonExample, "example2")

	// RubyExample represents the entire Ruby examples directory.
	RubyExample  = filepath.Join(ExamplesPath, "ruby")
	RubyExample1 = filepath.Join(RubyExample, "example1")

	// SwiftExample represents the entire Swift examples directory.
	SwiftExample  = filepath.Join(ExamplesPath, "swift")
	SwiftExample1 = filepath.Join(SwiftExample, "example1")

	// YamlExample represents the entire Yaml examples directory.
	YamlExample  = filepath.Join(ExamplesPath, "yaml")
	YamlExample1 = filepath.Join(YamlExample, "example1")
)

func findRootDirectory() string {
	// Get the current filename of this function and them join
	// the path to get the root directory of Horusec repository.
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get runtime caller info")
	}
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "..")

	if _, err := os.Stat(dir); err != nil {
		panic(fmt.Sprintf(
			"Failed to find horusec root directory: %v\nThe path %s should point to root directory of repository", err, dir,
		))
	}

	return dir
}

//nolint:gochecknoinits
func init() {
	if _, err := os.Stat(ExamplesPath); err != nil {
		panic(fmt.Sprintf(
			"Failed to find examples path: %v\nConsider running git submodule --update init to clone examples submodule", err,
		))
	}
}
