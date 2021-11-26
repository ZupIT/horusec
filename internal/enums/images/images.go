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

package images

import "github.com/ZupIT/horusec-devkit/pkg/enums/languages"

const (
	DefaultRegistry = "docker.io"
	C               = "horuszup/horusec-c:v1.0.1"
	Csharp          = "horuszup/horusec-csharp:v1.1.0"
	Elixir          = "horuszup/horusec-elixir:v1.1.0"
	Generic         = "horuszup/horusec-generic:v1.1.0"
	Go              = "horuszup/horusec-go:v1.2.0"
	HCL             = "horuszup/horusec-hcl:v1.1.0"
	Javascript      = "horuszup/horusec-js:v1.2.0"
	Leaks           = "horuszup/horusec-leaks:v1.1.0"
	PHP             = "horuszup/horusec-php:v1.0.1"
	Python          = "horuszup/horusec-python:v1.0.0"
	Ruby            = "horuszup/horusec-ruby:v1.1.0"
	Shell           = "horuszup/horusec-shell:v1.0.1"
)

func MapValues() map[languages.Language]string {
	return map[languages.Language]string{
		languages.CSharp:     Csharp,
		languages.Leaks:      Leaks,
		languages.Go:         Go,
		languages.Javascript: Javascript,
		languages.Python:     Python,
		languages.Ruby:       Ruby,
		languages.HCL:        HCL,
		languages.Generic:    Generic,
		languages.PHP:        PHP,
		languages.Elixir:     Elixir,
		languages.Shell:      Shell,
		languages.C:          C,
	}
}
