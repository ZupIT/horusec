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

package docker

import (
	"fmt"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
)

const DefaultRegistry = "docker.io"

type AnalysisData struct {
	CustomImage  string
	DefaultImage string
	CMD          string
	Language     languages.Language
}

func (a *AnalysisData) IsInvalid() bool {
	return a.DefaultImage == "" || a.CMD == ""
}

func (a *AnalysisData) SetData(customImage, imageName, imageTag string) *AnalysisData {
	a.CustomImage = customImage
	a.DefaultImage = fmt.Sprintf("%s/%s:%s", DefaultRegistry, imageName, imageTag)

	return a
}

func (a *AnalysisData) GetImageWithRegistry() string {
	if a.CustomImage != "" {
		return a.CustomImage
	}

	return a.DefaultImage
}

func (a *AnalysisData) GetImageWithoutRegistry() string {
	if a.CustomImage != "" {
		return a.removeRegistry(a.CustomImage)
	}

	return a.removeRegistry(a.DefaultImage)
}

func (a *AnalysisData) removeRegistry(fullImagePath string) string {
	index := strings.Index(fullImagePath, "/")
	if index < 0 {
		return fullImagePath
	}

	return fullImagePath[index+1:]
}
