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

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/internal/enums/images"
)

type AnalysisData struct {
	CustomImage  string
	DefaultImage string
	CMD          string
	Language     languages.Language
}

func (a *AnalysisData) IsInvalid() bool {
	return a.DefaultImage == "" || a.CMD == ""
}

func (a *AnalysisData) SetData(customImage, imageWithTag string) *AnalysisData {
	a.CustomImage = customImage
	a.DefaultImage = fmt.Sprintf("%s/%s", images.DefaultRegistry, imageWithTag)

	return a
}

func (a *AnalysisData) GetCustomOrDefaultImage() string {
	if a.CustomImage != "" {
		return a.CustomImage
	}

	return a.DefaultImage
}
