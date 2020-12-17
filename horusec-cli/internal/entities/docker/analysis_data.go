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

	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
)

type AnalysisData struct {
	ImagePath string
	CMD       string
	Language  languages.Language
}

func (a *AnalysisData) IsInvalid() bool {
	return a.ImagePath == "" || a.CMD == ""
}

func (a *AnalysisData) SetFullImagePath(imagePathInConfig, imageName, imageTag string) *AnalysisData {
	if imagePathInConfig != "" {
		a.ImagePath = imagePathInConfig
	} else {
		a.ImagePath = fmt.Sprintf("docker.io/%s:%s", imageName, imageTag)
	}

	return a
}
