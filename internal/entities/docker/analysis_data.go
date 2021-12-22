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
	"path"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"

	"github.com/ZupIT/horusec/internal/enums/images"
)

// AnalysisData holds the image and command that will be used to start an
// analysis of a tool inside a Docker container.
type AnalysisData struct {
	CustomImage  string
	DefaultImage string
	CMD          string
	Language     languages.Language
}

// IsInvalid check if current analysis data contains an empty image ou command.
func (a *AnalysisData) IsInvalid() bool {
	return a.DefaultImage == "" || a.CMD == ""
}

// SetImage set the custom image and default image that will be used by analysis
//
// Note that customImage could be an empty string and defaultImage **should**
// contains docker tag, e.g go:1.17.
func (a *AnalysisData) SetImage(customImage, defaultImage string) *AnalysisData {
	a.CustomImage = customImage
	a.DefaultImage = path.Join(images.DefaultRegistry, defaultImage)

	return a
}

// GetCustomOrDefaultImage return the user custom image or default.
func (a *AnalysisData) GetCustomOrDefaultImage() string {
	if a.CustomImage != "" {
		return a.CustomImage
	}

	return a.DefaultImage
}

func (a *AnalysisData) SetSlnName(slnName string) {
	if slnName == "" {
		a.CMD = strings.ReplaceAll(a.CMD, "{{SLN_NAME}}", "solution file not found")
		return
	}

	a.CMD = strings.ReplaceAll(a.CMD, "{{SLN_NAME}}", slnName)
}
