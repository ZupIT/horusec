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

package api

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type AnalysisData struct {
	Analysis       *horusec.Analysis `json:"analysis"`
	RepositoryName string            `json:"repositoryName"`
}

func (a *AnalysisData) ToBytes() []byte {
	bytes, _ := json.Marshal(a)
	ct := string(bytes)
	logger.LogWarnWithLevel("ATTENTION TO BODY SENDING TO API: ", logger.WarnLevel, ct)
	return bytes
}
