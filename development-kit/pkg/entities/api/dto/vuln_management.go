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

package dto

import (
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/google/uuid"
)

type VulnManagement struct {
	TotalItems int    `json:"totalItems"`
	Data       []data `json:"data"`
}

type data struct {
	AnalysisID      uuid.UUID                                  `json:"analysisID"`
	VulnerabilityID uuid.UUID                                  `json:"vulnerabilityID"`
	RepositoryID    uuid.UUID                                  `json:"repositoryID"`
	CompanyID       uuid.UUID                                  `json:"companyID"`
	Status          horusecEnums.AnalysisVulnerabilitiesStatus `json:"status"`
	Type            horusecEnums.AnalysisVulnerabilitiesType   `json:"type"`
	VulnHash        string                                     `json:"vulnHash"`
	Line            string                                     `json:"line"`
	Column          string                                     `json:"column"`
	Confidence      string                                     `json:"confidence"`
	File            string                                     `json:"file"`
	Code            string                                     `json:"code"`
	Details         string                                     `json:"details"`
	SecurityTool    tools.Tool                                 `json:"securityTool"`
	Language        languages.Language                         `json:"language"`
	Severity        severity.Severity                          `json:"severity"`
}
