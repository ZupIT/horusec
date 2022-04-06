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

package bundler

import (
	"fmt"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type AuditOutput struct {
	Version   string   `json:"version"`
	CreatedAt string   `json:"created_at"`
	Results   []Result `json:"results"`
}

type Result struct {
	Type     string   `json:"type"`
	Gem      Gem      `json:"gem"`
	Advisory Advisory `json:"advisory"`
}

type Gem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Advisory struct {
	Path               string      `json:"path"`
	ID                 string      `json:"id"`
	URL                string      `json:"url"`
	Title              string      `json:"title"`
	Date               string      `json:"date"`
	Description        string      `json:"description"`
	CvssV2             float64     `json:"cvss_v2"`
	CvssV3             float64     `json:"cvss_v3"`
	Cve                string      `json:"cve"`
	Osvdb              interface{} `json:"osvdb"`
	Ghsa               string      `json:"ghsa"`
	UnaffectedVersions []string    `json:"unaffected_versions"`
	PatchedVersions    []string    `json:"patched_versions"`
	Criticality        string      `json:"criticality"`
}

func (r *Result) getDetails() string {
	detail := fmt.Sprintf("%s\n%s\n%s%s", r.Advisory.Title, r.getFixedVersionString(),
		r.Advisory.Description, r.getCVE())
	detailWithoutSpace := strings.TrimSpace(detail)
	return strings.ReplaceAll(detailWithoutSpace, "\n\n", "")
}

func (r *Result) getFixedVersionString() (fixes string) {
	for _, v := range r.Advisory.PatchedVersions {
		fixes += fmt.Sprintf("Fixed Version: %s; ", v)
	}
	return fixes
}

func (r *Result) getCVE() string {
	return fmt.Sprintf("CVE: %s", r.Advisory.Cve)
}

func (r *Result) getSeverity() severities.Severity {
	severity := strings.ToUpper(r.Advisory.Criticality)
	return severities.GetSeverityByString(severity)
}
