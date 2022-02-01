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

package mixaudit

import (
	"fmt"
	"strings"
)

type mixAuditResult struct {
	Vulnerabilities []mixAuditVulnerability `json:"vulnerabilities"`
}

type mixAuditVulnerability struct {
	Advisory struct {
		Description string `json:"description"`
		Package     string `json:"package"`
		Title       string `json:"title"`
		CVE         string `json:cve`
	} `json:"advisory"`
	Dependency struct {
		Lockfile string `json:"lockfile"`
		Version  string `json:"version"`
	} `json:"dependency"`
}

func (v *mixAuditVulnerability) getDetails() string {
	title := strings.ReplaceAll(v.Advisory.Title, "\n", "")
	description := strings.ReplaceAll(v.Advisory.Description, "\n", "")
	return fmt.Sprintf("%s\n%s", title, description)
}
