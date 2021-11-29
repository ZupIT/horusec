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

package scs

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type (
	scsAnalysis struct {
		Runs []*scsRun `json:"runs"`
	}

	scsRun struct {
		Results []*scsResult `json:"results"`
		Tool    scsTool      `json:"tool"`
	}

	scsResult struct {
		RuleID    string         `json:"ruleId"`
		Message   scsMessage     `json:"message"`
		Locations []*scsLocation `json:"locations"`
	}

	scsTool struct {
		Driver scsDriver `json:"driver"`
	}

	scsDriver struct {
		Rules []*scsRule `json:"rules"`
	}

	scsRule struct {
		ID              string     `json:"id"`
		FullDescription scsMessage `json:"fullDescription"`
		HelpURI         string     `json:"helpUri"`
	}

	scsMessage struct {
		Text string `json:"text"`
	}

	scsLocation struct {
		PhysicalLocation scsPhysicalLocation `json:"physicalLocation"`
	}

	scsPhysicalLocation struct {
		ArtifactLocation scsArtifactLocation `json:"artifactLocation"`
		Region           scsRegion           `json:"region"`
	}

	scsArtifactLocation struct {
		URI string `json:"uri"`
	}

	scsRegion struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}
)

func (a *scsAnalysis) getRun() *scsRun {
	if len(a.Runs) > 0 {
		return a.Runs[0]
	}

	return nil
}

func (a *scsAnalysis) vulnerabilitiesByID() map[string]*scsRule {
	run := a.getRun()

	vulnMap := make(map[string]*scsRule, len(run.Tool.Driver.Rules))

	for _, rule := range run.Tool.Driver.Rules {
		vulnMap[rule.ID] = rule
	}

	return vulnMap
}

func (r *scsResult) getLine() string {
	if len(r.Locations) > 0 {
		return strconv.Itoa(r.Locations[0].PhysicalLocation.Region.StartLine)
	}

	return ""
}

func (r *scsResult) getColumn() string {
	if len(r.Locations) > 0 {
		return strconv.Itoa(r.Locations[0].PhysicalLocation.Region.StartColumn)
	}

	return ""
}

func (r *scsResult) getVulnName() string {
	return r.Message.Text
}

func (r *scsResult) getFile() string {
	if len(r.Locations) > 0 {
		// Since the scs will always run on Docker, we need to convert each slash ('/') to the specific OS slash.
		return filepath.FromSlash(
			strings.ReplaceAll(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, "file:///src/", ""),
		)
	}

	return ""
}

func (r *scsRule) getFullDescription() string {
	fullDescription := strings.ReplaceAll(r.FullDescription.Text, "{", "")
	fullDescription = strings.ReplaceAll(fullDescription, "}", "")
	return fullDescription
}

func (r *scsRule) getDescription(vulnName string) string {
	if r.HelpURI == "" {
		return vulnName
	}

	return fmt.Sprintf("%s\n%s For more information, check the following url (%s).",
		vulnName, r.getFullDescription(), r.HelpURI,
	)
}
