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

package java

import "encoding/xml"

// SpotBugsOutput is the struct that holds all data from SpotBugs output.
type SpotBugsOutput struct {
	XMLName       xml.Name        `xml:"BugCollection"`
	Project       Project         `xml:"Project"`
	SpotBugsIssue []SpotBugsIssue `xml:"BugInstance"`
	Errors        Error           `xml:"Errors"`
}

// Project is the struct that holds data about project
type Project struct {
	XMLName xml.Name `xml:"Project"`
	Name    string   `xml:"projectName,attr"`
	Jar     string   `xml:"Jar"`
	Plugin  string   `xml:"Plugin"`
}

// SpotBugsIssue is the struct that holds all issues from SpotBugs output.
type SpotBugsIssue struct {
	XMLName      xml.Name     `xml:"BugInstance"`
	Type         string       `xml:"type,attr"`
	Priority     string       `xml:"priority,attr"`
	Rank         string       `xml:"rank,attr"`
	Abbreviation string       `xml:"abbrev,attr"`
	Category     string       `xml:"category,attr"`
	SourceLine   []SourceLine `xml:"SourceLine"`
}

// Error is the struct that holds errors that happened in analysis
type Error struct {
	XMLName        xml.Name `xml:"Errors"`
	Errors         string   `xml:"errors,attr"`
	MissingClasses string   `xml:"missingClasses,attr"`
}

// SourceLine is the struct that holds details about issue location
type SourceLine struct {
	XMLName       xml.Name `xml:"SourceLine"`
	ClassName     string   `xml:"classname,attr"`
	Start         string   `xml:"start,attr"`
	End           string   `xml:"end,attr"`
	StartByteCode string   `xml:"startBytecode,attr"`
	EndByteCode   string   `xml:"endBytecode,attr"`
	SourceFile    string   `xml:"sourcefile,attr"`
	SourcePath    string   `xml:"sourcepath,attr"`
}
