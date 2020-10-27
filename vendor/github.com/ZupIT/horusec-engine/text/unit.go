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

package text

import engine "github.com/ZupIT/horusec-engine"

type TextUnit struct {
	Files []TextFile
}

func newFinding(ruleData TextRule, filename, codeSample string, line, column int) engine.Finding {
	return engine.Finding{
		ID:          ruleData.ID,
		Name:        ruleData.Name,
		Severity:    ruleData.Severity,
		Confidence:  ruleData.Confidence,
		Description: ruleData.Description,

		CodeSample: codeSample,

		SourceLocation: engine.Location{
			Filename: filename,
			Line:     line,
			Column:   column,
		},
	}
}

func createFindingsFromIndexes(findingIndexes [][]int, file TextFile, rule TextRule) (findings []engine.Finding) {
	for _, findingIndex := range findingIndexes {
		line, column := file.FindLineAndColumn(findingIndex[0])
		codeSample := file.ExtractSample(findingIndex[0])

		finding := newFinding(
			rule,
			file.DisplayName,
			codeSample,
			line,
			column,
		)

		findings = append(findings, finding)
	}

	return findings
}

func (unit TextUnit) evalRegularRule(textRule TextRule, findingsChan chan<- []engine.Finding) {
	for _, file := range unit.Files {
		localFile := file // Preventing Gorountines of accessing the shared memory bit :/
		go func() {
			var findings []engine.Finding

			for _, expression := range textRule.Expressions {
				findingIndexes := expression.FindAllStringIndex(localFile.Content(), -1)

				if findingIndexes != nil {
					ruleFindings := createFindingsFromIndexes(findingIndexes, localFile, textRule)
					findings = append(findings, ruleFindings...)

					continue
				}
			}

			findingsChan <- findings
		}()
	}
}

func (unit TextUnit) evalNotMatchRule(textRule TextRule, findingsChan chan<- []engine.Finding) {
	for _, file := range unit.Files {
		localFile := file // Preventing Gorountines of accessing the shared memory bit :/
		go func() {
			var findings []engine.Finding

			for _, expression := range textRule.Expressions {
				findingIndexes := expression.FindAllStringIndex(localFile.Content(), -1)

				if findingIndexes == nil {
					findings = append(findings, newFinding(textRule, localFile.DisplayName, "", 0, 0))
				}
			}

			findingsChan <- findings

		}()
	}
}

func (unit TextUnit) evalAndMatchRule(textRule TextRule, findingsChan chan<- []engine.Finding) {
	for _, file := range unit.Files {
		localFile := file // Preventing Gorountines of accessing the shared memory bit :/
		go func() {
			var findings []engine.Finding
			var ruleFindings []engine.Finding
			haveFound := true

			for _, expression := range textRule.Expressions {
				findingIndexes := expression.FindAllStringIndex(localFile.Content(), -1)

				if findingIndexes != nil {
					ruleFindings = append(ruleFindings, createFindingsFromIndexes(findingIndexes, localFile, textRule)...)
					continue
				}

				haveFound = false
				break
			}

			if haveFound {
				findings = append(findings, ruleFindings...)
			}

			findingsChan <- findings
		}()
	}
}

func (unit TextUnit) Type() engine.UnitType {
	return engine.ProgramTextUnit
}

func (unit TextUnit) Eval(rule engine.Rule) (unitFindings []engine.Finding) {
	if len(unit.Files) <= 0 {
		return unitFindings
	}

	chanSize := len(unit.Files)
	findingsChannel := make(chan []engine.Finding, chanSize)

	if textRule, ok := rule.(TextRule); ok {
		switch textRule.Type {
		case Regular:
			go unit.evalRegularRule(textRule, findingsChannel)
		case OrMatch:
			go unit.evalRegularRule(textRule, findingsChannel)
		case NotMatch:
			go unit.evalNotMatchRule(textRule, findingsChannel)
		case AndMatch:
			go unit.evalAndMatchRule(textRule, findingsChannel)
		}
	} else {
		// The rule isn't a TextRule, so we just bail out
		return []engine.Finding{}
	}

	for i := 1; i <= chanSize; i++ {
		fileFindings := <-findingsChannel
		unitFindings = append(unitFindings, fileFindings...)
	}

	close(findingsChannel)

	return unitFindings
}
