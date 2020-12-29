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

package horusecleaks

import (
	"fmt"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/leaks"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"math"
	"os"
	"path/filepath"
	"time"
)

type Formatter struct {
	formatters.IService
	leaks.Interface
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
		leaks.NewRules(),
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.HorusecLeaks) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.HorusecLeaks.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.execEngineAndParseResults(projectSubPath), tools.HorusecLeaks, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecLeaks)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) execEngineAndParseResults(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecLeaks)

	findings, err := f.execEngineAnalysis(projectSubPath)
	if err != nil {
		return err
	}

	return f.ParseFindingsToVulnerabilities(findings, tools.HorusecLeaks, languages.Leaks)
}

func (f *Formatter) execEngineAnalysis(projectSubPath string) (allFindings []engine.Finding, err error) {
	allRules := append(f.GetAllRules(), f.GetCustomRulesByTool(tools.HorusecLeaks)...)
	projectPath := f.GetProjectPathWithWorkdir(projectSubPath)
	f.LogDebugWithReplace("Extracting text units into directory for {{0}}", tools.HorusecLeaks)
	listUnits, err := f.extractUnitsIntoDirectory(projectPath)
	if err != nil {
		return allFindings, err
	}
	for key, units := range listUnits {
		f.LogDebugWithReplace(fmt.Sprintf("Start run analysis in {{0}} %v/%v", key, len(listUnits)), tools.HorusecLeaks)
		allFindings = append(allFindings, engine.Run(units, allRules)...)
	}
	return allFindings, nil
}

func (f *Formatter) extractUnitsIntoDirectory(projectPath string) (units [][]engine.Unit, err error) {
	filesToRun, err := f.getFilesToRun(projectPath)
	if err != nil {
		return units, err
	}
	textUnits, err := f.getTextUnitsFromFilesToRun(filesToRun)
	if err != nil {
		return units, err
	}
	return f.breakTextUnitsIntoLimitOfUnit(textUnits), nil
}

func (f *Formatter) getTextUnitsFromFilesToRun(filesToRun []string) (textUnits []text.TextUnit, err error) {
	textUnits = []text.TextUnit{{}}
	lastIndexToAdd := 0
	for k, currentFile := range filesToRun {
		time.Sleep(15 * time.Millisecond)
		currentTime := time.Now()
		textUnits, lastIndexToAdd, err = f.readFileAndExtractTextUnit(textUnits, lastIndexToAdd, currentFile)
		logger.LogTraceWithLevel(
			fmt.Sprintf("Read file in %v Microseconds. Total files read: %v/%v ",
				time.Since(currentTime).Microseconds(), k, len(filesToRun),
			), logger.TraceLevel, currentFile)
		if err != nil {
			return []text.TextUnit{}, err
		}
	}
	return textUnits, nil
}

func (f *Formatter) getFilesToRun(projectPath string) (filesToRun []string, err error) {
	return filesToRun, filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			filesToRun = append(filesToRun, path)
		}
		return nil
	})
}

func (f *Formatter) readFileAndExtractTextUnit(
	textUnits []text.TextUnit, lastIndexToAdd int, currentFile string) ([]text.TextUnit, int, error) {
	const maxFilesPerTextUnit = 5
	textFile, err := text.ReadAndCreateTextFile(currentFile)
	if err != nil {
		return []text.TextUnit{}, lastIndexToAdd, err
	}
	textUnits[lastIndexToAdd].Files = append(textUnits[lastIndexToAdd].Files, textFile)
	if len(textUnits[lastIndexToAdd].Files) >= maxFilesPerTextUnit {
		textUnits = append(textUnits, text.TextUnit{})
		return textUnits, lastIndexToAdd + 1, nil
	}
	return textUnits, lastIndexToAdd, nil
}

func (f *Formatter) breakTextUnitsIntoLimitOfUnit(textUnits []text.TextUnit) (units [][]engine.Unit) {
	const maxUnitsPerAnalysis = 200
	units = [][]engine.Unit{}
	startIndex := 0
	endIndex := maxUnitsPerAnalysis
	for i := 0; i < f.getTotalTextUnitsToRunByAnalysis(textUnits, maxUnitsPerAnalysis); i++ {
		units = append(units, []engine.Unit{})
		units = f.toBreakUnitsAddUnitAndUpdateStartEndIndex(textUnits, units, startIndex, endIndex, i)
		startIndex = endIndex + 1
		endIndex += maxUnitsPerAnalysis
	}
	return units
}

func (f *Formatter) toBreakUnitsAddUnitAndUpdateStartEndIndex(
	textUnits []text.TextUnit, units [][]engine.Unit, startIndex, endIndex, i int) [][]engine.Unit {
	if len(textUnits[startIndex:]) <= endIndex {
		for _, f := range textUnits[startIndex:] {
			units[i] = append(units[i], f)
		}
	} else {
		for _, f := range textUnits[startIndex:endIndex] {
			units[i] = append(units[i], f)
		}
	}
	return units
}

func (f *Formatter) getTotalTextUnitsToRunByAnalysis(textUnits []text.TextUnit, maxUnitsPerAnalysis int) int {
	totalTextUnits := len(textUnits)
	if totalTextUnits <= maxUnitsPerAnalysis {
		return 1
	}
	totalUnitsToRun := float64(totalTextUnits / maxUnitsPerAnalysis)
	// nolint:staticcheck is necessary usage pointless in math.ceil
	return int(math.Ceil(totalUnitsToRun))
}
