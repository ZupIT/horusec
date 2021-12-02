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

package languagedetect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/go-enry/go-enry/v2"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/enums/toignore"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/utils/copy"
)

const prefixGitSubModule = "gitdir: "

// LanguageDetect implements analyzer.LanguageDetect interface, which is
// resposable to detect all languages recursivily to a given base path.
type LanguageDetect struct {
	config     *config.Config
	analysisID uuid.UUID
}

// NewLanguageDetect create a new language detect.
func NewLanguageDetect(cfg *config.Config, analysisID uuid.UUID) *LanguageDetect {
	return &LanguageDetect{
		analysisID: analysisID,
		config:     cfg,
	}
}

// Detect implements analyzer.LanguageDetect.Detect.
func (ld *LanguageDetect) Detect(directory string) ([]languages.Language, error) {
	langs := []string{languages.Leaks.ToString(), languages.Generic.ToString()}

	languagesFound, err := ld.getLanguages(directory)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDetectLanguage, err)
		return nil, err
	}

	langs = ld.appendLanguagesFound(langs, languagesFound)

	if errCopy := ld.copyProjectToHorusecFolder(directory); errCopy != nil {
		return nil, errCopy
	}

	return ld.filterSupportedLanguages(langs), err
}

// getLanguages return all unique languages that exists on directory.
func (ld *LanguageDetect) getLanguages(directory string) ([]string, error) {
	skipedFiles, langs, err := ld.detectAllLanguages(directory)
	if err != nil {
		return nil, err
	}

	if skipedFiles > 0 {
		logger.LogWarnWithLevel(fmt.Sprintf(messages.MsgWarnTotalFolderOrFileWasIgnored, skipedFiles))
	}

	return ld.uniqueLanguages(langs), err
}

// detectAllLanguages return all languages that exists on directory and how many
// files was skipped when detecting their languages.
func (ld *LanguageDetect) detectAllLanguages(directory string) (totalToSkip int, languagesFound []string, err error) {
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		newLanguages, skip := ld.detectLanguages(path, info)
		if skip {
			totalToSkip++
		}

		languagesFound = ld.appendLanguagesFound(languagesFound, newLanguages)
		return nil
	})

	return totalToSkip, languagesFound, err
}

// detectLanguages return all languages that exists to a given path. If the path should be
// skipped, detectLanguages return nil and true, otherwise will return all languages and false
// if path is not a directory.
func (ld *LanguageDetect) detectLanguages(path string, info os.FileInfo) ([]string, bool) {
	if skip := ld.isPathToIgnore(path); skip {
		logger.LogDebugWithLevel(messages.MsgDebugFolderOrFileIgnored, filepath.Clean(path))
		return nil, true
	}

	if info.IsDir() {
		return nil, false
	}

	langs := enry.GetLanguages(path, nil)
	logger.LogTraceWithLevel(messages.MsgTraceLanguageFound, map[string][]string{path: langs})
	return langs, false
}

func (ld *LanguageDetect) uniqueLanguages(languagesFound []string) (output []string) {
	for _, language := range languagesFound {
		if len(output) == 0 {
			output = append(output, language)
			continue
		}
		output = ld.appendIfLanguageNotExists(output, language)
	}
	return output
}

func (ld *LanguageDetect) appendIfLanguageNotExists(allLanguages []string, newLanguage string) []string {
	existing := false
	for _, lang := range allLanguages {
		if lang == newLanguage {
			existing = true
			break
		}
	}
	if !existing {
		allLanguages = append(allLanguages, newLanguage)
	}
	return allLanguages
}

func (ld *LanguageDetect) isPathToIgnore(path string) bool {
	return ld.checkDefaultPathsToIgnore(path) || ld.checkAdditionalPathsToIgnore(path) || ld.checkExtensionToIgnore(path)
}

func (ld *LanguageDetect) checkDefaultPathsToIgnore(path string) bool {
	for _, value := range toignore.GetDefaultFoldersToIgnore() {
		if strings.Contains(path, value) {
			return true
		}
	}
	if !ld.config.EnableGitHistoryAnalysis {
		return strings.Contains(path, ".git")
	}
	return false
}

func (ld *LanguageDetect) checkAdditionalPathsToIgnore(path string) bool {
	for _, value := range ld.config.FilesOrPathsToIgnore {
		matched, _ := doublestar.Match(strings.TrimSpace(value), path)
		if matched {
			return true
		}
	}
	return false
}

func (ld *LanguageDetect) checkExtensionToIgnore(path string) bool {
	extensionFound := filepath.Ext(path)
	for _, value := range toignore.GetDefaultExtensionsToIgnore() {
		if strings.EqualFold(value, extensionFound) {
			return true
		}
	}
	return false
}

func (ld *LanguageDetect) copyProjectToHorusecFolder(directory string) error {
	folderDstName := filepath.Join(directory, ".horusec", ld.analysisID.String())
	if err := copy.Copy(directory, folderDstName, ld.isPathToIgnore); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorCopyProjectToHorusecAnalysis, err)
		return err
	}

	fmt.Print("\n")
	logger.LogWarnWithLevel(fmt.Sprintf(messages.MsgWarnMonitorTimeoutIn, ld.config.TimeoutInSecondsAnalysis))
	fmt.Print("\n")
	logger.LogWarnWithLevel(messages.MsgWarnDontRemoveHorusecFolder, folderDstName)
	fmt.Print("\n")

	return ld.copyGitFolderWhenIsSubmodule(directory, folderDstName)
}

func (ld *LanguageDetect) filterSupportedLanguages(langs []string) (onlySupportedLangs []languages.Language) {
	for _, lang := range langs {
		if ld.isSupportedLanguage(lang) {
			onlySupportedLangs = append(onlySupportedLangs, languages.ParseStringToLanguage(lang))
		}
	}

	return onlySupportedLangs
}

func (ld *LanguageDetect) isSupportedLanguage(langName string) bool {
	for _, lang := range languages.Values() {
		if langName == lang.ToString() {
			return true
		}
	}

	return false
}

func (ld *LanguageDetect) appendLanguagesFound(existingLanguages, languagesFound []string) []string {
	for _, lang := range languagesFound {
		existingLanguages = ld.updateExistingLanguages(lang, existingLanguages)
	}

	return ld.uniqueLanguages(existingLanguages)
}

func (ld *LanguageDetect) updateExistingLanguages(lang string, existingLanguages []string) []string {
	switch {
	case ld.isTypescriptOrJavascriptLang(lang):
		return append(existingLanguages, languages.Javascript.ToString())
	case ld.isCPlusPLusOrCLang(lang):
		return append(existingLanguages, languages.C.ToString())
	case ld.isBatFileOrShellFile(lang):
		return append(existingLanguages, languages.Shell.ToString())
	default:
		return append(existingLanguages, lang)
	}
}

func (ld *LanguageDetect) isTypescriptOrJavascriptLang(lang string) bool {
	return strings.EqualFold(lang, languages.Javascript.ToString()) ||
		strings.EqualFold(lang, languages.Typescript.ToString()) ||
		strings.EqualFold(lang, "TSX") ||
		strings.EqualFold(lang, "JSX")
}

func (ld *LanguageDetect) isCPlusPLusOrCLang(lang string) bool {
	return strings.EqualFold(lang, "C++") || strings.EqualFold(lang, "C")
}

func (ld *LanguageDetect) isBatFileOrShellFile(lang string) bool {
	return strings.EqualFold(lang, "Batchfile") || strings.EqualFold(lang, "Shell")
}

// copyGitFolderWhenIsSubmodule check if the analysis is running with GitHistory enabled,
// If so, we also check whether the .git is a submodule or not,
// so we can find where the original git folder is
// and replace it inside .horusec to run the gitleaks tool without any problems.
//nolint:funlen
func (ld *LanguageDetect) copyGitFolderWhenIsSubmodule(directory, folderDstName string) error {
	if ld.config.EnableGitHistoryAnalysis {
		isGitSubmodule, originalFolderPath := ld.returnGitFolderOriginalIfIsSubmodule(filepath.Join(directory, ".git"))
		if isGitSubmodule {
			logger.LogErrorWithLevel(
				messages.MsgErrorCopyProjectToHorusecAnalysis,
				os.RemoveAll(filepath.Join(folderDstName, ".git")),
			)

			err := copy.Copy(
				filepath.Join(directory, originalFolderPath),
				filepath.Join(folderDstName, ".git"),
				func(src string) bool { return false },
			)
			if err != nil {
				logger.LogErrorWithLevel(messages.MsgErrorCopyProjectToHorusecAnalysis, err)
				return err
			}
		}
	}
	return nil
}

//nolint:funlen // lines is not necessary broken
func (ld *LanguageDetect) returnGitFolderOriginalIfIsSubmodule(directory string) (bool, string) {
	fileInfo, err := os.Stat(directory)
	if err != nil {
		logger.LogError(messages.MsgErrorCopyProjectToHorusecAnalysis, err)
		return false, ""
	}
	if fileInfo.IsDir() {
		return false, ""
	}
	fileContentBytes, err := os.ReadFile(directory)
	if err != nil {
		logger.LogError(messages.MsgErrorCopyProjectToHorusecAnalysis, err)
		return false, ""
	}
	return ld.validateSubModuleContent(fileContentBytes)
}

func (ld *LanguageDetect) validateSubModuleContent(fileContentBytes []byte) (bool, string) {
	var fileContent string
	if fileContentBytes != nil {
		fileContent = string(fileContentBytes)
	}
	if !strings.HasPrefix(fileContent, prefixGitSubModule) {
		logger.LogErrorWithLevel(messages.MsgErrorCopyProjectToHorusecAnalysis,
			errors.New("file content wrong: "+fileContent))
		return false, ""
	}

	return true, ld.extractGitSubmoduleCorrectlyPath(fileContent)
}

// extractGitSubmoduleCorrectlyPath contains the logic for get correctly path
// from content of the symbolic link in git submodules.
// Its value is expected to be something like this "gitdir: ../.git/modules/examples".
// Then is prefix is removed and path returned for join with project path
func (ld *LanguageDetect) extractGitSubmoduleCorrectlyPath(fileContent string) string {
	prefix := len(prefixGitSubModule)
	suffix := len(fileContent) - 1
	return fileContent[prefix:suffix]
}
