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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-enry/go-enry/v2"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/cli"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	copyUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/copy"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	doublestar "github.com/bmatcuk/doublestar/v2"
	"github.com/google/uuid"
)

type Interface interface {
	LanguageDetect(directory string) ([]languages.Language, error)
}

type LanguageDetect struct {
	configs    *config.Config
	analysisID uuid.UUID
}

func NewLanguageDetect(configs *config.Config, analysisID uuid.UUID) Interface {
	return &LanguageDetect{
		analysisID: analysisID,
		configs:    configs,
	}
}

func (ld *LanguageDetect) LanguageDetect(directory string) ([]languages.Language, error) {
	langs := []string{languages.Leaks.ToString()}
	languagesFound, err := ld.getLanguages(directory)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDetectLanguage, err, logger.ErrorLevel)
		return nil, err
	}

	langs = append(langs, languagesFound...)

	ld.configs.SetProjectPath(directory)
	err = ld.copyProjectToHorusecFolder(directory)
	return ld.filterSupportedLanguages(langs), err
}

func (ld *LanguageDetect) getLanguages(directory string) (languagesFound []string, err error) {
	filesToSkip, languagesFound, err := ld.walkInPathAndReturnTotalToSkip(directory)
	if filesToSkip > 0 {
		print("\n")
		msg := strings.ReplaceAll(messages.MsgWarnTotalFolderOrFileWasIgnored, "{{0}}", strconv.Itoa(filesToSkip))
		logger.LogWarnWithLevel(msg, logger.WarnLevel)
	}
	return ld.uniqueLanguages(languagesFound), err
}

func (ld *LanguageDetect) walkInPathAndReturnTotalToSkip(
	directory string) (totalToSkip int, languagesFound []string, err error) {
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		currentLanguagesFound, skip := ld.execWalkToGetLanguagesAndReturnIfSkip(path, info)
		if skip {
			totalToSkip++
		}
		languagesFound = append(languagesFound, currentLanguagesFound...)
		return nil
	})
	return totalToSkip, languagesFound, err
}

func (ld *LanguageDetect) execWalkToGetLanguagesAndReturnIfSkip(
	path string, info os.FileInfo) (languagesFound []string, skip bool) {
	skip = ld.filesAndFoldersToIgnore(path)
	if skip {
		logger.LogDebugWithLevel(messages.MsgDebugFolderOrFileIgnored, logger.WarnLevel, path)
	}
	if !info.IsDir() && !skip {
		newLanguages := enry.GetLanguages(path, nil)
		logger.LogTraceWithLevel(messages.MsgTraceLanguageFound,
			logger.TraceLevel, map[string][]string{path: newLanguages})
		languagesFound = append(languagesFound, newLanguages...)
	}
	return languagesFound, skip
}

func (ld *LanguageDetect) uniqueLanguages(languagesFound []string) (output []string) {
	for _, language := range languagesFound {
		if len(output) == 0 {
			output = append(output, language)
		} else {
			output = ld.checkIfLanguageExistAndConcat(output, language)
		}
	}
	return output
}

func (ld *LanguageDetect) checkIfLanguageExistAndConcat(output []string, language string) []string {
	existing := false
	for _, appended := range output {
		if appended == language {
			existing = true
			break
		}
	}
	if !existing {
		output = append(output, language)
	}
	return output
}

func (ld *LanguageDetect) filesAndFoldersToIgnore(path string) bool {
	isToSkip := ld.checkDefaultPathsToIgnore(path) ||
		ld.checkAdditionalPathsToIgnore(path) ||
		ld.checkFileExtensionInvalid(path)
	return isToSkip
}

func (ld *LanguageDetect) checkDefaultPathsToIgnore(path string) bool {
	for _, value := range cli.GetDefaultFoldersToIgnore() {
		if strings.Contains(path, file.ReplacePathSeparator(value)) {
			return true
		}
	}
	return false
}

func (ld *LanguageDetect) checkAdditionalPathsToIgnore(path string) bool {
	if ld.configs.GetFilesOrPathsToIgnore() != "" {
		for _, value := range strings.Split(ld.configs.GetFilesOrPathsToIgnore(), ",") {
			pattern, err := filepath.Abs(value)
			if err != nil {
				continue
			}

			matched, _ := doublestar.Match(pattern, path)
			if matched {
				return true
			}
		}
	}
	return false
}

func (ld *LanguageDetect) checkFileExtensionInvalid(path string) bool {
	extensionFound := filepath.Ext(path)
	for _, value := range cli.GetDefaultExtensionsToIgnore() {
		if strings.EqualFold(value, extensionFound) {
			return true
		}
	}
	return false
}

func (ld *LanguageDetect) copyProjectToHorusecFolder(directory string) error {
	folderDstName := file.ReplacePathSeparator(fmt.Sprintf("%s/.horusec/%s", directory, ld.analysisID.String()))
	err := copyUtil.Copy(directory, folderDstName, ld.filesAndFoldersToIgnore)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorCopyProjectToHorusecAnalysis, err, logger.ErrorLevel)
	} else {
		fmt.Print("\n")
		logger.LogWarnWithLevel(messages.MsgWarnDontRemoveHorusecFolder, logger.WarnLevel, folderDstName)
		fmt.Print("\n")
	}
	return err
}

// WARNING: This method not be called because is feature is deprecated
func (ld *LanguageDetect) addIgnoreHorusecInGitFolder(directory string) error {
	err := ld.runAddIgnoreHorusecInGitFolder(directory)
	if err == nil {
		logger.LogErrorWithLevel(messages.MsgErrorInAddHorusecFolderInGitIgnore, err, logger.ErrorLevel)
	}
	return err
}

func (ld *LanguageDetect) runAddIgnoreHorusecInGitFolder(directory string) error {
	gitignorePath := directory + file.ReplacePathSeparator("/.gitignore")
	horusecPath := directory + file.ReplacePathSeparator("/.horusec")

	if err := ld.checkIfExistHorusecAndGitIgnoreFolders(horusecPath, gitignorePath); err != nil {
		return err
	}
	content, err := ioutil.ReadFile(gitignorePath)
	if err != nil {
		return err
	}
	if strings.Contains(string(content), ".horusec") {
		return nil
	}
	return ld.writeInGitIgnoreHorusecFolder(gitignorePath)
}

func (ld *LanguageDetect) checkIfExistHorusecAndGitIgnoreFolders(horusecPath, gitignorePath string) error {
	if _, err := os.Stat(horusecPath); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorNotFoundHorusecFolder, err, logger.ErrorLevel)
		return err
	}
	if _, err := os.Stat(gitignorePath); err != nil {
		if _, err := os.Create(gitignorePath); err != nil {
			return err
		}
		logger.LogDebugWithLevel(messages.MsgDebugGitIgnoreGenerated, logger.DebugLevel, gitignorePath)
	}
	return nil
}

func (ld *LanguageDetect) writeInGitIgnoreHorusecFolder(gitignorePath string) error {
	fileOpened, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_WRONLY, 0600)
	if fileOpened != nil {
		defer func() {
			logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileOpened.Close(), logger.ErrorLevel)
		}()
	}
	if err != nil {
		return err
	}
	_, err = fileOpened.Write([]byte(".horusec"))
	if err == nil {
		logger.LogDebugWithLevel(messages.MsgDebugAddingHorusecFolderInGitIgnore, logger.DebugLevel, gitignorePath)
	}
	return err
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
	supportedLangs := languages.SupportedLanguages()
	for _, lang := range supportedLangs {
		if langName == lang.ToString() {
			return true
		}
	}

	return false
}
