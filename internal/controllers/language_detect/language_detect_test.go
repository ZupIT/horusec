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
	"bytes"
	"fmt"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/enums/toignore"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec/internal/utils/testutil"

	"github.com/ZupIT/horusec/internal/utils/copy"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/config"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./examples")

	code := m.Run()

	_ = os.RemoveAll("./examples")
	os.Exit(code)
}

func TestNewLanguageDetect(t *testing.T) {
	t.Run("Should return error when the folder not exists", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		monitor, err := controller.Detect("./NOT-EXIST-PATH")

		assert.Error(t, err)
		assert.Nil(t, monitor)
	})

	t.Run("Should ignore files of the type images", func(t *testing.T) {
		dstPath := filepath.Join(".", "tmp-examples", uuid.New().String())
		srcPath := filepath.Join(testutil.RootPath, "assets")
		err := copy.Copy(srcPath, dstPath, func(src string) bool { return false })
		assert.NoError(t, err)
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(srcPath)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 2)
		assert.NoError(t, os.RemoveAll(filepath.Join(srcPath, ".horusec")))
	})

	t.Run("Should ignore additional folder setup in configs", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.GoExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should ignore additional specific file name setup in configs", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.GoExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})
	t.Run("Should run language detect and return GO and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.GoExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.LeaksExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
	})

	t.Run("Should run language detect and return JAVA and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.JavaExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Java)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.JavaScriptExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.JavaScriptExample2)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Yaml)
		assert.Len(t, langs, 4)
	})

	t.Run("Should run language detect and return KOTLIN and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.KotlinExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Kotlin)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return CSHARP and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.CsharpExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.CSharp)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PYTHON and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.PythonExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PYTHON safety and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.PythonExample2)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return RUBY and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.RubyExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Ruby)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Yaml)
		assert.Contains(t, langs, languages.HTML)
		assert.Len(t, langs, 6)
	})
	t.Run("Should run language detect on examples folder and return RUBY and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.RubyExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Ruby)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Yaml)
		assert.Contains(t, langs, languages.HTML)
		assert.Len(t, langs, 6)
	})
	t.Run("Should run language detect on examples folder and return all languages", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())

		langs, err := controller.Detect(testutil.ExamplesPath)

		assert.NoError(t, err)
		for _, lang := range languages.Values() {
			if lang == languages.Unknown || lang == languages.Typescript {
				continue
			}
			assert.Contains(t, langs, lang)
		}
		//TODO: We don't have examples of TypeScript language and Unknown language on examples folder, this will fail when we add them
		assert.Len(t, langs, len(languages.Values())-2)
	})
	t.Run("Should ignore folders present in toignore.GetDefaultFoldersToIgnore()", func(t *testing.T) {
		controller := NewLanguageDetect(&config.Config{}, uuid.New())
		wd, err := os.Getwd()
		assert.NoError(t, err)
		logger.SetLogLevel("debug")
		stdOutMock := bytes.NewBufferString("")
		logger.LogSetOutput(stdOutMock)
		for _, folderName := range toignore.GetDefaultFoldersToIgnore() {
			err = os.MkdirAll(filepath.Join(wd, folderName), 0700)
			assert.NoError(t, err)
		}
		langs, err := controller.Detect(wd)
		assert.NoError(t, err)
		assert.Len(t, langs, 3)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Leaks)

		for _, folderName := range toignore.GetDefaultFoldersToIgnore() {
			log := fmt.Sprint(messages.MsgDebugFolderOrFileIgnored, "[", filepath.Join(wd, folderName), "]")
			assert.Contains(t, stdOutMock.String(), strings.ReplaceAll(log, `\`, `\\`))
		}
		t.Cleanup(func() {
			logger.SetLogLevel("info")
			logger.LogSetOutput(os.Stdout)
			for _, folderName := range toignore.GetDefaultFoldersToIgnore() {
				err = os.RemoveAll(filepath.Join(wd, folderName))
			}
		})
	})
}
