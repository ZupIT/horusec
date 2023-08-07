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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/enums/toignore"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/utils/copy"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var tmpPath, _ = filepath.Abs("tmp")

func TestMain(m *testing.M) {
	_ = os.RemoveAll(tmpPath)

	code := m.Run()

	_ = os.RemoveAll(tmpPath)
	os.Exit(code)
}

func TestLanguageDetectIgnoreFilesUsingWindowsPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Only check if files is ignored correctly using Windows paths")
	}
	logger.LogSetOutput(io.Discard)

	cfg := config.New()
	cfg.FilesOrPathsToIgnore = []string{"**\\routes\\**", "**\\*.mod", "**\\*.sum"}
	cfg.ProjectPath = testutil.GoExample1

	assertTestLanguageDetectIgnoreFiles(t, cfg)
}

func TestLanguageDetectIgnoreFiles(t *testing.T) {
	logger.LogSetOutput(io.Discard)

	cfg := config.New()
	cfg.FilesOrPathsToIgnore = []string{"**/routes/**", "**/*.mod", "**/*.sum"}
	cfg.ProjectPath = testutil.GoExample1

	assertTestLanguageDetectIgnoreFiles(t, cfg)
}

func TestLanguageDetectIgnoreFilesGithubFolder(t *testing.T) {
	logger.LogSetOutput(io.Discard)

	cfg := config.New()
	cfg.EnableGitHistoryAnalysis = true
	cfg.EnableCommitAuthor = true
	cfg.FilesOrPathsToIgnore = []string{"**/leaks/**", "**/yaml/**"}
	cfg.ProjectPath = filepath.Join(testutil.RootPath)

	analysisID := uuid.New()

	ld := NewLanguageDetect(cfg, analysisID)

	langs, err := ld.Detect(cfg.ProjectPath)
	assert.Contains(t, langs, languages.Yaml)
	assert.NoError(t, err)
	assert.DirExists(t, filepath.Join(cfg.ProjectPath, ".horusec", analysisID.String(), ".git"))
	assert.DirExists(t, filepath.Join(cfg.ProjectPath, ".horusec", analysisID.String(), ".github"))
	assert.FileExists(t, filepath.Join(cfg.ProjectPath, ".horusec", analysisID.String(), ".github", "workflows", "license.yaml"))
}

func assertTestLanguageDetectIgnoreFiles(t *testing.T, cfg *config.Config) {
	analysisID := uuid.New()

	ld := NewLanguageDetect(cfg, analysisID)

	langs, err := ld.Detect(cfg.ProjectPath)

	assert.NoError(t, err, "Expected no error to detect languages: %v", err)

	assert.Equal(t, []languages.Language{languages.Leaks, languages.Generic, languages.Go}, langs)

	analysisPath := filepath.Join(cfg.ProjectPath, ".horusec", analysisID.String())
	assert.NoDirExists(t, filepath.Join(analysisPath, "api", "routes"))
	assert.NoFileExists(t, filepath.Join(analysisPath, "go.mod"))
	assert.NoFileExists(t, filepath.Join(analysisPath, "go.sum"))

	assert.FileExists(t, filepath.Join(analysisPath, "api", "server.go"))
	assert.FileExists(t, filepath.Join(analysisPath, "api", "util", "util.go"))
}

func TestLanguageDetect(t *testing.T) {
	logger.LogSetOutput(io.Discard)
	t.Cleanup(func() {
		err := os.RemoveAll(filepath.Join(testutil.ExamplesPath, ".horusec"))
		assert.NoError(t, err)
		for _, path := range testutil.GetAllExamples1Dir() {
			err = os.RemoveAll(filepath.Join(path, ".horusec"))
			assert.NoError(t, err)
		}
	})

	t.Run("Should return error when the folder not exists", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect("./NOT-EXIST-PATH")

		assert.Error(t, err)
		assert.Nil(t, langs)
	})

	t.Run("Should ignore files of the type images", func(t *testing.T) {
		dstPath := filepath.Join(tmpPath, uuid.New().String())
		srcPath := filepath.Join(testutil.RootPath, "assets")
		t.Cleanup(func() {
			assert.NoError(t, os.RemoveAll(filepath.Join(srcPath, ".horusec")))
		})

		err := copy.Copy(srcPath, dstPath, func(src string) bool { return false })
		assert.NoError(t, err)

		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(srcPath)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 2)
	})

	t.Run("Should ignore additional folder setup in configs", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.GoExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should ignore additional specific file name setup in configs", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.GoExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})
	t.Run("Should run language detect and return GO and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.GoExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.LeaksExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
	})

	t.Run("Should run language detect and return JAVA and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.JavaExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Java)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Shell)
		assert.Len(t, langs, 4)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.JavaScriptExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.JavaScriptExample2)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Yaml)
		assert.Len(t, langs, 4)
	})

	t.Run("Should run language detect and return PHP, LEAKS, GENERIC in example2", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.PHPExample2)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.PHP)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PHP, LEAKS, GENERIC in example1", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.PHPExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.PHP)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return KOTLIN and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.KotlinExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Kotlin)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return CSHARP and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.CsharpExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.CSharp)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PYTHON and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.PythonExample1)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PYTHON safety and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.PythonExample2)

		assert.NoError(t, err)
		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return RUBY and GITLEAKS", func(t *testing.T) {
		controller := NewLanguageDetect(config.New(), uuid.New())

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
		controller := NewLanguageDetect(config.New(), uuid.New())

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
		controller := NewLanguageDetect(config.New(), uuid.New())

		langs, err := controller.Detect(testutil.ExamplesPath)

		assert.NoError(t, err)
		for _, lang := range languages.Values() {
			if lang == languages.Unknown || lang == languages.Typescript {
				continue
			}
			assert.Contains(t, langs, lang)
		}
		// TODO: We don't have examples of TypeScript language and Unknown language on examples folder, this will fail when we add them
		assert.Len(t, langs, len(languages.Values())-2)
	})
	t.Run("Should ignore folders present in toignore.GetDefaultFoldersToIgnore()", func(t *testing.T) {
		wd, err := os.Getwd()
		assert.NoError(t, err)

		t.Cleanup(func() {
			logger.SetLogLevel("info")
			logger.LogSetOutput(os.Stdout)
			for _, folderName := range toignore.GetDefaultFoldersToIgnore() {
				err = os.RemoveAll(filepath.Join(wd, folderName))
			}
		})

		controller := NewLanguageDetect(config.New(), uuid.New())

		logger.SetLogLevel("debug")
		stdOutMock := bytes.NewBufferString("")
		logger.LogSetOutput(stdOutMock)

		for _, folderName := range toignore.GetDefaultFoldersToIgnore() {
			err = os.MkdirAll(filepath.Join(wd, folderName), 0o700)
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
	})
	t.Run("Should read git submodule path and copy to .horusec folder git submodule correctly", func(t *testing.T) {
		analysisID := uuid.New()
		configs := config.New()
		configs.EnableGitHistoryAnalysis = true

		controller := NewLanguageDetect(configs, analysisID)
		_, err := controller.Detect(testutil.ExamplesPath)

		assert.NoError(t, err)

		projectClonedPath := filepath.Join(testutil.ExamplesPath, ".horusec", analysisID.String())
		fileInfo, err := os.Stat(filepath.Join(projectClonedPath, ".git"))
		assert.NoError(t, err)

		assert.True(t, fileInfo.IsDir())
	})
}
