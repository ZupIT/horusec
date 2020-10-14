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
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	analysisUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/zip"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/google/uuid"
	CopyLib "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll(sourcePathBase)

	code := m.Run()

	_ = os.RemoveAll(sourcePathBase)
	_ = os.RemoveAll(".horusec")
	_ = os.RemoveAll(".gitignore")
	os.Exit(code)
}

const (
	zipPath        = "../../../../development-kit/pkg/utils/test/zips"
	sourcePathBase = "./tmp-analysis"
)

func getSourcePath(analysisID uuid.UUID) string {
	return fmt.Sprintf("%s/%s", sourcePathBase, analysisID.String())
}

func unZipToTmp(toolName string, analysisID uuid.UUID) error {
	zipFilePath := fmt.Sprintf("%s/%s/%s.zip", zipPath, toolName, toolName)
	sourcePath := getSourcePath(analysisID)
	return zip.NewZip().UnZip(zipFilePath, sourcePath)
}

func TestNewLanguageDetect(t *testing.T) {
	t.Run("Should return error when the folder not exists", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()

		controller := NewLanguageDetect(configs, analysis.ID)

		monitor, err := controller.LanguageDetect("./NOT-EXIST-PATH")

		assert.Error(t, err)
		assert.Nil(t, monitor)
	})

	t.Run("Should ignore files of the type images", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		srcPath := sourcePathBase + "/" + uuid.New().String()

		err := CopyLib.Copy("../../../../assets", srcPath)
		assert.NoError(t, err)

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, err := controller.LanguageDetect(srcPath)
		assert.NoError(t, err)

		assert.Contains(t, langs, languages.Leaks)
		assert.Len(t, langs, 1)
	})

	t.Run("Should ignore additional folder setup in configs", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "go-gosec"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Len(t, langs, 2)
	})

	t.Run("Should ignore additional specific file name setup in configs", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "go-gosec"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Len(t, langs, 2)
	})
	t.Run("Should run language detect and return GO and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "go-gosec"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Len(t, langs, 2)
	})

	t.Run("Should run language detect and return GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "gitleaks"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
	})

	t.Run("Should run language detect and return JAVA and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "java-spotbug"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Java)
		assert.Len(t, langs, 2)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "javascript-npm"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Len(t, langs, 2)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "javascript-yarn"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Len(t, langs, 2)
	})

	//t.Run("Should run language detect and return KOTLIN and GITLEAKS", func(t *testing.T) {
	//	configs := config.NewHorusecConfig()
	//	analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
	//	analysisName := "kotlin-spotbug"
	//
	//	assert.NoError(t, unZipToTmp(analysisName, analysis.ID))
	//
	//	controller := NewLanguageDetect(configs, analysis.ID)
	//
	//	monitor, _ := controller.LanguageDetect(getSourcePath(analysis.ID))
	//
	//	for lang, value := range monitor {
	//		if lang == languages.Kotlin || lang == languages.Leaks {
	//			assert.Equal(t, 1, value)
	//		} else {
	//			assert.Equal(t, 0, value)
	//		}
	//	}
	//})

	t.Run("Should run language detect and return DOTNET and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "netcore3-1"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.DotNet)
		assert.Len(t, langs, 2)
	})

	t.Run("Should run language detect and return PYTHON and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "python-bandit"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Len(t, langs, 2)
	})

	t.Run("Should run language detect and return PYTHON and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "python-safety"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Len(t, langs, 2)
	})

	t.Run("Should run language detect and return RUBY and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		analysisName := "ruby-brakeman"

		assert.NoError(t, unZipToTmp(analysisName, analysis.ID))

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect(getSourcePath(analysis.ID))

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Ruby)
		assert.Len(t, langs, 2)
	})
}
