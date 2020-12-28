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
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	analysisUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/google/uuid"
	CopyLib "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./examples")

	code := m.Run()

	_ = os.RemoveAll("./examples")
	os.Exit(code)
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
		srcPath := "./examples/" + uuid.New().String()

		err := CopyLib.Copy("../../../../assets", srcPath)
		assert.NoError(t, err)

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, err := controller.LanguageDetect(srcPath)
		assert.NoError(t, err)

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 2)
	})

	t.Run("Should ignore additional folder setup in configs", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/go/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should ignore additional specific file name setup in configs", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/go/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})
	t.Run("Should run language detect and return GO and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/go/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Go)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/leaks/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Generic)
	})

	t.Run("Should run language detect and return JAVA and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/java/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Java)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/javascript/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return JAVASCRIPT and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/javascript/example2")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Javascript)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Yaml)
		assert.Len(t, langs, 4)
	})

	t.Run("Should run language detect and return KOTLIN and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/kotlin/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Kotlin)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return CSHARP and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/csharp/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.CSharp)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PYTHON and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/python/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return PYTHON safety and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()

		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/python/example2")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Python)
		assert.Contains(t, langs, languages.Generic)
		assert.Len(t, langs, 3)
	})

	t.Run("Should run language detect and return RUBY and GITLEAKS", func(t *testing.T) {
		configs := &config.Config{}
		analysis := analysisUseCases.NewAnalysisUseCases().NewAnalysisRunning()
		controller := NewLanguageDetect(configs, analysis.ID)

		langs, _ := controller.LanguageDetect("../../../../examples/ruby/example1")

		assert.Contains(t, langs, languages.Leaks)
		assert.Contains(t, langs, languages.Ruby)
		assert.Contains(t, langs, languages.Generic)
		assert.Contains(t, langs, languages.Yaml)
		assert.Len(t, langs, 4)
	})
}
