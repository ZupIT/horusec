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

package customrules

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-engine/text"
)

func TestValidate1(t *testing.T) {
	type test struct {
		name     string
		cr       CustomRule
		validate func(err error)
	}

	tests := []test{
		{
			name: "should return no errors when valid custom rule",
			cr: CustomRule{
				ID:          "HS-LEAKS-1000",
				Name:        "test",
				Description: "test",
				Severity:    severities.Low,
				Confidence:  confidence.Low,
				Type:        OrMatch,
				Expressions: []string{""},
				Language:    languages.Leaks,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "should return error when empty custom rule",
			cr:   CustomRule{},
			validate: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "should return error when invalid ID",
			cr: CustomRule{
				ID:          "HS-INVALID-1",
				Name:        "test",
				Description: "test",
				Severity:    severities.Low,
				Confidence:  confidence.Low,
				Type:        Regular,
				Expressions: []string{""},
				Language:    languages.Java,
			},
			validate: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "should return error when duplicated ID",
			cr: CustomRule{
				ID:          "HS-LEAKS-1",
				Name:        "test",
				Description: "test",
				Severity:    severities.Low,
				Confidence:  confidence.Low,
				Type:        Regular,
				Expressions: []string{""},
				Language:    languages.Leaks,
			},
			validate: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "should return error when not supported language",
			cr: CustomRule{
				ID:          "HS-PYTHON-1",
				Name:        "test",
				Description: "test",
				Severity:    severities.Low,
				Confidence:  confidence.Low,
				Type:        Regular,
				Expressions: []string{""},
				Language:    languages.Python,
			},
			validate: func(err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cr.Validate()
			tt.validate(err)
		})
	}
}

func TestValidateAllLanguages1(t *testing.T) {
	type test struct {
		name     string
		cr       CustomRule
		validate func(err error)
	}

	tests := []test{
		{
			name: "Language CSharp",
			cr: CustomRule{
				ID:         "HS-CSHARP-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.CSharp,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language DART",
			cr: CustomRule{
				ID:         "HS-DART-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Dart,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language Java",
			cr: CustomRule{
				ID:         "HS-JAVA-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Java,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language Kotlin",
			cr: CustomRule{
				ID:         "HS-KOTLIN-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Kotlin,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language YAML",
			cr: CustomRule{
				ID:         "HS-YAML-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Yaml,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language Leaks",
			cr: CustomRule{
				ID:         "HS-LEAKS-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Leaks,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language JavaScript",
			cr: CustomRule{
				ID:         "HS-JAVASCRIPT-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Javascript,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Language Nginx",
			cr: CustomRule{
				ID:         "HS-NGINX-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Nginx,
			},
			validate: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Error due to invalid ID",
			cr: CustomRule{
				ID:         "HS-NOT-CORRECT-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Nginx,
			},
			validate: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "Language Nginx - Error due to invalid Language",
			cr: CustomRule{
				ID:         "HS-JAVA-10000",
				Severity:   severities.Low,
				Confidence: confidence.Low,
				Type:       Regular,
				Language:   languages.Language("DOESNTEXIST"),
			},
			validate: func(err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cr.Validate()
			tt.validate(err)
		})
	}
}

func TestGetRuleType1(t *testing.T) {
	type test struct {
		name     string
		cr       CustomRule
		validate func(m text.MatchType)
	}

	tests := []test{
		{
			name: "should return regular type",
			cr: CustomRule{
				Type: Regular,
			},
			validate: func(m text.MatchType) {
				require.Equal(t, text.Regular, m)
			},
		},
		{
			name: "should return regular type",
			cr:   CustomRule{},
			validate: func(m text.MatchType) {
				require.Equal(t, text.Regular, m)
			},
		},
		{
			name: "should return OR type",
			cr: CustomRule{
				Type: OrMatch,
			},
			validate: func(m text.MatchType) {
				require.Equal(t, text.OrMatch, m)
			},
		},
		{
			name: "should return AND type",
			cr: CustomRule{
				Type: AndMatch,
			},
			validate: func(m text.MatchType) {
				require.Equal(t, text.AndMatch, m)
			},
		},
		{
			name: "should return NOT type",
			cr: CustomRule{
				Type: NotMatch,
			},
			validate: func(m text.MatchType) {
				require.Equal(t, text.NotMatch, m)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.cr.GetRuleType()
			tt.validate(m)
		})
	}
}

func TestGetExpressions1(t *testing.T) {

	exprs := []string{"testOne", "testTwo"}
	exprOne, _ := regexp.Compile(exprs[0])
	exprTwo, _ := regexp.Compile(exprs[1])

	exprSl := []*regexp.Regexp{
		exprOne,
		exprTwo,
	}

	failedExpr := []string{"^\\/(?!\\/)(.*?)"}

	type test struct {
		name     string
		cr       CustomRule
		validate func(e []*regexp.Regexp)
	}

	tests := []test{
		{
			name: "successful get regex expressions",
			cr: CustomRule{
				Expressions: exprs,
			},
			validate: func(e []*regexp.Regexp) {
				require.Len(t, e, 2)
				require.ElementsMatch(t, exprSl, e)
			},
		},
		// TODO - Should this function not actually log its errors so we could
		// actually return and test for errors?
		{
			name: "should log an error when expression fails to complie",
			cr: CustomRule{
				Expressions: failedExpr,
			},
			validate: func(e []*regexp.Regexp) {
				require.Len(t, e, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.cr.GetExpressions()
			tt.validate(e)
		})
	}
}

func TestToString1(t *testing.T) {
	type test struct {
		name     string
		cr       CustomRule
		validate func(s string)
	}

	crStr := "{\"id\":\"test123\",\"name\":\"\",\"description\":\"\",\"language\":\"\",\"severity\":\"\",\"confidence\":\"\",\"type\":\"\",\"expressions\":null}"
	tests := []test{
		{
			name: "should log an error when failed to compile expression",
			cr: CustomRule{
				ID: "",
			},
			validate: func(s string) {
				require.NotEmpty(t, s)
			},
		},
		{
			name: "successful conversion to a string",
			cr: CustomRule{
				ID: "test123",
			},
			validate: func(s string) {
				require.NotEmpty(t, s)
				require.Equal(t, crStr, s)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.cr.String()
			tt.validate(s)
		})
	}
}
