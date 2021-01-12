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

//nolint:lll multiple regex is not possible broken lines
package and

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewDartAndUsageLocalDataWithoutCryptography() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2a1596de-d78a-4e35-8384-7fa7cebd3259",
			Name:        "Usage Local Data Without Cryptography",
			Description: "While useful to speed applications up on the client side, it can be dangerous to store sensitive information this way because the data is not encrypted by default and any script on the page may access it. This rule raises an issue when the SharedPreferences and localstorage API's are used. For more information checkout the OWSAP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SharedPreferences\.getInstance`),
			regexp.MustCompile(`\.(setInt|setDouble|setBool|setString|setStringList)\(.*,.*\)`),
		},
	}
}

func NewDartAndNoSendSensitiveInformation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "40f00585-6d4e-48ca-be41-3d906bf57a26",
			Name:        "No Send Sensitive Information in alternative channels (sms, mms, notifications)",
			Description: "Sensitive information should never send for this channels sms, mms, notifications. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(firebase|fb).*\.configure\(`),
			regexp.MustCompile(`onMessage|onResume`),
		},
	}
}