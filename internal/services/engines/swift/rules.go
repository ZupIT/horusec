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

package swift

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/swift/and"
	"github.com/ZupIT/horusec/internal/services/engines/swift/or"
	"github.com/ZupIT/horusec/internal/services/engines/swift/regular"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(rules(), extensions())
}

func extensions() []string {
	return []string{".swift"}
}

func rules() []engine.Rule {
	return []engine.Rule{
		// And rules
		and.NewSwiftAndWeakCommonDesCryptoCipher(),
		and.NewSwiftAndWeakIDZDesCryptoCipher(),
		and.NewSwiftAndWeakBlowfishCryptoCipher(),
		and.NewSwiftAndWeakMD5CryptoCipher(),
		and.NewSwiftAndReverseEngineering(),
		and.NewSwiftAndTLS13NotUsed(),
		and.NewSwiftAndDTLS12NotUsed(),
		and.NewSwiftAndCoreDataDatabase(),
		and.NewSwiftAndSQLiteDatabase(),

		// Or rules
		or.NewSwiftOrWeakDesCryptoCipher(),
		or.NewSwiftOrLoadHTMLString(),
		or.NewSwiftOrJailbreakDetect(),
		or.NewSwiftOrSha1Collision(),
		or.NewSwiftOrMD5Collision(),
		or.NewSwiftOrMD6Collision(),

		// Regular rules
		regular.NewSwiftRegularMD2Collision(),
		regular.NewSwiftRegularMD4Collision(),
		regular.NewSwiftRegularWebViewSafari(),
		regular.NewSwiftRegularFileProtection(),
		regular.NewSwiftRegularUIPasteboard(),
		regular.NewSwiftRegularKeyboardCache(),
		regular.NewSwiftRegularTLSMinimum(),
		regular.NewSwiftRegularRealmDatabase(),
	}
}
