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

package dart

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/dart/and"
	"github.com/ZupIT/horusec/internal/services/engines/dart/or"
	"github.com/ZupIT/horusec/internal/services/engines/dart/regular"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(rules(), extensions())
}

func rules() []engine.Rule {
	return []engine.Rule{
		// And Rules
		and.NewDartAndUsageLocalDataWithoutCryptography(),
		and.NewDartAndNoSendSensitiveInformation(),
		and.NewDartAndNoUseBiometricsTypeIOS(),
		and.NewDartAndXmlReaderExternalEntityExpansion(),

		// Or rules
		or.NewDartOrNoUseConnectionWithoutSSL(),
		or.NewDartOrSendSMS(),

		// Regular rules
		regular.NewDartRegularXSSAttack(),
		regular.NewDartRegularNoLogSensitive(),
		regular.NewDartRegularWeakHashingFunctionMd5OrSha1(),
		regular.NewDartRegularNoUseSelfSignedCertificate(),
		regular.NewDartRegularNoUseBiometricsTypeAndroid(),
		regular.NewDartRegularNoListClipboardChanges(),
		regular.NewDartRegularSQLInjection(),
		regular.NewDartRegularNoUseNSTemporaryDirectory(),
		regular.NewDartRegularNoUseCipherMode(),
		regular.NewDartRegularCorsAllowOriginWildCard(),
		regular.NewDartRegularUsingShellInterpreterWhenExecutingOSCommand(),
	}
}

func extensions() []string {
	return []string{".dart"}
}
