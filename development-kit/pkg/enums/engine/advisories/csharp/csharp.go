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

package csharp

import (
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/csharp/and"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/csharp/or"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/csharp/regular"
)

func AllRulesCsharpRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewCsharpRegularCrossSiteScripting(),
		regular.NewCsharpRegularOutputCacheConflict(),
		regular.NewCsharpRegularOpenRedirect(),
		regular.NewCsharpRegularRequestValidationDisabledAttribute(),
		regular.NewCsharpRegularRequestValidationDisabledConfigurationFile(),
		regular.NewCsharpRegularRequestValidationIsEnabledOnlyForPages(),
		regular.NewCsharpRegularViewStateNotEncrypted(),
		regular.NewCsharpRegularViewStateMacDisabled(),
		regular.NewCsharpRegularPasswordComplexity(),
		regular.NewCsharpRegularSQLInjectionOLEDB(),
		regular.NewCsharpRegularSQLInjectionMsSQLDataProvider(),
		regular.NewCsharpRegularSQLInjectionEntityFramework(),
		regular.NewCsharpRegularSQLInjectionNhibernate(),
		regular.NewCsharpRegularSQLInjectionNpgsql(),
		regular.NewCsharpRegularCertificateValidationDisabled(),
		regular.NewCsharpRegularWeakCipherAlgorithm(),
		regular.NewCsharpRegularNoUseHtmlRaw(),
		regular.NewCsharpRegularNoLogSensitiveInformation(),
		regular.NewCsharpRegularNoReturnStringConcatInController(),
		regular.NewCsharpRegularSQLInjectionOdbcCommand(),
		regular.NewCsharpRegularWeakHashingFunctionMd5OrSha1(),
		regular.NewCsharpRegularWeakHashingFunctionDESCrypto(),
		regular.NewCsharpRegularNoUseCipherMode(),
		regular.NewCsharpRegularCrossSiteRequestForgery(),
		regular.NewCsharpRegularDebugBuildEnabled(),
	}
}

func AllRulesCsharpAnd() []text.TextRule {
	return []text.TextRule{
		and.NewCsharpAndCommandInjection(),
		and.NewCsharpAndXPathInjection(),
		and.NewCsharpAndExternalEntityInjection(),
		and.NewCsharpAndPathTraversal(),
		and.NewCsharpAndSQLInjectionWebControls(),
		and.NewCsharpAndWeakRandomNumberGenerator(),
		and.NewCsharpAndFormsAuthenticationCookielessMode(),
		and.NewCsharpAndFormsAuthenticationWeakCookieProtection(),
		and.NewCsharpAndFormsAuthenticationCrossAppRedirects(),
		and.NewCsharpAndWeakCipherOrCBCOrECBMode(),
		and.NewCsharpAndFormsAuthenticationWeakTimeout(),
	}
}

func AllRulesCsharpOr() []text.TextRule {
	return []text.TextRule{
		or.NewCsharpOrLDAPInjection(),
		or.NewCsharpOrSQLInjectionLinq(),
		or.NewCsharpOrInsecureDeserialization(),
		or.NewCsharpOrCookieWithoutSSLFlag(),
		or.NewCsharpOrCookieWithoutHttpOnlyFlag(),
		or.NewCsharpOrSQLInjectionEnterpriseLibraryData(),
		or.NewCsharpOrCQLInjectionCassandra(),
		or.NewCsharpOrPasswordComplexity(),
		or.NewCsharpOrNoInputVariable(),
	}
}
