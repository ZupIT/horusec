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
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/csharp/and"
	"github.com/ZupIT/horusec/internal/services/engines/csharp/or"
	"github.com/ZupIT/horusec/internal/services/engines/csharp/regular"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(rules(), extensions())
}

func extensions() []string {
	return []string{".cs", ".vb", ".cshtml", ".csproj", ".xml"}
}

func rules() []engine.Rule {
	return []engine.Rule{
		// And rules
		and.NewCsharpAndCommandInjection(),
		and.NewCsharpAndXPathInjection(),
		and.NewCsharpAndExternalEntityInjection(),
		and.NewCsharpAndPathTraversal(),
		and.NewCsharpAndSQLInjectionWebControls(),
		and.NewCsharpAndFormsAuthenticationCookielessMode(),
		and.NewCsharpAndFormsAuthenticationWeakCookieProtection(),
		and.NewCsharpAndFormsAuthenticationCrossAppRedirects(),
		and.NewCsharpAndWeakCipherOrCBCOrECBMode(),
		and.NewCsharpAndFormsAuthenticationWeakTimeout(),
		and.NewCsharpAndHeaderCheckingDisabled(),
		and.NewCsharpAndVersionHeaderEnabled(),
		and.NewCsharpAndEventValidationDisabled(),
		and.NewCsharpAndWeakSessionTimeout(),
		and.NewCsharpAndStateServerMode(),
		and.NewCsharpAndJwtSignatureValidationDisabled(),
		and.NewCsharpAndInsecureHttpCookieTransport(),
		and.NewCsharpAndHttpCookieAccessibleViaScript(),
		and.NewCsharpAndDirectoryListingEnabled(),
		and.NewCsharpAndLdapAuthenticationDisabled(),
		and.NewCsharpAndCertificateValidationDisabled(),
		and.NewCsharpAndActionRequestValidationDisabled(),
		and.NewCsharpAndXmlDocumentExternalEntityExpansion(),
		and.NewCsharpAndLdapInjectionFilterAssignment(),
		and.NewCsharpAndSqlInjectionDynamicNHibernateQuery(),
		and.NewCsharpAndLdapInjectionDirectorySearcher(),
		and.NewCsharpAndLdapInjectionPathAssignment(),

		// Or rules
		or.NewCsharpOrLDAPInjection(),
		or.NewCsharpOrSQLInjectionLinq(),
		or.NewCsharpOrInsecureDeserialization(),
		or.NewCsharpOrCookieWithoutSSLFlag(),
		or.NewCsharpOrCookieWithoutHttpOnlyFlag(),
		or.NewCsharpOrSQLInjectionEnterpriseLibraryData(),
		or.NewCsharpOrCQLInjectionCassandra(),
		or.NewCsharpOrPasswordComplexity(),
		or.NewCsharpOrNoInputVariable(),
		or.NewCsharpOrIdentityWeakPasswordComplexity(),

		// Regular rules
		regular.NewCsharpRegularNoLogSensitiveInformationInConsole(),
		regular.NewCsharpRegularOutputCacheConflict(),
		regular.NewCsharpRegularOpenRedirect(),
		regular.NewCsharpRegularRequestValidationDisabledAttribute(),
		regular.NewCsharpRegularRequestValidationDisabledConfigurationFile(),
		regular.NewCsharpRegularRequestValidationIsEnabledOnlyForPages(),
		regular.NewCsharpRegularViewStateNotEncrypted(),
		regular.NewCsharpRegularViewStateMacDisabled(),
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
		regular.NewCsharpRegularDebugBuildEnabled(),
		regular.NewCsharpRegularVulnerablePackageReference(),
		regular.NewCsharpRegularCorsAllowOriginWildCard(),
		regular.NewCsharpRegularMissingAntiForgeryTokenAttribute(),
		regular.NewCsharpRegularUnvalidatedWebFormsRedirect(),
		regular.NewCsharpRegularIdentityPasswordLockoutDisabled(),
		regular.NewCsharpRegularRawInlineExpression(),
		regular.NewCsharpRegularRawBindingExpression(),
		regular.NewCsharpRegularRawWriteLiteralMethod(),
		regular.NewCsharpRegularUnencodedWebFormsProperty(),
		regular.NewCsharpRegularUnencodedLabelText(),
		regular.NewCsharpRegularWeakRandomNumberGenerator(),
		regular.NewCsharpRegularWeakRsaKeyLength(),
		regular.NewCsharpRegularXmlReaderExternalEntityExpansion(),
		regular.NewCsharpRegularLdapInjectionDirectoryEntry(),
	}
}
