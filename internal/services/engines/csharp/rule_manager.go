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
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(Rules(), extensions())
}

func extensions() []string {
	return []string{".cs", ".vb", ".cshtml", ".csproj", ".xml"}
}

// Rules return all rules registred to C# engine.
func Rules() []engine.Rule {
	return []engine.Rule{
		// And rules
		NewCommandInjection(),
		NewXPathInjection(),
		NewExternalEntityInjection(),
		NewPathTraversal(),
		NewSQLInjectionWebControls(),
		NewFormsAuthenticationCookielessMode(),
		NewFormsAuthenticationWeakCookieProtection(),
		NewFormsAuthenticationCrossAppRedirects(),
		NewWeakCipherOrCBCOrECBMode(),
		NewFormsAuthenticationWeakTimeout(),
		NewHeaderCheckingDisabled(),
		NewVersionHeaderEnabled(),
		NewEventValidationDisabled(),
		NewWeakSessionTimeout(),
		NewStateServerMode(),
		NewJwtSignatureValidationDisabled(),
		NewInsecureHttpCookieTransport(),
		NewHttpCookieAccessibleViaScript(),
		NewDirectoryListingEnabled(),
		NewLdapAuthenticationDisabled(),
		NewCertificateValidationDisabledAndMatch(),
		NewActionRequestValidationDisabled(),
		NewXmlDocumentExternalEntityExpansion(),
		NewLdapInjectionFilterAssignment(),
		NewSqlInjectionDynamicNHibernateQuery(),
		NewLdapInjectionDirectorySearcher(),
		NewLdapInjectionPathAssignment(),

		// Or rules
		NewLDAPInjection(),
		NewSQLInjectionLinq(),
		NewInsecureDeserialization(),
		NewCookieWithoutSSLFlag(),
		NewCookieWithoutHttpOnlyFlag(),
		NewSQLInjectionEnterpriseLibraryData(),
		NewCQLInjectionCassandra(),
		NewPasswordComplexity(),
		NewNoInputVariable(),
		NewIdentityWeakPasswordComplexity(),

		// Regular rules
		NewNoLogSensitiveInformationInConsole(),
		NewOutputCacheConflict(),
		NewOpenRedirect(),
		NewRequestValidationDisabledAttribute(),
		NewRequestValidationDisabledConfigurationFile(),
		NewRequestValidationIsEnabledOnlyForPages(),
		NewViewStateNotEncrypted(),
		NewViewStateMacDisabled(),
		NewSQLInjectionOLEDB(),
		NewSQLInjectionMsSQLDataProvider(),
		NewSQLInjectionEntityFramework(),
		NewSQLInjectionNhibernate(),
		NewSQLInjectionNpgsql(),
		NewCertificateValidationDisabled(),
		NewWeakCipherAlgorithm(),
		NewNoUseHtmlRaw(),
		NewNoLogSensitiveInformation(),
		NewNoReturnStringConcatInController(),
		NewSQLInjectionOdbcCommand(),
		NewWeakHashingFunctionMd5OrSha1(),
		NewWeakHashingFunctionDESCrypto(),
		NewNoUseCipherMode(),
		NewDebugBuildEnabled(),
		NewVulnerablePackageReference(),
		NewCorsAllowOriginWildCard(),
		NewMissingAntiForgeryTokenAttribute(),
		NewUnvalidatedWebFormsRedirect(),
		NewIdentityPasswordLockoutDisabled(),
		NewRawInlineExpression(),
		NewRawBindingExpression(),
		NewRawWriteLiteralMethod(),
		NewUnencodedWebFormsProperty(),
		NewUnencodedLabelText(),
		NewWeakRandomNumberGenerator(),
		NewWeakRsaKeyLength(),
		NewXmlReaderExternalEntityExpansion(),
		NewLdapInjectionDirectoryEntry(),
	}
}
