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

package javascript

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/services/engines"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(Rules(), extensions())
}

func extensions() []string {
	return []string{".js", ".ts", ".jsx", ".tsx"}
}

// Rules return all rules registred to Javascript engine.
func Rules() []engine.Rule {
	return []engine.Rule{
		// Regular rules
		NewNoUseEval(),
		NewNoDisableTlsRejectUnauthorized(),
		NewNoUseMD5Hashing(),
		NewNoUseSHA1Hashing(),
		NewNoReadFileUsingDataFromRequest(),
		NewNoCreateReadStreamUsingDataFromRequest(),
		NewSQLInjectionUsingParams(),
		NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
		NewOriginsNotVerified(),
		NewWeakSSLTLSProtocolsShouldNotBeUsed(),
		NewWebSQLDatabasesShouldNotBeUsed(),
		NewLocalStorageShouldNotBeUsed(),
		NewDebuggerStatementsShouldNotBeUsed(),
		NewAlertStatementsShouldNotBeUsed(),
		NewNoUseWeakRandom(),
		NewStaticallyServingHiddenFilesIsSecuritySensitive(),
		NewUsingIntrusivePermissionsWithGeolocation(),
		NewHavingAPermissiveCrossOriginResourceSharingPolicy(),
		NewReadingTheStandardInput(),
		NewUsingCommandLineArguments(),
		NewNoLogSensitiveInformationInConsole(),
		NewRedirectToUnknownPath(),
		NewNoRenderContentFromRequest(),
		NewNoWriteOnDocumentContentFromRequest(),
		NewNoExposeStackTrace(),
		NewInsecureDownload(),

		// And rules
		NewNoUseGetMethodUsingDataFromRequestOfUserInput(),
		NewNoUseRequestMethodUsingDataFromRequestOfUserInput(),
		NewCryptographicRsaShouldBeRobust(),
		NewCryptographicEcShouldBeRobust(),
		NewJWTNeedStrongCipherAlgorithms(),
		NewServerHostnameNotVerified(),
		NewServerCertificatesNotVerified(),
		NewUntrustedContentShouldNotBeIncluded(),
		NewMysqlHardCodedCredentialsSecuritySensitive(),
		NewUsingShellInterpreterWhenExecutingOSCommands(),
		NewForwardingClientIPAddress(),
		NewAllowingConfidentialInformationToBeLoggedWithSignale(),
		NewAllowingBrowsersToPerformDNSPrefetching(),
		NewDisablingCertificateTransparencyMonitoring(),
		NewDisablingStrictHTTPNoReferrerPolicy(),
		NewAllowingBrowsersToSniffMIMETypes(),
		NewDisablingContentSecurityPolicyFrameAncestorsDirective(),
		NewAllowingMixedContent(),
		NewDisablingContentSecurityPolicyFetchDirectives(),
		NewCreatingCookiesWithoutTheHttpOnlyFlag(),
		NewCreatingCookiesWithoutTheSecureFlag(),
		NewNoUseSocketManually(),

		// Or rules
		NewEncryptionAlgorithmsWeak(),
		NewFileUploadsShouldBeRestricted(),
		NewAllowingRequestsWithExcessiveContentLengthSecurity(),
		NewNoDisableSanitizeHtml(),
		NewSQLInjection(),
	}
}
