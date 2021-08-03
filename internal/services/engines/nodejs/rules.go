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

package nodejs

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/nodejs/and"
	"github.com/ZupIT/horusec/internal/services/engines/nodejs/or"
	"github.com/ZupIT/horusec/internal/services/engines/nodejs/regular"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(rules(), extensions())
}

func extensions() []string {
	return []string{".js", ".ts", ".jsx", ".tsx"}
}

func rules() []engine.Rule {
	return []engine.Rule{
		// Regular rules
		regular.NewNodeJSRegularNoUseEval(),
		regular.NewNodeJSRegularNoDisableTlsRejectUnauthorized(),
		regular.NewNodeJSRegularNoUseMD5Hashing(),
		regular.NewNodeJSRegularNoUseSAH1Hashing(),
		regular.NewNodeJSRegularNoReadFileUsingDataFromRequest(),
		regular.NewNodeJSRegularNoCreateReadStreamUsingDataFromRequest(),
		regular.NewNodeJSRegularSQLInjectionUsingParams(),
		regular.NewNodeJSRegularXMLParsersShouldNotBeVulnerableToXXEAttacks(),
		regular.NewNodeJSRegularOriginsNotVerified(),
		regular.NewNodeJSRegularWeakSSLTLSProtocolsShouldNotBeUsed(),
		regular.NewNodeJSRegularWebSQLDatabasesShouldNotBeUsed(),
		regular.NewNodeJSRegularLocalStorageShouldNotBeUsed(),
		regular.NewNodeJSRegularDebuggerStatementsShouldNotBeUsed(),
		regular.NewNodeJSRegularAlertStatementsShouldNotBeUsed(),
		regular.NewNodeJSRegularNoUseWeakRandom(),
		regular.NewNodeJSRegularStaticallyServingHiddenFilesIsSecuritySensitive(),
		regular.NewNodeJSRegularUsingIntrusivePermissionsWithGeolocation(),
		regular.NewNodeJSRegularHavingAPermissiveCrossOriginResourceSharingPolicy(),
		regular.NewNodeJSRegularReadingTheStandardInput(),
		regular.NewNodeJSRegularUsingCommandLineArguments(),
		regular.NewNodeJSRegularNoLogSensitiveInformationInConsole(),
		regular.NewNodeJSRegularRedirectToUnknownPath(),
		regular.NewNodeJSRegularNoRenderContentFromRequest(),
		regular.NewNodeJSRegularNoWriteOnDocumentContentFromRequest(),
		regular.NewNodeJSRegularNoExposeStackTrace(),

		// And rules
		and.NewNodeJSAndNoUseGetMethodUsingDataFromRequestOfUserInput(),
		and.NewNodeJSAndNoUseRequestMethodUsingDataFromRequestOfUserInput(),
		and.NewNodeJSAndCryptographicRsaShouldBeRobust(),
		and.NewNodeJSAndCryptographicEcShouldBeRobust(),
		and.NewNodeJSAndJWTNeedStrongCipherAlgorithms(),
		and.NewNodeJSAndServerHostnameNotVerified(),
		and.NewNodeJSAndServerCertificatesNotVerified(),
		and.NewNodeJSAndUntrustedContentShouldNotBeIncluded(),
		and.NewNodeJSAndMysqlHardCodedCredentialsSecuritySensitive(),
		and.NewNodeJSAndUsingShellInterpreterWhenExecutingOSCommands(),
		and.NewNodeJSAndForwardingClientIPAddress(),
		and.NewNodeJSAndAllowingConfidentialInformationToBeLoggedWithSignale(),
		and.NewNodeJSAndAllowingBrowsersToPerformDNSPrefetching(),
		and.NewNodeJSAndDisablingCertificateTransparencyMonitoring(),
		and.NewNodeJSAndDisablingStrictHTTPNoReferrerPolicy(),
		and.NewNodeJSAndAllowingBrowsersToSniffMIMETypes(),
		and.NewNodeJSAndDisablingContentSecurityPolicyFrameAncestorsDirective(),
		and.NewNodeJSAndAllowingMixedContent(),
		and.NewNodeJSAndDisablingContentSecurityPolicyFetchDirectives(),
		and.NewNodeJSAndCreatingCookiesWithoutTheHttpOnlyFlag(),
		and.NewNodeJSAndCreatingCookiesWithoutTheSecureFlag(),
		and.NewNodeJSAndNoUseSocketManually(),

		// Or rules
		or.NewNodeJSOrEncryptionAlgorithmsWeak(),
		or.NewNodeJSOrFileUploadsShouldBeRestricted(),
		or.NewNodeJSOrAllowingRequestsWithExcessiveContentLengthSecurity(),
		or.NewNodeJSOrNoDisableSanitizeHtml(),
		or.NewNodeJSOrSQLInjection(),
	}
}
