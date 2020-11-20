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
package nodejs

import (
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/nodejs/and"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/nodejs/or"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/nodejs/regular"
)

func AllRulesNodeJSRegular() []text.TextRule {
	return []text.TextRule{
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
	}
}

func AllRulesNodeJSAnd() []text.TextRule {
	return []text.TextRule{
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
	}
}

func AllRulesNodeJSOr() []text.TextRule {
	return []text.TextRule{
		or.NewNodeJSOrEncryptionAlgorithmsWeak(),
		or.NewNodeJSOrFileUploadsShouldBeRestricted(),
		or.NewNodeJSOrAllowingRequestsWithExcessiveContentLengthSecurity(),
		or.NewNodeJSOrNoDisableSanitizeHtml(),
		or.NewNodeJSOrSQLInjection(),
	}
}
