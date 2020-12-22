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
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/nodejs/and"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/nodejs/or"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/nodejs/regular"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Interface interface {
	GetAllRules() (rules []engine.Rule)
	GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error)
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	rules = r.addRules(rules)
	return rules
}

func (r *Rules) addRules(rules []engine.Rule) []engine.Rule {
	for _, rule := range allRulesNodeJSAnd() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesNodeJSOr() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesNodeJSRegular() {
		rules = append(rules, rule)
	}

	return rules
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnits, err := text.LoadDirIntoMultiUnit(projectPath, 5, r.getExtensions())
	units := r.parseTextUnitsToUnits(textUnits)
	logger.LogDebugJSON("Texts Units selected are: ", units)
	return units, err
}

func (r *Rules) getExtensions() []string {
	return []string{".js", ".ts", ".jsx", ".tsx"}
}

func (r *Rules) parseTextUnitsToUnits(textUnits []text.TextUnit) (units []engine.Unit) {
	for index := range textUnits {
		units = append(units, textUnits[index])
	}

	return units
}

func allRulesNodeJSRegular() []text.TextRule {
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

func allRulesNodeJSAnd() []text.TextRule {
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

func allRulesNodeJSOr() []text.TextRule {
	return []text.TextRule{
		or.NewNodeJSOrEncryptionAlgorithmsWeak(),
		or.NewNodeJSOrFileUploadsShouldBeRestricted(),
		or.NewNodeJSOrAllowingRequestsWithExcessiveContentLengthSecurity(),
		or.NewNodeJSOrNoDisableSanitizeHtml(),
		or.NewNodeJSOrSQLInjection(),
	}
}
