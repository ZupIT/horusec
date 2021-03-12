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
package java

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/java/and"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/java/or"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/java/regular"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/jvm"
)

type Interface interface {
	GetAllRules() (rules []engine.Rule)
	GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error)
}

type Rules struct {
	jvmRules jvm.Interface
}

func NewRules() Interface {
	return &Rules{
		jvmRules: jvm.NewRules(),
	}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	rules = r.addJavaRules(rules)
	rules = r.jvmRules.GetAllRules(rules)
	return rules
}

func (r *Rules) addJavaRules(rules []engine.Rule) []engine.Rule {
	for _, rule := range allRulesJavaAnd() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesJavaOr() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesJavaRegular() {
		rules = append(rules, rule)
	}

	return rules
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnits, err := text.LoadDirIntoMultiUnit(projectPath, 5, r.getExtensions())
	if err != nil {
		return []engine.Unit{}, err
	}
	return r.parseTextUnitsToUnits(textUnits), nil
}

func (r *Rules) parseTextUnitsToUnits(textUnits []text.TextUnit) (units []engine.Unit) {
	for index := range textUnits {
		units = append(units, textUnits[index])
	}
	return units
}

func (r *Rules) getExtensions() []string {
	return []string{".java"}
}

func allRulesJavaRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewJavaRegularHiddenElements(),
		regular.NewJavaRegularWeakCypherBlockMode(),
		regular.NewJavaRegularPossibleFileWithVulnerabilityWhenOpen(),
		regular.NewJavaRegularWeakHash(),
		regular.NewJavaRegularSensitiveInformationNotEncrypted(),
		regular.NewJavaRegularInsecureRandomNumberGenerator(),
		regular.NewJavaRegularNoDefaultJavaHash(),
		regular.NewJavaRegularLayoutParamsFlagSecure(),
		regular.NewJavaRegularNoUseSQLCipher(),
		regular.NewJavaRegularPreventTapJackingAttacks(),
		regular.NewJavaRegularPreventWriteSensitiveInformationInTmpFile(),
		regular.NewJavaRegularGetWindowFlagSecure(),
		regular.NewJavaRegularLoadingNativeCode(),
		regular.NewJavaRegularDynamicClassAndDexloading(),
		regular.NewJavaRegularCryptoImport(),
		regular.NewJavaRegularStartingService(),
		regular.NewJavaRegularSendingBroadcast(),
		regular.NewJavaRegularLocalFileOperations(),
		regular.NewJavaRegularInterProcessCommunication(),
		regular.NewJavaRegularURLRewritingMethod(),
		regular.NewJavaRegularOverlyPermissiveCORSPolicy(),
		regular.NewJavaRegularHostnameVerifierThatAcceptAnySignedCertificates(),
		regular.NewJavaRegularDefaultHttpClient(),
		regular.NewJavaRegularWeakSSLContext(),
		regular.NewJavaRegularSQLInjection(),
		regular.NewJavaRegularDisablingHTMLEscaping(),
		regular.NewJavaRegularSQLInjectionWithTurbine(),
		regular.NewJavaRegularSQLInjectionWithHibernate(),
		regular.NewJavaRegularSQLInjectionWithJDO(),
		regular.NewJavaRegularSQLInjectionWithJPA(),
		regular.NewJavaRegularSQLInjectionWithSpringJDBC(),
		regular.NewJavaRegularSQLInjectionWithJDBC(),
		regular.NewJavaRegularLDAPInjection(),
		regular.NewJavaRegularUnsafeHashEquals(),
		regular.NewJavaRegularPotentialExternalControl(),
		regular.NewJavaRegularBadHexadecimalConcatenation(),
		regular.NewJavaRegularNullCipherInsecure(),
		regular.NewJavaRegularUnvalidatedRedirect(),
		regular.NewJavaRegularRequestMappingMethodsNotPublic(),
		regular.NewJavaRegularLDAPDeserializationNotDisabled(),
		regular.NewJavaRegularDatabasesPasswordNotProtected(),
	}
}

func allRulesJavaAnd() []text.TextRule {
	return []text.TextRule{
		and.NewJavaAndMessageDigestIsCustom(),
		and.NewJavaAndInsecureImplementationOfSSL(),
		and.NewJavaAndWebViewLoadFilesFromExternalStorage(),
		and.NewJavaAndInsecureWebViewImplementation(),
		and.NewJavaAndNoUseSQLCipher(),
		and.NewJavaAndNoUseRealmDatabaseWithEncryptionKey(),
		and.NewJavaAndNoUseWebviewDebuggingEnable(),
		and.NewJavaAndNoListenToClipboard(),
		and.NewJavaAndNoCopyContentToClipboard(),
		and.NewJavaAndNoUseWebviewIgnoringSSL(),
		and.NewJavaAndSQLInjectionWithSqlUtil(),
		and.NewJavaAndNoUseFridaServer(),
		and.NewJavaAndNoUseSSLPinningLib(),
		and.NewJavaAndNoUseDexGuardAppDebuggable(),
		and.NewJavaAndNoUseDexGuardDebuggerConnected(),
		and.NewJavaAndNoUseDexGuardEmulatorDetection(),
		and.NewJavaAndNoUseDexGuardWithDebugKey(),
		and.NewJavaAndNoUseDexGuardRoot(),
		and.NewJavaAndNoUseDexGuard(),
		and.NewJavaAndNoUseDexGuardInSigner(),
		and.NewJavaAndNoUsePackageWithTamperDetection(),
		and.NewJavaAndLoadAndManipulateDexFiles(),
		and.NewJavaAndObfuscation(),
		and.NewJavaAndExecuteOSCommand(),
		and.NewJavaAndTCPServerSocket(),
		and.NewJavaAndTCPSocket(),
		and.NewJavaAndUDPDatagramPacket(),
		and.NewJavaAndUDPDatagramSocket(),
		and.NewJavaAndWebViewJavaScriptInterface(),
		and.NewJavaAndGetCellInformation(),
		and.NewJavaAndGetCellLocation(),
		and.NewJavaAndGetSubscriberID(),
		and.NewJavaAndGetDeviceID(),
		and.NewJavaAndGetSoftwareVersion(),
		and.NewJavaAndGetSIMSerialNumber(),
		and.NewJavaAndGetSIMProviderDetails(),
		and.NewJavaAndGetSIMOperatorName(),
		and.NewJavaAndQueryDatabaseOfSMSContacts(),
		and.NewJavaAndPotentialPathTraversal(),
		and.NewJavaAndPotentialPathTraversalUsingScalaAPI(),
		and.NewJavaAndSMTPHeaderInjection(),
		and.NewJavaAndInsecureSMTPSSLConnection(),
		and.NewJavaAndAnonymousLDAPBind(),
		and.NewJavaAndLDAPEntryPoisoning(),
		and.NewJavaAndTrustManagerThatAcceptAnyCertificatesClient(),
		and.NewJavaAndTrustManagerThatAcceptAnyCertificatesServer(),
		and.NewJavaAndTrustManagerThatAcceptAnyCertificatesIssuers(),
		and.NewJavaAndXMLParsingVulnerableToXXE(),
		and.NewJavaAndIgnoringXMLCommentsInSAML(),
		and.NewJavaAndInformationExposureThroughAnErrorMessage(),
		and.NewJavaAndHTTPParameterPollution(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithDocumentBuilder(),
		and.NewJavaAndAWSQueryInjection(),
		and.NewJavaAndPotentialTemplateInjectionPebble(),
		and.NewJavaAndPotentialTemplateInjectionFreemarker(),
		and.NewJavaAndPersistentCookieUsage(),
		and.NewJavaAndRequestDispatcherFileDisclosure(),
		and.NewJavaAndSpringFileDisclosure(),
		and.NewJavaAndStrutsFileDisclosure(),
		and.NewJavaAndUnsafeJacksonDeserializationConfiguration(),
		and.NewJavaAndObjectDeserializationUsed(),
		and.NewJavaAndPotentialCodeScriptInjection(),
		and.NewJavaAndPotentialCodeScriptInjectionWithSpringExpression(),
		and.NewJavaAndCookieWithoutTheHttpOnlyFlag(),
		and.NewJavaAndWebViewWithGeolocationActivated(),
		and.NewJavaAndUseOfESAPIEncryptor(),
		and.NewJavaAndStaticIV(),
		and.NewJavaAndXMLDecoderUsage(),
		and.NewJavaAndPotentialXSSInServlet(),
		and.NewJavaAndEscapingOfSpecialXMLCharactersIsDisabled(),
		and.NewJavaAndDynamicVariableInSpringExpression(),
		and.NewJavaAndRSAUsageWithShortKey(),
		and.NewJavaAndBlowfishUsageWithShortKey(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithXMLInputFactory(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithSAXParserFactory(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithTransformerFactory(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithSchemaFactory(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithDom4j(),
		and.NewJavaAndXMLParsingVulnerableToXXEWithJdom2(),
		and.NewJavaAndClassesShouldNotBeLoadedDynamically(),
		and.NewJavaAndHostnameVerifierVerifyShouldNotAlwaysReturnTrue(),
		and.NewJavaAndXPathExpressionsShouldNotBeVulnerableToInjectionAttacks(),
		and.NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnections(),
		and.NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail(),
		and.NewJavaAndFunctionCallsShouldNotBeVulnerableToPathInjectionAttacks(),
		and.NewJavaAndServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithJavaMail(),
		and.NewJavaAndHTTPResponseHeadersShouldNotBeVulnerableToInjectionAttacks(),
		and.NewJavaAndLDAPAuthenticatedAnalyzeYourCode(),
		and.NewJavaAndSecureRandomSeedsShouldNotBePredictable(),
		and.NewJavaAndExceptionsShouldNotBeThrownFromServletMethods(),
		and.NewJavaAndActiveMQConnectionFactoryVulnerableToMaliciousCodeDeserialization(),
		and.NewJavaAndOpenSAML2ShouldBeConfiguredToPreventAuthenticationBypass(),
		and.NewJavaAndHttpServletRequestGetRequestedSessionIdShouldNotBeUsed(),
		and.NewJavaAndWebApplicationsShouldHotHaveAMainMethod(),
	}
}

func allRulesJavaOr() []text.TextRule {
	return []text.TextRule{
		or.NewJavaOrFileIsWorldReadable(),
		or.NewJavaOrFileIsWorldWritable(),
		or.NewJavaOrNoWriteExternalContent(),
		or.NewJavaOrNoUseIVsWeak(),
		or.NewJavaOrRootDetectionCapabilities(),
		or.NewJavaOrJARURLConnection(),
		or.NewJavaOrSetOrReadClipboardData(),
		or.NewJavaOrMessageDigest(),
		or.NewJavaOrOverlyPermissiveFilePermission(),
		or.NewJavaOrCipherGetInstanceInsecure(),
	}
}
