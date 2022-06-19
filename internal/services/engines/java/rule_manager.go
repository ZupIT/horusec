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

package java

import (
	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/jvm"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(Rules(), extensions())
}

func extensions() []string {
	return []string{".java", ".xml", ".gradle"}
}

// Rules return all rules registred to Java engine.
func Rules() []engine.Rule {
	java := []engine.Rule{
		// And rules
		NewMessageDigestIsCustom(),
		NewInsecureImplementationOfSSL(),
		NewWebViewLoadFilesFromExternalStorage(),
		NewInsecureWebViewImplementation(),
		// NewNoUseSQLCipherAndMatch(),
		// NewNoUseRealmDatabaseWithEncryptionKey(),
		NewNoUseWebviewDebuggingEnable(),
		NewNoListenToClipboard(),
		NewNoCopyContentToClipboard(),
		NewNoUseWebviewIgnoringSSL(),
		NewSQLInjectionWithSqlUtil(),
		NewLoadAndManipulateDexFiles(),
		NewObfuscation(),
		NewExecuteOSCommand(),
		NewTCPServerSocket(),
		NewTCPSocket(),
		NewUDPDatagramPacket(),
		NewUDPDatagramSocket(),
		NewWebViewScriptInterface(),
		NewGetCellInformation(),
		NewGetCellLocation(),
		NewGetSubscriberID(),
		NewGetDeviceID(),
		NewGetSoftwareVersion(),
		NewGetSIMSerialNumber(),
		NewGetSIMProviderDetails(),
		NewGetSIMOperatorName(),
		NewQueryDatabaseOfSMSContacts(),
		NewPotentialPathTraversal(),
		NewJakartaAndPotentialPathTraversal(),
		NewPotentialPathTraversalUsingScalaAPI(),
		NewSMTPHeaderInjection(),
		NewInsecureSMTPSSLConnection(),
		NewAnonymousLDAPBind(),
		NewLDAPEntryPoisoning(),
		NewTrustManagerThatAcceptAnyCertificatesClient(),
		// NewTrustManagerThatAcceptAnyCertificatesServer(),
		// NewTrustManagerThatAcceptAnyCertificatesIssuers(),
		NewXMLParsingVulnerableToXXE(),
		NewIgnoringXMLCommentsInSAML(),
		NewInformationExposureThroughAnErrorMessage(),
		NewHTTPParameterPollution(),
		NewXMLParsingVulnerableToXXEWithDocumentBuilder(),
		NewAWSQueryInjection(),
		NewPotentialTemplateInjectionPebble(),
		NewPotentialTemplateInjectionFreemarker(),
		NewPersistentCookieUsage(),
		NewRequestDispatcherFileDisclosure(),
		NewSpringFileDisclosure(),
		NewStrutsFileDisclosure(),
		NewUnsafeJacksonDeserializationConfiguration(),
		NewObjectDeserializationUsed(),
		NewPotentialCodeScriptInjection(),
		NewPotentialCodeScriptInjectionWithSpringExpression(),
		NewCookieWithoutTheHttpOnlyFlag(),
		NewWebViewWithGeolocationActivated(),
		NewUseOfESAPIEncryptor(),
		NewStaticIV(),
		NewXMLDecoderUsage(),
		NewPotentialXSSInServlet(),
		NewEscapingOfSpecialXMLCharactersIsDisabled(),
		NewDynamicVariableInSpringExpression(),
		NewRSAUsageWithShortKey(),
		NewBlowfishUsageWithShortKey(),
		NewXMLParsingVulnerableToXXEWithXMLInputFactory(),
		NewXMLParsingVulnerableToXXEWithSAXParserFactory(),
		NewXMLParsingVulnerableToXXEWithTransformerFactory(),
		// NewXMLParsingVulnerableToXXEWithSchemaFactory(),
		NewXMLParsingVulnerableToXXEWithDom4j(),
		NewXMLParsingVulnerableToXXEWithJdom2(),
		NewClassesShouldNotBeLoadedDynamically(),
		// NewHostnameVerifierVerifyShouldNotAlwaysReturnTrue(),
		NewXPathExpressionsShouldNotBeVulnerableToInjectionAttacks(),
		NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnections(),
		NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithSimpleEmail(),
		NewFunctionCallsShouldNotBeVulnerableToPathInjectionAttacks(),
		NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithMail(),
		// NewServerHostnamesShouldBeVerifiedDuringSSLTLSConnectionsWithJakartaMail(),
		NewHTTPResponseHeadersShouldNotBeVulnerableToInjectionAttacks(),
		NewLDAPAuthenticatedAnalyzeYourCode(),
		NewSecureRandomSeedsShouldNotBePredictable(),
		NewExceptionsShouldNotBeThrownFromServletMethods(),
		NewActiveMQConnectionFactoryVulnerableToMaliciousCodeDeserialization(),
		NewOpenSAML2ShouldBeConfiguredToPreventAuthenticationBypass(),
		NewHttpServletRequestGetRequestedSessionIdShouldNotBeUsed(),
		NewJakartaAndHttpServletRequestGetRequestedSessionIdShouldNotBeUsed(),
		NewWebApplicationsShouldHotHaveAMainMethod(),
		NewJakartaAndWebApplicationsShouldHotHaveAMainMethod(),

		// Or Rules
		NewFileIsWorldReadable(),
		NewFileIsWorldWritable(),
		NewNoWriteExternalContent(),
		NewNoUseIVsWeak(),
		NewRootDetectionCapabilities(),
		NewJARURLConnection(),
		// NewSetOrReadClipboardData(),
		// NewMessageDigest(),
		NewOverlyPermissiveFilePermission(),
		NewCipherGetInstanceInsecure(),
		NewVulnerableRemoteCodeExecutionSpringFramework(),

		// Regular rules
		NewHiddenElements(),
		NewWeakCypherBlockMode(),
		NewPossibleFileWithVulnerabilityWhenOpen(),
		NewWeakHash(),
		NewSensitiveInformationNotEncrypted(),
		NewInsecureRandomNumberGenerator(),
		NewNoDefaultHash(),
		NewLayoutParamsFlagSecure(),
		NewNoUseSQLCipher(),
		NewPreventTapJackingAttacks(),
		NewPreventWriteSensitiveInformationInTmpFile(),
		NewGetWindowFlagSecure(),
		NewLoadingNativeCode(),
		NewDynamicClassAndDexloading(),
		NewCryptoImport(),
		NewStartingService(),
		NewSendingBroadcast(),
		NewLocalFileOperations(),
		NewInterProcessCommunication(),
		NewURLRewritingMethod(),
		NewOverlyPermissiveCORSPolicy(),
		NewHostnameVerifierThatAcceptAnySignedCertificates(),
		NewDefaultHttpClient(),
		NewWeakSSLContext(),
		NewSQLInjection(),
		NewDisablingHTMLEscaping(),
		NewSQLInjectionWithTurbine(),
		NewSQLInjectionWithHibernate(),
		NewSQLInjectionWithJDO(),
		NewSQLInjectionWithJPA(),
		NewSQLInjectionWithSpringJDBC(),
		NewSQLInjectionWithJDBC(),
		NewLDAPInjection(),
		NewUnsafeHashEquals(),
		NewPotentialExternalControl(),
		NewBadHexadecimalConcatenation(),
		NewNullCipherInsecure(),
		NewUnvalidatedRedirect(),
		NewRequestMappingMethodsNotPublic(),
		NewLDAPDeserializationNotDisabled(),
		NewDatabasesPasswordNotProtected(),
		NewVulnerableRemoteCodeInjectionApacheLog4j(),
		NewUncheckedClassInstatiation(),
	}
	return append(java, jvm.Rules()...)
}
