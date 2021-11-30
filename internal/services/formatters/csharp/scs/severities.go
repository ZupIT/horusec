// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package scs

import "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

// These constants represents high vulnerabilities from scs.
const (
	commandInjection                  = "SCS0001"
	xPathInjection                    = "SCS0003"
	xmlExternalEntityInjectionXXE     = "SCS0007"
	crossSiteScriptingXSS             = "SCS0029"
	ldapInjection                     = "SCS0031"
	sqlInjectionLINQ                  = "SCS0002"
	sqlInjectionWebControls           = "SCS0014"
	sqlInjectionOLEDB                 = "SCS0020"
	sqlInjectionODBC                  = "SCS0025"
	sqlInjectionMsSQLDataProvider     = "SCS0026"
	sqlInjectionEntityFramework       = "SCS0035"
	sqlInjectionEnterpriseLibraryData = "SCS0036"
	sqlInjectionNHibernate            = "SCS0037"
	cqlInjectionCassandra             = "SCS0038"
	sqlInjectionNPGSQL                = "SCS0039"
	certificateValidationDisabled     = "SCS0004"
	crossSiteRequestForgeryCSRF       = "SCS0016"
	insecureDeserialization           = "SCS0028"
	openRedirect                      = "SCS0027"
	weakHashingFunction               = "SCS0006"
	weakCipherAlgorithm               = "SCS0010"
)

// These constants represents medium vulnerabilities from scs.
const (
	pathTraversal                  = "SCS0018"
	weakRandomNumberGenerator      = "SCS0005"
	weakCBCMode                    = "SCS0011"
	weakECBMode                    = "SCS0012"
	weakCipherMode                 = "SCS0013"
	viewStateNotEncrypted          = "SCS0023"
	viewStateMACDisabled           = "SCS0024"
	passwordRequiredLengthNotSet   = "SCS0034"
	passwordRequiredLengthTooSmall = "SCS0032"
	passwordComplexity             = "SCS0033"
	legacyPacket                   = "SCS9999"
)

// These constants represents low vulnerabilities from scs.
const (
	cookieWithoutSSLFlag                                    = "SCS0008"
	cookieWithoutHTTPOnlyFlag                               = "SCS0009"
	requestValidationDisabledAttribute                      = "SCS0017"
	requestValidationDisabledConfigurationFile              = "SCS0021"
	requestValidationIsEnabledOnlyForPagesConfigurationFile = "SCS0030"
	outputCacheConflict                                     = "SCS0019"
	eventValidationDisabled                                 = "SCS0022"
)

func criticalSeverities() map[string]severities.Severity {
	return map[string]severities.Severity{
		"SCS0015": severities.Critical,
	}
}

// nolint
func highSeverities() map[string]severities.Severity {
	return map[string]severities.Severity{
		commandInjection:                  severities.High,
		xPathInjection:                    severities.High,
		xmlExternalEntityInjectionXXE:     severities.High,
		crossSiteScriptingXSS:             severities.High,
		ldapInjection:                     severities.High,
		sqlInjectionLINQ:                  severities.High,
		sqlInjectionWebControls:           severities.High,
		sqlInjectionOLEDB:                 severities.High,
		sqlInjectionODBC:                  severities.High,
		sqlInjectionMsSQLDataProvider:     severities.High,
		sqlInjectionEntityFramework:       severities.High,
		sqlInjectionEnterpriseLibraryData: severities.High,
		sqlInjectionNHibernate:            severities.High,
		cqlInjectionCassandra:             severities.High,
		sqlInjectionNPGSQL:                severities.High,
		certificateValidationDisabled:     severities.High,
		crossSiteRequestForgeryCSRF:       severities.High,
		insecureDeserialization:           severities.High,
		openRedirect:                      severities.High,
		weakHashingFunction:               severities.High,
		weakCipherAlgorithm:               severities.High,
	}
}

func lowSevetiries() map[string]severities.Severity {
	return map[string]severities.Severity{
		cookieWithoutSSLFlag:                                    severities.Low,
		cookieWithoutHTTPOnlyFlag:                               severities.Low,
		requestValidationDisabledAttribute:                      severities.Low,
		requestValidationDisabledConfigurationFile:              severities.Low,
		requestValidationIsEnabledOnlyForPagesConfigurationFile: severities.Low,
		outputCacheConflict:                                     severities.Low,
		eventValidationDisabled:                                 severities.Low,
	}
}

func mediumSeverities() map[string]severities.Severity {
	return map[string]severities.Severity{
		pathTraversal:                  severities.Medium,
		weakRandomNumberGenerator:      severities.Medium,
		weakCBCMode:                    severities.Medium,
		weakECBMode:                    severities.Medium,
		weakCipherMode:                 severities.Medium,
		viewStateNotEncrypted:          severities.Medium,
		viewStateMACDisabled:           severities.Medium,
		passwordRequiredLengthNotSet:   severities.Medium,
		passwordRequiredLengthTooSmall: severities.Medium,
		passwordComplexity:             severities.Medium,
		legacyPacket:                   severities.Medium,
	}
}
