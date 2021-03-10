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

package severities

import "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

const (
	CommandInjection                  = "SCS0001"
	XPathInjection                    = "SCS0003"
	XMLExternalEntityInjectionXXE     = "SCS0007"
	CrossSiteScriptingXSS             = "SCS0029"
	LDAPInjection                     = "SCS0031"
	SQLInjectionLINQ                  = "SCS0002"
	SQLInjectionWebControls           = "SCS0014"
	SQLInjectionOLEDB                 = "SCS0020"
	SQLInjectionODBC                  = "SCS0025"
	SQLInjectionMsSQLDataProvider     = "SCS0026"
	SQLInjectionEntityFramework       = "SCS0035"
	SQLInjectionEnterpriseLibraryData = "SCS0036"
	SQLInjectionNHibernate            = "SCS0037"
	CQLInjectionCassandra             = "SCS0038"
	SQLInjectionNPGSQL                = "SCS0039"
	CertificateValidationDisabled     = "SCS0004"
	CrossSiteRequestForgeryCSRF       = "SCS0016"
	InsecureDeserialization           = "SCS0028"
	OpenRedirect                      = "SCS0027"
	WeakHashingFunction               = "SCS0006"
	WeakCipherAlgorithm               = "SCS0010"
)

// nolint
func MapHighValues() map[string]severity.Severity {
	return map[string]severity.Severity{
		CommandInjection:                  severity.High,
		XPathInjection:                    severity.High,
		XMLExternalEntityInjectionXXE:     severity.High,
		CrossSiteScriptingXSS:             severity.High,
		LDAPInjection:                     severity.High,
		SQLInjectionLINQ:                  severity.High,
		SQLInjectionWebControls:           severity.High,
		SQLInjectionOLEDB:                 severity.High,
		SQLInjectionODBC:                  severity.High,
		SQLInjectionMsSQLDataProvider:     severity.High,
		SQLInjectionEntityFramework:       severity.High,
		SQLInjectionEnterpriseLibraryData: severity.High,
		SQLInjectionNHibernate:            severity.High,
		CQLInjectionCassandra:             severity.High,
		SQLInjectionNPGSQL:                severity.High,
		CertificateValidationDisabled:     severity.High,
		CrossSiteRequestForgeryCSRF:       severity.High,
		InsecureDeserialization:           severity.High,
		OpenRedirect:                      severity.High,
		WeakHashingFunction:               severity.High,
		WeakCipherAlgorithm:               severity.High,
	}
}
