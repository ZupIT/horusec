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

const (
	CookieWithoutSSLFlag                                    = "SCS0008"
	CookieWithoutHTTPOnlyFlag                               = "SCS0009"
	RequestValidationDisabledAttribute                      = "SCS0017"
	RequestValidationDisabledConfigurationFile              = "SCS0021"
	RequestValidationIsEnabledOnlyForPagesConfigurationFile = "SCS0030"
	OutputCacheConflict                                     = "SCS0019"
	EventValidationDisabled                                 = "SCS0022"
)

func MapLowValues() map[string]string {
	return map[string]string{
		CookieWithoutSSLFlag:                                    "LOW",
		CookieWithoutHTTPOnlyFlag:                               "LOW",
		RequestValidationDisabledAttribute:                      "LOW",
		RequestValidationDisabledConfigurationFile:              "LOW",
		RequestValidationIsEnabledOnlyForPagesConfigurationFile: "LOW",
		OutputCacheConflict:                                     "LOW",
		EventValidationDisabled:                                 "LOW",
	}
}

func GetLowSeverityByCode(id string) string {
	values := MapLowValues()
	return values[id]
}

func IsLowSeverity(id string) bool {
	return GetLowSeverityByCode(id) != ""
}
