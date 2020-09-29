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
	PathTraversal                  = "SCS0018"
	WeakRandomNumberGenerator      = "SCS0005"
	WeakHashingFunction            = "SCS0006"
	WeakCipherAlgorithm            = "SCS0010"
	WeakCBCMode                    = "SCS0011"
	WeakECBMode                    = "SCS0012"
	WeakCipherMode                 = "SCS0013"
	ViewStateNotEncrypted          = "SCS0023"
	ViewStateMACDisabled           = "SCS0024"
	PasswordRequiredLengthNotSet   = "SCS0034"
	PasswordRequiredLengthTooSmall = "SCS0032"
	PasswordComplexity             = "SCS0033"
	OpenRedirect                   = "SCS0027"
)

func MapMediumValues() map[string]string {
	return map[string]string{
		PathTraversal:                  "MEDIUM",
		WeakRandomNumberGenerator:      "MEDIUM",
		WeakHashingFunction:            "MEDIUM",
		WeakCipherAlgorithm:            "MEDIUM",
		WeakCBCMode:                    "MEDIUM",
		WeakECBMode:                    "MEDIUM",
		WeakCipherMode:                 "MEDIUM",
		ViewStateNotEncrypted:          "MEDIUM",
		ViewStateMACDisabled:           "MEDIUM",
		PasswordRequiredLengthNotSet:   "MEDIUM",
		PasswordRequiredLengthTooSmall: "MEDIUM",
		PasswordComplexity:             "MEDIUM",
		OpenRedirect:                   "MEDIUM",
	}
}

func GetMediumSeverityByCode(id string) string {
	values := MapMediumValues()
	return values[id]
}

func IsMediumSeverity(id string) bool {
	return GetMediumSeverityByCode(id) != ""
}
