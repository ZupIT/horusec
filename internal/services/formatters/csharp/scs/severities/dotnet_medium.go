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

package severities

import "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

const (
	PathTraversal                  = "SCS0018"
	WeakRandomNumberGenerator      = "SCS0005"
	WeakCBCMode                    = "SCS0011"
	WeakECBMode                    = "SCS0012"
	WeakCipherMode                 = "SCS0013"
	ViewStateNotEncrypted          = "SCS0023"
	ViewStateMACDisabled           = "SCS0024"
	PasswordRequiredLengthNotSet   = "SCS0034"
	PasswordRequiredLengthTooSmall = "SCS0032"
	PasswordComplexity             = "SCS0033"
	LegacyPacket                   = "SCS9999"
)

func MapMediumValues() map[string]severities.Severity {
	return map[string]severities.Severity{
		PathTraversal:                  severities.Medium,
		WeakRandomNumberGenerator:      severities.Medium,
		WeakCBCMode:                    severities.Medium,
		WeakECBMode:                    severities.Medium,
		WeakCipherMode:                 severities.Medium,
		ViewStateNotEncrypted:          severities.Medium,
		ViewStateMACDisabled:           severities.Medium,
		PasswordRequiredLengthNotSet:   severities.Medium,
		PasswordRequiredLengthTooSmall: severities.Medium,
		PasswordComplexity:             severities.Medium,
		LegacyPacket:                   severities.Medium,
	}
}
