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

// Entities created in this files are exclusive from keycloak e2e
package entities

import "encoding/json"

type UserRepresentation struct {
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	Enabled       bool   `json:"enabled"`
}

type UserRepresentationCredentials struct {
	Temporary bool   `json:"temporary"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

func (u *UserRepresentation) ToBytes() []byte {
	content, _ := json.Marshal(u)
	return content
}

func (u *UserRepresentationCredentials) ToBytes() []byte {
	content, _ := json.Marshal(u)
	return content
}
