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

package auth

type HorusecRoles string

const (
	ApplicationAdmin     HorusecRoles = "applicationAdmin"
	CompanyMember        HorusecRoles = "companyMember"
	CompanyAdmin         HorusecRoles = "companyAdmin"
	RepositoryMember     HorusecRoles = "repositoryMember"
	RepositorySupervisor HorusecRoles = "repositorySupervisor"
	RepositoryAdmin      HorusecRoles = "repositoryAdmin"
)

func (h HorusecRoles) IsInvalid() bool {
	for _, v := range h.Values() {
		if v == h {
			return false
		}
	}

	return true
}

func (h HorusecRoles) Values() []HorusecRoles {
	return []HorusecRoles{
		ApplicationAdmin,
		CompanyMember,
		CompanyAdmin,
		RepositoryMember,
		RepositorySupervisor,
		RepositoryAdmin,
	}
}

func (h HorusecRoles) IsEqual(value string) bool {
	return value == h.ToString()
}

func (h HorusecRoles) ToString() string {
	return string(h)
}
