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

package management

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/google/uuid"
	"testing"
)

func Test(t *testing.T) {
	t.Run("", func(t *testing.T) {
		repository := NewManagementRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())

		repository.GetAllVulnManagementData(uuid.MustParse("759d8c85-48d7-42f0-b7da-d320bbb0c5ca"), 1, 1,
			horusec.FalsePositive, horusec.Reproved)
	})
}
