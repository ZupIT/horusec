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
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"io"
)

type IUseCases interface {
	NewUpdateVulnTypeFromReadCloser(body io.ReadCloser) (updateData *dto.UpdateVulnType, err error)
}

type UseCases struct {
}

func NewManagementUseCases() IUseCases {
	return &UseCases{}
}

func (u *UseCases) NewUpdateVulnTypeFromReadCloser(body io.ReadCloser) (updateData *dto.UpdateVulnType, err error) {
	err = json.NewDecoder(body).Decode(&updateData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return updateData, updateData.Validate()
}
