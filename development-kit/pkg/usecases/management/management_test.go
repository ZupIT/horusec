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
	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestNewRepositoryFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to update data", func(t *testing.T) {
		bytes, _ := json.Marshal(&dto.UpdateVulnManagementData{Status: horusecEnum.Approved})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewManagementUseCases()
		data, err := useCases.NewUpdateVulnManagementDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("should return error when invalid read closer", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))

		useCases := NewManagementUseCases()
		_, err := useCases.NewUpdateVulnManagementDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}
