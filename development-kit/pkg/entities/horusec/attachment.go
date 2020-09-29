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

package horusec

import (
	"mime/multipart"
	"net/textproto"
	"time"

	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/google/uuid"
)

type Attachment struct {
	FileZip    multipart.File `json:"fileZip"`
	FileName   string
	FileSize   int64
	FileHeader textproto.MIMEHeader
}

func (r *Attachment) ToAnalysis(repositoryID, companyID uuid.UUID) *Analysis {
	return &Analysis{
		ID:              uuid.New(),
		CreatedAt:       time.Now(),
		RepositoryID:    repositoryID,
		CompanyID:       companyID,
		Status:          horusecEnum.Running,
		Vulnerabilities: []Vulnerability{},
	}
}
