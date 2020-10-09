// // Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

// @todo fix tests
package analysis

import (
	"errors"
	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Required in gorm usage

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	enumHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAnalysisController(t *testing.T) {
	t.Run("should create a new controller", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		controller := NewAnalysisController(mockRead, mockWrite)

		assert.NotNil(t, controller)
	})
}

func TestController_SaveAnalysis(t *testing.T) {
	t.Run("should send a new analysis without errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}
		repository := &account.Repository{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(&response.Response{})

		controller := NewAnalysisController(mockRead, mockWrite)

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "test",
		}
		id, err := controller.SaveAnalysis(analysis)
		assert.NoError(t, err)
		assert.NotEmpty(t, id)
	})
	t.Run("should return error while getting repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(resp)
		mockRead.On("Find").Return(respWithError.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewAnalysisController(mockRead, mockWrite)

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}
		_, err := controller.SaveAnalysis(analysis)

		assert.Error(t, err)
	})
	t.Run("should return error while getting company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewAnalysisController(mockRead, mockWrite)

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}
		_, err := controller.SaveAnalysis(analysis)

		assert.Error(t, err)
	})
	t.Run("should return error when send analysis and database create exist error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		resp := &response.Response{}
		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("RollbackTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(resp.SetError(errors.New("some error")))

		controller := NewAnalysisController(mockRead, mockWrite)

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}
		_, err := controller.SaveAnalysis(analysis)
		assert.Error(t, err)
	})

	t.Run("should success remove duplicated", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}
		repository := &account.Repository{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		createResponse := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(createResponse.SetError(errors.New("test")))
		mockWrite.On("GetConnection").Return(&gorm.DB{})
		mockWrite.On("RollbackTransaction").Return(&response.Response{})

		controller := NewAnalysisController(mockRead, mockWrite)

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
				AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{
					{
						Vulnerability: horusec.Vulnerability{
							VulnHash: "1",
						},
					},
					{
						Vulnerability: horusec.Vulnerability{
							VulnHash: "2",
						},
					},
					{
						Vulnerability: horusec.Vulnerability{
							VulnHash: "2",
						},
					},
				},
			},
			RepositoryName: "test",
		}
		id, err := controller.SaveAnalysis(analysis)
		assert.Error(t, err)
		assert.NotEmpty(t, id)
	})
}

func TestController_GetAnalysis(t *testing.T) {
	t.Run("should get analysis without errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		repo := &horusec.Analysis{ID: uuid.New()}
		resp := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp.SetData(repo))

		controller := NewAnalysisController(mockRead, mockWrite)

		_, err = controller.GetAnalysis(repo.ID)

		assert.NoError(t, err)
	})
	t.Run("should get analysis return error unknown", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp.SetError(errors.New("error")))

		controller := NewAnalysisController(mockRead, mockWrite)

		_, err = controller.GetAnalysis(uuid.New())
		assert.Error(t, err)
	})
	t.Run("should return analysis with status running", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		repo := &horusec.Analysis{ID: uuid.New(), Status: enumHorusec.Running}
		resp := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp.SetData(repo))

		controller := NewAnalysisController(mockRead, mockWrite)

		_, err = controller.GetAnalysis(repo.ID)

		assert.NoError(t, err)
	})
}
