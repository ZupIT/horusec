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

package analysis

import (
	"errors"
	repositoryAnalysis "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/analysis"
	repositoryCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	analysisUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/ZupIT/horusec/horusec-api/config/app"
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

		controller := NewAnalysisController(mockRead, mockWrite, nil, nil)

		assert.NotNil(t, controller)
	})
}

func TestController_SaveAnalysis(t *testing.T) {
	conn, err := gorm.Open("sqlite3", ":memory:")
	assert.NoError(t, err)
	conn.Table("analysis").AutoMigrate(&horusec.Analysis{})
	conn.Table("analysis_vulnerabilities").AutoMigrate(&horusec.AnalysisVulnerabilities{})
	conn.Table("vulnerabilities").AutoMigrate(&horusec.Vulnerability{})
	conn.LogMode(true)

	t.Run("should send a new analysis without errors", func(t *testing.T) {
		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}
		repository := &account.Repository{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetData(repository))
		mockRead.On("SetFilter").Return(conn)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(&response.Response{})
		mockWrite.On("GetConnection").Return(conn)
		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)
		analysis := test.CreateAnalysisMock()
		analysis.CompanyID = uuid.Nil
		analysis.RepositoryID = uuid.Nil
		analysisData := &apiEntities.AnalysisData{
			Analysis:       analysis,
			RepositoryName: "test",
		}
		id, err := controller.SaveAnalysis(analysisData)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, id)
	})
	t.Run("should send a new analysis without errors with broker disabled", func(t *testing.T) {
		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(true)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}
		repository := &account.Repository{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetData(repository))
		mockRead.On("SetFilter").Return(conn)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(&response.Response{})
		mockWrite.On("GetConnection").Return(conn)
		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)
		analysis := test.CreateAnalysisMock()
		analysis.CompanyID = uuid.Nil
		analysis.RepositoryID = uuid.Nil
		analysisData := &apiEntities.AnalysisData{
			Analysis:       analysis,
			RepositoryName: "test",
		}
		id, err := controller.SaveAnalysis(analysisData)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, id)
	})
	t.Run("should send a new analysis but return error when publish in broker", func(t *testing.T) {
		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(errors.New("unexpected error"))
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}
		repository := &account.Repository{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetData(repository))
		mockRead.On("SetFilter").Return(conn)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(&response.Response{})
		mockWrite.On("GetConnection").Return(conn)
		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)
		analysis := test.CreateAnalysisMock()
		analysis.CompanyID = uuid.Nil
		analysis.RepositoryID = uuid.Nil
		analysisData := &apiEntities.AnalysisData{
			Analysis:       analysis,
			RepositoryName: "test",
		}
		_, err := controller.SaveAnalysis(analysisData)
		assert.Error(t, err)
	})
	t.Run("should send a new analysis without errors expected remove vulnerabilities hash duplicated", func(t *testing.T) {

		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}
		repository := &account.Repository{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetData(repository))
		mockRead.On("SetFilter").Return(conn)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(&response.Response{})
		mockWrite.On("GetConnection").Return(conn)

		controller := &Controller{
			broker:           mockBroker,
			config:           config,
			postgresWrite:    mockWrite,
			useCasesAnalysis: analysisUseCases.NewAnalysisUseCases(),
			repoRepository:   repositoryRepo.NewRepository(mockRead, mockWrite),
			repoCompany:      repositoryCompany.NewCompanyRepository(mockRead, mockWrite),
			repoAnalysis:     repositoryAnalysis.NewAnalysisRepository(mockRead, mockWrite),
		}

		analysis := test.CreateAnalysisMock()
		analysis.AnalysisVulnerabilities = append(analysis.AnalysisVulnerabilities, test.CreateAnalysisMock().AnalysisVulnerabilities...)
		assert.Equal(t, 22, len(analysis.AnalysisVulnerabilities))
		newAnalysis := controller.removeAnalysisVulnerabilityWithHashDuplicate(analysis)
		assert.Equal(t, 11, len(newAnalysis.AnalysisVulnerabilities))
		analysisData := &apiEntities.AnalysisData{
			Analysis:       newAnalysis,
			RepositoryName: "test",
		}
		id, err := controller.SaveAnalysis(analysisData)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, id)
	})
	t.Run("should send a new analysis without errors and create repository", func(t *testing.T) {

		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		company := &account.Company{Name: "test"}

		respComp := &response.Response{}
		respRepo := &response.Response{}
		mockRead.On("Find").Once().Return(respComp.SetData(company))
		mockRead.On("Find").Return(respRepo.SetError(errorsEnums.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(&response.Response{})

		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
				CompanyID:  uuid.New(),
			},
			RepositoryName: "test",
		}
		id, err := controller.SaveAnalysis(analysis)
		assert.NoError(t, err)
		assert.NotEmpty(t, id)
	})
	t.Run("should return error while getting repository", func(t *testing.T) {

		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(resp)
		mockRead.On("Find").Return(respWithError.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(conn)

		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)

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

		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(conn)

		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)

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
		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		resp := &response.Response{}
		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(conn)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("RollbackTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(resp.SetError(errors.New("some error")))

		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)

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

		mockBroker := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)
		mockBroker.On("Publish").Return(nil)
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

		controller := NewAnalysisController(mockRead, mockWrite, mockBroker, config)

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

		repo := test.CreateAnalysisMock()
		resp := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp.SetData(repo))

		controller := NewAnalysisController(mockRead, mockWrite, nil, nil)

		r, err := controller.GetAnalysis(repo.ID)

		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, r.ID)
		assert.NotEmpty(t, r.AnalysisVulnerabilities)
		assert.Equal(t, 11, len(r.AnalysisVulnerabilities))
	})
	t.Run("should get analysis return error unknown", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp.SetError(errors.New("error")))

		controller := NewAnalysisController(mockRead, mockWrite, nil, nil)

		_, err = controller.GetAnalysis(uuid.New())
		assert.Error(t, err)
	})
	t.Run("should get analysis return error not found", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		repo := &horusec.Analysis{ID: uuid.New(), Status: enumHorusec.Running}
		resp := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp.SetData(repo).SetError(errorsEnum.ErrNotFoundRecords))

		controller := NewAnalysisController(mockRead, mockWrite, nil, nil)

		_, err = controller.GetAnalysis(repo.ID)

		assert.Equal(t, errorsEnum.ErrNotFoundRecords, err)
	})
}
