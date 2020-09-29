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

package adapter

import (
	"os"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	EntitiesHorusec "github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	EnumHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func SetEnvironmentsRelational() {
	_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
	_ = os.Setenv(config.EnvRelationalURI, "tmp.db")
	_ = os.Setenv(config.EnvRelationalLogMode, "false")
}

func TestNewRepository(t *testing.T) {
	t.Run("Should return panics if start is wrong with default database", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = os.Setenv(config.EnvRelationalDialect, "0")
			NewRepositoryRead()
		})
	})
	t.Run("Should NOT return panics with database relational", func(t *testing.T) {
		SetEnvironmentsRelational()
		assert.NotPanics(t, func() {
			NewRepositoryRead()
		})
	})
}

func executeCRUD(instanceRead relational.InterfaceRead, instanceWrite relational.InterfaceWrite, t *testing.T) {
	analysisToCreate := getAnalysisData()
	tableAnalysis := &EntitiesHorusec.Analysis{}
	tableVulnerability := &EntitiesHorusec.Vulnerability{}
	instanceWrite.SetLogMode(true)
	instanceWrite.GetConnection().Table(tableAnalysis.GetTable()).AutoMigrate(tableAnalysis)
	instanceWrite.GetConnection().Table(tableVulnerability.GetTable()).AutoMigrate(tableVulnerability)

	instanceRead.SetLogMode(true)
	instanceRead.GetConnection().Table(tableAnalysis.GetTable()).AutoMigrate(tableAnalysis)
	instanceRead.GetConnection().Table(tableVulnerability.GetTable()).AutoMigrate(tableVulnerability)

	analysisUseCases := analysis.NewAnalysisUseCases()

	logger.LogInfo("Analysis to test: ", map[string]interface{}{"analysis": analysisToCreate.ToString()})
	tableName := analysisToCreate.GetTable()

	resultCreate := instanceWrite.Create(analysisToCreate, tableName)
	assert.NoError(t, resultCreate.GetError())

	if resultCreate.GetError() == nil {
		filterOne := instanceRead.GetConnection().Where(map[string]interface{}{})
		resultFindAll := instanceRead.Find(&[]*EntitiesHorusec.Analysis{}, filterOne, tableName)
		assert.NotNil(t, resultFindAll.GetData())
		if resultFindAll.GetData() != nil {
			list, err := analysisUseCases.ParseInterfaceToListAnalysis(resultFindAll.GetData())
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, len(list), 1)
		}

		analysisToFindOne := EntitiesHorusec.Analysis{}
		filterTwo := instanceRead.GetConnection().Where(map[string]interface{}{"analysis_id": analysisToCreate.ID})
		resultFindOne := instanceRead.Find(&analysisToFindOne, filterTwo, tableName)
		assert.NoError(t, resultFindOne.GetError())
		assert.NotNil(t, resultFindOne.GetData())
		if resultFindOne.GetData() != nil {
			analysisToFindOne, err := analysisUseCases.ParseInterfaceToAnalysis(resultFindOne.GetData())
			assert.NoError(t, err)
			assert.Equal(t, analysisToFindOne.RepositoryID, analysisToCreate.RepositoryID)
		}

		analysisToUpdate := analysisToFindOne
		analysisToUpdate.RepositoryID = uuid.New()
		resultUpdate := instanceWrite.Update(analysisToUpdate, map[string]interface{}{"analysis_id": analysisToCreate.ID}, tableName)
		assert.NoError(t, resultUpdate.GetError())
		assert.NotNil(t, resultUpdate.GetData())
		if resultUpdate.GetData() != nil {
			analysisToUpdate, err := analysisUseCases.ParseInterfaceToAnalysis(resultUpdate.GetData())
			assert.NoError(t, err)
			assert.NotEqual(t, analysisToUpdate.RepositoryID, analysisToCreate.RepositoryID)
		}

		resultDelete := instanceWrite.Delete(map[string]interface{}{"analysis_id": analysisToCreate.ID}, tableName)
		assert.NoError(t, resultDelete.GetError())

		analysisToFindOneAfterDelete := EntitiesHorusec.Analysis{}
		filterTree := instanceRead.GetConnection().Where(map[string]interface{}{"analysis_id": analysisToCreate.ID})
		resultFindOneAfterDelete := instanceRead.Find(analysisToFindOneAfterDelete, filterTree, tableName)
		assert.Equal(t, resultFindOneAfterDelete.GetError(), EnumErrors.ErrNotFoundRecords)
	}
}

func getAnalysisData() EntitiesHorusec.Analysis {
	return EntitiesHorusec.Analysis{
		ID:              uuid.New(),
		CreatedAt:       time.Now(),
		RepositoryID:    uuid.New(),
		CompanyID:       uuid.New(),
		Status:          EnumHorusec.Success,
		Errors:          "",
		FinishedAt:      time.Now(),
		Vulnerabilities: []EntitiesHorusec.Vulnerability{},
	}
}
func TestCRUD_Relational(t *testing.T) {
	t.Run("Test CRUD Of Database Relational", func(t *testing.T) {
		SetEnvironmentsRelational()
		executeCRUD(NewRepositoryRead(), NewRepositoryWrite(), t)
	})
}
