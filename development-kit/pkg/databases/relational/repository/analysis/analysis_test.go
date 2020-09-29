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
	"os"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	dashboardEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var accountID = uuid.New()
var companyID = uuid.New()
var repositoryID = uuid.New()
var analysisID = uuid.New()
var vulnerabilityID = uuid.New()

func insertAnalysisData() error {
	_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
	_ = os.Setenv(config.EnvRelationalURI, "tmp.db")
	_ = os.Setenv(config.EnvRelationalLogMode, "false")

	databaseWrite := adapter.NewRepositoryWrite()

	account := &accountEntities.Account{
		Email:     "test@test.com",
		Username:  "test",
		CreatedAt: time.Now(),
		Password:  "test",
		AccountID: accountID,
	}

	company := &accountEntities.Company{
		CompanyID:   companyID,
		Name:        "test",
		Description: "test",
		CreatedAt:   time.Now(),
	}

	repository := &accountEntities.Repository{
		RepositoryID: repositoryID,
		CompanyID:    company.CompanyID,
		Name:         "test",
		CreatedAt:    time.Now(),
	}

	accountCompany := &roles.AccountCompany{
		AccountID: account.AccountID,
		CompanyID: company.CompanyID,
		Role:      rolesEnum.Admin,
		CreatedAt: time.Now(),
	}

	accountRepository := &roles.AccountRepository{
		AccountID:    account.AccountID,
		CompanyID:    company.CompanyID,
		RepositoryID: repository.RepositoryID,
		Role:         rolesEnum.Admin,
		CreatedAt:    time.Now(),
	}

	analysis := &horusec.Analysis{
		ID:             analysisID,
		CompanyID:      company.CompanyID,
		CompanyName:    "test",
		RepositoryID:   repository.RepositoryID,
		RepositoryName: "test",
		CreatedAt:      time.Now(),
		FinishedAt:     time.Now(),
	}

	vulnerability := &horusec.Vulnerability{
		VulnerabilityID: vulnerabilityID,
		AnalysisID:      analysis.ID,
		Severity:        severity.Low,
		CommitEmail:     "test@test.com",
	}

	databaseWrite.SetLogMode(true)
	databaseWrite.GetConnection().Table(account.GetTable()).AutoMigrate(account)
	databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
	databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
	databaseWrite.GetConnection().Table(accountRepository.GetTable()).AutoMigrate(accountRepository)
	databaseWrite.GetConnection().Table(accountCompany.GetTable()).AutoMigrate(accountCompany)
	databaseWrite.GetConnection().Table(analysis.GetTable()).AutoMigrate(analysis)
	databaseWrite.GetConnection().Table(vulnerability.GetTable()).AutoMigrate(vulnerability)

	resp := databaseWrite.Create(account, account.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	resp = databaseWrite.Create(company, company.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	resp = databaseWrite.Create(repository, repository.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	resp = databaseWrite.Create(accountRepository, accountRepository.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	resp = databaseWrite.Create(accountCompany, accountCompany.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	resp = databaseWrite.Create(analysis, analysis.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	resp = databaseWrite.Create(vulnerability, vulnerability.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	return nil
}

func getCreatedAtTime() time.Time {
	return time.Date(2020, 1, 1, 00, 00, 00, 00, time.UTC)
}

func getFinishedAtTime() time.Time {
	finishedAt := time.Now()
	finishedAt.AddDate(1, 1, 1)
	return finishedAt
}

func testGetDetailsPaginated() ([]dashboardEntities.VulnDetails, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetDetailsPaginated(companyID, repositoryID, 1, 10, getCreatedAtTime(), getFinishedAtTime())
}

func testGetDetailsCount() (int, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetDetailsCount(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetDeveloperCount() (int, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetDeveloperCount(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetRepositoryCount() (int, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetRepositoryCount(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetVulnBySeverity() ([]dashboardEntities.VulnBySeverity, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetVulnBySeverity(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetVulnByDeveloper() ([]dashboardEntities.VulnByDeveloper, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetVulnByDeveloper(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetVulnByLanguage() ([]dashboardEntities.VulnByLanguage, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetVulnByLanguage(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetVulnByRepository() ([]dashboardEntities.VulnByRepository, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetVulnByRepository(companyID, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func testGetVulnByTime() ([]dashboardEntities.VulnByTime, error) {
	repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())
	return repository.GetVulnByTime(uuid.Nil, repositoryID, getCreatedAtTime(), getFinishedAtTime())
}

func TestRunDashboardTests(t *testing.T) {
	err := insertAnalysisData()
	assert.NoError(t, err)

	t.Run("should success get paginated details", func(t *testing.T) {
		details, err := testGetDetailsPaginated()

		assert.NoError(t, err)
		assert.Len(t, details, 1)
	})

	t.Run("should success get details count", func(t *testing.T) {
		count, err := testGetDetailsCount()

		assert.Error(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("should success get developer count", func(t *testing.T) {
		devCount, err := testGetDeveloperCount()

		assert.NoError(t, err)
		assert.Equal(t, 1, devCount)
	})

	t.Run("should success get repository count", func(t *testing.T) {
		repoCount, err := testGetRepositoryCount()

		assert.NoError(t, err)
		assert.Equal(t, 1, repoCount)
	})

	t.Run("should success get vulns by severity", func(t *testing.T) {
		vulnsBySeverity, err := testGetVulnBySeverity()

		assert.NoError(t, err)
		assert.Len(t, vulnsBySeverity, 1)
	})

	t.Run("should success get vulns by developer", func(t *testing.T) {
		vulnsByDeveloper, err := testGetVulnByDeveloper()

		assert.NoError(t, err)
		assert.Len(t, vulnsByDeveloper, 1)
	})

	t.Run("should success get vulns by language", func(t *testing.T) {
		vulnsByLanguage, err := testGetVulnByLanguage()

		assert.NoError(t, err)
		assert.Len(t, vulnsByLanguage, 1)
	})

	t.Run("should success get vulns by repository", func(t *testing.T) {
		vulnsByRepository, err := testGetVulnByRepository()

		assert.NoError(t, err)
		assert.Len(t, vulnsByRepository, 1)
	})

	t.Run("should success get vulns by time", func(t *testing.T) {
		vulnsByTime, err := testGetVulnByTime()

		assert.NoError(t, err)
		assert.Len(t, vulnsByTime, 1)
	})
}

func TestCreate(t *testing.T) {
	t.Run("should success create a new analysis", func(t *testing.T) {
		repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())

		err := repository.Create(&horusec.Analysis{ID: uuid.New(), RepositoryID: repositoryID, CompanyID: companyID}, nil)

		assert.NoError(t, err)
	})
}

func TestGetByID(t *testing.T) {
	t.Run("should success get by id", func(t *testing.T) {
		repository := NewAnalysisRepository(adapter.NewRepositoryRead(), adapter.NewRepositoryWrite())

		result, err := repository.GetByID(analysisID)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}
