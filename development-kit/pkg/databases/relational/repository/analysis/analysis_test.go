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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	dashboardEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	enumHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
	"os"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
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

	account := &authEntities.Account{
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
		Severity:        severity.Low,
		CommitEmail:     "test@test.com",
		Type:            enumHorusec.Vulnerability,
	}

	analysisVulnerabilities := &horusec.AnalysisVulnerabilities{
		VulnerabilityID: vulnerabilityID,
		AnalysisID:      analysisID,
	}

	databaseWrite.SetLogMode(true)
	databaseWrite.GetConnection().Table(account.GetTable()).AutoMigrate(account)
	databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
	databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
	databaseWrite.GetConnection().Table(accountRepository.GetTable()).AutoMigrate(accountRepository)
	databaseWrite.GetConnection().Table(accountCompany.GetTable()).AutoMigrate(accountCompany)
	databaseWrite.GetConnection().Table(analysis.GetTable()).AutoMigrate(analysis)
	databaseWrite.GetConnection().Table(analysisVulnerabilities.GetTable()).AutoMigrate(analysisVulnerabilities)
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

	resp = databaseWrite.Create(analysisVulnerabilities, analysisVulnerabilities.GetTable())
	if resp.GetError() != nil {
		return resp.GetError()
	}

	return nil
}

func TestMock(t *testing.T) {
	t.Run("Should run mock", func(t *testing.T) {
		mock := &Mock{}
		mock.On("Create").Return(nil)
		mock.On("GetByID").Return(&horusec.Analysis{}, nil)
		mock.On("GetDetailsPaginated").Return([]dashboardEntities.VulnDetails{}, nil)
		mock.On("GetDetailsCount").Return(0, nil)
		mock.On("GetDeveloperCount").Return(0, nil)
		mock.On("GetRepositoryCount").Return(0, nil)
		mock.On("GetVulnBySeverity").Return([]dashboardEntities.VulnBySeverity{}, nil)
		mock.On("GetVulnByDeveloper").Return([]dashboardEntities.VulnByDeveloper{}, nil)
		mock.On("GetVulnByLanguage").Return([]dashboardEntities.VulnByLanguage{}, nil)
		mock.On("GetVulnByRepository").Return([]dashboardEntities.VulnByRepository{}, nil)
		mock.On("GetVulnByTime").Return([]dashboardEntities.VulnByTime{}, nil)
		var tx SQL.InterfaceWrite
		_ = mock.Create(&horusec.Analysis{}, tx)
		_, _ = mock.GetByID(uuid.New())
		_, _ = mock.GetDetailsPaginated(uuid.New(), uuid.New(), 1, 1, time.Now(), time.Now())
		_, _ = mock.GetDetailsCount(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetDeveloperCount(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetRepositoryCount(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetVulnBySeverity(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetVulnByDeveloper(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetVulnByLanguage(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetVulnByRepository(uuid.New(), uuid.New(), time.Now(), time.Now())
		_, _ = mock.GetVulnByTime(uuid.New(), uuid.New(), time.Now(), time.Now())
	})
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

	t.Run("should return error sqlite do not supports distinct on", func(t *testing.T) {
		details, err := testGetDetailsPaginated()

		assert.Error(t, err)
		assert.Len(t, details, 0)
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
		dbFile := uuid.New().String() + "-tmp.db"
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
		_ = os.Setenv(config.EnvRelationalURI, dbFile)
		_ = os.Setenv(config.EnvRelationalLogMode, "false")

		databaseRead := adapter.NewRepositoryRead()
		databaseWrite := adapter.NewRepositoryWrite()

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

		databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
		databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
		analysis := &horusec.Analysis{}
		analysisVulnerabilities := &horusec.AnalysisVulnerabilities{}
		vulnerabilities := &horusec.Vulnerability{}
		databaseWrite.GetConnection().Table(analysis.GetTable()).AutoMigrate(analysis)
		databaseWrite.GetConnection().Table(analysisVulnerabilities.GetTable()).AutoMigrate(analysisVulnerabilities)
		databaseWrite.GetConnection().Table(vulnerabilities.GetTable()).AutoMigrate(vulnerabilities)
		analysisRepository := NewAnalysisRepository(databaseRead, databaseWrite)
		err := analysisRepository.Create(&horusec.Analysis{
			ID:             analysisID,
			RepositoryID:   repository.RepositoryID,
			RepositoryName: "test",
			CompanyID:      company.CompanyID,
			CompanyName:    "test",
			Status:         enumHorusec.Success,
			Errors:         "",
			CreatedAt:      time.Now(),
			FinishedAt:     time.Now(),
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{
				{
					VulnerabilityID: vulnerabilityID,
					AnalysisID:      analysisID,
					CreatedAt:       time.Now(),
					Vulnerability: horusec.Vulnerability{
						VulnerabilityID: vulnerabilityID,
						Line:            "1",
						Column:          "1",
						Confidence:      confidence.High.ToString(),
						File:            "vul.file",
						Code:            "code",
						Details:         "details",
						SecurityTool:    tools.HorusecLeaks,
						Language:        languages.Leaks,
						Severity:        severity.High,
						VulnHash:        "123456789",
						Type:            enumHorusec.Vulnerability,
					},
				},
			},
		}, nil)

		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(dbFile))
	})
	t.Run("Should create analysis in transaction", func(t *testing.T) {
		dbFile := uuid.New().String() + "-tmp.db"
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
		_ = os.Setenv(config.EnvRelationalURI, dbFile)
		_ = os.Setenv(config.EnvRelationalLogMode, "false")

		databaseRead := adapter.NewRepositoryRead()
		databaseWrite := adapter.NewRepositoryWrite()

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

		databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
		databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
		analysis := &horusec.Analysis{}
		analysisVulnerabilities := &horusec.AnalysisVulnerabilities{}
		vulnerabilities := &horusec.Vulnerability{}
		databaseWrite.GetConnection().Table(analysis.GetTable()).AutoMigrate(analysis)
		databaseWrite.GetConnection().Table(analysisVulnerabilities.GetTable()).AutoMigrate(analysisVulnerabilities)
		databaseWrite.GetConnection().Table(vulnerabilities.GetTable()).AutoMigrate(vulnerabilities)
		transaction := databaseWrite.StartTransaction()
		analysisRepository := NewAnalysisRepository(databaseRead, databaseWrite)
		err := analysisRepository.Create(&horusec.Analysis{
			ID:             analysisID,
			RepositoryID:   repository.RepositoryID,
			RepositoryName: "test",
			CompanyID:      company.CompanyID,
			CompanyName:    "test",
			Status:         enumHorusec.Success,
			Errors:         "",
			CreatedAt:      time.Now(),
			FinishedAt:     time.Now(),
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{
				{
					VulnerabilityID: vulnerabilityID,
					AnalysisID:      analysisID,
					CreatedAt:       time.Now(),
					Vulnerability: horusec.Vulnerability{
						VulnerabilityID: vulnerabilityID,
						Line:            "1",
						Column:          "1",
						Confidence:      confidence.High.ToString(),
						File:            "vul.file",
						Code:            "code",
						Details:         "details",
						SecurityTool:    tools.HorusecLeaks,
						Language:        languages.Leaks,
						Severity:        severity.High,
						VulnHash:        "123456789",
						Type:            enumHorusec.Vulnerability,
					},
				},
			},
		}, transaction)

		assert.NoError(t, err)
		if err != nil {
			assert.NoError(t, transaction.RollbackTransaction().GetError())
		} else {
			assert.NoError(t, transaction.CommitTransaction().GetError())
		}
		assert.NoError(t, os.RemoveAll(dbFile))
	})
	t.Run("Should return error whe create analysis with transaction", func(t *testing.T) {
		databaseRead := &SQL.MockRead{}
		databaseWrite := &SQL.MockWrite{}
		databaseWrite.On("Create").Return(response.NewResponse(0, errors.New("some error"), nil))

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

		analysisRepository := NewAnalysisRepository(databaseRead, databaseWrite)
		err := analysisRepository.Create(&horusec.Analysis{
			ID:             analysisID,
			RepositoryID:   repository.RepositoryID,
			RepositoryName: "test",
			CompanyID:      company.CompanyID,
			CompanyName:    "test",
			Status:         enumHorusec.Success,
			Errors:         "",
			CreatedAt:      time.Now(),
			FinishedAt:     time.Now(),
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{
				{
					VulnerabilityID: vulnerabilityID,
					AnalysisID:      analysisID,
					CreatedAt:       time.Now(),
					Vulnerability: horusec.Vulnerability{
						VulnerabilityID: vulnerabilityID,
						Line:            "1",
						Column:          "1",
						Confidence:      confidence.High.ToString(),
						File:            "vul.file",
						Code:            "code",
						Details:         "details",
						SecurityTool:    tools.HorusecLeaks,
						Language:        languages.Leaks,
						Severity:        severity.High,
						VulnHash:        "123456789",
						Type:            enumHorusec.Vulnerability,
					},
				},
			},
		}, nil)

		assert.Error(t, err)
	})
	t.Run("Should return error whe find analysis and found unexpected error", func(t *testing.T) {
		dbFile := uuid.New().String() + "-tmp.db"
		databaseRead := &SQL.MockRead{}
		databaseWrite := &SQL.MockWrite{}

		conn, err := gorm.Open("sqlite3", dbFile)
		assert.NoError(t, err)
		conn.Table("analysis").AutoMigrate(&horusec.Analysis{})
		conn.Table("analysis_vulnerabilities").AutoMigrate(&horusec.AnalysisVulnerabilities{})
		conn.Table("vulnerabilities").AutoMigrate(&horusec.Vulnerability{})
		conn.LogMode(true)
		databaseWrite.On("Create").Return(response.NewResponse(0, nil, nil))
		getConnectionMock := conn
		getConnectionMock.Error = errors.New("unexpected")
		databaseWrite.On("GetConnection").Return(getConnectionMock)

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

		analysisRepository := NewAnalysisRepository(databaseRead, databaseWrite)
		err = analysisRepository.Create(&horusec.Analysis{
			ID:             analysisID,
			RepositoryID:   repository.RepositoryID,
			RepositoryName: "test",
			CompanyID:      company.CompanyID,
			CompanyName:    "test",
			Status:         enumHorusec.Success,
			Errors:         "",
			CreatedAt:      time.Now(),
			FinishedAt:     time.Now(),
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{
				{
					VulnerabilityID: vulnerabilityID,
					AnalysisID:      analysisID,
					CreatedAt:       time.Now(),
					Vulnerability: horusec.Vulnerability{
						VulnerabilityID: vulnerabilityID,
						Line:            "1",
						Column:          "1",
						Confidence:      confidence.High.ToString(),
						File:            "vul.file",
						Code:            "code",
						Details:         "details",
						SecurityTool:    tools.HorusecLeaks,
						Language:        languages.Leaks,
						Severity:        severity.High,
						VulnHash:        "123456789",
						Type:            enumHorusec.Vulnerability,
					},
				},
			},
		}, nil)

		assert.Error(t, err)
		assert.NoError(t, os.RemoveAll(dbFile))
	})
}

func TestGetByID(t *testing.T) {
	t.Run("should success create a new analysis", func(t *testing.T) {
		dbFile := uuid.New().String() + "-tmp.db"
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
		_ = os.Setenv(config.EnvRelationalURI, dbFile)
		_ = os.Setenv(config.EnvRelationalLogMode, "false")

		databaseRead := adapter.NewRepositoryRead()
		databaseWrite := adapter.NewRepositoryWrite()

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

		databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
		databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
		analysis := &horusec.Analysis{}
		analysisVulnerabilities := &horusec.AnalysisVulnerabilities{}
		vulnerabilities := &horusec.Vulnerability{}
		databaseWrite.GetConnection().Table(analysis.GetTable()).AutoMigrate(analysis)
		databaseWrite.GetConnection().Table(analysisVulnerabilities.GetTable()).AutoMigrate(analysisVulnerabilities)
		databaseWrite.GetConnection().Table(vulnerabilities.GetTable()).AutoMigrate(vulnerabilities)
		analysisRepository := NewAnalysisRepository(databaseRead, databaseWrite)
		err := analysisRepository.Create(&horusec.Analysis{
			ID:             analysisID,
			RepositoryID:   repository.RepositoryID,
			RepositoryName: "test",
			CompanyID:      company.CompanyID,
			CompanyName:    "test",
			Status:         enumHorusec.Success,
			Errors:         "",
			CreatedAt:      time.Now(),
			FinishedAt:     time.Now(),
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{
				{
					VulnerabilityID: vulnerabilityID,
					AnalysisID:      analysisID,
					CreatedAt:       time.Now(),
					Vulnerability: horusec.Vulnerability{
						VulnerabilityID: vulnerabilityID,
						Line:            "1",
						Column:          "1",
						Confidence:      confidence.High.ToString(),
						File:            "vul.file",
						Code:            "code",
						Details:         "details",
						SecurityTool:    tools.HorusecLeaks,
						Language:        languages.Leaks,
						Severity:        severity.High,
						VulnHash:        "123456789",
						Type:            enumHorusec.Vulnerability,
					},
				},
			},
		}, nil)

		assert.NoError(t, err)
		result, err := analysisRepository.GetByID(analysisID)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		if result != nil {
			assert.NotEqual(t, uuid.Nil, result.ID)
			assert.Len(t, result.AnalysisVulnerabilities, 1)
			assert.NotEqual(t, uuid.Nil, result.AnalysisVulnerabilities[0].VulnerabilityID)
			assert.NotEqual(t, uuid.Nil, result.AnalysisVulnerabilities[0].Vulnerability.VulnerabilityID)
		}
		assert.NoError(t, os.RemoveAll(dbFile))
	})
}
