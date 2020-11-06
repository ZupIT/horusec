package server

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestMain(m *testing.M) {
	migration, err := migrate.New(
		"file://../../development-kit/pkg/databases/relational/migration",
		env.GetEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@localhost:5432/horusec_db?sslmode=disable"),
	)
	if err != nil {
		logger.LogPanic("Error in create instance migration: ", err)
	}

	if err := migration.Down(); err != nil {
		if err.Error() != "no change" {
			logger.LogPanic("Error in down migration: ", err)
		}
	}
	if err := migration.Up(); err != nil {
		if err.Error() != "no change" {
			logger.LogPanic("Error in down migration: ", err)
		}
	}
	code := m.Run()
	os.Exit(code)
}

func TestServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Run("Should tests default auth-type (horusec) http requests", func(t *testing.T) {
		CreateAccount(t, &accountentities.Account{
			Email:    "e2e@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user",
		})
		bearerToken, _ := Login(t, &accountentities.LoginData{
			Email:    "e2e@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user",
		})
		bearerToken, _ := Login(t, &authEntities.Credentials{
			Username: "e2e@example.com",
			Password: "Ch@ng3m3",
		})
		companyID := RunCompanyCRUD(t, bearerToken)
		repositoryID := RunRepositoryCRUD(t, bearerToken, companyID)
		repositoryToken := RunRepositoryTokenCRUD(t, bearerToken, companyID, repositoryID)
		_ = InsertAnalysisWithRepositoryToken(t, &api.AnalysisData{
			Analysis: test.CreateAnalysisMock(),
		}, repositoryToken)
		RunDashboardByCompany(t, bearerToken, companyID)
		RunDashboardByRepository(t, bearerToken, companyID, repositoryID)
		Logout(t, bearerToken)
	})
	fmt.Println("All tests was finished in server test")
}

func RunDashboardByCompany(t *testing.T, bearerToken, companyID string) {
	bodyAllVulnerabilities := GetChartContent(t, "all-vulnerabilities", bearerToken, companyID, "")
	bodyAllVulnerabilitiesString := string(bodyAllVulnerabilities)
	assert.NotEmpty(t, bodyAllVulnerabilitiesString)

	bodyVulnerabilitiesByAuthor := GetChartContent(t, "vulnerabilities-by-author", bearerToken, companyID, "")
	bodyVulnerabilitiesByAuthorString := string(bodyVulnerabilitiesByAuthor)
	assert.NotEmpty(t, bodyVulnerabilitiesByAuthorString)

	bodyVulnerabilitiesByLanguage := GetChartContent(t, "vulnerabilities-by-language", bearerToken, companyID, "")
	bodyVulnerabilitiesByLanguageString := string(bodyVulnerabilitiesByLanguage)
	assert.NotEmpty(t, bodyVulnerabilitiesByLanguageString)

	bodyVulnerabilitiesByRepository := GetChartContent(t, "vulnerabilities-by-repository", bearerToken, companyID, "")
	bodyVulnerabilitiesByRepositoryString := string(bodyVulnerabilitiesByRepository)
	assert.NotEmpty(t, bodyVulnerabilitiesByRepositoryString)

	bodyVulnerabilitiesByTime := GetChartContent(t, "vulnerabilities-by-time", bearerToken, companyID, "")
	bodyVulnerabilitiesByTimeString := string(bodyVulnerabilitiesByTime)
	assert.NotEmpty(t, bodyVulnerabilitiesByTimeString)

	bodyTotalDevelopers := GetChartContent(t, "total-developers", bearerToken, companyID, "")
	bodyTotalDevelopersString := string(bodyTotalDevelopers)
	assert.NotEmpty(t, bodyTotalDevelopersString)

	bodyTotalRepositories := GetChartContent(t, "total-repositories", bearerToken, companyID, "")
	bodyTotalRepositoriesString := string(bodyTotalRepositories)
	assert.NotEmpty(t, bodyTotalRepositoriesString)

	bodyDetailsChart := GetChartDetailsUsingGraphQLAndReturnBody(t, bearerToken, companyID, "")
	bodyDetailsChartString := string(bodyDetailsChart)
	assert.NotEmpty(t, bodyDetailsChartString)
}

func RunDashboardByRepository(t *testing.T, bearerToken, companyID, repositoryID string) {
	bodyAllVulnerabilities := GetChartContent(t, "all-vulnerabilities", bearerToken, companyID, repositoryID)
	bodyAllVulnerabilitiesString := string(bodyAllVulnerabilities)
	assert.NotEmpty(t, bodyAllVulnerabilitiesString)

	bodyVulnerabilitiesByAuthor := GetChartContent(t, "vulnerabilities-by-author", bearerToken, companyID, repositoryID)
	bodyVulnerabilitiesByAuthorString := string(bodyVulnerabilitiesByAuthor)
	assert.NotEmpty(t, bodyVulnerabilitiesByAuthorString)

	bodyVulnerabilitiesByLanguage := GetChartContent(t, "vulnerabilities-by-language", bearerToken, companyID, repositoryID)
	bodyVulnerabilitiesByLanguageString := string(bodyVulnerabilitiesByLanguage)
	assert.NotEmpty(t, bodyVulnerabilitiesByLanguageString)

	bodyVulnerabilitiesByRepository := GetChartContent(t, "vulnerabilities-by-repository", bearerToken, companyID, repositoryID)
	bodyVulnerabilitiesByRepositoryString := string(bodyVulnerabilitiesByRepository)
	assert.NotEmpty(t, bodyVulnerabilitiesByRepositoryString)

	bodyVulnerabilitiesByTime := GetChartContent(t, "vulnerabilities-by-time", bearerToken, companyID, repositoryID)
	bodyVulnerabilitiesByTimeString := string(bodyVulnerabilitiesByTime)
	assert.NotEmpty(t, bodyVulnerabilitiesByTimeString)

	bodyTotalDevelopers := GetChartContent(t, "total-developers", bearerToken, companyID, repositoryID)
	bodyTotalDevelopersString := string(bodyTotalDevelopers)
	assert.NotEmpty(t, bodyTotalDevelopersString)

	bodyTotalRepositories := GetChartContent(t, "total-repositories", bearerToken, companyID, repositoryID)
	bodyTotalRepositoriesString := string(bodyTotalRepositories)
	assert.NotEmpty(t, bodyTotalRepositoriesString)

	bodyDetailsChart := GetChartDetailsUsingGraphQLAndReturnBody(t, bearerToken, companyID, repositoryID)
	bodyDetailsChartString := string(bodyDetailsChart)
	assert.NotEmpty(t, bodyDetailsChartString)
}

func RunCompanyCRUD(t *testing.T, bearerToken string) string {
	companyID := CreateCompany(t, bearerToken, &accountentities.Company{
		Name: "zup",
	})
	_ = ReadAllCompanies(t, bearerToken)
	UpdateCompany(t, bearerToken, companyID, &accountentities.Company{
		Name: "zup-1",
	})
	allCompaniesUpdated := ReadAllCompanies(t, bearerToken)
	allCompaniesBytes, _ := json.Marshal(allCompaniesUpdated)
	assert.Contains(t, string(allCompaniesBytes), "zup-1")
	DeleteCompany(t, bearerToken, companyID)
	return CreateCompany(t, bearerToken, &accountentities.Company{
		Name: "zup",
	})
}

func RunRepositoryCRUD(t *testing.T, bearerToken, companyID string) string {
	repositoryID := CreateRepository(t, bearerToken, companyID, &accountentities.Repository{
		Name: "horusec",
	})
	return repositoryID
}

func RunRepositoryTokenCRUD(t *testing.T, bearerToken, companyID, repositoryID string) string {
	return GenerateRepositoryToken(t, bearerToken, companyID, repositoryID, api.Token{Description: "access_token"})
}
