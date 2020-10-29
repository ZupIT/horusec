package server

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
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
	fmt.Println("Running test for CreateAccount")
	CreateAccount(t, &accountentities.Account{
		Email:              "e2e@example.com",
		Password:           "Ch@ng3m3",
		Username:           "e2e_user",
	})
	fmt.Println("Running test for Login")
	bearerToken, _ := Login(t, &accountentities.LoginData{
		Email:    "e2e@example.com",
		Password: "Ch@ng3m3",
	})

	companyID := RunCompanyCRUD(t, bearerToken)
	bearerToken, _ = Login(t, &accountentities.LoginData{
		Email:    "e2e@example.com",
		Password: "Ch@ng3m3",
	})
	fmt.Println("Running test for CreateRepository")
	repositoryID := CreateRepository(t, bearerToken, companyID, &accountentities.Repository{
		Name: "horusec",
	})
	fmt.Println("Running test for GenerateRepositoryToken")
	_ = GenerateRepositoryToken(t, bearerToken, companyID, repositoryID, api.Token{Description: "access_token"})
	fmt.Println("All tests was finished in server test")

}

func RunCompanyCRUD(t *testing.T, bearerToken string) string {
	fmt.Println("Running test for CreateCompany")
	companyID := CreateCompany(t, bearerToken, &accountentities.Company{
		Name:  "zup",
	})
	fmt.Println("Running test for ReadAllCompanies")
	_ = ReadAllCompanies(t, bearerToken)
	fmt.Println("Running test for UpdateCompany")
	UpdateCompany(t, bearerToken, companyID, &accountentities.Company{
		Name:  "zup-1",
	})
	allCompaniesUpdated := ReadAllCompanies(t, bearerToken)
	allCompaniesBytes, _ := json.Marshal(allCompaniesUpdated)
	assert.Contains(t, string(allCompaniesBytes), "zup-1")
	fmt.Println("Running test for DeleteCompany")
	DeleteCompany(t, bearerToken, companyID)
	return companyID
}
