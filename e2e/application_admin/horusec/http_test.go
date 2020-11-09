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

// Test e2e refers workflow: .github/workflows/e2e.yml
// In step: e2e-application-admin-horusec
package horusec

import (
	"fmt"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	folderOfMigration := "file://../../../development-kit/pkg/databases/relational/migration"
	connectionStringDB := env.GetEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable")
	migration, err := migrate.New(folderOfMigration, connectionStringDB)
	if err != nil {
		logger.LogPanic("Error in create first instance migration: ", err)
	}
	if err := migration.Drop(); err != nil {
		logger.LogPanic("Error in drop migration: ", err)
	}
	sourceErr, dbErr := migration.Close()
	if sourceErr != nil {
		logger.LogPanic("Error in source err to close connection: ", sourceErr)
	}
	if dbErr != nil {
		logger.LogPanic("Error in database err to close connection: ", dbErr)
	}
	migration, err = migrate.New(folderOfMigration, connectionStringDB)
	if err != nil {
		logger.LogPanic("Error in create second instance migration: ", err)
	}
	if err := migration.Up(); err != nil {
		if err.Error() != "no change" {
			logger.LogPanic("Error in up migration: ", err)
		}
	}
	output, err := exec.Command("docker", "restart", "horusec-auth").Output()
	if err != nil {
		logger.LogPanic("Error restart auth service: "+string(output), err)
	}
	time.Sleep(3 * time.Second)
	code := m.Run()
	os.Exit(code)
}

func TestServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Run("Should tests default auth-type (horusec) http requests in application admin enable", func(t *testing.T) {
		time.Sleep(10 * time.Second)
		// Login with default application admin
		contentLogin := Login(t, &authEntities.Credentials{
			Username: "horusec-admin@example.com",
			Password: "Devpass0*",
		})
		bearerToken := contentLogin["accessToken"]

		// create company and add to logged user
		companyID := CreateCompanyApplicationAdmin(t, bearerToken, &accountentities.CompanyApplicationAdmin{
			Name:       "zup",
			AdminEmail: "horusec-admin@example.com",
		})
		// check if company show to logged user
		allCompanies := ReadAllCompanies(t, bearerToken, true)
		assert.Contains(t, allCompanies, "zup")
		// Update company name
		UpdateCompany(t, bearerToken, companyID, &accountentities.Company{
			Name: "zup-1",
		})
		// Check if company was updated
		allCompaniesUpdated := ReadAllCompanies(t, bearerToken, true)
		assert.Contains(t, allCompaniesUpdated, "zup-1")
		// Delete company
		DeleteCompany(t, bearerToken, companyID)

		// Create new user
		CreateAccount(t, &accountentities.Account{
			Email:    "e2e@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user",
		})
		// Create new company to new user in system
		_ = CreateCompanyApplicationAdmin(t, bearerToken, &accountentities.CompanyApplicationAdmin{
			Name:       "zup",
			AdminEmail: "e2e@example.com",
		})
		// Not can possible show company to first user
		allCompanies = ReadAllCompanies(t, bearerToken, false)
		assert.NotContains(t, allCompanies, "zup")

		// Login with new user
		contentLoginNewUser := Login(t, &authEntities.Credentials{
			Username: "e2e@example.com",
			Password: "Ch@ng3m3",
		})
		bearerTokenNewUser := contentLoginNewUser["accessToken"]
		// Check if exists an company for new user
		allCompanies = ReadAllCompanies(t, bearerTokenNewUser, true)
		assert.Contains(t, allCompanies, "zup")
		// Logout both users
		Logout(t, bearerToken)
		Logout(t, bearerTokenNewUser)
	})
	fmt.Println("All tests was finished in server test")
}
