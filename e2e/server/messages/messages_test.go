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
// In step: e2e-messages
package messages

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authDto "github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
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
	code := m.Run()
	os.Exit(code)
}

func TestMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Run("Should run analysis and check if messages are dispatch correctly", func(t *testing.T) {
		accountToCreate := &authEntities.Account{
			Email:    "e2e@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user",
		}
		// Create account
		CreateAccount(t, accountToCreate)

		// When try login without confirm account return unauthorized
		loginResp := Login(t, &authDto.Credentials{
			Username: accountToCreate.Email,
			Password: accountToCreate.Password,
		})
		assert.Equal(t, http.StatusOK, loginResp.GetStatusCode())

		// Get Last account created in database
		accountCreated := GetLastAccountCreated(t)

		// Confirm account in database
		ValidateAccount(t, accountCreated.AccountID.String())

		// Check if is possible login now
		bearerToken := LoginAndReturnAccessToken(t, &authDto.Credentials{
			Username: accountToCreate.Email,
			Password: accountToCreate.Password,
		})
		Logout(t, bearerToken)
	})
}

func GetLastAccountCreated(t *testing.T) (accountCreated authEntities.Account) {
	dbRead := adapter.NewRepositoryRead()
	sqlUtil := test.NewSQLUtil(dbRead)
	sqlUtil.GetLast(&accountCreated)
	assert.NotEmpty(t, accountCreated)
	assert.NotEqual(t, accountCreated.AccountID, uuid.Nil)
	return accountCreated
}
