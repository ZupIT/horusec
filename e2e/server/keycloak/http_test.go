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
// In step: e2e-server-keycloak
package keycloak

import (
	"encoding/json"
	"fmt"
	accountDto "github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	authDto "github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/e2e/server"
	"github.com/ZupIT/horusec/e2e/server/keycloak/entities"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var SecretKeyCloak = ""

func TestMain(m *testing.M) {
	folderOfMigration := "file://../../../development-kit/pkg/databases/relational/migration"
	var connectionStringDB = env.GetEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable")
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

func TestServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Run("Should tests auth-type keycloak http requests", func(t *testing.T) {
		time.Sleep(10 * time.Second)
		user := &entities.UserRepresentation{
			Username:      "e2e_user",
			Email:         "e2e@example.com",
			EmailVerified: true,
			Enabled:       true,
		}
		credential := &entities.UserRepresentationCredentials{
			Temporary: false,
			Type:      "password",
			Value:     "Ch@ng3m3",
		}

		SetupKeycloak(t, user, credential)

		bearerToken := LoginInKeycloak(t, user.Username, credential.Value)["access_token"].(string)
		CheckIfTokenIsValid(t, bearerToken, SecretKeyCloak)

		CreateUserFromKeycloakInHorusec(t, &authDto.KeycloakToken{AccessToken: bearerToken})

		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, Update and Delete company
		companyID := RunCompanyCRUD(t, bearerToken)
		assert.NotEmpty(t, companyID)

		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, Update and Delete users in company
		RunCRUDUserInCompany(t, bearerToken, companyID)
	})
}

func SetupKeycloak(t *testing.T, user *entities.UserRepresentation, credential *entities.UserRepresentationCredentials) {
	responseLogin := LoginInKeycloak(t, "keycloak", "keycloak")
	bearerToken := "Bearer " + responseLogin["access_token"].(string)
	UpdateRolesToAcceptOAuth(t, bearerToken)
	DeleteAllUsersInKeyCloak(t, bearerToken)
	CreateUserInKeyCloak(t, user, credential, bearerToken)
	SecretKeyCloak = GetClientSecretInAccountClient(t, bearerToken)
	assert.NotEmpty(t, SecretKeyCloak)
	StartAuthHorusecServices(t, SecretKeyCloak)
}

func StartAuthHorusecServices(t *testing.T, secret string) {
	fmt.Println("Starting Horusec-Auth container...")
	output, err := exec.Command("whereis", "docker-compose").Output()
	assert.NoError(t, err)
	assert.NotEmpty(t, output)
	pathComposeSplited := strings.Split(string(output), "docker-compose: ")
	assert.Len(t, pathComposeSplited, 2)
	pathCompose := pathComposeSplited[1][0 : len(pathComposeSplited[1])-1]
	cmd := exec.Command(pathCompose, "-f", "../../deployments/docker-compose.server.keycloak.yaml", "up", "-d", "--build", "horusec-auth")
	cmd.Env = append(cmd.Env, "HORUSEC_KEYCLOAK_CLIENT_SECRET="+secret)
	output, err = cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.NotEmpty(t, output)
	fmt.Println("Waiting Horusec-Auth container up...")
	time.Sleep(3 * time.Second)
}

func RunCompanyCRUD(t *testing.T, bearerToken string) string {
	companyID := server.CreateCompany(t, bearerToken, &accountEntities.Company{
		Name: "zup",
	})
	allCompanies := server.ReadAllCompanies(t, bearerToken, true)
	assert.Contains(t, allCompanies, "zup")
	server.UpdateCompany(t, bearerToken, companyID, &accountEntities.Company{
		Name: "zup-1",
	})
	allCompaniesUpdated := server.ReadAllCompanies(t, bearerToken, true)
	assert.Contains(t, allCompaniesUpdated, "zup-1")
	server.DeleteCompany(t, bearerToken, companyID)
	return server.CreateCompany(t, bearerToken, &accountEntities.Company{
		Name: "zup",
	})
}

func RunCRUDUserInCompany(t *testing.T, bearerTokenAccount1, companyID string) {
	companyIDParsed, _ := uuid.Parse(companyID)

	// Add new user to invite
	user := &entities.UserRepresentation{
		Username:      "e2e_user_2",
		Email:         "e2e_2@example.com",
		EmailVerified: true,
		Enabled:       true,
	}
	credential := &entities.UserRepresentationCredentials{
		Temporary: false,
		Type:      "password",
		Value:     "Ch@ng3m3",
	}

	// Create second user in keycloak
	responseLoginAdmin := LoginInKeycloak(t, "keycloak", "keycloak")
	tokenKeycloakAdmin := "Bearer " + responseLoginAdmin["access_token"].(string)
	CreateUserInKeyCloak(t, user, credential, tokenKeycloakAdmin)

	// Login in keycloak and Create user in Horusec
	bearerTokenAccount2 := LoginInKeycloak(t, user.Username, credential.Value)["access_token"].(string)
	CreateUserFromKeycloakInHorusec(t, &authDto.KeycloakToken{AccessToken: bearerTokenAccount2})

	fmt.Println("Waiting register token in keycloak and register new user in horusec...")
	time.Sleep(3 * time.Second)

	// Invite user to existing company
	server.InviteUserToCompany(t, bearerTokenAccount1, companyID, &accountDto.InviteUser{
		Role:      rolesEnum.Member,
		Email:     user.Email,
		CompanyID: companyIDParsed,
	})

	// Check if exist two users in company
	allUsersInCompany := server.ReadAllUserInCompany(t, bearerTokenAccount1, companyID)
	accountRoles := []roles.AccountRole{}
	assert.NoError(t, json.Unmarshal([]byte(allUsersInCompany), &accountRoles))
	assert.NotEmpty(t, accountRoles)
	assert.Equal(t, 2, len(accountRoles))
	accountID := ""
	for _, currentUser := range accountRoles {
		if currentUser.Email == user.Email {
			accountID = currentUser.AccountID.String()
		}
	}
	assert.NotEmpty(t, accountID)

	// Check if company exists to new user
	allCompanies := server.ReadAllCompanies(t, bearerTokenAccount2, true)
	assert.Contains(t, allCompanies, "zup")

	// Expected return unauthorized because user is not admin of company to see dashboard in company view
	responseChart := server.GetChartContentWithoutTreatment(t, "total-repositories", bearerTokenAccount2, companyID, "")
	assert.Equal(t, http.StatusUnauthorized, responseChart.GetStatusCode())

	// Update permission of new user to admin
	server.UpdateUserInCompany(t, bearerTokenAccount1, companyID, accountID, &roles.AccountCompany{
		Role: rolesEnum.Admin,
	})
	time.Sleep(1 * time.Second)

	// Expected return OK because user is authorized view dashboard in company view
	responseChart = server.GetChartContentWithoutTreatment(t, "total-repositories", bearerTokenAccount2, companyID, "")
	assert.Equal(t, http.StatusOK, responseChart.GetStatusCode())

	// Expected remove user from company
	server.RemoveUserInCompany(t, bearerTokenAccount1, companyID, accountID)

	// Not show company for user when get all companies
	allCompanies = server.ReadAllCompanies(t, bearerTokenAccount2, false)
	assert.NotContains(t, allCompanies, "zup")
}
