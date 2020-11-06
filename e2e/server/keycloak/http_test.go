// Test e2e refers workflow: .github/workflows/e2e.yml
// In step: e2e-server-keycloak
package keycloak

import (
	"encoding/json"
	"fmt"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
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
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

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
		bearerToken := SetupKeycloakAndGetFirstAccessToken(t, user, credential)
		assert.NotEmpty(t, bearerToken)

		CreateUserFromKeycloakInHorusec(t, &accountentities.KeycloakToken{AccessToken: bearerToken})

		bearerToken = LoginInKeycloak(t, user.Username, credential.Value)["access_token"].(string)

		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, Update and Delete company
		companyID := RunCompanyCRUD(t, bearerToken)
		assert.NotEmpty(t, companyID)
		RunCRUDUserInCompany(t, bearerToken, companyID)
	})
}

func SetupKeycloakAndGetFirstAccessToken(t *testing.T, user *entities.UserRepresentation, credential *entities.UserRepresentationCredentials) string {
	responseLogin := LoginInKeycloak(t, "keycloak", "keycloak")
	bearerToken := "Bearer " + responseLogin["access_token"].(string)
	UpdateRolesToAcceptOAuth(t, bearerToken)
	DeleteAllUsersInKeyCloak(t, bearerToken)
	CreateUserInKeyCloak(t, user, credential, bearerToken)
	secret := GetClientSecretInAccountClient(t, bearerToken)
	assert.NotEmpty(t, secret)
	StartAuthHorusecServices(t, secret)
	responseLogin = LoginInKeycloak(t, user.Username, credential.Value)
	return responseLogin["access_token"].(string)
}

func StartAuthHorusecServices(t *testing.T, secret string) {
	fmt.Println("Starting auth horusec service...")
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
	fmt.Println("Waiting container up...")
	time.Sleep(3 * time.Second)
}

func RunCompanyCRUD(t *testing.T, bearerToken string) string {
	t.Run("Should create an company, check if it exists, update your name check if name was updated delete a company and return new company to manager in other steps", func(t *testing.T) {
		companyID := server.CreateCompany(t, bearerToken, &accountentities.Company{
			Name: "zup",
		})
		allCompanies := server.ReadAllCompanies(t, bearerToken, true)
		assert.Contains(t, allCompanies, "zup")
		server.UpdateCompany(t, bearerToken, companyID, &accountentities.Company{
			Name: "zup-1",
		})
		allCompaniesUpdated := server.ReadAllCompanies(t, bearerToken, true)
		assert.Contains(t, allCompaniesUpdated, "zup-1")
		server.DeleteCompany(t, bearerToken, companyID)
	})
	return server.CreateCompany(t, bearerToken, &accountentities.Company{
		Name: "zup",
	})
}

func RunCRUDUserInCompany(t *testing.T, bearerTokenAccount1, companyID string) {
	t.Run("Should create new user and invite to existing company with permission of the member after update your permission to admin and check if is enable view dashboard by company and remove user from company", func(t *testing.T) {
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
		responseLoginAdmin := LoginInKeycloak(t, "keycloak", "keycloak")
		CreateUserInKeyCloak(t, user, credential, "Bearer "+responseLoginAdmin["access_token"].(string))
		responseLoginNewUser := LoginInKeycloak(t, user.Username, credential.Value)
		bearerTokenAccount2 := responseLoginNewUser["access_token"].(string)
		CreateUserFromKeycloakInHorusec(t, &accountentities.KeycloakToken{AccessToken: bearerTokenAccount2})

		// Invite user to existing company
		server.InviteUserToCompany(t, bearerTokenAccount1, companyID, &accountentities.InviteUser{
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

		// Expected return OK because user is authorized view dashboard in company view
		responseChart = server.GetChartContentWithoutTreatment(t, "total-repositories", bearerTokenAccount2, companyID, "")
		assert.Equal(t, http.StatusOK, responseChart.GetStatusCode())

		// Expected remove user from company
		server.RemoveUserInCompany(t, bearerTokenAccount1, companyID, accountID)

		// Not show company for user when get all companies
		allCompanies = server.ReadAllCompanies(t, bearerTokenAccount2, false)
		assert.NotContains(t, allCompanies, "zup")
	})
}
