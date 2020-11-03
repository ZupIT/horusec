package ldap

import (
	"fmt"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/e2e/server"
	"github.com/ZupIT/horusec/e2e/server/keycloak/entities"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	folderOfMigration := "file://../../../development-kit/pkg/databases/relational/migration"
	var connectionStringDB = env.GetEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@localhost:5432/horusec_db?sslmode=disable")
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
		bearerToken := CreateDefaultUserInKeycloakAndGetAccessToken(t)
		assert.NotEmpty(t, bearerToken)

		CreateUserFromKeycloakInHorusec(t, &accountentities.KeycloakToken{AccessToken: bearerToken})
		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, Update and Delete company
		companyID := RunCompanyCRUD(t, bearerToken)
		assert.NotEmpty(t, companyID)
	})
}

func CreateDefaultUserInKeycloakAndGetAccessToken(t *testing.T) string {
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
	//responseLogin := LoginInKeycloak(t, "keycloak", "keycloak")
	//bearerToken := "Bearer " + responseLogin["access_token"].(string)
	//DeleteAllUsersInKeyCloak(t, bearerToken)
	//CreateUserInKeyCloak(t, user, credential, bearerToken)
	//StartAuthHorusecServices(t, bearerToken)
	responseLogin := LoginInKeycloak(t, user.Username, credential.Value)
	return "Bearer " + GetOAuthToken(t, "Bearer " + responseLogin["access_token"].(string))
}

func StartAuthHorusecServices(t *testing.T, bearerToken string) {
	secret := GetClientSecretInAccountClient(t, bearerToken)
	assert.NotEmpty(t, secret)
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
