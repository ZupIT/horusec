package horusec

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
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
	folderOfMigration := "file://../../../development-kit/pkg/databases/relational/migration"
	connectionStringDB := env.GetEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@localhost:5432/horusec_db?sslmode=disable")
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
	t.Run("Should tests default auth-type (horusec) http requests", func(t *testing.T) {
		// TESTBOOK: Create account
		CreateAccount(t, &accountentities.Account{
			Email:    "e2e@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user",
		})
		// TESTBOOK: Login
		contentLogin := Login(t, &accountentities.LoginData{
			Email:    "e2e@example.com",
			Password: "Ch@ng3m3",
		})
		bearerToken := contentLogin["accessToken"]
		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, Update and Delete company
		companyID := RunCompanyCRUD(t, bearerToken)
		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, Update, and Delete repositories
		repositoryID := RunRepositoryCRUD(t, bearerToken, companyID)
		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, and Delete repository token
		repositoryToken := RunRepositoryTokenCRUD(t, bearerToken, companyID, repositoryID)
		// TESTBOOK: Authorize
		// TESTBOOK: Create, Read, and Delete company token
		companyToken := RunCompanyTokenCRUD(t, bearerToken, companyID)
		// TESTBOOK: Create and Read analysis - Repository Token
		// TESTBOOK: Create and Read analysis -  Company Token + repository name
		RunAnalysisRoutes(t, repositoryToken, companyToken)
		// TESTBOOK: Get Dashboard content - Company view
		RunDashboardByCompany(t, bearerToken, companyID)
		// TESTBOOK: Get Dashboard content - Repository view
		RunDashboardByRepository(t, bearerToken, companyID, repositoryID)
		// TESTBOOK: Get Dashboard content - Repository view
		RunManagerVulnerabilities(t, bearerToken, companyID, repositoryID)
		// TESTBOOK: Invite, Read, Update and Remove users in company
		RunCRUDUserInCompany(t, bearerToken, companyID)
		// TESTBOOK: Invite, Read, Update and Remove users in repository
		RunCRUDUserInRepository(t, bearerToken, companyID, repositoryID)
		// TESTBOOK: Logout
		Logout(t, bearerToken)
	})
	fmt.Println("All tests was finished in server test")
}

func RunCompanyCRUD(t *testing.T, bearerToken string) string {
	t.Run("Should create an company, check if it exists, update your name check if name was updated delete a company and return new company to manager in other steps", func(t *testing.T) {
		companyID := CreateCompany(t, bearerToken, &accountentities.Company{
			Name: "zup",
		})
		allCompanies := ReadAllCompanies(t, bearerToken, true)
		assert.Contains(t, allCompanies, "zup")
		UpdateCompany(t, bearerToken, companyID, &accountentities.Company{
			Name: "zup-1",
		})
		allCompaniesUpdated := ReadAllCompanies(t, bearerToken, true)
		assert.Contains(t, allCompaniesUpdated, "zup-1")
		DeleteCompany(t, bearerToken, companyID)
	})
	return CreateCompany(t, bearerToken, &accountentities.Company{
		Name: "zup",
	})
}

func RunRepositoryCRUD(t *testing.T, bearerToken, companyID string) string {
	t.Run("Should create an repository, check if it exists, update your name check if name was updated delete a repository and return new repository to manager in other steps", func(t *testing.T) {
		repositoryID := CreateRepository(t, bearerToken, companyID, &accountentities.Repository{
			Name: "horusec",
		})
		allRepositories := ReadAllRepositories(t, bearerToken, companyID, true)
		assert.Contains(t, allRepositories, "horusec")
		UpdateRepository(t, bearerToken, companyID, repositoryID, &accountentities.Repository{
			Name: "horusec-1",
		})
		allRepositoriesUpdated := ReadAllRepositories(t, bearerToken, companyID, true)
		assert.Contains(t, allRepositoriesUpdated, "horusec-1")
		DeleteRepository(t, bearerToken, companyID, repositoryID)
	})
	return CreateRepository(t, bearerToken, companyID, &accountentities.Repository{
		Name: "horusec",
	})
}

func RunRepositoryTokenCRUD(t *testing.T, bearerToken, companyID, repositoryID string) string {
	t.Run("Should create an repository token, check if return your content correctly and delete a repository token and return new repository token to manager in other steps", func(t *testing.T) {
		_ = GenerateRepositoryToken(t, bearerToken, companyID, repositoryID, api.Token{Description: "access_token"})
		allTokens := ReadAllRepositoryToken(t, bearerToken, companyID, repositoryID)
		assert.Contains(t, allTokens, "access_token")
		allTokensStruct := []api.Token{}
		assert.NoError(t, json.Unmarshal([]byte(allTokens), &allTokensStruct))
		assert.NotEmpty(t, allTokensStruct)
		RevokeRepositoryToken(t, bearerToken, companyID, repositoryID, allTokensStruct[0].TokenID.String())
	})
	return GenerateRepositoryToken(t, bearerToken, companyID, repositoryID, api.Token{Description: "access_token"})
}

func RunCompanyTokenCRUD(t *testing.T, bearerToken string, companyID string) string {
	t.Run("Should create an company token, check if return your content correctly and delete a company token and return new company token to manager in other steps", func(t *testing.T) {
		_ = GenerateCompanyToken(t, bearerToken, companyID, api.Token{Description: "access_token"})
		allTokens := ReadAllCompanyToken(t, bearerToken, companyID)
		assert.Contains(t, allTokens, "access_token")
		allTokensStruct := []api.Token{}
		assert.NoError(t, json.Unmarshal([]byte(allTokens), &allTokensStruct))
		assert.NotEmpty(t, allTokensStruct)
		RevokeCompanyToken(t, bearerToken, companyID, allTokensStruct[0].TokenID.String())
	})
	return GenerateCompanyToken(t, bearerToken, companyID, api.Token{Description: "access_token"})
}

func RunAnalysisRoutes(t *testing.T, repositoryToken, companyToken string) {
	t.Run("Should create an analysis using repository token and check if exists your content in system", func(t *testing.T) {
		analysisIDInsertedWithRepositoryToken := InsertAnalysisWithRepositoryToken(t, &api.AnalysisData{
			Analysis: test.CreateAnalysisMock(),
		}, repositoryToken)
		contentInsertedWithRepositoryToken := GetAnalysisByID(t, analysisIDInsertedWithRepositoryToken, repositoryToken)
		analysisInsertedWithRepositoryToken := horusec.Analysis{}
		assert.NoError(t, json.Unmarshal([]byte(contentInsertedWithRepositoryToken), &analysisInsertedWithRepositoryToken))
		assert.NotEmpty(t, analysisInsertedWithRepositoryToken)
		assert.Greater(t, len(analysisInsertedWithRepositoryToken.AnalysisVulnerabilities), 0)
	})
	t.Run("Should create an analysis using company token and check if exists your content in system", func(t *testing.T) {
		analysisIDInsertedWithCompanyToken := InsertAnalysisWithCompanyToken(t, &api.AnalysisData{
			Analysis:       test.CreateAnalysisMock(),
			RepositoryName: "new-repository",
		}, companyToken)
		contentInsertedWithCompanyToken := GetAnalysisByID(t, analysisIDInsertedWithCompanyToken, repositoryToken)
		analysisInsertedWithCompanyToken := horusec.Analysis{}
		assert.NoError(t, json.Unmarshal([]byte(contentInsertedWithCompanyToken), &analysisInsertedWithCompanyToken))
		assert.NotEmpty(t, analysisInsertedWithCompanyToken)
		assert.Greater(t, len(analysisInsertedWithCompanyToken.AnalysisVulnerabilities), 0)
	})
}

func RunDashboardByCompany(t *testing.T, bearerToken, companyID string) {
	t.Run("Check if all graphs routes return content in view by company", func(t *testing.T) {
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
	})
}

func RunDashboardByRepository(t *testing.T, bearerToken, companyID, repositoryID string) {
	t.Run("Check if all graphs routes return content in view by repository", func(t *testing.T) {
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
	})
}

func RunManagerVulnerabilities(t *testing.T, bearerToken, companyID, repositoryID string) {
	t.Run("Should get all vulnerabilities in system and check if all are vulnerabilities after we need update one item to false positive and check if exists how false positive in list", func(t *testing.T) {
		allVulnerabilitiesString := GetAllVulnerabilitiesToManager(t, bearerToken, companyID, repositoryID, "page=1&size=10")
		allVulnerabilities := dto.VulnManagement{}
		assert.NoError(t, json.Unmarshal([]byte(allVulnerabilitiesString), &allVulnerabilities))
		assert.NotEmpty(t, allVulnerabilities)
		assert.Equal(t, allVulnerabilities.TotalItems, 11)
		assert.Equal(t, len(allVulnerabilities.Data), 10)
		for _, vuln := range allVulnerabilities.Data {
			assert.Equal(t, vuln.Type, horusecEnums.Vulnerability)
		}
		vulnIDToUpdate := allVulnerabilities.Data[0].VulnerabilityID.String()
		_ = UpdateVulnerabilitiesType(t, bearerToken, companyID, repositoryID, vulnIDToUpdate, dto.UpdateVulnType{Type: horusecEnums.FalsePositive})
		allVulnerabilitiesUpdatedString := GetAllVulnerabilitiesToManager(t, bearerToken, companyID, repositoryID, "page=1&size=11")
		allVulnerabilitiesUpdated := dto.VulnManagement{}
		assert.NoError(t, json.Unmarshal([]byte(allVulnerabilitiesUpdatedString), &allVulnerabilitiesUpdated))
		assert.NotEmpty(t, allVulnerabilitiesUpdated)
		assert.Equal(t, allVulnerabilitiesUpdated.TotalItems, 11)
		assert.Equal(t, len(allVulnerabilitiesUpdated.Data), 11)
		for _, vuln := range allVulnerabilitiesUpdated.Data {
			if vuln.VulnerabilityID.String() == vulnIDToUpdate {
				assert.Equal(t, vuln.Type, horusecEnums.FalsePositive)
			} else {
				assert.Equal(t, vuln.Type, horusecEnums.Vulnerability)
			}
		}
	})
}

func RunCRUDUserInCompany(t *testing.T, bearerTokenAccount1, companyID string) {
	t.Run("Should create new user and invite to existing company with permission of the member after update your permission to admin and check if is enable view dashboard by company and remove user from company", func(t *testing.T) {
		account2 := &accountentities.Account{
			Email:    "e2e_test2@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user_test2",
		}
		companyIDParsed, _ := uuid.Parse(companyID)

		// Add new user to invite
		CreateAccount(t, account2)

		// Invite user to existing company
		InviteUserToCompany(t, bearerTokenAccount1, companyID, &accountentities.InviteUser{
			Role:      rolesEnum.Member,
			Email:     account2.Email,
			CompanyID: companyIDParsed,
		})

		// Check if exist two users in company
		allUsersInCompany := ReadAllUserInCompany(t, bearerTokenAccount1, companyID)
		accountRoles := []roles.AccountRole{}
		assert.NoError(t, json.Unmarshal([]byte(allUsersInCompany), &accountRoles))
		assert.NotEmpty(t, accountRoles)
		assert.Equal(t, 2, len(accountRoles))
		accountID := ""
		for _, user := range accountRoles {
			if user.Email == account2.Email {
				accountID = user.AccountID.String()
			}
		}
		assert.NotEmpty(t, accountID)
		// Login with new user
		contentLoginAccount2 := Login(t, &accountentities.LoginData{
			Email:    account2.Email,
			Password: account2.Password,
		})
		bearerTokenAccount2 := contentLoginAccount2["accessToken"]

		// Check if company exists to new user
		allCompanies := ReadAllCompanies(t, bearerTokenAccount2, true)
		assert.Contains(t, allCompanies, "zup")

		// Expected return unauthorized because user is not admin of company to see dashboard in company view
		responseChart := GetChartContentWithoutTreatment(t, "total-repositories", bearerTokenAccount2, companyID, "")
		assert.Equal(t, http.StatusUnauthorized, responseChart.GetStatusCode())

		// Update permission of new user to admin
		UpdateUserInCompany(t, bearerTokenAccount1, companyID, accountID, &roles.AccountCompany{
			Role: rolesEnum.Admin,
		})

		// Expected return OK because user is authorized view dashboard in company view
		responseChart = GetChartContentWithoutTreatment(t, "total-repositories", bearerTokenAccount2, companyID, "")
		assert.Equal(t, http.StatusOK, responseChart.GetStatusCode())

		// Expected remove user from company
		RemoveUserInCompany(t, bearerTokenAccount1, companyID, accountID)

		// Not show company for user when get all companies
		allCompanies = ReadAllCompanies(t, bearerTokenAccount2, false)
		assert.NotContains(t, allCompanies, "zup")

		// Logout session new user
		Logout(t, bearerTokenAccount2)
	})
}

func RunCRUDUserInRepository(t *testing.T, bearerTokenAccount1, companyID, repositoryID string) {
	t.Run("Should create new user and invite to existing company and invite to existing repository, with permission of the member in repository after update your permission to admin of repository and check if is enable show all tokens in repository and remove user from repository", func(t *testing.T) {
		account2 := &accountentities.Account{
			Email:    "e2e_test3@example.com",
			Password: "Ch@ng3m3",
			Username: "e2e_user_test3",
		}
		companyIDParsed, _ := uuid.Parse(companyID)

		// Add new user to invite
		CreateAccount(t, account2)

		// Invite new user to existing company
		InviteUserToCompany(t, bearerTokenAccount1, companyID, &accountentities.InviteUser{
			Role:      rolesEnum.Member,
			Email:     account2.Email,
			CompanyID: companyIDParsed,
		})
		// Invite new user to existing repository
		InviteUserToRepository(t, bearerTokenAccount1, companyID, repositoryID, &accountentities.InviteUser{
			Role:      rolesEnum.Member,
			Email:     account2.Email,
			CompanyID: companyIDParsed,
		})

		// Check if exist two users in repository
		allUsersInRepository := ReadAllUserInRepository(t, bearerTokenAccount1, companyID, repositoryID)
		accountRoles := []roles.AccountRole{}
		assert.NoError(t, json.Unmarshal([]byte(allUsersInRepository), &accountRoles))
		assert.NotEmpty(t, accountRoles)
		assert.Equal(t, 2, len(accountRoles))
		accountID := ""
		for _, user := range accountRoles {
			if user.Email == account2.Email {
				accountID = user.AccountID.String()
			}
		}
		assert.NotEmpty(t, accountID)

		// Login with new user
		contentLoginAccount2 := Login(t, &accountentities.LoginData{
			Email:    account2.Email,
			Password: account2.Password,
		})
		bearerTokenAccount2 := contentLoginAccount2["accessToken"]

		// Check if repository exists to new user
		allRepositories := ReadAllRepositories(t, bearerTokenAccount2, companyID, true)
		assert.Contains(t, allRepositories, "horusec")

		// Expected return unauthorized because user is not admin of repository to see tokens of repository
		responseRepositoryToken := ReadAllRepositoryTokenWithoutTreatment(t, bearerTokenAccount2, companyID, repositoryID)
		assert.Equal(t, http.StatusUnauthorized, responseRepositoryToken.GetStatusCode())

		// Update permission of new user to admin in repository
		UpdateUserInRepository(t, bearerTokenAccount1, companyID, repositoryID, accountID, &roles.AccountCompany{
			Role: rolesEnum.Admin,
		})

		// Expected return OK because user is authorized to see tokens of repository
		responseRepositoryToken = ReadAllRepositoryTokenWithoutTreatment(t, bearerTokenAccount2, companyID, repositoryID)
		assert.Equal(t, http.StatusOK, responseRepositoryToken.GetStatusCode())

		// Expected remove user from company
		RemoveUserInRepository(t, bearerTokenAccount1, companyID, repositoryID, accountID)

		// Not show repository for user when get all repositories
		allRepositories = ReadAllRepositories(t, bearerTokenAccount2, companyID, false)
		assert.NotContains(t, allRepositories, "horusec")

		// Logout session new user
		Logout(t, bearerTokenAccount2)
	})
}
