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

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"

	databasesql "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/request"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/zip"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var BearerToken = ""
var RefreshToken = ""
var RepositoryToken = ""
var CompanyToken = ""
var CompanyID = ""
var RepositoryID = ""

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./analysis")
	_ = os.RemoveAll("./tmp")
	migration, err := migrate.New(
		"file://../development-kit/pkg/databases/relational/migration",
		env.GetEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@localhost:5432/horusec_db?sslmode=disable"),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = migration.Down()
	_ = migration.Up()
	code := m.Run()

	_ = os.RemoveAll("./analysis")
	_ = os.RemoveAll("./tmp")
	os.Exit(code)
}

func TestE2E(t *testing.T) {
	createAccount(t)
	validateAccount(t)
	login(t)
	createCompany(t)
	createRepository(t)
	generateRepositoryToken(t)
	//generateCompanyToken(t)

	t.Run("Should run analysis and check if your response exist on analytics by company", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test")
		}
		var wgGolang sync.WaitGroup
		wgGolang.Add(1)
		go runGolangTest(t, RepositoryToken, &wgGolang)
		wgGolang.Wait()

		bodyAllVulnerabilities := getChartRESTContentAndReturnBody(t, "all-vulnerabilities", "")
		bodyAllVulnerabilitiesString := string(bodyAllVulnerabilities)
		assert.NotEmpty(t, bodyAllVulnerabilitiesString)

		bodyVulnerabilitiesByAuthor := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-author", "")
		bodyVulnerabilitiesByAuthorString := string(bodyVulnerabilitiesByAuthor)
		assert.NotEmpty(t, bodyVulnerabilitiesByAuthorString)

		bodyVulnerabilitiesByLanguage := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-language", "")
		bodyVulnerabilitiesByLanguageString := string(bodyVulnerabilitiesByLanguage)
		assert.NotEmpty(t, bodyVulnerabilitiesByLanguageString)

		bodyVulnerabilitiesByRepository := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-repository", "")
		bodyVulnerabilitiesByRepositoryString := string(bodyVulnerabilitiesByRepository)
		assert.NotEmpty(t, bodyVulnerabilitiesByRepositoryString)

		bodyVulnerabilitiesByTime := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-time", "")
		bodyVulnerabilitiesByTimeString := string(bodyVulnerabilitiesByTime)
		assert.NotEmpty(t, bodyVulnerabilitiesByTimeString)

		bodyTotalDevelopers := getChartRESTContentAndReturnBody(t, "total-developers", "")
		bodyTotalDevelopersString := string(bodyTotalDevelopers)
		assert.NotEmpty(t, bodyTotalDevelopersString)

		bodyTotalRepositories := getChartRESTContentAndReturnBody(t, "total-repositories", "")
		bodyTotalRepositoriesString := string(bodyTotalRepositories)
		assert.NotEmpty(t, bodyTotalRepositoriesString)

		bodyDetailsChart := getChartDetailsUsingGraphQLAndReturnBody(t, "")
		bodyDetailsChartString := string(bodyDetailsChart)
		assert.NotEmpty(t, bodyDetailsChartString)
	})
	t.Run("Should run analysis and check if your response exist on analytics by repository", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test")
		}
		var wgGolang sync.WaitGroup
		wgGolang.Add(1)
		go runGolangTest(t, RepositoryToken, &wgGolang)
		wgGolang.Wait()

		bodyAllVulnerabilities := getChartRESTContentAndReturnBody(t, "all-vulnerabilities", RepositoryID)
		bodyAllVulnerabilitiesString := string(bodyAllVulnerabilities)
		assert.NotEmpty(t, bodyAllVulnerabilitiesString)

		bodyVulnerabilitiesByAuthor := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-author", RepositoryID)
		bodyVulnerabilitiesByAuthorString := string(bodyVulnerabilitiesByAuthor)
		assert.NotEmpty(t, bodyVulnerabilitiesByAuthorString)

		bodyVulnerabilitiesByLanguage := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-language", RepositoryID)
		bodyVulnerabilitiesByLanguageString := string(bodyVulnerabilitiesByLanguage)
		assert.NotEmpty(t, bodyVulnerabilitiesByLanguageString)

		bodyVulnerabilitiesByRepository := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-repository", RepositoryID)
		bodyVulnerabilitiesByRepositoryString := string(bodyVulnerabilitiesByRepository)
		assert.NotEmpty(t, bodyVulnerabilitiesByRepositoryString)

		bodyVulnerabilitiesByTime := getChartRESTContentAndReturnBody(t, "vulnerabilities-by-time", RepositoryID)
		bodyVulnerabilitiesByTimeString := string(bodyVulnerabilitiesByTime)
		assert.NotEmpty(t, bodyVulnerabilitiesByTimeString)

		bodyTotalDevelopers := getChartRESTContentAndReturnBody(t, "total-developers", RepositoryID)
		bodyTotalDevelopersString := string(bodyTotalDevelopers)
		assert.NotEmpty(t, bodyTotalDevelopersString)

		bodyTotalRepositories := getChartRESTContentAndReturnBody(t, "total-repositories", RepositoryID)
		bodyTotalRepositoriesString := string(bodyTotalRepositories)
		assert.NotEmpty(t, bodyTotalRepositoriesString)

		bodyDetailsChart := getChartDetailsUsingGraphQLAndReturnBody(t, RepositoryID)
		bodyDetailsChartString := string(bodyDetailsChart)
		assert.NotEmpty(t, bodyDetailsChartString)
	})
	//t.Run("Should run analysis and check if sended analysis using token of the company and repository name", func(t *testing.T) {
	//	if testing.Short() {
	//		t.Skip("skipping integration test")
	//	}
	//	repositoryName := uuid.New().String()
	//	//fileOutput := runHorusecCLIUsingZip(t, "go-gosec", CompanyToken, map[string]string{"-n": repositoryName})
	//	//analysis := extractVulnerabilitiesFromOutput(fileOutput)
	//	//assert.Equal(t, 2, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in golang is not expected")
	//
	//	req, _ := http.NewRequest(
	//		http.MethodGet,
	//		"http://localhost:8003/api/companies/"+CompanyID+"/repositories",
	//		nil,
	//	)
	//	req.Header.Add("Authorization", BearerToken)
	//	httpClient := http.Client{}
	//	apiTokenResp, err := httpClient.Do(req)
	//	assert.NoError(t, err, "company token and repository name")
	//	assert.Equal(t, http.StatusOK, apiTokenResp.StatusCode, "company token and repository name")
	//
	//	var body map[string]string
	//	_ = json.NewDecoder(apiTokenResp.Body).Decode(&body)
	//	assert.NoError(t, apiTokenResp.Body.Close())
	//	assert.Contains(t, body["content"], repositoryName)
	//})
	t.Run("Test of the integration", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test")
		}
		var wgPythonBandit sync.WaitGroup
		wgPythonBandit.Add(1)
		go runPythonBanditTest(t, RepositoryToken, &wgPythonBandit)
		var wgPythonSafety sync.WaitGroup
		wgPythonSafety.Add(1)
		go runPythonSafetyTest(t, RepositoryToken, &wgPythonSafety)
		var wgJavascriptNpm sync.WaitGroup
		wgJavascriptNpm.Add(1)
		go runJavascriptNpmTest(t, RepositoryToken, &wgJavascriptNpm)
		var wgJavascriptYarn sync.WaitGroup
		wgJavascriptYarn.Add(1)
		go runJavascriptYarnTest(t, RepositoryToken, &wgJavascriptYarn)
		var wgGolang sync.WaitGroup
		wgGolang.Add(1)
		go runGolangTest(t, RepositoryToken, &wgGolang)
		var wgRuby sync.WaitGroup
		wgRuby.Add(1)
		go runRubyTest(t, RepositoryToken, &wgRuby)
		var wgGit sync.WaitGroup
		wgGit.Add(1)
		go runGitTest(t, RepositoryToken, &wgGit)
		var wgNetCore sync.WaitGroup
		wgNetCore.Add(1)
		go runNetCoreTest(t, RepositoryToken, &wgNetCore)
		var wgJava sync.WaitGroup
		wgJava.Add(1)
		go runJavaTest(t, RepositoryToken, &wgJava)
		var wgKotlin sync.WaitGroup
		wgKotlin.Add(1)
		go runKotlinTest(t, RepositoryToken, &wgKotlin)
		var wgHCL sync.WaitGroup
		wgHCL.Add(1)
		go runHclTest(t, RepositoryToken, &wgHCL)
		wgPythonBandit.Wait()
		wgPythonSafety.Wait()
		wgJavascriptNpm.Wait()
		wgJavascriptYarn.Wait()
		wgGolang.Wait()
		wgRuby.Wait()
		wgGit.Wait()
		wgNetCore.Wait()
		wgJava.Wait()
		wgKotlin.Wait()
		wgHCL.Wait()
	})

	t.Run("test ignore files flag", func(t *testing.T) {
		fileOutput := runHorusecCLIUsingZip(t, "go-gosec", "**/*.go")
		analysis := extractVulnerabilitiesFromOutput(fileOutput)
		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in golang is not expected")
	})
}

// Receive repositoryID on params because you can generate other repository and run analysis inside this new repository
func getChartRESTContentAndReturnBody(t *testing.T, route string, repositoryID string) []byte {
	now := time.Now()
	initialDateStr := now.Format("2006-01-02") + "T00:00:00Z"
	finalDateStr := now.Format("2006-01-02") + "T23:59:59Z"
	URL := fmt.Sprintf("http://localhost:8005/api/dashboard/companies/%s/%s?initialDate=%s&finalDate=%s", CompanyID, route, initialDateStr, finalDateStr)
	if repositoryID != "" {
		URL = fmt.Sprintf("http://localhost:8005/api/dashboard/repositories/%s/%s?initialDate=%s&finalDate=%s", repositoryID, route, initialDateStr, finalDateStr)
	}
	req, err := request.NewHTTPRequest().Request(http.MethodGet, URL, nil, map[string]string{"Authorization": BearerToken, "Content-type": "application/json"})
	assert.NoError(t, err)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	assert.Equal(t, res.GetStatusCode(), http.StatusOK)
	body, err := res.GetBody()
	assert.NoError(t, err)
	return body
}

// Receive repositoryID on params because you can generate other repository and run analysis inside this new repository
func getChartDetailsUsingGraphQLAndReturnBody(t *testing.T, repositoryID string) []byte {
	now := time.Now()
	initialDateStr := now.Format("2006-01-02") + "T00:00:00Z"
	finalDateStr := now.Format("2006-01-02") + "T23:59:59Z"
	filterGraphQL := fmt.Sprintf("companyID: \"%s\"", CompanyID)
	if repositoryID != "" {
		filterGraphQL = fmt.Sprintf("repositoryID: \"%s\"", repositoryID)
	}
	filterTotalItemsAndAnalysis := fmt.Sprintf("(%s, initialDate: \"%s\", finalDate: \"%s\")", filterGraphQL, initialDateStr, finalDateStr)
	queryGraphQL := "{" +
		fmt.Sprintf("totalItems%s", filterTotalItemsAndAnalysis) +
		fmt.Sprintf("analysis%s", filterTotalItemsAndAnalysis) +
		`{
       repositoryName
       companyName
       vulnerability {
         line
         column
         confidence
         file
         code
         details
         securityTool
         language
         severity
         commitAuthor {
           author
           email
         }
       }
     }
    }`
	queryGraphQL = strings.ReplaceAll(queryGraphQL, "\n", "%20")
	queryGraphQL = strings.ReplaceAll(queryGraphQL, "\t", "%20")
	queryGraphQL = strings.ReplaceAll(queryGraphQL, " ", "%20")
	URL := fmt.Sprintf("http://localhost:8005/api/dashboard/companies/%s/details?query=%s&page=1&size=1000", CompanyID, queryGraphQL)
	if repositoryID != "" {
		URL = fmt.Sprintf("http://localhost:8005/api/dashboard/repositories/%s/details?query=%s&page=1&size=1000", repositoryID, queryGraphQL)
	}
	req, err := request.NewHTTPRequest().Request(http.MethodGet, URL, nil, map[string]string{"Authorization": BearerToken, "Content-Type": "application/json"})
	assert.NoError(t, err)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	assert.Equal(t, res.GetStatusCode(), http.StatusOK)
	body, err := res.GetBody()
	assert.NoError(t, err)
	return body
}

func createAccount(t *testing.T) {
	account := &accountentities.Account{
		Email:    "horusec@zup.com.br",
		Password: "Ch@ng3m3",
		Username: "Horusec",
	}
	accountBytes, _ := json.Marshal(account)
	createAccountResp, err := http.Post("http://localhost:8003/api/account/create-account", "text/json", bytes.NewReader(accountBytes))
	assert.NoError(t, err, "create account")
	assert.Equal(t, http.StatusCreated, createAccountResp.StatusCode, "create account")
	assert.NoError(t, createAccountResp.Body.Close())
}

func validateAccount(t *testing.T) {
	dbRead := databasesql.NewRepositoryRead()
	sqlUtil := test.NewSQLUtil(dbRead)
	vAccount := accountentities.Account{}
	sqlUtil.GetLast(&vAccount)
	validateAccountResp, err := http.Get("http://localhost:8003/api/account/validate/" + vAccount.AccountID.String())
	if err != nil {
		assert.Contains(t, err.Error(), "Get \"http://localhost:8043\": ")
	} else {
		assert.NoError(t, err, "validate account")
		assert.Equal(t, http.StatusOK, validateAccountResp.StatusCode, "validate account")
		assert.NoError(t, validateAccountResp.Body.Close())
	}
}

func login(t *testing.T) {
	credentials := &accountentities.LoginData{
		Email:    "horusec@zup.com.br",
		Password: "Ch@ng3m3",
	}
	credentialsBytes, _ := json.Marshal(credentials)
	loginResp, err := http.Post(
		"http://localhost:8003/api/account/login",
		"text/json",
		bytes.NewReader(credentialsBytes),
	)
	assert.NoError(t, err, "login")
	assert.Equal(t, http.StatusOK, loginResp.StatusCode, "login")

	var loginResponse map[string]map[string]string
	_ = json.NewDecoder(loginResp.Body).Decode(&loginResponse)
	assert.NoError(t, loginResp.Body.Close())
	BearerToken = "Bearer " + loginResponse["content"]["accessToken"]
	RefreshToken = loginResponse["content"]["refreshToken"]
}

func createCompany(t *testing.T) {
	company := &accountentities.Company{
		Name: "Horusec",
	}
	companyBytes, _ := json.Marshal(company)
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8003/api/companies", bytes.NewReader(companyBytes))
	req.Header.Add("Authorization", BearerToken)
	httpClient := http.Client{}
	createCompanyResp, err := httpClient.Do(req)
	assert.NoError(t, err, "create company")
	assert.Equal(t, http.StatusCreated, createCompanyResp.StatusCode, "create company")
	var createdCompany map[string]map[string]string
	_ = json.NewDecoder(createCompanyResp.Body).Decode(&createdCompany)
	assert.NoError(t, createCompanyResp.Body.Close())
	CompanyID = createdCompany["content"]["companyID"]
}

func createRepository(t *testing.T) {
	repository := &accountentities.Company{
		Name: "Horusec",
	}
	repositoryBytes, _ := json.Marshal(repository)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8003/api/companies/"+CompanyID+"/repositories",
		bytes.NewReader(repositoryBytes),
	)
	req.Header.Add("Authorization", BearerToken)
	httpClient := http.Client{}
	createRepositoryResp, err := httpClient.Do(req)
	assert.NoError(t, err, "create repository")
	assert.Equal(t, http.StatusCreated, createRepositoryResp.StatusCode, "create repository")
	var createdRepository map[string]map[string]string
	_ = json.NewDecoder(createRepositoryResp.Body).Decode(&createdRepository)
	assert.NoError(t, createRepositoryResp.Body.Close())
	RepositoryID = createdRepository["content"]["repositoryID"]

	refreshToken(t)
}

func refreshToken(t *testing.T) {
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8003/api/account/renew-token",
		bytes.NewReader([]byte(RefreshToken)),
	)
	req.Header.Add("Authorization", BearerToken)
	httpClient := http.Client{}
	refreshTokenResp, err := httpClient.Do(req)
	assert.NoError(t, err, "refresh token")
	assert.Equal(t, http.StatusOK, refreshTokenResp.StatusCode, "refresh token")
	var refreshResponse map[string]map[string]string
	_ = json.NewDecoder(refreshTokenResp.Body).Decode(&refreshResponse)
	assert.NoError(t, refreshTokenResp.Body.Close())
	BearerToken = "Bearer " + refreshResponse["content"]["accessToken"]
	RefreshToken = refreshResponse["content"]["refreshToken"]
}

func generateCompanyToken(t *testing.T) {
	token := &api.Token{
		Description: "Zup",
	}
	tokenBytes, _ := json.Marshal(token)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8000/api/companies/"+CompanyID+"/tokens",
		bytes.NewReader(tokenBytes),
	)
	req.Header.Add("Authorization", BearerToken)
	httpClient := http.Client{}
	apiTokenResp, err := httpClient.Do(req)
	assert.NoError(t, err, "API token")
	assert.Equal(t, http.StatusCreated, apiTokenResp.StatusCode, "API token")

	var apiToken map[string]string
	_ = json.NewDecoder(apiTokenResp.Body).Decode(&apiToken)
	assert.NoError(t, apiTokenResp.Body.Close())
	CompanyToken = apiToken["content"]
}

func generateRepositoryToken(t *testing.T) {
	token := &api.Token{
		Description: "Horusec",
	}
	tokenBytes, _ := json.Marshal(token)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8000/api/companies/"+CompanyID+"/repositories/"+RepositoryID+"/tokens",
		bytes.NewReader(tokenBytes),
	)
	req.Header.Add("Authorization", BearerToken)
	httpClient := http.Client{}
	apiTokenResp, err := httpClient.Do(req)
	assert.NoError(t, err, "API token")
	assert.Equal(t, http.StatusCreated, apiTokenResp.StatusCode, "API token")

	var apiToken map[string]string
	_ = json.NewDecoder(apiTokenResp.Body).Decode(&apiToken)
	assert.NoError(t, apiTokenResp.Body.Close())
	RepositoryToken = apiToken["content"]
}

func runHorusecCLIUsingZip(t *testing.T, zipName, apiToken string, othersFlags ...map[string]string) string {
	assert.NoError(t, os.MkdirAll("./tmp", 0750))
	fakeAnalysisID := uuid.New().String()
	fileOutput := fmt.Sprintf("./tmp/horusec-analysis-%s.json", fakeAnalysisID)
	destPath := "analysis/" + fakeAnalysisID
	destPath, err := filepath.Abs(destPath)
	assert.NoError(t, err)
	srcPath := "../development-kit/pkg/utils/test/zips/" + zipName + "/" + zipName + ".zip"
	assert.NoError(t, zip.NewZip().UnZip(srcPath, destPath))
	flags := map[string]string{
		"-p": strings.TrimSpace(destPath),
		"-a": strings.TrimSpace(apiToken),
		"-o": strings.TrimSpace("json"),
		"-O": strings.TrimSpace(fileOutput),
	}
	for _, otherFlag := range othersFlags {
		for flag, value := range otherFlag {
			flags[flag] = value
		}
	}
	cmdArguments := []string{
		"run",
		"../horusec-cli/cmd/horusec/main.go",
		"start",
	}
	for flag, value := range flags {
		cmdArguments = append(cmdArguments, fmt.Sprintf("%s=%s", flag, value))
	}
	logger.LogInfo(fmt.Sprintf("Running command: go %s", strings.Join(cmdArguments, " ")))
	cmd := exec.Command("go", cmdArguments...)
	_ = cmd.Run()

	return fileOutput
}

func runHorusecCLIUsingZipIgnoringFiles(t *testing.T, zipName, ignore string) string {
	assert.NoError(t, os.MkdirAll("./tmp", 0750))
	fakeAnalysisID := uuid.New().String()
	fileOutput := fmt.Sprintf("./tmp/horusec-analysis-%s.json", fakeAnalysisID)
	destPath := "analysis/" + fakeAnalysisID
	destPath, err := filepath.Abs(destPath)
	assert.NoError(t, err)
	srcPath := "../development-kit/pkg/utils/test/zips/" + zipName + "/" + zipName + ".zip"
	assert.NoError(t, zip.NewZip().UnZip(srcPath, destPath))
	cmdArguments := []string{
		"run",                                // command go
		"../horusec-cli/cmd/horusec/main.go", // file main of the project golang
		"start",                              // Command start of the Horusec
		fmt.Sprintf("-p=%s", strings.TrimSpace(destPath)),   // flag path to run analysis
		fmt.Sprintf("-o=%s", strings.TrimSpace("json")),     // output type json
		fmt.Sprintf("-O=%s", strings.TrimSpace(fileOutput)), // output location file
		fmt.Sprintf("-i=\"%s\"", strings.TrimSpace(ignore)), // ignoring files
	}
	logger.LogInfo(fmt.Sprintf("Running command: go %s", strings.Join(cmdArguments, " ")))
	cmd := exec.Command("go", cmdArguments...)
	_ = cmd.Run()

	return fileOutput
}

func runGitTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "gitleaks", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 6, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in leaks is not expected")
}

func runPythonBanditTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "python-bandit", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 6, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in python-bandit is not expected")
}

func runPythonSafetyTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "python-safety", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Greater(t, len(analysis.AnalysisVulnerabilities), 10, "Vulnerabilities in python-safety is not expected")
}

func runJavascriptNpmTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "javascript-npm", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 12, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in javascript-npm is not expected")

}

func runJavascriptYarnTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "javascript-yarn", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 19, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in javascript-yarn is not expected")
}

func runKotlinTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "kotlin-spotbug", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 6, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in kotlin is not expected")
}

func runNetCoreTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "netcore3-1", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 6, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in netcore is not expected")
}

func runRubyTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "ruby-brakeman", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 2, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in ruby is not expected")
}

func runJavaTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "java-spotbug", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 3, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in java is not expected")
}

func runGolangTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "go-gosec", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 2, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in golang is not expected")
}

func runHclTest(t *testing.T, apiToken string, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "hcl-tfsec", apiToken)
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.Equal(t, 5, len(analysis.AnalysisVulnerabilities), "Vulnerabilities in hcl is not expected")
}

func extractVulnerabilitiesFromOutput(fileOutput string) horusec.Analysis {
	fileContent, err := ioutil.ReadFile(fileOutput)
	logger.LogError("Error on read file to check vulnerabilities", err)
	horusecAnalysis := horusec.Analysis{}
	logger.LogError("Error on unmarshal fileContent to horusecAnalysis", json.Unmarshal(fileContent, &horusecAnalysis))
	return horusecAnalysis
}
