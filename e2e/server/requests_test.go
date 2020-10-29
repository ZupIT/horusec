package server

import (
	"bytes"
	"encoding/json"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func CreateAccount(t *testing.T, account *accountentities.Account) {
	createAccountResp, err := http.Post("http://localhost:8003/api/account/create-account", "text/json", bytes.NewReader(account.ToBytes()))
	assert.NoError(t, err, "create account")
	assert.Equal(t, http.StatusCreated, createAccountResp.StatusCode, "create account")

	var createAccountResponse map[string]interface{}
	_ = json.NewDecoder(createAccountResp.Body).Decode(&createAccountResponse)
	assert.NoError(t, createAccountResp.Body.Close())
	assert.NotEmpty(t, createAccountResponse["content"])
}

func ValidateAccount(t *testing.T, accountID string) {
	validateAccountResp, err := http.Get("http://localhost:8003/api/account/validate/" + accountID)
	if err != nil {
		assert.Contains(t, err.Error(), "Get \"http://localhost:8043\": ")
	} else {
		assert.NoError(t, err, "validate account")
		assert.Equal(t, http.StatusOK, validateAccountResp.StatusCode, "validate account")
		assert.NoError(t, validateAccountResp.Body.Close())
	}
}

func Login(t *testing.T, credentials *accountentities.LoginData) (bearerToken string, refreshToken string) {
	loginResp, err := http.Post(
		"http://localhost:8003/api/account/login",
		"text/json",
		bytes.NewReader(credentials.ToBytes()),
	)
	assert.NoError(t, err, "login")
	assert.Equal(t, http.StatusOK, loginResp.StatusCode, "login")

	var loginResponse map[string]map[string]string
	_ = json.NewDecoder(loginResp.Body).Decode(&loginResponse)
	assert.NoError(t, loginResp.Body.Close())
	bearerToken = "Bearer " + loginResponse["content"]["accessToken"]
	refreshToken = loginResponse["content"]["refreshToken"]
	return bearerToken, refreshToken
}

func CreateCompany(t *testing.T, bearerToken string, company *accountentities.Company) (CompanyID string) {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8003/api/companies", bytes.NewReader(company.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	createCompanyResp, err := httpClient.Do(req)
	assert.NoError(t, err, "create company")
	assert.Equal(t, http.StatusCreated, createCompanyResp.StatusCode, "create company")
	var createdCompany map[string]map[string]string
	_ = json.NewDecoder(createCompanyResp.Body).Decode(&createdCompany)
	assert.NoError(t, createCompanyResp.Body.Close())
	assert.NotEmpty(t, createdCompany["content"]["companyID"])
	return createdCompany["content"]["companyID"]
}

func UpdateCompany(t *testing.T, bearerToken string, companyID string, company *accountentities.Company) {
	req, _ := http.NewRequest(http.MethodPatch, "http://localhost:8003/api/companies/"+companyID, bytes.NewReader(company.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "update company")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "update company")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
}

func ReadAllCompanies(t *testing.T, bearerToken string) interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8003/api/companies", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all companies")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all companies")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	return body["content"]
}

func DeleteCompany(t *testing.T, bearerToken, companyID string) {
	req, _ := http.NewRequest(http.MethodDelete, "http://localhost:8003/api/companies/"+companyID, nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete company")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete company")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}

func CreateRepository(t *testing.T, bearerToken, companyID string, repository *accountentities.Repository) string {
	repositoryBytes, _ := json.Marshal(repository)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8003/api/companies/"+companyID+"/repositories",
		bytes.NewReader(repositoryBytes),
	)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	createRepositoryResp, err := httpClient.Do(req)
	assert.NoError(t, err, "create repository")
	assert.Equal(t, http.StatusCreated, createRepositoryResp.StatusCode, "create repository")
	var createdRepository map[string]map[string]string
	_ = json.NewDecoder(createRepositoryResp.Body).Decode(&createdRepository)
	assert.NoError(t, createRepositoryResp.Body.Close())
	assert.NotEmpty(t, createdRepository["content"]["repositoryID"])
	return createdRepository["content"]["repositoryID"]
}

func GenerateRepositoryToken(t *testing.T, bearerToken, companyID, repositoryID string, token api.Token) string {
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/tokens",
		bytes.NewReader(token.ToBytes()),
	)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	apiTokenResp, err := httpClient.Do(req)
	assert.NoError(t, err, "API token")
	assert.Equal(t, http.StatusCreated, apiTokenResp.StatusCode, "API token")

	var apiToken map[string]string
	_ = json.NewDecoder(apiTokenResp.Body).Decode(&apiToken)
	assert.NoError(t, apiTokenResp.Body.Close())
	assert.NotEmpty(t, apiToken["content"])
	return apiToken["content"]
}
