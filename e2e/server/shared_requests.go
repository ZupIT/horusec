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

// Requests save in this file are shared into all server e2e.
package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	authDto "github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/request"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/stretchr/testify/assert"
)

func Login(t *testing.T, credentials *authDto.Credentials) map[string]string {
	fmt.Println("Running test for Login")
	loginResp, err := http.Post(
		"http://127.0.0.1:8006/api/auth/authenticate",
		"text/json",
		bytes.NewReader(credentials.ToBytes()),
	)
	assert.NoError(t, err, "login, error mount request")
	assert.Equal(t, http.StatusOK, loginResp.StatusCode, "login error send request")

	var loginResponse map[string]map[string]string
	_ = json.NewDecoder(loginResp.Body).Decode(&loginResponse)
	assert.NoError(t, loginResp.Body.Close())
	return loginResponse["content"]
}

func CreateCompany(t *testing.T, bearerToken string, company *accountEntities.Company) (CompanyID string) {
	fmt.Println("Running test for CreateCompany")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8003/api/companies", bytes.NewReader(company.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	createCompanyResp, err := httpClient.Do(req)
	assert.NoError(t, err, "create company error send request")
	assert.Equal(t, http.StatusCreated, createCompanyResp.StatusCode, "create company error check response")
	var createdCompany map[string]map[string]string
	_ = json.NewDecoder(createCompanyResp.Body).Decode(&createdCompany)
	assert.NoError(t, createCompanyResp.Body.Close())
	assert.NotEmpty(t, createdCompany["content"]["companyID"])
	return createdCompany["content"]["companyID"]
}

func UpdateCompany(t *testing.T, bearerToken string, companyID string, company *accountEntities.Company) {
	fmt.Println("Running test for UpdateCompany")
	req, _ := http.NewRequest(http.MethodPatch, "http://127.0.0.1:8003/api/companies/"+companyID, bytes.NewReader(company.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "update company error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "update company error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
}

func ReadAllCompanies(t *testing.T, bearerToken string, isCheckBodyEmpty bool) string {
	fmt.Println("Running test for ReadAllCompanies")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8003/api/companies", nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all companies error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all companies error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	if isCheckBodyEmpty {
		assert.NotEmpty(t, body["content"])
	}
	content, _ := json.Marshal(body["content"])
	return string(content)
}

func DeleteCompany(t *testing.T, bearerToken, companyID string) {
	fmt.Println("Running test for DeleteCompany")
	req, _ := http.NewRequest(http.MethodDelete, "http://127.0.0.1:8003/api/companies/"+companyID, nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete company error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete company error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}

func InviteUserToCompany(t *testing.T, bearerToken, companyID string, user *dto.InviteUser) {
	fmt.Println("Running test for InviteUserToCompany")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8003/api/companies/"+companyID+"/roles",
		bytes.NewReader(user.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "invite user error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "invite user error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}
func ReadAllUserInCompany(t *testing.T, bearerToken, companyID string) string {
	fmt.Println("Running test for InviteUserToCompany")
	req, _ := http.NewRequest(
		http.MethodGet,
		"http://127.0.0.1:8003/api/companies/"+companyID+"/roles",
		nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all user in company error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all user in company error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}
func UpdateUserInCompany(t *testing.T, bearerToken, companyID, accountID string, account *roles.AccountCompany) string {
	fmt.Println("Running test for UpdateUserInCompany")
	req, _ := http.NewRequest(
		http.MethodPatch,
		"http://127.0.0.1:8003/api/companies/"+companyID+"/roles/"+accountID,
		bytes.NewReader(account.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "update user in company error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "update user in company error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}
func RemoveUserInCompany(t *testing.T, bearerToken, companyID, accountID string) {
	fmt.Println("Running test for RemoveUserInCompany")
	req, _ := http.NewRequest(
		http.MethodDelete,
		"http://127.0.0.1:8003/api/companies/"+companyID+"/roles/"+accountID,
		nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete user in company error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete user in company error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}
func GetChartContentWithoutTreatment(t *testing.T, route, bearerToken, companyID, repositoryID string) httpResponse.Interface {
	fmt.Println("Running test for GetChartContentWithoutTreatment in route: " + route)
	now := time.Now()
	initialDateStr := now.Format("2006-01-02") + "T00:00:00Z"
	finalDateStr := now.Format("2006-01-02") + "T23:59:59Z"
	URL := fmt.Sprintf("http://127.0.0.1:8005/api/dashboard/companies/%s/%s?initialDate=%s&finalDate=%s", companyID, route, initialDateStr, finalDateStr)
	if repositoryID != "" {
		URL = fmt.Sprintf("http://127.0.0.1:8005/api/dashboard/companies/%s/repositories/%s/%s?initialDate=%s&finalDate=%s", companyID, repositoryID, route, initialDateStr, finalDateStr)
	}
	req, err := request.NewHTTPRequest().Request(http.MethodGet, URL, nil, map[string]string{"X-Horusec-Authorization": bearerToken, "Content-type": "application/json"})
	assert.NoError(t, err)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	return res
}

func CreateRepository(t *testing.T, bearerToken, companyID string, repository *accountEntities.Repository) string {
	repositoryBytes, _ := json.Marshal(repository)
	fmt.Println("Running test for CreateRepository")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8003/api/companies/"+companyID+"/repositories", bytes.NewReader(repositoryBytes))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "create repository error send request")
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "create repository error check response")
	var body map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"]["repositoryID"])
	return body["content"]["repositoryID"]
}

func UpdateRepository(t *testing.T, bearerToken, companyID, repositoryID string, repository *accountEntities.Repository) {
	fmt.Println("Running test for UpdateRepository")
	repositoryBytes, _ := json.Marshal(repository)
	fmt.Println("Running test for UpdateRepository")
	req, _ := http.NewRequest(http.MethodPatch, "http://127.0.0.1:8003/api/companies/"+companyID+"/repositories/"+repositoryID, bytes.NewReader(repositoryBytes))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "update repository error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "update repository error check response")
	var body map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}

func ReadAllRepositories(t *testing.T, bearerToken, companyID string, isCheckBodyEmpty bool) string {
	fmt.Println("Running test for ReadAllRepositories")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8003/api/companies/"+companyID+"/repositories", nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all repositories error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all repositories error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	if isCheckBodyEmpty {
		assert.NotEmpty(t, body["content"])
	}
	content, _ := json.Marshal(body["content"])
	return string(content)
}

func DeleteRepository(t *testing.T, bearerToken, companyID, repositoryID string) {
	fmt.Println("Running test for DeleteRepository")
	req, _ := http.NewRequest(http.MethodDelete, "http://127.0.0.1:8003/api/companies/"+companyID+"/repositories/"+repositoryID, nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete repository error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete repository error check response")
	var body map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}

func GenerateRepositoryToken(t *testing.T, bearerToken, companyID, repositoryID string, token api.Token) string {
	fmt.Println("Running test for GenerateRepositoryToken")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/tokens",
		bytes.NewReader(token.ToBytes()),
	)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	apiTokenResp, err := httpClient.Do(req)
	assert.NoError(t, err, "generate repository token error send response")
	assert.Equal(t, http.StatusCreated, apiTokenResp.StatusCode, "generate repository token error check response")

	var apiToken map[string]string
	_ = json.NewDecoder(apiTokenResp.Body).Decode(&apiToken)
	assert.NoError(t, apiTokenResp.Body.Close())
	assert.NotEmpty(t, apiToken["content"])
	return apiToken["content"]
}

func ReadAllRepositoryToken(t *testing.T, bearerToken, companyID, repositoryID string) string {
	fmt.Println("Running test for ReadAllRepositoryToken")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/tokens", nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all repositories tokens error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all repositories tokens error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}

func RevokeRepositoryToken(t *testing.T, bearerToken, companyID, repositoryID, tokenID string) {
	fmt.Println("Running test for RevokeRepositoryToken")
	req, _ := http.NewRequest(http.MethodDelete, "http://127.0.0.1:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/tokens/"+tokenID, nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete repository token error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete repository token error check response")
	var body map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}
