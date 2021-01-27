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

// Requests save in this file are exclusive of horusec e2e
package horusec

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	accountDto "github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authDto "github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/request"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/stretchr/testify/assert"
)

func CreateAccount(t *testing.T, account *authEntities.Account) {
	fmt.Println("Running test for CreateAccount")
	createAccountResp, err := http.Post("http://127.0.0.1:8006/auth/account/create-account", "text/json", bytes.NewReader(account.ToBytes()))
	assert.NoError(t, err, "create account error mount request")
	assert.Equal(t, http.StatusCreated, createAccountResp.StatusCode, "create account error send request")

	var createAccountResponse map[string]interface{}
	_ = json.NewDecoder(createAccountResp.Body).Decode(&createAccountResponse)
	assert.NoError(t, createAccountResp.Body.Close())
	assert.NotEmpty(t, createAccountResponse["content"])
}

func Login(t *testing.T, credentials *authDto.Credentials) map[string]string {
	fmt.Println("Running test for Login")
	loginResp, err := http.Post(
		"http://127.0.0.1:8006/auth/auth/authenticate",
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

func Logout(t *testing.T, bearerToken string) {
	fmt.Println("Running test for Logout")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8006/auth/account/logout", nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "logout error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "logout error send request")

	var logoutResponse map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&logoutResponse)
	assert.NoError(t, resp.Body.Close())
}

func ReadAllRepositoryTokenWithoutTreatment(t *testing.T, bearerToken, companyID, repositoryID string) httpResponse.Interface {
	fmt.Println("Running test for ReadAllRepositoryToken")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/tokens", nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	return res
}
func GenerateCompanyToken(t *testing.T, bearerToken, companyID string, token api.Token) string {
	fmt.Println("Running test for GenerateCompanyToken")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8000/api/companies/"+companyID+"/tokens",
		bytes.NewReader(token.ToBytes()),
	)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	apiTokenResp, err := httpClient.Do(req)
	assert.NoError(t, err, "generate company token error send response")
	assert.Equal(t, http.StatusCreated, apiTokenResp.StatusCode, "generate company token error check response")

	var apiToken map[string]string
	_ = json.NewDecoder(apiTokenResp.Body).Decode(&apiToken)
	assert.NoError(t, apiTokenResp.Body.Close())
	assert.NotEmpty(t, apiToken["content"])
	return apiToken["content"]
}

func ReadAllCompanyToken(t *testing.T, bearerToken, companyID string) string {
	fmt.Println("Running test for ReadAllCompanyToken")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8000/api/companies/"+companyID+"/tokens", nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all companies tokens error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all companies tokens error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}

func RevokeCompanyToken(t *testing.T, bearerToken, companyID, tokenID string) {
	fmt.Println("Running test for RevokeCompanyToken")
	req, _ := http.NewRequest(http.MethodDelete, "http://127.0.0.1:8000/api/companies/"+companyID+"/tokens/"+tokenID, nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete company token error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete company token error check response")
	var body map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}

func InsertAnalysisWithRepositoryToken(t *testing.T, analysisData *api.AnalysisData, repositoryToken string) string {
	fmt.Println("Running test for InsertAnalysisWithRepositoryToken")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8000/api/analysis",
		bytes.NewReader(analysisData.ToBytes()),
	)
	req.Header.Add("X-Horusec-Authorization", repositoryToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "InsertAnalysisWithRepositoryToken error send response")
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "InsertAnalysisWithRepositoryToken error check response")

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	return body["content"]
}

func InsertAnalysisWithCompanyToken(t *testing.T, analysisData *api.AnalysisData, companyToken string) string {
	fmt.Println("Running test for InsertAnalysisWithRepositoryToken")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8000/api/analysis",
		bytes.NewReader(analysisData.ToBytes()),
	)
	req.Header.Add("X-Horusec-Authorization", companyToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "InsertAnalysisWithRepositoryToken error send response")
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "InsertAnalysisWithRepositoryToken error check response")

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	return body["content"]
}

func GetAnalysisByID(t *testing.T, analysisID, authorization string) string {
	fmt.Println("Running test for GetAnalysisByID")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8000/api/analysis/"+analysisID, nil)
	req.Header.Add("X-Horusec-Authorization", authorization)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read analysis by ID error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read analysis by ID error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}

func GetChartContent(t *testing.T, route, bearerToken, companyID, repositoryID string) []byte {
	fmt.Println("Running test for GetChartContent in route: " + route)
	fmt.Println("Running test for GetChartRESTContentAndReturnBody")
	now := time.Now()
	initialDateStr := now.Format("2006-01-02") + "T00:00:00Z"
	finalDateStr := now.Format("2006-01-02") + "T23:59:59Z"
	URL := fmt.Sprintf("http://127.0.0.1:8005/analytic/dashboard/companies/%s/%s?initialDate=%s&finalDate=%s", companyID, route, initialDateStr, finalDateStr)
	if repositoryID != "" {
		URL = fmt.Sprintf("http://127.0.0.1:8005/analytic/dashboard/companies/%s/repositories/%s/%s?initialDate=%s&finalDate=%s", companyID, repositoryID, route, initialDateStr, finalDateStr)
	}
	req, err := request.NewHTTPRequest().Request(http.MethodGet, URL, nil, map[string]string{"X-Horusec-Authorization": bearerToken, "Content-type": "application/json"})
	assert.NoError(t, err)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	assert.Equal(t, res.GetStatusCode(), http.StatusOK)
	body, err := res.GetBody()
	defer res.CloseBody()
	assert.NoError(t, err)
	return body
}

func GetChartDetailsUsingGraphQLAndReturnBody(t *testing.T, bearerToken, companyID, repositoryID string) []byte {
	fmt.Println("Running test for GetChartContent using graphql")
	now := time.Now()
	initialDateStr := now.Format("2006-01-02") + "T00:00:00Z"
	finalDateStr := now.Format("2006-01-02") + "T23:59:59Z"
	filterGraphQL := fmt.Sprintf("companyID: \"%s\"", companyID)
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
        commitAuthor 
		commitEmail
		commitHash
		commitMessage
		commitDate
      }
    }
   }`
	queryGraphQL = strings.ReplaceAll(queryGraphQL, "\n", "%20")
	queryGraphQL = strings.ReplaceAll(queryGraphQL, "\t", "%20")
	queryGraphQL = strings.ReplaceAll(queryGraphQL, " ", "%20")
	URL := fmt.Sprintf("http://127.0.0.1:8005/analytic/dashboard/companies/%s/details?query=%s&page=1&size=1000", companyID, queryGraphQL)
	if repositoryID != "" {
		URL = fmt.Sprintf("http://127.0.0.1:8005/analytic/dashboard/companies/%s/repositories/%s/details?query=%s&page=1&size=1000", companyID, repositoryID, queryGraphQL)
	}
	req, err := request.NewHTTPRequest().Request(http.MethodGet, URL, nil, map[string]string{"X-Horusec-Authorization": bearerToken, "Content-Type": "application/json"})
	assert.NoError(t, err)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	assert.Equal(t, res.GetStatusCode(), http.StatusOK)
	body, err := res.GetBody()
	assert.NoError(t, err)
	defer res.CloseBody()
	return body
}

func GetAllVulnerabilitiesToManager(t *testing.T, bearerToken, companyID, repositoryID string, queryString string) string {
	fmt.Println("Running test for GetAllVulnerabilitiesToManager")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/management?"+queryString, nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read vulnerabilities error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read vulnerabilities error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}

func UpdateVulnerabilitiesType(t *testing.T, bearerToken, companyID, repositoryID, vulnerabilityID string, vulnType dto.UpdateVulnType) string {
	fmt.Println("Running test for UpdateVulnerabilitiesType")
	req, _ := http.NewRequest(
		http.MethodPut,
		"http://127.0.0.1:8000/api/companies/"+companyID+"/repositories/"+repositoryID+"/management/"+vulnerabilityID+"/type",
		bytes.NewReader(vulnType.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "update vulnerabilities error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "update vulnerabilities error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}
func InviteUserToRepository(t *testing.T, bearerToken, companyID, repositoryID string, user *accountDto.InviteUser) {
	fmt.Println("Running test for InviteUserToRepository")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8003/account/companies/"+companyID+"/repositories/"+repositoryID+"/roles",
		bytes.NewReader(user.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "invite user in repository error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "invite user in repository error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}
func ReadAllUserInRepository(t *testing.T, bearerToken, companyID, repositoryID string) string {
	fmt.Println("Running test for InviteUserToCompany")
	req, _ := http.NewRequest(
		http.MethodGet,
		"http://127.0.0.1:8003/account/companies/"+companyID+"/repositories/"+repositoryID+"/roles",
		nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "read all user in repository error send request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read all user in repository error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, body["content"])
	content, _ := json.Marshal(body["content"])
	return string(content)
}
func UpdateUserInRepository(t *testing.T, bearerToken, companyID, repositoryID, accountID string, account *roles.AccountCompany) {
	fmt.Println("Running test for UpdateUserInRepository")
	req, _ := http.NewRequest(
		http.MethodPatch,
		"http://127.0.0.1:8003/account/companies/"+companyID+"/repositories/"+repositoryID+"/roles/"+accountID,
		bytes.NewReader(account.ToBytes()))
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "update user in repository error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "update user in repository error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}
func RemoveUserInRepository(t *testing.T, bearerToken, companyID, repositoryID, accountID string) {
	fmt.Println("Running test for RemoveUserInRepository")
	req, _ := http.NewRequest(
		http.MethodDelete,
		"http://127.0.0.1:8003/account/companies/"+companyID+"/repositories/"+repositoryID+"/roles/"+accountID,
		nil)
	req.Header.Add("X-Horusec-Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete user in repository error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete user in repository error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}
