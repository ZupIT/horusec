// Requests save in this file are shared into all server e2e.
package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/request"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func CreateCompany(t *testing.T, bearerToken string, company *accountentities.Company) (CompanyID string) {
	fmt.Println("Running test for CreateCompany")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8003/api/companies", bytes.NewReader(company.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
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

func UpdateCompany(t *testing.T, bearerToken string, companyID string, company *accountentities.Company) {
	fmt.Println("Running test for UpdateCompany")
	req, _ := http.NewRequest(http.MethodPatch, "http://127.0.0.1:8003/api/companies/"+companyID, bytes.NewReader(company.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
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
	req.Header.Add("Authorization", bearerToken)
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
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "delete company error send request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "delete company error check response")
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, resp.Body.Close())
}

func InviteUserToCompany(t *testing.T, bearerToken, companyID string, user *accountentities.InviteUser) {
	fmt.Println("Running test for InviteUserToCompany")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8003/api/companies/"+companyID+"/roles",
		bytes.NewReader(user.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
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
	req.Header.Add("Authorization", bearerToken)
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
	req.Header.Add("Authorization", bearerToken)
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
	req.Header.Add("Authorization", bearerToken)
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
	req, err := request.NewHTTPRequest().Request(http.MethodGet, URL, nil, map[string]string{"Authorization": bearerToken, "Content-type": "application/json"})
	assert.NoError(t, err)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	return res
}
