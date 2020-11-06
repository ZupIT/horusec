// Requests save in this file are exclusive of messages e2e
package messages

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
)

func CreateAccount(t *testing.T, account *accountentities.Account) {
	fmt.Println("Running test for CreateAccount")
	createAccountResp, err := http.Post("http://127.0.0.1:8003/api/account/create-account", "text/json", bytes.NewReader(account.ToBytes()))
	assert.NoError(t, err, "create account error mount request")
	assert.Equal(t, http.StatusCreated, createAccountResp.StatusCode, "create account error send request")

	var createAccountResponse map[string]interface{}
	_ = json.NewDecoder(createAccountResp.Body).Decode(&createAccountResponse)
	assert.NoError(t, createAccountResp.Body.Close())
	assert.NotEmpty(t, createAccountResponse["content"])
}

func Login(t *testing.T, credentials *authEntities.Credentials) httpResponse.Interface {
	fmt.Println("Running test for Login")
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8006/api/auth/authenticate",
		bytes.NewReader(credentials.ToBytes()))
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	assert.NoError(t, err)
	return res
}
func LoginAndReturnAccessToken(t *testing.T, credentials *authEntities.Credentials) string {
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
	return loginResponse["content"]["accessToken"]
}
func ValidateAccount(t *testing.T, accountID string) {
	fmt.Println("Running test for ValidateAccount")
	req, _ := http.NewRequest(
		http.MethodGet,
		"http://127.0.0.1:8003/api/account/validate/"+accountID,
		nil)
	res, err := client.NewHTTPClient(15).DoRequest(req, &tls.Config{})
	if err != nil {
		if !strings.Contains(err.Error(), "Get \"http://127.0.0.1:8043\": ") {
			assert.NoError(t, err)
		}
	} else {
		assert.Equal(t, http.StatusSeeOther, res.GetStatusCode())
	}
}

func Logout(t *testing.T, bearerToken string) {
	fmt.Println("Running test for Logout")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8003/api/account/logout", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "logout error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "logout error send request")

	var logoutResponse map[string]map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&logoutResponse)
	assert.NoError(t, resp.Body.Close())
}

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
