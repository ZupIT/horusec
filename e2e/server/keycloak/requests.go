package ldap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/e2e/server/keycloak/entities"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
)


func LoginInKeycloak(t *testing.T, username, password string) map[string]interface{} {
	fmt.Println("Running test for LoginInKeycloak in Keycloak")
	payload := strings.NewReader(fmt.Sprintf("client_id=admin-cli&username=%s&password=%s&grant_type=password", username, password))
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8080/auth/realms/master/protocol/openid-connect/token", payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cache-control", "no-cache")

	res, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, res.StatusCode, "LoginInKeycloak error send request")
	var response map[string]interface{}
	_ = json.NewDecoder(res.Body).Decode(&response)
	assert.NoError(t, res.Body.Close())
	assert.NotEmpty(t, response)
	return response
}

func GetOAuthToken(t *testing.T, bearerToken string) string {
	fmt.Println("Running test for GetOAuthToken in Keycloak")
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8080/auth/admin/realms/master/clients-initial-access", bytes.NewReader([]byte("{\"count\": 5,\"expiration\": 5}")))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "GetOAuthToken, create user error mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetOAuthToken create user error send request")
	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	return response["token"].(string)
}

func CreateUserInKeyCloak(t *testing.T, userRepresentation *entities.UserRepresentation, credentials *entities.UserRepresentationCredentials, bearerToken string) {
	fmt.Println("Running test for CreateUserInKeyCloak")
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8080/auth/admin/realms/master/users", bytes.NewReader(userRepresentation.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "CreateUserInKeyCloak, create user error mount request")
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "CreateUserInKeyCloak create user error send request")
	assert.NoError(t, resp.Body.Close())
	allUsers := ListAllUsersInKeycloak(t, bearerToken)
	idToSetCredential := ""
	for _, user := range allUsers {
		if user["username"] == userRepresentation.Username {
			idToSetCredential = user["id"].(string)
		}
	}
	assert.NotEmpty(t, idToSetCredential)
	req, _ = http.NewRequest(http.MethodPut, "http://localhost:8080/auth/admin/realms/master/users/"+idToSetCredential+"/reset-password", bytes.NewReader(credentials.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient = http.Client{}
	resp, err = httpClient.Do(req)
	assert.NoError(t, err, "CreateUserInKeyCloak, update credentials user error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "CreateUserInKeyCloak update credentials user error send request")
	assert.NoError(t, resp.Body.Close())
}

func ListAllUsersInKeycloak(t *testing.T, bearerToken string) []map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/auth/admin/realms/master/users", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "DeleteAllUsersInKeyCloak: get all users error mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteAllUsersInKeyCloak: get all users error send request")
	var response []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	return response
}

func DeleteAllUsersInKeyCloak(t *testing.T, bearerToken string) {
	fmt.Println("Running test for DeleteAllUsersInKeyCloak")
	allUsers := ListAllUsersInKeycloak(t, bearerToken)
	idsToRemove := []string{}
	for _, user := range allUsers {
		if user["username"] != "keycloak" {
			idsToRemove = append(idsToRemove, user["id"].(string))
		}
	}
	assert.Equal(t, len(allUsers) - 1, len(idsToRemove))
	for _, id := range idsToRemove {
		req, _ := http.NewRequest(http.MethodDelete, "http://localhost:8080/auth/admin/realms/master/users/"+id, nil)
		req.Header.Add("Authorization", bearerToken)
		httpClient := http.Client{}
		resp, err := httpClient.Do(req)
		assert.NoError(t, err, "DeleteAllUsersInKeyCloak: remove user of id: " +id+ " error mount request")
		assert.Equal(t, http.StatusNoContent, resp.StatusCode, "DeleteAllUsersInKeyCloak: remove user of id: " +id+ " error send request")
	}
}

func GetClientSecretInAccountClient(t *testing.T, bearerToken string) string {
	fmt.Println("Running test for GetClientSecretInAccountClient")
	allClients := ListAllClientsInKeycloak(t, bearerToken)
	clientID := ""
	for _, client := range allClients {
		if client["clientId"] == "account" {
			clientID = client["id"].(string)
		}
	}
	assert.NotEmpty(t, clientID)
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/auth/admin/realms/master/clients/"+clientID+"/client-secret", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "GetClientSecretInAccountClient mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetClientSecretInAccountClient error send request")
	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	return response["value"].(string)
}

func ListAllClientsInKeycloak(t *testing.T, bearerToken string) []map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/auth/admin/realms/master/clients", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "ListAllClientsInKeuycloak mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAllClientsInKeuycloak error send request")
	var response []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	return response
}

func CreateUserFromKeycloakInHorusec(t *testing.T, token *account.KeycloakToken) {
	fmt.Println("Running test for CreateUserFromKeycloakInHorusec")
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8007/api/account/create-account-from-keycloak", bytes.NewReader(token.ToBytes()))
	httpClient := http.Client{}
	createCompanyResp, err := httpClient.Do(req)
	assert.NoError(t, err, "CreateUserFromKeycloakInHorusec error send request")
	assert.Equal(t, http.StatusOK, createCompanyResp.StatusCode, "CreateUserFromKeycloakInHorusec error check response")
	var bodyResponse map[string]map[string]string
	_ = json.NewDecoder(createCompanyResp.Body).Decode(&bodyResponse)
	assert.NoError(t, createCompanyResp.Body.Close())
	assert.NotEmpty(t, bodyResponse)
}
