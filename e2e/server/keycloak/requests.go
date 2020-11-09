// Requests save in this file are exclusive of keycloak e2e
package keycloak

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
	fmt.Println("Running test for LoginInKeycloak")
	payload := strings.NewReader(fmt.Sprintf("client_id=admin-cli&username=%s&password=%s&grant_type=password", username, password))
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/token", payload)
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

func LogoutUserInKeycloak(t *testing.T, bearerToken, username string)  {
	allUsers := ListAllUsersInKeycloak(t, bearerToken)
	userID := ""
	for _, user := range allUsers {
		if user["username"] == username {
			userID = user["id"].(string)
		}
	}
	assert.NotEmpty(t, userID)
	fmt.Println("Running test for LogoutUsersInKeycloak: " + username)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/auth/admin/realms/master/users/"+userID+"/logout", nil)
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("Content-Type", "application/json")
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "LogoutUsersInKeycloak, create user error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "LogoutUsersInKeycloak create user error send request")
	assert.NoError(t, resp.Body.Close())
}

func CreateUserInKeyCloak(t *testing.T, userRepresentation *entities.UserRepresentation, credentials *entities.UserRepresentationCredentials, bearerToken string) {
	fmt.Println("Running test for CreateUserInKeyCloak")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/auth/admin/realms/master/users", bytes.NewReader(userRepresentation.ToBytes()))
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
	req, _ = http.NewRequest(http.MethodPut, "http://127.0.0.1:8080/auth/admin/realms/master/users/"+idToSetCredential+"/reset-password", bytes.NewReader(credentials.ToBytes()))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient = http.Client{}
	resp, err = httpClient.Do(req)
	assert.NoError(t, err, "CreateUserInKeyCloak, update credentials user error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "CreateUserInKeyCloak update credentials user error send request")
	assert.NoError(t, resp.Body.Close())

	role := GetRoleAdminInKeycloak(t, bearerToken)
	var allRoles []map[string]interface{}
	allRoles = append(allRoles, role)
	allRolesBytes, _ := json.Marshal(allRoles)
	req, _ = http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/auth/admin/realms/master/users/"+idToSetCredential+"/role-mappings/realm", bytes.NewReader(allRolesBytes))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient = http.Client{}
	resp, err = httpClient.Do(req)
	assert.NoError(t, err, "CreateUserInKeyCloak, update role mapping user error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "CreateUserInKeyCloak, update role mapping user error send request")
	assert.NoError(t, resp.Body.Close())
}

func ListAllUsersInKeycloak(t *testing.T, bearerToken string) []map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/admin/realms/master/users", nil)
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
	assert.Equal(t, len(allUsers)-1, len(idsToRemove))
	for _, id := range idsToRemove {
		req, _ := http.NewRequest(http.MethodDelete, "http://127.0.0.1:8080/auth/admin/realms/master/users/"+id, nil)
		req.Header.Add("Authorization", bearerToken)
		httpClient := http.Client{}
		resp, err := httpClient.Do(req)
		assert.NoError(t, err, "DeleteAllUsersInKeyCloak: remove user of id: "+id+" error mount request")
		assert.Equal(t, http.StatusNoContent, resp.StatusCode, "DeleteAllUsersInKeyCloak: remove user of id: "+id+" error send request")
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
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/admin/realms/master/clients/"+clientID+"/client-secret", nil)
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

func UpdateRolesToAcceptOAuth(t *testing.T, bearerToken string) {
	fmt.Println("Running test for UpdateRolesToAcceptOAuth")
	allClients := ListAllClientsInKeycloak(t, bearerToken)
	var client map[string]interface{}
	for _, actualClient := range allClients {
		if actualClient["clientId"] == "account" {
			client = actualClient
		}
	}
	assert.NotEmpty(t, client)
	client["authorizationServicesEnabled"] = true
	client["directAccessGrantsEnabled"] = true
	client["enabled"] = true
	client["implicitFlowEnabled"] = true
	client["serviceAccountsEnabled"] = true
	client["standardFlowEnabled"] = true
	client["surrogateAuthRequired"] = true
	client["attributes"].(map[string]interface{})["access.token.lifespan"] = 5940
	client["attributes"].(map[string]interface{})["client.offline.session.idle.timeout"] = 5940
	client["attributes"].(map[string]interface{})["client.offline.session.max.lifespan"] = 5940
	client["attributes"].(map[string]interface{})["client.session.idle.timeout"] = 5940
	client["attributes"].(map[string]interface{})["client.session.max.lifespan"] = 5940
	clientID := client["id"].(string)
	clientBytes, _ := json.Marshal(client)
	req, _ := http.NewRequest(http.MethodPut, "http://127.0.0.1:8080/auth/admin/realms/master/clients/"+clientID, bytes.NewReader(clientBytes))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "UpdateRolesToAcceptOAuth, update account client content error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "UpdateRolesToAcceptOAuth, update account client error send request")
	assert.NoError(t, resp.Body.Close())

	// Update Role to admin accept all content
	role := GetRoleAdminInKeycloak(t, bearerToken)
	roleID := role["id"].(string)
	allRoles := GetAllRolesFromClientID(t, bearerToken, clientID)
	allRolesBytes, _ := json.Marshal(allRoles)
	req, _ = http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/auth/admin/realms/master/roles-by-id/"+roleID+"/composites", bytes.NewReader(allRolesBytes))
	req.Header.Add("Authorization", bearerToken)
	req.Header.Add("content-type", "application/json")
	httpClient = http.Client{}
	resp, err = httpClient.Do(req)
	assert.NoError(t, err, "UpdateRolesToAcceptOAuth, update account client content error mount request")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "UpdateRolesToAcceptOAuth, update account client error send request")
	assert.NoError(t, resp.Body.Close())
}

func ListAllClientsInKeycloak(t *testing.T, bearerToken string) []map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/admin/realms/master/clients", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "ListAllClientsInKeycloak mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAllClientsInKeycloak error send request")
	var response []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	return response
}

func GetRoleAdminInKeycloak(t *testing.T, bearerToken string) map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/admin/realms/master/roles", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "ListAllRolesInKeycloak mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAllRolesInKeycloak error send request")
	var response []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	var role map[string]interface{}
	for _, currentRole := range response {
		if currentRole["name"] == "admin" {
			role = currentRole
		}
	}
	assert.NotEmpty(t, role)
	return role
}

func GetAllRolesFromClientID(t *testing.T, bearerToken, clientID string) []map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/admin/realms/master/clients/"+clientID+"/roles", nil)
	req.Header.Add("Authorization", bearerToken)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err, "ListAllRolesInKeycloak mount request")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAllRolesInKeycloak error send request")
	var response []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, resp.Body.Close())
	assert.NotEmpty(t, response)
	return response
}

func CreateUserFromKeycloakInHorusec(t *testing.T, token *account.KeycloakToken) {
	fmt.Println("Running test for CreateUserFromKeycloakInHorusec")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8006/api/account/create-account-from-keycloak", bytes.NewReader(token.ToBytes()))
	httpClient := http.Client{}
	createCompanyResp, err := httpClient.Do(req)
	assert.NoError(t, err, "CreateUserFromKeycloakInHorusec error send request")
	assert.Equal(t, http.StatusOK, createCompanyResp.StatusCode, "CreateUserFromKeycloakInHorusec error check response")
	var bodyResponse map[string]interface{}
	_ = json.NewDecoder(createCompanyResp.Body).Decode(&bodyResponse)
	assert.NoError(t, createCompanyResp.Body.Close())
	assert.NotEmpty(t, bodyResponse)
}

func CheckIfTokenIsValid(t *testing.T, token string) {
	//fmt.Println("Running test for CheckIfTokenIsValid")
	//req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8006/api/account/create-account-from-keycloak", bytes.NewReader(token.ToBytes()))
	//httpClient := http.Client{}
	//createCompanyResp, err := httpClient.Do(req)
	//assert.NoError(t, err, "CreateUserFromKeycloakInHorusec error send request")
	//assert.Equal(t, http.StatusOK, createCompanyResp.StatusCode, "CreateUserFromKeycloakInHorusec error check response")
	//var bodyResponse map[string]interface{}
	//_ = json.NewDecoder(createCompanyResp.Body).Decode(&bodyResponse)
	//assert.NoError(t, createCompanyResp.Body.Close())
	//assert.NotEmpty(t, bodyResponse)
}
