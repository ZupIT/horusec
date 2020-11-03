package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func CreateCompany(t *testing.T, bearerToken string, company *accountentities.Company) (CompanyID string) {
	fmt.Println("Running test for CreateCompany")
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8003/api/companies", bytes.NewReader(company.ToBytes()))
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
