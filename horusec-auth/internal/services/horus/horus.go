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

package horus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"net/http"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
)

type Service struct {
	httpUtil     httpClient.Interface
	postgresRead relational.InterfaceRead
}

func NewHorusAuthService(postgresRead relational.InterfaceRead) services.IAuthService {
	return &Service{
		httpUtil:     httpClient.NewHTTPClient(10),
		postgresRead: postgresRead,
	}
}

func (s *Service) Authenticate(
	credentials *authEntities.Credentials) (interface{}, error) {
	requestResponse, err := s.sendLoginRequest(credentials)
	if err != nil {
		return nil, err
	}

	loginResponse, err := s.parseToLoginResponse(requestResponse)
	if err != nil {
		return nil, err
	}

	return loginResponse, nil
}

func (s *Service) sendLoginRequest(credentials *authEntities.Credentials) (httpResponse.Interface, error) {
	req, err := http.NewRequest(http.MethodPost, s.getHorusecAPIURL(), bytes.NewReader(s.newLoginRequestData(credentials)))
	if err != nil {
		return nil, err
	}

	return s.httpUtil.DoRequest(req, nil)
}

func (s *Service) newLoginRequestData(credentials *authEntities.Credentials) []byte {
	loginData := &accountEntities.LoginData{
		Email:    credentials.Username,
		Password: credentials.Password,
	}

	return loginData.ToBytes()
}

func (s *Service) getHorusecAPIURL() string {
	return fmt.Sprintf("%s/api/account/login",
		env.GetEnvOrDefault("HORUSEC_ACCOUNT_URL", "http://0.0.0.0:8003"))
}

func (s *Service) parseToLoginResponse(
	requestResponse httpResponse.Interface) (loginResponse map[string]interface{}, err error) {
	body, err := requestResponse.GetBody()
	if err != nil {
		return nil, err
	}

	return loginResponse, json.Unmarshal(body, &loginResponse)
}

func (s *Service) IsAuthorized(authorizationData *authEntities.AuthorizationData) (bool, error) {
	return false, nil
}
