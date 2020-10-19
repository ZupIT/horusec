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

package keycloak

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"strings"
)

type Service struct {
	keycloak.IService
}

func NewKeycloakAuthService(databaseRead relational.InterfaceRead) services.IAuthService {
	return &Service{
		keycloak.NewKeycloakService(databaseRead),
	}
}

func (s *Service) Authenticate(credentials *authEntities.Credentials) (interface{}, error) {
	return s.LoginOtp(credentials.Username, credentials.Password, credentials.Otp)
}

func (s *Service) IsAuthorized(authorization *authEntities.AuthorizationData) (bool, error) {
	accessToken := strings.Replace(authorization.Token, "Bearer ", "", 1)

	if _, err := s.GetUserInfo(accessToken); err != nil {
		return false, errors.New("Authorization blocked because: " + err.Error())
	}
	return true, nil
}
