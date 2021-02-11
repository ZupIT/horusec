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
	"context"
	"errors"
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"strings"

	"github.com/Nerzal/gocloak/v7"
	"github.com/google/uuid"
)

type IService interface {
	LoginOtp(username, password, otp string) (*gocloak.JWT, error)
	IsActiveToken(token string) (bool, error)
	GetAccountIDByJWTToken(token string) (uuid.UUID, error)
	GetUserInfo(accessToken string) (*gocloak.UserInfo, error)
}

type Service struct {
	ctx    context.Context
	config IKeycloakConfig
}

func NewKeycloakService(databaseRead SQL.InterfaceRead) IService {
	return &Service{
		ctx:    context.Background(),
		config: NewKeycloakConfig(databaseRead),
	}
}

func (s *Service) LoginOtp(username, password, otp string) (*gocloak.JWT, error) {
	if otp == "" && s.config.getOtp() {
		return nil, errors.New("invalid otp")
	}

	return s.config.getClient().LoginOtp(s.ctx, s.config.getClientID(), s.config.getClientSecret(), s.config.getRealm(), username, password, otp)
}

func (s *Service) IsActiveToken(token string) (bool, error) {
	result, err := s.config.getClient().
		RetrospectToken(s.ctx, s.removeBearer(token), s.config.getClientID(), s.config.getClientSecret(), s.config.getRealm())
	if err != nil {
		return false, err
	}

	return *result.Active, nil
}

func (s *Service) GetAccountIDByJWTToken(token string) (uuid.UUID, error) {
	userInfo, err := s.GetUserInfo(s.removeBearer(token))
	if err != nil {
		return uuid.Nil, err
	}

	return uuid.Parse(*userInfo.Sub)
}

func (s *Service) GetUserInfo(accessToken string) (*gocloak.UserInfo, error) {
	if isActive, err := s.IsActiveToken(accessToken); err != nil || !isActive {
		return nil, errorsEnum.ErrorUnauthorized
	}

	return s.config.getClient().GetUserInfo(s.ctx, s.removeBearer(accessToken), s.config.getRealm())
}

func (s *Service) removeBearer(accessToken string) string {
	return strings.ReplaceAll(accessToken, "Bearer ", "")
}
