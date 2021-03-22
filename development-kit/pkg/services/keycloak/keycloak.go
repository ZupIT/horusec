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
	"fmt"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"strings"

	"github.com/Nerzal/gocloak/v7"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/google/uuid"
)

type IService interface {
	LoginOtp(username, password, otp string) (*gocloak.JWT, error)
	IsActiveToken(token string) (bool, error)
	GetAccountIDByJWTToken(token string) (uuid.UUID, error)
	GetUserInfo(accessToken string) (*gocloak.UserInfo, error)
}

type Service struct {
	ctx          context.Context
	client       gocloak.GoCloak
	clientID     string
	clientSecret string
	realm        string
	otp          bool
}

func NewKeycloakService() IService {
	return &Service{
		ctx:          context.Background(),
		client:       gocloak.NewClient(env.GetEnvOrDefault("HORUSEC_KEYCLOAK_BASE_PATH", "")),
		clientID:     env.GetEnvOrDefault("HORUSEC_KEYCLOAK_CLIENT_ID", ""),
		clientSecret: env.GetEnvOrDefault("HORUSEC_KEYCLOAK_CLIENT_SECRET", ""),
		realm:        env.GetEnvOrDefault("HORUSEC_KEYCLOAK_REALM", ""),
		otp:          env.GetEnvOrDefaultBool("HORUSEC_KEYCLOAK_OTP", false),
	}
}

func (s *Service) LoginOtp(username, password, otp string) (*gocloak.JWT, error) {
	if otp == "" && s.otp {
		return nil, errors.New("invalid otp")
	}

	return s.client.LoginOtp(s.ctx, s.clientID, s.clientSecret, s.realm, username, password, otp)
}

func (s *Service) IsActiveToken(token string) (bool, error) {
	result, err := s.client.RetrospectToken(s.ctx, s.removeBearer(token), s.clientID, s.clientSecret, s.realm)
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
	isActive, err := s.IsActiveToken(accessToken)
	if err != nil || !isActive {
		logger.LogError(
			fmt.Sprintf("{Keycloak} Error on check if token is active: IsActive=%v, err=%v", isActive, err),
			errorsEnum.ErrorUnauthorized)
		return nil, errorsEnum.ErrorUnauthorized
	}

	userInfo, err := s.client.GetUserInfo(s.ctx, s.removeBearer(accessToken), s.realm)
	if err != nil {
		logger.LogError("{Keycloak} Error on get user info", err)
		return nil, errorsEnum.ErrorInvalidKeycloakToken
	}
	return userInfo, nil
}

func (s *Service) removeBearer(accessToken string) string {
	return strings.ReplaceAll(accessToken, "Bearer ", "")
}
