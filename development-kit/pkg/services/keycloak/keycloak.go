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
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v7"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/google/uuid"
)

type IService interface {
	LoginOtp(username, password, totp string) (*gocloak.JWT, error)
	GetAccountIDByJWTToken(token string) (uuid.UUID, error)
	ValidateJWTToken(next http.Handler) http.Handler
	IsActiveToken(accessToken string) (bool, error)
	GetUserInfo(accessToken string) (*gocloak.UserInfo, error)
}

type Service struct {
	ctx          context.Context
	client       gocloak.GoCloak
	clientID     string
	clientSecret string
	realm        string
	otp          bool
	databaseRead relational.InterfaceRead
}

func NewKeycloakService(databaseRead relational.InterfaceRead) IService {
	return &Service{
		ctx:          context.Background(),
		client:       gocloak.NewClient(env.GetEnvOrDefault("HORUSEC_KEYCLOAK_BASE_PATH", "")),
		clientID:     env.GetEnvOrDefault("HORUSEC_KEYCLOAK_CLIENT_ID", ""),
		clientSecret: env.GetEnvOrDefault("HORUSEC_KEYCLOAK_CLIENT_SECRET", ""),
		realm:        env.GetEnvOrDefault("HORUSEC_KEYCLOAK_REALM", ""),
		otp:          env.GetEnvOrDefaultBool("HORUSEC_KEYCLOAK_OTP", false),
		databaseRead: databaseRead,
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
	entity := &account.Account{}
	response := s.databaseRead.Find(
		entity, s.databaseRead.SetFilter(map[string]interface{}{"email": *userInfo.Email}), entity.GetTable())
	if response.GetError() != nil {
		return uuid.Nil, response.GetError()
	}
	return response.GetData().(*account.Account).AccountID, nil
}

func (s *Service) ValidateJWTToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		accessToken := strings.Replace(authorization, "Bearer ", "", 1)

		if _, err := s.GetUserInfo(accessToken); err != nil {
			httpUtil.StatusUnauthorized(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) GetUserInfo(accessToken string) (*gocloak.UserInfo, error) {
	if isActive, err := s.IsActiveToken(accessToken); err != nil || !isActive {
		return nil, errorsEnum.ErrorUnauthorized
	}

	return s.client.GetUserInfo(s.ctx, accessToken, s.realm)
}

func (s *Service) removeBearer(accessToken string) string {
	return strings.ReplaceAll(accessToken, "Bearer ", "")
}
