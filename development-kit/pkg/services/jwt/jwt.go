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

package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/warnings"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/google/uuid"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

const DefaultSecretJWT = "horusec-secret"

func CreateToken(account *accountEntities.Account, permissions map[string]string) (string, time.Time, error) {
	expiresAt := time.Now().Add(time.Hour * time.Duration(1))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &accountEntities.ClaimsJWT{
		Email:            account.Email,
		Username:         account.Username,
		RepositoriesRole: permissions,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "horusec",
			Subject:   account.AccountID.String(),
		},
	})

	tokenSigned, err := token.SignedString(getHorusecJWTKey())
	return tokenSigned, expiresAt, err
}

func DecodeToken(tokenString string) (*accountEntities.ClaimsJWT, error) {
	token, err := parseStringToToken(strings.ReplaceAll(tokenString, "Bearer ", ""))
	if err != nil {
		return nil, err
	}

	return token.Claims.(*accountEntities.ClaimsJWT), nil
}

func parseStringToToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &accountEntities.ClaimsJWT{}, func(token *jwt.Token) (interface{}, error) {
		return getHorusecJWTKey(), nil
	})
}

func AuthMiddleware(next http.Handler) http.Handler {
	middleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return getHorusecJWTKey(), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	return middleware.Handler(next)
}

func GetAccountIDByJWTToken(token string) (uuid.UUID, error) {
	claims, err := DecodeToken(verifyIfContainsBearer(token))
	if err != nil {
		return uuid.Nil, err
	}

	return uuid.Parse(claims.Subject)
}

func GetRepositoryPermissionsByJWTTOken(token string) (map[string]string, error) {
	claims, err := DecodeToken(verifyIfContainsBearer(token))
	if err != nil {
		return nil, err
	}

	return claims.RepositoriesRole, nil
}

func getHorusecJWTKey() []byte {
	secretKey := env.GetEnvOrDefault("HORUSEC_JWT_SECRET_KEY", DefaultSecretJWT)
	if secretKey == DefaultSecretJWT {
		logger.LogInfo(warnings.WarningDefaultJWTSecretKey)
	}

	return []byte(secretKey)
}

func verifyIfContainsBearer(token string) string {
	if strings.Contains(token, "Bearer") {
		return token
	}

	return fmt.Sprintf("Bearer %s", token)
}

func CreateRefreshToken() string {
	refreshToken := fmt.Sprintf("%s%s", uuid.New(), uuid.New())
	return strings.ReplaceAll(refreshToken, "-", "")
}
