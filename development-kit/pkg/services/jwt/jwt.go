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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"net/http"
	"strings"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	jwtMiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

const (
	DefaultSecretJWT           = "horusec-secret"
	WarningDefaultJWTSecretKey = "{JWT-INSECURE} horusec JWT secret key is the default one, for security " +
		"reasons please replace it for a secure value, secret key environment variable name --> {HORUSEC_JWT_SECRET_KEY}"
)

type JWT struct {
	databaseRead SQL.InterfaceRead
}

type IJWT interface {
	CreateToken(account *authEntities.Account, permissions []string) (string, time.Time, error)
	DecodeToken(tokenString string) (*dto.ClaimsJWT, error)
	AuthMiddleware(next http.Handler) http.Handler
	GetAccountIDByJWTToken(token string) (uuid.UUID, error)
	CreateRefreshToken() string
}

func NewJWT(databaseRead SQL.InterfaceRead) IJWT {
	return &JWT{
		databaseRead: databaseRead,
	}
}

func (j *JWT) CreateToken(account *authEntities.Account, permissions []string) (string, time.Time, error) {
	expiresAt := time.Now().Add(time.Hour * time.Duration(1))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &dto.ClaimsJWT{
		Email:       account.Email,
		Username:    account.Username,
		Permissions: permissions,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "horusec",
			Subject:   account.AccountID.String(),
		},
	})

	tokenSigned, err := token.SignedString(j.getHorusecJWTKey())
	return tokenSigned, expiresAt, err
}

func (j *JWT) DecodeToken(tokenString string) (*dto.ClaimsJWT, error) {
	token, err := j.parseStringToToken(strings.ReplaceAll(tokenString, "Bearer ", ""))
	if err != nil {
		return nil, err
	}

	return token.Claims.(*dto.ClaimsJWT), nil
}

func (j *JWT) parseStringToToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &dto.ClaimsJWT{}, func(token *jwt.Token) (interface{}, error) {
		return j.getHorusecJWTKey(), nil
	})
}

func (j *JWT) AuthMiddleware(next http.Handler) http.Handler {
	middleware := jwtMiddleware.New(jwtMiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return j.getHorusecJWTKey(), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	return middleware.Handler(next)
}

func (j *JWT) GetAccountIDByJWTToken(token string) (uuid.UUID, error) {
	claims, err := j.DecodeToken(j.verifyIfContainsBearer(token))
	if err != nil {
		return uuid.Nil, err
	}

	return uuid.Parse(claims.Subject)
}

func (j *JWT) getHorusecJWTKey() []byte {
	secretKey := env.GetEnvFromAdminOrDefault(j.databaseRead, "HORUSEC_JWT_SECRET_KEY", DefaultSecretJWT).ToString()
	if secretKey == DefaultSecretJWT {
		logger.LogInfo(WarningDefaultJWTSecretKey)
	}

	return []byte(secretKey)
}

func (j *JWT) verifyIfContainsBearer(token string) string {
	if strings.Contains(token, "Bearer") {
		return token
	}

	return fmt.Sprintf("Bearer %s", token)
}

func (j *JWT) CreateRefreshToken() string {
	refreshToken := fmt.Sprintf("%s%s", uuid.New(), uuid.New())
	return strings.ReplaceAll(refreshToken, "-", "")
}
