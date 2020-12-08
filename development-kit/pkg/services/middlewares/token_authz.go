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

package middlewares

import (
	"context"
	"net/http"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	tokenRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/token"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/crypto"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
)

type CtxKey string

const RepositoryIDCtxKey CtxKey = "repositoryID"
const CompanyIDCtxKey CtxKey = "companyID"

type ITokenAuthz interface {
	IsAuthorized(next http.Handler) http.Handler
}

type TokenAuthz struct {
	repository tokenRepository.IRepository
}

func NewTokenAuthz(postgresRead relational.InterfaceRead) ITokenAuthz {
	return &TokenAuthz{
		repository: tokenRepository.NewTokenRepository(postgresRead, nil),
	}
}

func (t *TokenAuthz) IsAuthorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := t.getTokenHashFromAuthorizationHeader(r)
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		ctx, err := t.getContextAndValidateIsValidToken(tokenValue, r)
		if err != nil {
			t.verifyValidateTokenErrors(w, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (t *TokenAuthz) verifyValidateTokenErrors(w http.ResponseWriter, err error) {
	if err == errors.ErrorTokenExpired {
		httpUtil.StatusUnauthorized(w, errors.ErrorTokenExpired)
		return
	}

	httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
}

func (t *TokenAuthz) getTokenHashFromAuthorizationHeader(r *http.Request) (string, error) {
	tokenStr := r.Header.Get("X-Horusec-Authorization")
	if tokenStr == "" {
		return "", errors.ErrorUnauthorized
	}

	return crypto.HashToken(tokenStr), nil
}

func (t *TokenAuthz) getContextAndValidateIsValidToken(
	tokenValue string, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	token, err := t.repository.GetByValue(tokenValue)
	if err != nil {
		return nil, err
	}
	if token.RepositoryID != nil {
		ctx = t.bindRepositoryIDCtx(ctx, *token.RepositoryID)
	}
	ctx = t.bindCompanyIDCtx(ctx, token.CompanyID)
	return ctx, t.returnErrorIfTokenIsExpired(token)
}

func (t *TokenAuthz) bindRepositoryIDCtx(ctx context.Context, repositoryID uuid.UUID) context.Context {
	return context.WithValue(ctx, RepositoryIDCtxKey, repositoryID)
}

func (t *TokenAuthz) bindCompanyIDCtx(ctx context.Context, companyID uuid.UUID) context.Context {
	return context.WithValue(ctx, CompanyIDCtxKey, companyID)
}

func (t *TokenAuthz) returnErrorIfTokenIsExpired(token *api.Token) error {
	if token.CreatedAt.AddDate(0, 3, 0).Before(time.Now()) {
		return errors.ErrorTokenExpired
	}

	return nil
}
