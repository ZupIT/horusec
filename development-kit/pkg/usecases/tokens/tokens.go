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

package tokenusecases

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
)

type ITokenUseCases interface {
	ValidateTokenRepository(r *http.Request) (token *api.Token, err error)
	ValidateTokenCompany(r *http.Request) (token *api.Token, err error)
}

type TokenUseCases struct {
}

func NewTokenUseCases() ITokenUseCases {
	return &TokenUseCases{}
}

// nolint
func (u *TokenUseCases) ValidateTokenRepository(r *http.Request) (token *api.Token, err error) {
	err = json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	token, err = u.validateCompanyIDAndRepositoryID(r, token)
	if err != nil {
		return nil, err
	}
	return token, token.Validate(true)
}

func (u *TokenUseCases) validateCompanyIDAndRepositoryID(r *http.Request, token *api.Token) (*api.Token, error) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil || repositoryID == uuid.Nil {
		return nil, errors.New("invalid repositoryID")
	}
	token.RepositoryID = &repositoryID
	if token.CompanyID, err = uuid.Parse(chi.URLParam(r, "companyID")); err != nil || token.CompanyID == uuid.Nil {
		return nil, errors.New("invalid companyID")
	}
	return token, nil
}

func (u *TokenUseCases) ValidateTokenCompany(r *http.Request) (token *api.Token, err error) {
	err = json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	token.CompanyID, err = uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil || token.CompanyID == uuid.Nil {
		return nil, errors.New("invalid companyID")
	}
	token.RepositoryID = nil
	return token, token.Validate(false)
}
