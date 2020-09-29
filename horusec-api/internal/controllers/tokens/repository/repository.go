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

package repository

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	tokenRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/token"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	tokenUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/tokens"
	"github.com/google/uuid"
)

type IController interface {
	CreateTokenRepository(*api.Token) (string, error)
	DeleteTokenRepository(tokenID uuid.UUID) error
	GetAllTokenRepository(repositoryID uuid.UUID) (*[]api.Token, error)
}

type Controller struct {
	tokenRepository tokenRepository.IRepository
	tokenUseCases   tokenUseCases.ITokenUseCases
}

func NewController(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) IController {
	return &Controller{
		tokenRepository: tokenRepository.NewTokenRepository(postgresRead, postgresWrite),
		tokenUseCases:   tokenUseCases.NewTokenUseCases(),
	}
}

func (c *Controller) CreateTokenRepository(token *api.Token) (key string, err error) {
	token.SetKey(uuid.New())

	_, err = c.tokenRepository.Create(token)
	if err != nil {
		return "", err
	}

	return token.GetKey().String(), nil
}

func (c *Controller) DeleteTokenRepository(tokenID uuid.UUID) error {
	return c.tokenRepository.Delete(tokenID)
}

func (c *Controller) GetAllTokenRepository(repositoryID uuid.UUID) (*[]api.Token, error) {
	return c.tokenRepository.GetAllOfRepository(repositoryID)
}
