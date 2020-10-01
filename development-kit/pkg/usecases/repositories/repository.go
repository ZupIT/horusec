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

package repositories

import (
	"encoding/json"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"io"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
)

type IRepository interface {
	NewRepositoryFromReadCloser(body io.ReadCloser) (repository *accountEntities.Repository, err error)
	NewAccountRepositoryFromReadCloser(body io.ReadCloser) (accountRepository *roles.AccountRepository, err error)
	NewInviteUserFromReadCloser(body io.ReadCloser) (inviteUser *accountEntities.InviteUser, err error)
	CheckCreateRepositoryErrors(err error) error
}

type Repository struct {
}

func NewRepositoryUseCases() IRepository {
	return &Repository{}
}

func (r *Repository) NewRepositoryFromReadCloser(body io.ReadCloser) (
	repository *accountEntities.Repository, err error) {
	err = json.NewDecoder(body).Decode(&repository)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return repository, repository.Validate()
}

func (r *Repository) NewAccountRepositoryFromReadCloser(body io.ReadCloser) (
	accountRepository *roles.AccountRepository, err error) {
	err = json.NewDecoder(body).Decode(&accountRepository)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return accountRepository, accountRepository.Validate()
}

func (r *Repository) NewInviteUserFromReadCloser(body io.ReadCloser) (
	inviteUser *accountEntities.InviteUser, err error) {
	err = json.NewDecoder(body).Decode(&inviteUser)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return inviteUser, inviteUser.Validate()
}

func (r *Repository) CheckCreateRepositoryErrors(err error) error {
	if err.Error() == "pq: duplicate key value violates unique constraint \"uk_repositories_username\"" {
		return errorsEnum.ErrorRepositoryNameAlreadyInUse
	}

	return err
}
