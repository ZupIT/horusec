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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	relationalRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	accountEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	emailEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/queues"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	repositoriesUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/repositories"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/google/uuid"
)

type IController interface {
	Create(accountID uuid.UUID, data *accountEntities.Repository) (*accountEntities.Repository, error)
	Update(repositoryID uuid.UUID, repository *accountEntities.Repository) (*accountEntities.Repository, error)
	Get(repositoryID, accountID uuid.UUID) (*accountEntities.RepositoryResponse, error)
	List(accountID uuid.UUID, companyID uuid.UUID) (repositories *[]accountEntities.RepositoryResponse, err error)
	CreateAccountRepository(accountRepository *roles.AccountRepository) error
	UpdateAccountRepository(companyID uuid.UUID, accountRepository *roles.AccountRepository) error
	InviteUser(inviteUser *accountEntities.InviteUser) error
	Delete(repositoryID uuid.UUID) error
	GetAllAccountsInRepository(repositoryID uuid.UUID) (*[]roles.AccountRole, error)
	RemoveUser(removeUser *accountEntities.RemoveUser) error
}

type Controller struct {
	databaseWrite            SQL.InterfaceWrite
	databaseRead             SQL.InterfaceRead
	repository               relationalRepository.IRepository
	accountRepositoryRepo    repoAccountRepository.IAccountRepository
	accountRepository        repositoryAccount.IAccount
	accountCompanyRepository repositoryAccountCompany.IAccountCompany
	broker                   brokerLib.IBroker
	appConfig                app.IAppConfig
	repositoriesUseCases     repositoriesUseCases.IRepository
}

func NewController(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead,
	broker brokerLib.IBroker, appConfig app.IAppConfig) IController {
	return &Controller{
		databaseWrite:            databaseWrite,
		databaseRead:             databaseRead,
		repository:               relationalRepository.NewRepository(databaseRead, databaseWrite),
		accountRepositoryRepo:    repoAccountRepository.NewAccountRepositoryRepository(databaseRead, databaseWrite),
		accountRepository:        repositoryAccount.NewAccountRepository(databaseRead, databaseWrite),
		accountCompanyRepository: repositoryAccountCompany.NewAccountCompanyRepository(databaseRead, databaseWrite),
		broker:                   broker,
		appConfig:                appConfig,
		repositoriesUseCases:     repositoriesUseCases.NewRepositoryUseCases(),
	}
}

func (c *Controller) Create(accountID uuid.UUID, repositoryEntity *accountEntities.Repository) (
	*accountEntities.Repository, error) {
	transaction := c.databaseWrite.StartTransaction()
	if err := c.repository.Create(repositoryEntity, transaction); err != nil {
		return nil, err
	}

	if err := c.accountRepositoryRepo.Create(repositoryEntity.ToAccountRepository(accountEnum.Admin, accountID),
		transaction); err != nil {
		return nil, transaction.RollbackTransaction().GetError()
	}

	transaction.CommitTransaction()
	return repositoryEntity, nil
}

func (c *Controller) Update(repositoryID uuid.UUID, repositoryEntity *accountEntities.Repository) (
	*accountEntities.Repository, error) {
	return c.repository.Update(repositoryID, repositoryEntity)
}

func (c *Controller) Get(repositoryID, accountID uuid.UUID) (*accountEntities.RepositoryResponse, error) {
	accountRepository, err := c.accountRepositoryRepo.GetAccountRepository(accountID, repositoryID)
	if err != nil {
		return nil, err
	}

	response, err := c.repository.Get(repositoryID)
	if err != nil {
		return nil, err
	}

	return response.ToRepositoryResponse(accountRepository.Role), nil
}

func (c *Controller) List(accountID,
	companyID uuid.UUID) (repositories *[]accountEntities.RepositoryResponse, err error) {
	return c.repository.List(accountID, companyID)
}

func (c *Controller) UpdateAccountRepository(companyID uuid.UUID, accountRepository *roles.AccountRepository) error {
	if c.isUserNotInCompany(companyID, accountRepository.AccountID) {
		return errors.ErrorUserNotMemberOfCompany
	}

	return c.accountRepositoryRepo.UpdateAccountRepository(accountRepository)
}

func (c *Controller) CreateAccountRepository(accountRepository *roles.AccountRepository) error {
	if c.isUserNotInCompany(accountRepository.CompanyID, accountRepository.AccountID) {
		return errors.ErrorUserNotMemberOfCompany
	}

	return c.accountRepositoryRepo.Create(accountRepository, nil)
}

func (c *Controller) InviteUser(inviteUser *accountEntities.InviteUser) error {
	account, err := c.accountRepository.GetByEmail(inviteUser.Email)
	if err != nil {
		return err
	}

	response, err := c.repository.Get(inviteUser.RepositoryID)
	if err != nil {
		return err
	}

	if err := c.CreateAccountRepository(inviteUser.ToAccountRepository(account.AccountID)); err != nil {
		return err
	}
	return c.sendInviteUserEmail(account.Email, account.Username, response.Name)
}

func (c *Controller) sendInviteUserEmail(email, username, repositoryName string) error {
	if c.appConfig.IsEmailServiceDisabled() {
		return nil
	}

	emailMessage := messages.EmailMessage{
		To:           email,
		TemplateName: emailEnum.RepositoryInvite,
		Subject:      "[Horusec] Repository invite",
		Data:         map[string]interface{}{"repositoryName": repositoryName, "username": username},
	}

	return c.broker.Publish(queues.HorusecEmail.ToString(), "", "", emailMessage.ToBytes())
}

func (c *Controller) isUserNotInCompany(companyID, accountID uuid.UUID) bool {
	account, err := c.accountCompanyRepository.GetAccountCompany(accountID, companyID)
	if err != nil || account == nil {
		return true
	}

	return false
}

func (c *Controller) Delete(repositoryID uuid.UUID) error {
	return c.repository.Delete(repositoryID)
}

func (c *Controller) GetAllAccountsInRepository(repositoryID uuid.UUID) (*[]roles.AccountRole, error) {
	return c.repository.GetAllAccountsInRepository(repositoryID)
}

func (c *Controller) RemoveUser(removeUser *accountEntities.RemoveUser) error {
	account, err := c.accountRepository.GetByAccountID(removeUser.AccountID)
	if err != nil {
		return err
	}

	return c.accountRepositoryRepo.DeleteAccountRepository(account.AccountID, removeUser.RepositoryID)
}
