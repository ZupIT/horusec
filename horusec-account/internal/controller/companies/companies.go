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

package companies

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repoAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	repositoryCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	emailEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/queues"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	companyUseCases "github.com/ZupIT/horusec/horusec-account/internal/usecases/company"
	"github.com/google/uuid"
)

type IController interface {
	Create(accountID uuid.UUID, data *accountEntities.Company, permissions []string) (*accountEntities.Company, error)
	Update(companyID uuid.UUID, data *accountEntities.Company, permissions []string) (*accountEntities.Company, error)
	Get(companyID, accountID uuid.UUID) (*accountEntities.CompanyResponse, error)
	List(accountID uuid.UUID, permissions []string) (*[]accountEntities.CompanyResponse, error)
	UpdateAccountCompany(role *roles.AccountCompany) error
	InviteUser(inviteUser *dto.InviteUser) error
	Delete(companyID uuid.UUID) error
	GetAllAccountsInCompany(companyID uuid.UUID) (*[]roles.AccountRole, error)
	RemoveUser(removeUser *dto.RemoveUser) error
	GetAccountIDByEmail(email string) (uuid.UUID, error)
}

type Controller struct {
	databaseWrite         SQL.InterfaceWrite
	databaseRead          SQL.InterfaceRead
	repoCompany           repositoryCompany.ICompanyRepository
	repoAccount           repositoryAccount.IAccount
	repoAccountCompany    repoAccountCompany.IAccountCompany
	repoAccountRepository repoAccountRepository.IAccountRepository
	broker                brokerLib.IBroker
	appConfig             app.IAppConfig
	accountRepository     repositoryAccount.IAccount
	companyUseCases       companyUseCases.ICompany
}

func NewController(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead,
	broker brokerLib.IBroker, appConfig app.IAppConfig) IController {
	return &Controller{
		databaseWrite:         databaseWrite,
		databaseRead:          databaseRead,
		repoCompany:           repositoryCompany.NewCompanyRepository(databaseRead, databaseWrite),
		repoAccountCompany:    repoAccountCompany.NewAccountCompanyRepository(databaseRead, databaseWrite),
		repoAccount:           repositoryAccount.NewAccountRepository(databaseRead, databaseWrite),
		repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(databaseRead, databaseWrite),
		broker:                broker,
		appConfig:             appConfig,
		companyUseCases:       companyUseCases.NewCompanyUseCases(),
		accountRepository:     repositoryAccount.NewAccountRepository(databaseRead, databaseWrite),
	}
}

func (c *Controller) Create(accountID uuid.UUID, data *accountEntities.Company,
	permissions []string) (*accountEntities.Company, error) {
	if c.appConfig.GetAuthType() == authEnums.Ldap && c.companyUseCases.IsInvalidLdapGroup(data.AuthzAdmin, permissions) {
		return nil, errorsEnums.ErrorInvalidLdapGroup
	}

	return c.createCompanyWithTransaction(accountID, data)
}

func (c *Controller) createCompanyWithTransaction(accountID uuid.UUID,
	data *accountEntities.Company) (*accountEntities.Company, error) {
	tx := c.databaseWrite.StartTransaction()
	newCompany, err := c.repoCompany.Create(data, tx)
	if err != nil {
		return nil, err
	}

	if err = c.repoAccountCompany.CreateAccountCompany(
		newCompany.CompanyID, accountID, accountEnums.Admin, tx); err != nil {
		_ = tx.RollbackTransaction()
		return nil, err
	}

	_ = tx.CommitTransaction()
	return newCompany, nil
}

func (c *Controller) Update(companyID uuid.UUID,
	data *accountEntities.Company, permissions []string) (*accountEntities.Company, error) {
	if c.appConfig.GetAuthType() == authEnums.Ldap && c.companyUseCases.IsInvalidLdapGroup(data.AuthzAdmin, permissions) {
		return nil, errorsEnums.ErrorInvalidLdapGroup
	}

	return c.repoCompany.Update(companyID, data)
}

func (c *Controller) Get(companyID, accountID uuid.UUID) (*accountEntities.CompanyResponse, error) {
	accountCompany, err := c.repoAccountCompany.GetAccountCompany(accountID, companyID)
	if err != nil {
		return nil, err
	}

	company, err := c.repoCompany.GetByID(companyID)
	if err != nil {
		return nil, err
	}

	return company.ToCompanyResponse(accountCompany.Role), nil
}

func (c *Controller) List(accountID uuid.UUID, permissions []string) (*[]accountEntities.CompanyResponse, error) {
	if c.appConfig.GetAuthType() == authEnums.Ldap {
		return c.repoCompany.GetAllOfAccountLdap(permissions)
	}

	return c.repoCompany.GetAllOfAccount(accountID)
}

func (c *Controller) Delete(companyID uuid.UUID) error {
	return c.repoCompany.Delete(companyID)
}

func (c *Controller) UpdateAccountCompany(role *roles.AccountCompany) error {
	return c.repoAccountCompany.UpdateAccountCompany(role)
}

func (c *Controller) InviteUser(inviteUser *dto.InviteUser) error {
	account, err := c.repoAccount.GetByEmail(inviteUser.Email)
	if err != nil {
		return err
	}

	company, err := c.repoCompany.GetByID(inviteUser.CompanyID)
	if err != nil {
		return err
	}

	if err := c.repoAccountCompany.CreateAccountCompany(inviteUser.CompanyID, account.AccountID,
		inviteUser.Role, nil); err != nil {
		return err
	}
	return c.sendInviteUserEmail(account.Email, account.Username, company.Name)
}

func (c *Controller) sendInviteUserEmail(email, username, companyName string) error {
	if c.appConfig.IsDisabledBroker() {
		return nil
	}

	emailMessage := messages.EmailMessage{
		To:           email,
		TemplateName: emailEnum.OrganizationInvite,
		Subject:      "[Horusec] Organization invite",
		Data: map[string]interface{}{
			"CompanyName": companyName,
			"Username":    username,
			"URL":         env.GetHorusecManagerURL()},
	}

	return c.broker.Publish(queues.HorusecEmail.ToString(), "", "", emailMessage.ToBytes())
}

func (c *Controller) GetAllAccountsInCompany(companyID uuid.UUID) (*[]roles.AccountRole, error) {
	return c.repoCompany.GetAllAccountsInCompany(companyID)
}

func (c *Controller) RemoveUser(removeUser *dto.RemoveUser) error {
	account, err := c.repoAccount.GetByAccountID(removeUser.AccountID)
	if err != nil {
		return err
	}

	err = c.repoAccountRepository.DeleteFromAllRepositories(account.AccountID, removeUser.CompanyID)
	if err != nil {
		return err
	}

	return c.repoAccountCompany.DeleteAccountCompany(account.AccountID, removeUser.CompanyID)
}

func (c *Controller) GetAccountIDByEmail(email string) (uuid.UUID, error) {
	account, err := c.accountRepository.GetByEmail(email)
	if err != nil {
		return uuid.Nil, err
	}

	return account.AccountID, nil
}
