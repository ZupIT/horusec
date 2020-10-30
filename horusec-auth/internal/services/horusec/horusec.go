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

package horusec

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
	"time"
)

type Service struct {
	repoAccountCompany    repositoryAccountCompany.IAccountCompany
	repoAccountRepository repoAccountRepository.IAccountRepository
	repositoryRepo        repositoryRepo.IRepository
	accountRepository     repositoryAccount.IAccount
	accountUseCases       accountUseCases.IAccount
	cacheRepository       cache.Interface
	accountRepositoryRepo repoAccountRepository.IAccountRepository
}

func NewHorusAuthService(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) services.IAuthService {
	return &Service{
		repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(postgresRead, postgresWrite),
		repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(postgresRead, postgresWrite),
		repositoryRepo:        repositoryRepo.NewRepository(postgresRead, postgresWrite),
		accountRepository:     repositoryAccount.NewAccountRepository(postgresRead, postgresWrite),
		accountUseCases:       accountUseCases.NewAccountUseCases(),
		accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(postgresRead, postgresWrite),
		cacheRepository:       cache.NewCacheRepository(postgresRead, postgresWrite),
	}
}

func (s *Service) Authenticate(credentials *authEntities.Credentials) (interface{}, error) {
	loginData := &accountEntities.LoginData{
		Email:    credentials.Username,
		Password: credentials.Password,
	}

	return s.login(loginData)
}

func (s *Service) login(loginData *accountEntities.LoginData) (*accountEntities.LoginResponse, error) {
	account, err := s.accountRepository.GetByEmail(loginData.Email)
	if err != nil {
		return nil, err
	}

	if err := s.accountUseCases.ValidateLogin(account, loginData); err != nil {
		return nil, err
	}

	return s.setLoginResponse(account)
}

func (s *Service) setLoginResponse(account *accountEntities.Account) (*accountEntities.LoginResponse, error) {
	accessToken, expiresAt, _ := s.createTokenWithAccountPermissions(account)
	refreshToken := jwt.CreateRefreshToken()
	err := s.cacheRepository.Set(
		&entityCache.Cache{Key: account.AccountID.String(), Value: []byte(refreshToken)}, time.Hour*2)
	if err != nil {
		return nil, err
	}

	return account.ToLoginResponse(accessToken, refreshToken, expiresAt), nil
}

func (s *Service) createTokenWithAccountPermissions(account *accountEntities.Account) (string, time.Time, error) {
	accountRepository, _ := s.accountRepositoryRepo.GetOfAccount(account.AccountID)
	return jwt.CreateToken(account, s.accountUseCases.MapRepositoriesRoles(&accountRepository))
}

func (s *Service) IsAuthorized(authorizationData *authEntities.AuthorizationData) (bool, error) {
	return s.authorizeByRole()[authorizationData.Role](authorizationData)
}

func (s *Service) authorizeByRole() map[authEnums.HorusecRoles]func(*authEntities.AuthorizationData) (bool, error) {
	return map[authEnums.HorusecRoles]func(*authEntities.AuthorizationData) (bool, error){
		authEnums.CompanyMember:        s.isCompanyMember,
		authEnums.CompanyAdmin:         s.isCompanyAdmin,
		authEnums.RepositoryMember:     s.isRepositoryMember,
		authEnums.RepositorySupervisor: s.isRepositorySupervisor,
		authEnums.RepositoryAdmin:      s.isRepositoryAdmin,
		authEnums.ApplicationAdmin:     s.isApplicationAdmin,
	}
}

func (s *Service) isCompanyMember(authorizationData *authEntities.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if _, err = s.repoAccountCompany.GetAccountCompany(accountID, authorizationData.CompanyID); err != nil {
		return false, errors.ErrorUnauthorized
	}

	return true, nil
}

func (s *Service) isCompanyAdmin(authorizationData *authEntities.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if s.isNotCompanyAdmin(authorizationData, accountID) {
		return false, errors.ErrorUnauthorized
	}

	return true, nil
}

func (s *Service) isRepositoryMember(authorizationData *authEntities.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if _, err = s.repoAccountRepository.GetAccountRepository(accountID, authorizationData.RepositoryID); err != nil {
		if s.isNotCompanyAdmin(authorizationData, accountID) {
			return false, errors.ErrorUnauthorized
		}
	}

	return true, nil
}

func (s *Service) isRepositorySupervisor(authorizationData *authEntities.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if accountRepository, err := s.repoAccountRepository.GetAccountRepository(accountID,
		authorizationData.RepositoryID); err != nil || accountRepository.IsNotSupervisorOrAdmin() {
		if s.isNotCompanyAdmin(authorizationData, accountID) {
			return false, errors.ErrorUnauthorized
		}
	}

	return true, nil
}

func (s *Service) isRepositoryAdmin(authorizationData *authEntities.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if accountRepository, errRepository := s.repoAccountRepository.GetAccountRepository(accountID,
		authorizationData.RepositoryID); errRepository != nil || accountRepository.IsNotAdmin() {
		if s.isNotCompanyAdmin(authorizationData, accountID) {
			return false, errors.ErrorUnauthorized
		}
	}

	return true, nil
}

func (s *Service) isNotCompanyAdmin(authorizationData *authEntities.AuthorizationData, accountID uuid.UUID) bool {
	accountCompany, errCompany := s.repositoryRepo.GetAccountCompanyRole(accountID, authorizationData.CompanyID)
	return errCompany != nil || accountCompany.IsNotAdmin()
}

func (s *Service) isApplicationAdmin(authorizationData *authEntities.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if account, errRepository := s.accountRepository.GetByAccountID(
		accountID); errRepository != nil || account.IsNotApplicationAdminAccount() {
		return false, errors.ErrorUnauthorized
	}

	return true, nil
}
