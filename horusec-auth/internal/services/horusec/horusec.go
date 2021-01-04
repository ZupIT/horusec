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
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
)

type Service struct {
	repoAccountCompany    repositoryAccountCompany.IAccountCompany
	repoAccountRepository repoAccountRepository.IAccountRepository
	repositoryRepo        repositoryRepo.IRepository
	accountRepository     repositoryAccount.IAccount
	cacheRepository       cache.Interface
	authUseCases          authUseCases.IUseCases
	accountRepositoryRepo repoAccountRepository.IAccountRepository
}

func NewHorusAuthService(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) services.IAuthService {
	return &Service{
		repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(postgresRead, postgresWrite),
		repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(postgresRead, postgresWrite),
		repositoryRepo:        repositoryRepo.NewRepository(postgresRead, postgresWrite),
		accountRepository:     repositoryAccount.NewAccountRepository(postgresRead, postgresWrite),
		accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(postgresRead, postgresWrite),
		cacheRepository:       cache.NewCacheRepository(postgresRead, postgresWrite),
		authUseCases:          authUseCases.NewAuthUseCases(),
	}
}

func (s *Service) Authenticate(credentials *dto.Credentials) (interface{}, error) {
	loginData := &dto.LoginData{
		Email:    credentials.Username,
		Password: credentials.Password,
	}

	return s.login(loginData)
}

func (s *Service) login(loginData *dto.LoginData) (*dto.LoginResponse, error) {
	account, err := s.accountRepository.GetByEmail(loginData.Email)
	if err != nil {
		return nil, err
	}

	if err := s.authUseCases.ValidateLogin(account, loginData); err != nil {
		return nil, err
	}

	return s.setLoginResponse(account)
}

func (s *Service) setLoginResponse(account *authEntities.Account) (*dto.LoginResponse, error) {
	accessToken, expiresAt, _ := jwt.CreateToken(account, nil)
	refreshToken := jwt.CreateRefreshToken()
	err := s.cacheRepository.Set(
		&entityCache.Cache{Key: account.AccountID.String(), Value: []byte(refreshToken)}, time.Hour*2)
	if err != nil {
		return nil, err
	}

	return s.authUseCases.ToLoginResponse(account, accessToken, refreshToken, expiresAt), nil
}

func (s *Service) IsAuthorized(authorizationData *dto.AuthorizationData) (bool, error) {
	return s.authorizeByRole()[authorizationData.Role](authorizationData)
}

func (s *Service) authorizeByRole() map[authEnums.HorusecRoles]func(*dto.AuthorizationData) (bool, error) {
	return map[authEnums.HorusecRoles]func(*dto.AuthorizationData) (bool, error){
		authEnums.CompanyMember:        s.isCompanyMember,
		authEnums.CompanyAdmin:         s.isCompanyAdmin,
		authEnums.RepositoryMember:     s.isRepositoryMember,
		authEnums.RepositorySupervisor: s.isRepositorySupervisor,
		authEnums.RepositoryAdmin:      s.isRepositoryAdmin,
		authEnums.ApplicationAdmin:     s.isApplicationAdmin,
	}
}

func (s *Service) isCompanyMember(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorizedCompanyMember
	}

	if _, err = s.repoAccountCompany.GetAccountCompany(accountID, authorizationData.CompanyID); err != nil {
		return false, errors.ErrorUnauthorizedCompanyMember
	}

	return true, nil
}

func (s *Service) isCompanyAdmin(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorizedCompanyAdmin
	}

	if s.isNotCompanyAdmin(authorizationData, accountID) {
		return false, errors.ErrorUnauthorizedCompanyAdmin
	}

	return true, nil
}

func (s *Service) isRepositoryMember(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorizedRepositoryMember
	}

	if _, err = s.repoAccountRepository.GetAccountRepository(accountID, authorizationData.RepositoryID); err != nil {
		if s.isNotCompanyAdmin(authorizationData, accountID) {
			return false, errors.ErrorUnauthorizedRepositoryMember
		}
	}

	return true, nil
}

func (s *Service) isRepositorySupervisor(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorizedRepositorySupervisor
	}

	if accountRepository, err := s.repoAccountRepository.GetAccountRepository(accountID,
		authorizationData.RepositoryID); err != nil || accountRepository.IsNotSupervisorOrAdmin() {
		if s.isNotCompanyAdmin(authorizationData, accountID) {
			return false, errors.ErrorUnauthorizedRepositorySupervisor
		}
	}

	return true, nil
}

func (s *Service) isRepositoryAdmin(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorizedRepositoryAdmin
	}

	if accountRepository, errRepository := s.repoAccountRepository.GetAccountRepository(accountID,
		authorizationData.RepositoryID); errRepository != nil || accountRepository.IsNotAdmin() {
		if s.isNotCompanyAdmin(authorizationData, accountID) {
			return false, errors.ErrorUnauthorizedRepositoryAdmin
		}
	}

	return true, nil
}

func (s *Service) isNotCompanyAdmin(authorizationData *dto.AuthorizationData, accountID uuid.UUID) bool {
	accountCompany, errCompany := s.repositoryRepo.GetAccountCompanyRole(accountID, authorizationData.CompanyID)
	return errCompany != nil || accountCompany.IsNotAdmin()
}

func (s *Service) isApplicationAdmin(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := jwt.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorizedApplicationAdmin
	}

	if account, errRepository := s.accountRepository.GetByAccountID(
		accountID); errRepository != nil || account.IsNotApplicationAdminAccount() {
		return false, errors.ErrorUnauthorizedApplicationAdmin
	}

	return true, nil
}
