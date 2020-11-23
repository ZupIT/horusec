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

package keycloak

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
)

type Service struct {
	keycloak              keycloak.IService
	repoAccountCompany    repositoryAccountCompany.IAccountCompany
	repoAccountRepository repoAccountRepository.IAccountRepository
	repositoryRepo        repositoryRepo.IRepository
}

func NewKeycloakAuthService(databaseRead relational.InterfaceRead) services.IAuthService {
	return &Service{
		keycloak:              keycloak.NewKeycloakService(),
		repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(databaseRead, nil),
		repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(databaseRead, nil),
		repositoryRepo:        repositoryRepo.NewRepository(databaseRead, nil),
	}
}

func (s *Service) Authenticate(credentials *dto.Credentials) (interface{}, error) {
	return s.keycloak.LoginOtp(credentials.Username, credentials.Password, credentials.Otp)
}

func (s *Service) IsAuthorized(authorizationData *dto.AuthorizationData) (bool, error) {
	if isActive, err := s.keycloak.IsActiveToken(authorizationData.Token); err != nil || !isActive {
		return false, err
	}

	return s.authorizeByRole()[authorizationData.Role](authorizationData)
}

func (s *Service) authorizeByRole() map[authEnums.HorusecRoles]func(*dto.AuthorizationData) (bool, error) {
	return map[authEnums.HorusecRoles]func(*dto.AuthorizationData) (bool, error){
		authEnums.CompanyMember:        s.isCompanyMember,
		authEnums.CompanyAdmin:         s.isCompanyAdmin,
		authEnums.RepositoryMember:     s.isRepositoryMember,
		authEnums.RepositorySupervisor: s.isRepositorySupervisor,
		authEnums.RepositoryAdmin:      s.isRepositoryAdmin,
	}
}

func (s *Service) isCompanyMember(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := s.keycloak.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if _, err = s.repoAccountCompany.GetAccountCompany(accountID, authorizationData.CompanyID); err != nil {
		return false, errors.ErrorUnauthorized
	}

	return true, nil
}

func (s *Service) isCompanyAdmin(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := s.keycloak.GetAccountIDByJWTToken(authorizationData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	if s.isNotCompanyAdmin(authorizationData, accountID) {
		return false, errors.ErrorUnauthorized
	}

	return true, nil
}

func (s *Service) isRepositoryMember(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := s.keycloak.GetAccountIDByJWTToken(authorizationData.Token)
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

func (s *Service) isRepositorySupervisor(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := s.keycloak.GetAccountIDByJWTToken(authorizationData.Token)
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

func (s *Service) isRepositoryAdmin(authorizationData *dto.AuthorizationData) (bool, error) {
	accountID, err := s.keycloak.GetAccountIDByJWTToken(authorizationData.Token)
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

func (s *Service) isNotCompanyAdmin(authorizationData *dto.AuthorizationData, accountID uuid.UUID) bool {
	accountCompany, errCompany := s.repositoryRepo.GetAccountCompanyRole(accountID, authorizationData.CompanyID)
	return errCompany != nil || accountCompany.IsNotAdmin()
}
