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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/google/uuid"
	"net/http"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
)

type Service struct {
	httpUtil              httpClient.Interface
	repoAccountCompany    repositoryAccountCompany.IAccountCompany
	repoAccountRepository repoAccountRepository.IAccountRepository
	repositoryRepo        repositoryRepo.IRepository
	accountRepository     repositoryAccount.IAccount
}

func NewHorusAuthService(postgresRead relational.InterfaceRead) services.IAuthService {
	return &Service{
		httpUtil:              httpClient.NewHTTPClient(10),
		repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(postgresRead, nil),
		repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(postgresRead, nil),
		repositoryRepo:        repositoryRepo.NewRepository(postgresRead, nil),
		accountRepository:     repositoryAccount.NewAccountRepository(postgresRead, nil),
	}
}

func (s *Service) Authenticate(
	credentials *authEntities.Credentials) (interface{}, error) {
	requestResponse, err := s.sendLoginRequest(credentials)
	if err != nil {
		return nil, err
	}

	loginResponse, err := s.parseToLoginResponse(requestResponse)
	if err != nil {
		return nil, err
	}

	return loginResponse, nil
}

func (s *Service) sendLoginRequest(credentials *authEntities.Credentials) (httpResponse.Interface, error) {
	req, _ := http.NewRequest(http.MethodPost, s.getHorusecAccountURL(),
		bytes.NewReader(s.newLoginRequestData(credentials)))
	return s.httpUtil.DoRequest(req, nil)
}

func (s *Service) newLoginRequestData(credentials *authEntities.Credentials) []byte {
	loginData := &accountEntities.LoginData{
		Email:    credentials.Username,
		Password: credentials.Password,
	}

	return loginData.ToBytes()
}

func (s *Service) getHorusecAccountURL() string {
	return fmt.Sprintf("%s/api/account/login",
		env.GetEnvOrDefault("HORUSEC_ACCOUNT_URL", "http://0.0.0.0:8003"))
}

func (s *Service) parseToLoginResponse(
	requestResponse httpResponse.Interface) (loginResponse map[string]interface{}, err error) {
	body, _ := requestResponse.GetBody()
	return loginResponse, json.Unmarshal(body, &loginResponse)
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
