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

package ldap

import (
	"strings"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	companyrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountentities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	auth "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authenums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapservice "github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
)

type Service struct {
	client         ldapservice.ILDAPService
	accountRepo    accountrepo.IAccount
	companyRepo    companyrepo.ICompanyRepository
	repositoryRepo repositoryrepo.IRepository
	cacheRepo      cache.Interface
}

type ldapAuthResponse struct {
	AccessToken string
	ExpiresAt   time.Time
	Username    string
	Email       string
}

type AuthzEntity interface {
	GetAuthzMember() string
	GetAuthzAdmin() string
	GetAuthzSupervisor() string
}

func NewService(databaseRead relational.InterfaceRead, databaseWrite relational.InterfaceWrite) services.IAuthService {
	return &Service{
		client:         ldapservice.NewLDAPClient(),
		accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
		companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
		repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
		cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
	}
}

func (s *Service) Authenticate(credentials *auth.Credentials) (interface{}, error) {
	ok, data, err := s.client.Authenticate(credentials.Username, credentials.Password)
	if err != nil || !ok {
		return nil, errors.ErrorUnauthorized
	}

	account, err := s.getAccountAndCreateIfNotExist(data)
	if err != nil {
		return nil, err
	}

	accessToken, expiresAt, _ := jwt.CreateToken(account, nil)

	return s.setLDAPAuthResponse(account, accessToken, expiresAt), nil
}

func (s *Service) IsAuthorized(authzData *auth.AuthorizationData) (bool, error) {
	userGroups, err := s.getUserGroups(authzData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	authzGroups, err := s.getAuthzGroupsName(authzData)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	return s.checkIsAuthorized(userGroups, authzGroups), nil
}

func (s *Service) setLDAPAuthResponse(
	account *accountentities.Account, accessToken string, expiresAt time.Time) *ldapAuthResponse {
	return &ldapAuthResponse{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
		Username:    account.Username,
		Email:       account.Email,
	}
}

func (s *Service) getAccountAndCreateIfNotExist(data map[string]string) (*accountentities.Account, error) {
	account, err := s.accountRepo.GetByEmail(data["email"])

	if account == nil || err != nil {
		account = &accountentities.Account{
			Email:    data["email"],
			Username: data["username"],
		}

		err = s.accountRepo.Create(account.SetAccountData())
		if err != nil {
			return nil, err
		}
	}

	return account, nil
}

func (s *Service) getAuthzGroupsName(authzData *auth.AuthorizationData) ([]string, error) {
	switch authzData.Role {
	case authenums.CompanyAdmin, authenums.CompanyMember:
		return s.getCompanyAuthzGroupsName(authzData.CompanyID, authzData.Role)

	case authenums.RepositoryAdmin, authenums.RepositoryMember, authenums.RepositorySupervisor:
		return s.getRepositoryAuthzGroupsName(authzData.RepositoryID, authzData.Role)
	}

	return []string{}, nil
}

func (s *Service) checkIsAuthorized(userGroups, groups []string) bool {
	for _, userGroup := range userGroups {
		if s.contains(groups, userGroup) {
			return true
		}
	}

	return false
}

func (s *Service) getCompanyAuthzGroupsName(companyID uuid.UUID, role authenums.HorusecRoles) ([]string, error) {
	company, err := s.companyRepo.GetByID(companyID)
	if err != nil {
		return nil, err
	}

	return s.getEntityGroupsNameByRole(company, role), nil
}

func (s *Service) getRepositoryAuthzGroupsName(repositoryID uuid.UUID, role authenums.HorusecRoles) ([]string, error) {
	repository, err := s.repositoryRepo.Get(repositoryID)
	if err != nil {
		return nil, err
	}

	return s.getEntityGroupsNameByRole(repository, role), nil
}

func (s *Service) getEntityGroupsNameByRole(entity AuthzEntity, role authenums.HorusecRoles) []string {
	var groupsName string

	switch role {
	case authenums.RepositoryMember, authenums.CompanyMember:
		groupsName = entity.GetAuthzMember()

	case authenums.CompanyAdmin, authenums.RepositoryAdmin:
		groupsName = entity.GetAuthzAdmin()

	case authenums.RepositorySupervisor:
		groupsName = entity.GetAuthzSupervisor()
	}

	return strings.Split(groupsName, ",")
}

func (s *Service) getUserGroups(tokenStr string) ([]string, error) {
	token, err := jwt.DecodeToken(tokenStr)
	if err != nil {
		return nil, err
	}

	userGroups, err := s.client.GetGroupsOfUser(token.Username)
	if err != nil {
		return nil, err
	}

	return userGroups, nil
}

func (s *Service) contains(collection []string, value string) bool {
	for _, a := range collection {
		if a == value {
			return true
		}
	}

	return false
}
