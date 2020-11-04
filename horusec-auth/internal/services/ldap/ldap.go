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
	"fmt"
	"strings"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	companyRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapService "github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
	"github.com/kofalt/go-memoize"
)

type Service struct {
	client         ldapService.ILDAPService
	accountRepo    accountRepo.IAccount
	companyRepo    companyRepo.ICompanyRepository
	repositoryRepo repositoryRepo.IRepository
	cacheRepo      cache.Interface
	memo           *memoize.Memoizer
}

func NewService(databaseRead relational.InterfaceRead, databaseWrite relational.InterfaceWrite) services.IAuthService {
	return &Service{
		client:         ldapService.NewLDAPClient(),
		accountRepo:    accountRepo.NewAccountRepository(databaseRead, databaseWrite),
		companyRepo:    companyRepo.NewCompanyRepository(databaseRead, databaseWrite),
		repositoryRepo: repositoryRepo.NewRepository(databaseRead, databaseWrite),
		cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		memo:           memoize.NewMemoizer(90*time.Second, 1*time.Minute),
	}
}

func (s *Service) Authenticate(credentials *auth.Credentials) (interface{}, error) {
	ok, data, err := s.client.Authenticate(credentials.Username, credentials.Password)
	if err != nil || !ok {
		return nil, s.verifyAuthenticateErrors(err)
	}

	account, err := s.getAccountAndCreateIfNotExist(data)
	if err != nil {
		return nil, err
	}

	return s.setLDAPAuthResponse(account), nil
}

func (s *Service) verifyAuthenticateErrors(err error) error {
	if err != nil && err == errors.ErrorUserDoesNotExist {
		return err
	}

	return errors.ErrorUnauthorized
}

func (s *Service) IsAuthorized(authzData *auth.AuthorizationData) (bool, error) {
	getUserGroups := func() (interface{}, error) {
		return s.getUserGroups(authzData.Token)
	}
	userGroups, err, _ := s.memo.Memoize(authzData.Token+authzData.Role.ToString(), getUserGroups)

	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	authzGroups, err := s.getAuthzGroupsName(authzData)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	return s.checkIsAuthorized(userGroups.([]string), authzGroups)
}

func (s *Service) setLDAPAuthResponse(account *accountEntities.Account) *auth.LdapAuthResponse {
	accessToken, expiresAt, _ := jwt.CreateToken(account, nil)

	return &auth.LdapAuthResponse{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
		Username:    account.Username,
		Email:       account.Email,
	}
}

func (s *Service) getAccountAndCreateIfNotExist(data map[string]string) (*accountEntities.Account, error) {
	account, err := s.accountRepo.GetByEmail(data["mail"])

	if account == nil || err != nil {
		account = &accountEntities.Account{
			Email:    s.pickOne(data, "mail", "uid"),
			Username: s.pickOne(data, "givenName", "uid"),
		}

		err = s.accountRepo.Create(account.SetAccountData())
		if err != nil {
			return nil, err
		}
	}

	return account, nil
}

func (s *Service) pickOne(data map[string]string, first, second string) string {
	if data[first] == "" {
		return data[second]
	}

	return data[first]
}

func (s *Service) getAuthzGroupsName(authzData *auth.AuthorizationData) ([]string, error) {
	switch authzData.Role {
	case authEnums.CompanyAdmin, authEnums.CompanyMember:
		return s.getCompanyAuthzGroupsName(authzData.CompanyID, authzData.Role)

	case authEnums.RepositoryAdmin, authEnums.RepositoryMember, authEnums.RepositorySupervisor:
		return s.handleGetAuthzGroupsNameForRepository(authzData)
	}

	return []string{}, errors.ErrorUnauthorized
}

func (s *Service) handleGetAuthzGroupsNameForRepository(authzData *auth.AuthorizationData) ([]string, error) {
	companyAuthzAdmin, err := s.getCompanyAuthzGroupsName(authzData.CompanyID, authzData.Role)
	if err != nil {
		return []string{}, err
	}

	repositoryAuthz, err := s.getRepositoryAuthzGroupsName(authzData.RepositoryID, authEnums.CompanyAdmin)
	if err != nil {
		return []string{}, err
	}

	return append(repositoryAuthz, companyAuthzAdmin...), nil
}

func (s *Service) checkIsAuthorized(userGroups, groups []string) (bool, error) {
	for _, userGroup := range userGroups {
		if s.contains(groups, userGroup) {
			return true, nil
		}
	}

	return false, errors.ErrorUnauthorized
}

func (s *Service) getCompanyAuthzGroupsName(companyID uuid.UUID, role authEnums.HorusecRoles) ([]string, error) {
	company, err := s.companyRepo.GetByID(companyID)
	if err != nil {
		return nil, err
	}

	return s.getEntityGroupsNameByRole(company.GetAuthzMember(),
		company.GetAuthzSupervisor(), company.GetAuthzAdmin(), role), nil
}

func (s *Service) getRepositoryAuthzGroupsName(repositoryID uuid.UUID, role authEnums.HorusecRoles) ([]string, error) {
	repository, err := s.repositoryRepo.Get(repositoryID)
	if err != nil {
		return nil, err
	}

	return s.getEntityGroupsNameByRole(repository.GetAuthzMember(),
		repository.GetAuthzSupervisor(), repository.GetAuthzAdmin(), role), nil
}

func (s *Service) getEntityGroupsNameByRole(member, supervisor, admin string, role authEnums.HorusecRoles) []string {
	var groupsName string

	switch role {
	case authEnums.RepositoryMember, authEnums.CompanyMember:
		groupsName = fmt.Sprintf("%s,%s,%s", member, supervisor, admin)

	case authEnums.RepositorySupervisor:
		groupsName = fmt.Sprintf("%s,%s", supervisor, admin)

	case authEnums.CompanyAdmin, authEnums.RepositoryAdmin:
		groupsName = admin
	}

	return s.removeEmptyGroupsName(strings.Split(groupsName, ","))
}

func (s *Service) removeEmptyGroupsName(groupsName []string) []string {
	var updatedGroups []string

	for _, group := range groupsName {
		if group != "" {
			updatedGroups = append(updatedGroups, group)
		}
	}

	return updatedGroups
}

func (s *Service) getUserGroups(tokenStr string) ([]string, error) {
	token, err := jwt.DecodeToken(tokenStr)
	if err != nil {
		return nil, err
	}

	return s.client.GetGroupsOfUser(token.Username)
}

func (s *Service) contains(groups []string, userGroup string) bool {
	for _, group := range groups {
		if group == userGroup {
			return true
		}
	}

	return false
}
