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
	accountRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	companyRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapService "github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
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

func (s *Service) Authenticate(credentials *dto.Credentials) (interface{}, error) {
	ok, data, err := s.client.Authenticate(credentials.Username, credentials.Password)
	if err != nil || !ok {
		return nil, s.verifyAuthenticateErrors(err)
	}

	account, err := s.getAccountAndCreateIfNotExist(data)
	if err != nil {
		return nil, err
	}

	defer s.client.Close()
	return s.setLDAPAuthResponse(account, data["dn"])
}

func (s *Service) IsAuthorized(authzData *dto.AuthorizationData) (bool, error) {
	tokenGroups, err := s.getUserGroupsByJWT(authzData.Token)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	horusecGroups, err := s.getAuthzGroupsName(authzData)
	if err != nil {
		return false, errors.ErrorUnauthorized
	}

	return s.checkIsAuthorized(tokenGroups, horusecGroups)
}

func (s *Service) isApplicationAdmin(userGroups []string) bool {
	applicationAdminGroups, _ := s.getApplicationAdminAuthzGroupsName()
	isApplicationAdmin, err := s.checkIsAuthorized(applicationAdminGroups, userGroups)
	if err != nil {
		return false
	}

	return isApplicationAdmin
}

func (s *Service) getUserGroupsInLdap(userDN string) ([]string, error) {
	memoizedGetUserGroups := func() (interface{}, error) {
		return s.client.GetGroupsOfUser(userDN)
	}

	userGroups, err, _ := s.memo.Memoize(userDN, memoizedGetUserGroups)
	if err != nil {
		return []string{}, err
	}

	return userGroups.([]string), nil
}

func (s *Service) verifyAuthenticateErrors(err error) error {
	if err != nil && err == errors.ErrorUserDoesNotExist {
		return err
	}

	return errors.ErrorUnauthorized
}

func (s *Service) setLDAPAuthResponse(account *authEntities.Account, userDN string) (*dto.LdapAuthResponse, error) {
	userGroups, err := s.getUserGroupsInLdap(userDN)
	if err != nil {
		return nil, err
	}

	accessToken, expiresAt, _ := jwt.CreateToken(account, userGroups)
	return &dto.LdapAuthResponse{
		AccessToken:        accessToken,
		ExpiresAt:          expiresAt,
		Username:           account.Username,
		Email:              account.Email,
		IsApplicationAdmin: s.isApplicationAdmin(userGroups),
	}, nil
}

func (s *Service) getAccountAndCreateIfNotExist(data map[string]string) (*authEntities.Account, error) {
	account, err := s.accountRepo.GetByUsername(data["sAMAccountName"])
	if account == nil || err != nil {
		account = &authEntities.Account{
			Email:    s.pickOne(data, "mail", "sAMAccountName"),
			Username: data["sAMAccountName"],
		}

		if err := s.accountRepo.Create(account.SetAccountData()); err != nil {
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

func (s *Service) getAuthzGroupsName(authzData *dto.AuthorizationData) ([]string, error) {
	switch authzData.Role {
	case authEnums.CompanyAdmin, authEnums.CompanyMember:
		return s.getCompanyAuthzGroupsName(authzData.CompanyID, authzData.Role)

	case authEnums.RepositoryAdmin, authEnums.RepositoryMember, authEnums.RepositorySupervisor:
		return s.handleGetAuthzGroupsNameForRepository(authzData)

	case authEnums.ApplicationAdmin:
		return s.getApplicationAdminAuthzGroupsName()
	}

	return []string{}, errors.ErrorUnauthorized
}

func (s *Service) handleGetAuthzGroupsNameForRepository(authzData *dto.AuthorizationData) ([]string, error) {
	companyAuthzAdmin, err := s.getCompanyAuthzGroupsName(authzData.CompanyID, authEnums.CompanyAdmin)
	if err != nil {
		return []string{}, err
	}

	repositoryAuthz, err := s.getRepositoryAuthzGroupsName(authzData.RepositoryID, authzData.Role)
	if err != nil {
		return []string{}, err
	}

	return append(repositoryAuthz, companyAuthzAdmin...), nil
}

func (s *Service) checkIsAuthorized(tokenGroups, horusecGroups []string) (bool, error) {
	for _, tokenGroup := range tokenGroups {
		if s.contains(horusecGroups, tokenGroup) {
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

func (s *Service) getApplicationAdminAuthzGroupsName() ([]string, error) {
	applicationAdminGroup := env.GetEnvOrDefault("HORUSEC_LDAP_ADMIN_GROUP", "")
	if applicationAdminGroup == "" {
		return []string{}, errors.ErrorUnauthorized
	}

	return []string{applicationAdminGroup}, nil
}

func (s *Service) getEntityGroupsNameByRole(member, supervisor, admin []string,
	role authEnums.HorusecRoles) (groups []string) {
	groups = admin

	switch role {
	case authEnums.RepositoryMember, authEnums.CompanyMember:
		groups = append(groups, append(member, supervisor...)...)

	case authEnums.RepositorySupervisor:
		groups = append(groups, supervisor...)
	}

	return groups
}

func (s *Service) getUserGroupsByJWT(tokenStr string) ([]string, error) {
	token, err := jwt.DecodeToken(tokenStr)
	if err != nil {
		return nil, err
	}

	return token.Permissions, nil
}

func (s *Service) contains(horusecGroups []string, tokenGroup string) bool {
	for _, horusecGroup := range horusecGroups {
		if strings.TrimSpace(horusecGroup) == tokenGroup {
			return true
		}
	}

	return false
}
