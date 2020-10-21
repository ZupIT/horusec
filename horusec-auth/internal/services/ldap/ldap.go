package ldap

import (
	"errors"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	companyrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	auth "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapconfig "github.com/ZupIT/horusec/horusec-auth/config/ldap"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
	ldapclient "github.com/jtblin/go-ldap-client"
)

type Service struct {
	client         ldapclient.LDAPClient
	accountRepo    account.IAccount
	companyRepo    companyrepo.ICompanyRepository
	repositoryRepo repositoryrepo.IRepository
}

type AuthzEntity interface {
	GetAuthzMember() string
	GetAuthzAdmin() string
	GetAuthzSupervisor() string
}

func NewService(
	databaseRead relational.InterfaceRead, databaseWrite relational.InterfaceWrite) services.IAuthService {
	return &Service{
		client:         ldapconfig.NewLDAPClient(),
		accountRepo:    account.NewAccountRepository(databaseRead, databaseWrite),
		companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
		repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
	}
}

func (s *Service) Authenticate(credentials *auth.Credentials) (interface{}, error) {
	var result map[string]interface{}

	ok, data, err := s.client.Authenticate(credentials.Username, credentials.Password)
	if err != nil {
		return nil, err
	}

	result["ok"] = ok
	result["data"] = data

	return result, nil
}

func (s *Service) IsAuthorized(authzData *auth.AuthorizationData) (bool, error) {
	userGroups, err := s.getUserGroups(authzData.Token)
	if err != nil {
		return false, err
	}

	authzGroups, err := s.getAuthzGroupsName(authzData)
	if err != nil {
		return false, err
	}

	return s.checkIsAuthorized(userGroups, authzGroups)
}

func (s *Service) getAuthzGroupsName(authzData *auth.AuthorizationData) ([]string, error) {
	switch authzData.Role {
	case authEnums.CompanyAdmin, authEnums.CompanyMember:
		return s.getCompanyAuthzGroupsName(authzData.CompanyID, authzData.Role)

	case authEnums.RepositoryAdmin, authEnums.RepositoryMember, authEnums.RepositorySupervisor:
		return s.getRepositoryAuthzGroupsName(authzData.RepositoryID, authzData.Role)
	}

	return nil, errors.New("")
}

func (s *Service) checkIsAuthorized(userGroups, groups []string) (bool, error) {
	for _, userGroup := range userGroups {
		if s.contains(groups, userGroup) {
			return true, nil
		}
	}

	return false, errors.New("not authorized")
}

func (s *Service) getCompanyAuthzGroupsName(companyID uuid.UUID, role authEnums.HorusecRoles) ([]string, error) {
	company, err := s.companyRepo.GetByID(companyID)
	if err != nil {
		return nil, err
	}

	return s.getEntityGroupsNameByRole(company, role), nil
}

func (s *Service) getRepositoryAuthzGroupsName(repositoryID uuid.UUID, role authEnums.HorusecRoles) ([]string, error) {
	repository, err := s.repositoryRepo.Get(repositoryID)
	if err != nil {
		return nil, err
	}

	return s.getEntityGroupsNameByRole(repository, role), nil
}

func (s *Service) getEntityGroupsNameByRole(entity AuthzEntity, role authEnums.HorusecRoles) []string {
	var groupsName string

	switch role {
	case authEnums.RepositoryMember, authEnums.CompanyMember:
		groupsName = entity.GetAuthzMember()

	case authEnums.CompanyAdmin, authEnums.RepositoryAdmin:
		groupsName = entity.GetAuthzAdmin()

	case authEnums.RepositorySupervisor:
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
