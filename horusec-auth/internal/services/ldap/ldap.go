package ldap

import (
	"errors"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	auth "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapconfig "github.com/ZupIT/horusec/horusec-auth/config/ldap"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
	ldapclient "github.com/jtblin/go-ldap-client"
)

type Service struct {
	client      ldapclient.LDAPClient
	accountRepo account.IAccount
	companyRepo company.ICompanyRepository
}

func NewService(
	databaseRead relational.InterfaceRead, databaseWrite relational.InterfaceWrite) services.IAuthService {
	return &Service{
		client:      ldapconfig.NewLDAPClient(),
		accountRepo: account.NewAccountRepository(databaseRead, databaseWrite),
		companyRepo: company.NewCompanyRepository(databaseRead, databaseWrite),
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

	for _, userGroup := range userGroups {
		if s.contains(authzData.Groups, userGroup) {
			return true, nil
		}
	}

	return false, errors.New("not authorized")
}

func (s *Service) getCompanyAuthzGroupsName(companyID uuid.UUID) ([]string, error) {
	company, err := s.companyRepo.GetByID(companyID)
	if err != nil {
		return nil, err
	}
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
