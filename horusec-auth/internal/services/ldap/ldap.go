package ldap

import (
	"errors"

	auth "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	ldapconfig "github.com/ZupIT/horusec/horusec-auth/config/ldap"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	ldapclient "github.com/jtblin/go-ldap-client"
)

type Service struct {
	client ldapclient.LDAPClient
}

func NewService() services.AuthService {
	return &Service{
		client: ldapconfig.NewLDAPClient(),
	}
}

func (s *Service) Authenticate(credentials *auth.Credentials) (bool, map[string]string, error) {
	return s.client.Authenticate(credentials.Username, credentials.Password)
}

func (s *Service) IsAuthorized(userID string, groups []string) (bool, error) {
	userGroups, err := s.client.GetGroupsOfUser(userID)

	if err != nil {
		return false, err
	}

	for _, userGroup := range userGroups {
		if s.contains(groups, userGroup) {
			return true, nil
		}
	}

	return false, errors.New("not authorized")
}

func (s *Service) contains(collection []string, value string) bool {
	for _, a := range collection {
		if a == value {
			return true
		}
	}

	return false
}
