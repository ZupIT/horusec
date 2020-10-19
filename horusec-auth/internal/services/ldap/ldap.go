package ldap

import (
	"errors"

	auth "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapconfig "github.com/ZupIT/horusec/horusec-auth/config/ldap"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	ldapclient "github.com/jtblin/go-ldap-client"
)

type Service struct {
	client ldapclient.LDAPClient
}

func NewService() services.IAuthService {
	return &Service{
		client: ldapconfig.NewLDAPClient(),
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
	token, err := jwt.DecodeToken(authzData.Token)
	if err != nil {
		return false, err
	}

	userGroups, err := s.client.GetGroupsOfUser(token.Username)
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

func (s *Service) contains(collection []string, value string) bool {
	for _, a := range collection {
		if a == value {
			return true
		}
	}

	return false
}
