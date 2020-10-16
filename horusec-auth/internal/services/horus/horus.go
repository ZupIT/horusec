package horus

import (
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
)

type Service struct {
	httpUtil httpClient.Interface
}

func NewHorusAuthService() services.IAuthService {
	return &Service{
		httpUtil: httpClient.NewHTTPClient(10),
	}
}

func (s *Service) Authenticate(credentials authEntities.Credentials) (bool, map[string]interface{}, error) {
	return false, nil, nil
}

func (s *Service) IsAuthorized(token string, groups []string) (bool, error) {
	return false, nil
}
