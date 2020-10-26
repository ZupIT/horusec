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
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	goldapclient "github.com/jtblin/go-ldap-client"
)

type ILDAPService interface {
	Authenticate(username, password string) (bool, map[string]string, error)
	GetGroupsOfUser(username string) ([]string, error)
}

type Service struct {
	client goldapclient.LDAPClient
}

func NewLDAPClient() ILDAPService {
	return &Service{
		client: goldapclient.LDAPClient{
			Base:               env.GetEnvOrDefault("HORUS_LDAP_BASE", ""),
			Host:               env.GetEnvOrDefault("HORUS_LDAP_HOST", ""),
			Port:               env.GetEnvOrDefaultInt("HORUS_LDAP_PORT", 389),
			UseSSL:             env.GetEnvOrDefaultBool("HORUS_LDAP_USESSL", false),
			SkipTLS:            env.GetEnvOrDefaultBool("HORUS_LDAP_SKIP_TLS", true),
			InsecureSkipVerify: env.GetEnvOrDefaultBool("HORUS_LDAP_INSECURE_SKIP_VERIFY", true),
			BindDN:             env.GetEnvOrDefault("HORUS_LDAP_BINDDN", ""),
			BindPassword:       env.GetEnvOrDefault("HORUS_LDAP_BINDPASSWORD", ""),
			UserFilter:         env.GetEnvOrDefault("HORUS_LDAP_USERFILTER", ""),
			GroupFilter:        env.GetEnvOrDefault("HORUS_LDAP_GROUPFILTER", ""),
			Attributes:         []string{"uid", "mail", "givenName"},
		},
	}
}

func (s *Service) Authenticate(username, password string) (bool, map[string]string, error) {
	defer s.client.Close()
	return s.client.Authenticate(username, password)
}

func (s *Service) GetGroupsOfUser(username string) ([]string, error) {
	defer s.client.Close()
	return s.client.GetGroupsOfUser(username)
}
