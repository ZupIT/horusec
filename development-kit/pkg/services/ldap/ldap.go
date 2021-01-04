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
	"crypto/tls"
	"fmt"
	"time"

	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/go-ldap/ldap/v3"
)

type ILDAPService interface {
	Connect() error
	Close()
	Authenticate(username, password string) (bool, map[string]string, error)
	GetGroupsOfUser(username string) ([]string, error)
}

type ILdapClient interface {
	Start()
	Close()
	SetTimeout(timeout time.Duration)
	StartTLS(config *tls.Config) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Bind(username, password string) error
}

type Service struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string
	Host               string
	ServerName         string
	UserFilter         string
	Conn               ILdapClient
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate
}

func NewLDAPClient() ILDAPService {
	return &Service{
		Base:               env.GetEnvOrDefault("HORUSEC_LDAP_BASE", ""),
		Host:               env.GetEnvOrDefault("HORUSEC_LDAP_HOST", ""),
		Port:               env.GetEnvOrDefaultInt("HORUSEC_LDAP_PORT", 389),
		UseSSL:             env.GetEnvOrDefaultBool("HORUSEC_LDAP_USESSL", false),
		SkipTLS:            env.GetEnvOrDefaultBool("HORUSEC_LDAP_SKIP_TLS", true),
		InsecureSkipVerify: env.GetEnvOrDefaultBool("HORUSEC_LDAP_INSECURE_SKIP_VERIFY", true),
		BindDN:             env.GetEnvOrDefault("HORUSEC_LDAP_BINDDN", ""),
		BindPassword:       env.GetEnvOrDefault("HORUSEC_LDAP_BINDPASSWORD", ""),
		UserFilter:         env.GetEnvOrDefault("HORUSEC_LDAP_USERFILTER", ""),
		GroupFilter:        env.GetEnvOrDefault("HORUSEC_LDAP_GROUPFILTER", ""),
		Attributes:         []string{"uid", "mail", "givenName"},
	}
}

func (s *Service) Connect() error {
	if s.Conn != nil {
		return nil
	}

	if s.UseSSL {
		return s.dialWithSSL()
	}

	return s.dialWithoutSSL()
}

//nolint gosec
func (s *Service) dialWithoutSSL() error {
	conn, err := ldap.Dial("tcp", s.getLdapURL())
	if err != nil {
		return err
	}

	if !s.SkipTLS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
	}

	return s.setLDAPServiceConnection(conn, err)
}

//nolint gosec
func (s *Service) dialWithSSL() error {
	config := &tls.Config{
		InsecureSkipVerify: s.InsecureSkipVerify,
		ServerName:         s.ServerName,
	}

	if s.ClientCertificates != nil && len(s.ClientCertificates) > 0 {
		config.Certificates = s.ClientCertificates
	}

	return s.setLDAPServiceConnection(ldap.DialTLS("tcp", s.getLdapURL(), config))
}

func (s *Service) getLdapURL() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Service) setLDAPServiceConnection(conn *ldap.Conn, err error) error {
	if err != nil {
		return err
	}

	s.Conn = conn
	return nil
}

func (s *Service) Close() {
	if s.Conn != nil {
		s.Conn.Close()
		s.Conn = nil
	}
}

func (s *Service) Authenticate(username, password string) (bool, map[string]string, error) {
	err := s.Connect()
	if err != nil {
		return false, nil, err
	}

	err = s.bindByEnvVars()
	if err != nil {
		return false, nil, err
	}

	return s.searchAndCreateUser(username, password)
}

func (s *Service) searchAndCreateUser(username, password string) (bool, map[string]string, error) {
	searchResult, err := s.searchUserByUsername(username)
	if err != nil {
		return false, nil, err
	}

	if err := s.Conn.Bind(s.getDNBySearchResult(searchResult), password); err != nil {
		return false, nil, err
	}

	if err := s.bindByEnvVars(); err != nil {
		return false, nil, err
	}

	return true, s.createUser(searchResult), nil
}

func (s *Service) getDNBySearchResult(searchResult *ldap.SearchResult) string {
	return searchResult.Entries[0].DN
}

func (s *Service) bindByEnvVars() error {
	if s.BindDN != "" && s.BindPassword != "" {
		return s.Conn.Bind(s.BindDN, s.BindPassword)
	}

	return errorsEnums.ErrorEmptyBindDNOrBindPassword
}

func (s *Service) searchUserByUsername(username string) (*ldap.SearchResult, error) {
	searchResult, err := s.Conn.Search(s.newSearchRequestByUserFilter(username))
	if err != nil {
		return nil, err
	}

	return searchResult, s.validateSearchResult(searchResult)
}

func (s *Service) newSearchRequestByUserFilter(username string) *ldap.SearchRequest {
	attributes := append(s.Attributes, "dn")

	return ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(s.UserFilter, username),
		attributes,
		nil,
	)
}

func (s *Service) validateSearchResult(searchResult *ldap.SearchResult) error {
	if searchResult == nil || searchResult.Entries == nil || len(searchResult.Entries) < 1 {
		return errorsEnums.ErrorUserDoesNotExist
	}

	if len(searchResult.Entries) > 1 {
		return errorsEnums.ErrorTooManyEntries
	}

	return nil
}

func (s *Service) createUser(searchResult *ldap.SearchResult) map[string]string {
	user := map[string]string{}

	for _, attr := range s.Attributes {
		user[attr] = searchResult.Entries[0].GetAttributeValue(attr)
	}

	return user
}

func (s *Service) GetGroupsOfUser(username string) ([]string, error) {
	if err := s.Connect(); err != nil {
		return nil, err
	}

	if err := s.bindByEnvVars(); err != nil {
		return nil, err
	}

	searchResult, err := s.Conn.Search(s.newSearchRequestByGroupFilter(username))
	if err != nil {
		return nil, err
	}

	return s.getGroupsBySearchResult(searchResult), nil
}

func (s *Service) newSearchRequestByGroupFilter(username string) *ldap.SearchRequest {
	ldapSearchRequest := ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(s.GroupFilter, username),
		[]string{"cn"},
		nil,
	)

	logger.LogInfo("{newSearchRequestByGroupFilter} ldap search request -> ", ldapSearchRequest.Filter)
	return ldapSearchRequest
}

func (s *Service) getGroupsBySearchResult(searchResult *ldap.SearchResult) []string {
	var groups []string

	for _, entry := range searchResult.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups
}
