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
	"strings"
	"time"

	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/go-ldap/ldap/v3"
)

type ILDAPService interface {
	Connect() error
	Close()
	Authenticate(username, password string) (bool, map[string]string, error)
	GetGroupsOfUser(userDN string) ([]string, error)
	Check() error
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
	Host               string
	Port               int
	Base               string
	BindDN             string
	BindPassword       string
	ServerName         string
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate
	Conn               ILdapClient
	UserFilter         string
}

func NewLDAPClient() ILDAPService {
	return &Service{
		Host:               env.GetEnvOrDefault("HORUSEC_LDAP_HOST", ""),
		Port:               env.GetEnvOrDefaultInt("HORUSEC_LDAP_PORT", 389),
		Base:               env.GetEnvOrDefault("HORUSEC_LDAP_BASE", ""),
		BindDN:             env.GetEnvOrDefault("HORUSEC_LDAP_BINDDN", ""),
		BindPassword:       env.GetEnvOrDefault("HORUSEC_LDAP_BINDPASSWORD", ""),
		UseSSL:             env.GetEnvOrDefaultBool("HORUSEC_LDAP_USESSL", false),
		SkipTLS:            env.GetEnvOrDefaultBool("HORUSEC_LDAP_SKIP_TLS", true),
		InsecureSkipVerify: env.GetEnvOrDefaultBool("HORUSEC_LDAP_INSECURE_SKIP_VERIFY", true),
		UserFilter:         env.GetEnvOrDefault("HORUSEC_LDAP_USERFILTER", "(sAMAccountName=%s)"),
	}
}

func (s *Service) Check() error {
	if err := s.Connect(); err != nil {
		return err
	}

	_, err := s.Conn.Search(ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"",
		[]string{},
		nil,
	))

	return err
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

func (s *Service) connectAndBind() error {
	if err := s.Connect(); err != nil {
		return err
	}

	return s.bindByEnvVars()
}

func (s *Service) Authenticate(username, password string) (bool, map[string]string, error) {
	if err := s.connectAndBind(); err != nil {
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
	return ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(s.UserFilter, username),
		[]string{"sAMAccountName", "mail"},
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
	user := map[string]string{"dn": s.getDNBySearchResult(searchResult)}

	for _, attr := range []string{"sAMAccountName", "mail"} {
		if value := searchResult.Entries[0].GetAttributeValue(attr); value != "" {
			user[attr] = value
		} else {
			user[attr] = searchResult.Entries[0].GetAttributeValue(strings.ToLower(attr))
		}
	}

	return user
}

func (s *Service) GetGroupsOfUser(userDN string) ([]string, error) {
	if err := s.connectAndBind(); err != nil {
		return nil, err
	}

	return s.getGroupsByDN(userDN)
}

func (s *Service) getGroupsByDN(userDN string) ([]string, error) {
	searchResult, err := s.Conn.Search(s.newSearchRequestByGroupMember(userDN))
	if err != nil {
		return nil, err
	}

	return s.getGroupsNames(searchResult), nil
}

func (s *Service) newSearchRequestByGroupMember(userDN string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		s.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", userDN),
		[]string{"cn"},
		nil,
	)
}

func (s *Service) getGroupsNames(searchResult *ldap.SearchResult) []string {
	var groups []string

	for _, entry := range searchResult.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups
}
