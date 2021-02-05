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
	"errors"
	"testing"
	"time"

	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockLdapConn struct {
	mock.Mock
}

func (m *MockLdapConn) Start() {
	_ = m.MethodCalled("Start")
}

func (m *MockLdapConn) Close() {
	_ = m.MethodCalled("Close")
}

func (m *MockLdapConn) SetTimeout(timeout time.Duration) {
	_ = m.MethodCalled("SetTimeout")
}

func (m *MockLdapConn) StartTLS(config *tls.Config) error {
	args := m.MethodCalled("StartTLS")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *MockLdapConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := m.MethodCalled("Search")
	return args.Get(0).(*ldap.SearchResult), mockUtils.ReturnNilOrError(args, 1)
}

func (m *MockLdapConn) Bind(username, password string) error {
	args := m.MethodCalled("Bind")
	return mockUtils.ReturnNilOrError(args, 0)
}

func TestNewLDAPClient(t *testing.T) {
	t.Run("should create a new ldap client instance", func(t *testing.T) {
		ldapClient := NewLDAPClient()
		assert.NotNil(t, ldapClient)
	})
}

func TestConnect(t *testing.T) {
	t.Run("should return error when connecting without ssl", func(t *testing.T) {
		service := Service{}

		err := service.Connect()

		assert.Error(t, err)
	})

	t.Run("should return error when connecting with ssl", func(t *testing.T) {
		service := Service{
			UseSSL:             true,
			ClientCertificates: []tls.Certificate{{}},
		}

		err := service.Connect()

		assert.Error(t, err)
	})
}

func TestAuthenticate(t *testing.T) {
	t.Run("should success authenticate", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{Entries: []*ldap.Entry{{DN: "test",
			Attributes: []*ldap.EntryAttribute{{Name: "test", Values: []string{"test"}}}}}}, nil)

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		isValid, data, err := service.Authenticate("test", "test")

		assert.NoError(t, err)
		assert.True(t, isValid)
		assert.NotNil(t, data)
	})

	t.Run("should return error too many entries", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{Entries: []*ldap.Entry{{}, {}}}, nil)

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		isValid, data, err := service.Authenticate("test", "test")

		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorTooManyEntries, err)
		assert.False(t, isValid)
		assert.Nil(t, data)
	})

	t.Run("should return error user does not exist", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{}, nil)

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		isValid, data, err := service.Authenticate("test", "test")

		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorUserDoesNotExist, err)
		assert.False(t, isValid)
		assert.Nil(t, data)
	})

	t.Run("should return error when empty bind user or password", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{}, nil)

		service := Service{
			Conn: ldapMock,
		}

		isValid, data, err := service.Authenticate("test", "test")

		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorEmptyBindDNOrBindPassword, err)
		assert.False(t, isValid)
		assert.Nil(t, data)
	})

	t.Run("should return error when while searching", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{}, errors.New("test"))

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		isValid, data, err := service.Authenticate("test", "test")

		assert.Error(t, err)
		assert.False(t, isValid)
		assert.Nil(t, data)
	})

	t.Run("should return when binding with user data", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Once().Return(nil)
		ldapMock.On("Bind").Return(errors.New("test"))
		ldapMock.On("Search").Return(&ldap.SearchResult{Entries: []*ldap.Entry{{DN: "test",
			Attributes: []*ldap.EntryAttribute{{Name: "test", Values: []string{"test"}}}}}}, nil)

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		isValid, data, err := service.Authenticate("test", "test")

		assert.Error(t, err)
		assert.False(t, isValid)
		assert.Nil(t, data)
	})

	t.Run("should return error when failed to connect", func(t *testing.T) {
		service := Service{}

		isValid, data, err := service.Authenticate("test", "test")

		assert.Error(t, err)
		assert.False(t, isValid)
		assert.Nil(t, data)
	})
}

func TestClose(t *testing.T) {
	t.Run("should success close connection", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Close").Return(nil)

		service := Service{
			Conn: ldapMock,
		}

		assert.NotPanics(t, func() {
			service.Close()
		})
	})
}

func TestGetGroupsOfUser(t *testing.T) {
	t.Run("should success get groups", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{Entries: []*ldap.Entry{{DN: "test",
			Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"test"}}}}}}, nil)

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		groups, err := service.GetGroupsOfUser("test")

		assert.NotEmpty(t, groups)
		assert.NoError(t, err)
	})

	t.Run("should return error while searching groups", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(nil)
		ldapMock.On("Search").Return(&ldap.SearchResult{}, errors.New("test"))

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		groups, err := service.GetGroupsOfUser("test")

		assert.Nil(t, groups)
		assert.Error(t, err)
	})

	t.Run("should return error while biding with env vars", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Bind").Return(errors.New("test"))

		service := Service{
			BindDN:       "test",
			BindPassword: "test",
			Conn:         ldapMock,
		}

		groups, err := service.GetGroupsOfUser("test")

		assert.Nil(t, groups)
		assert.Error(t, err)
	})

	t.Run("should return error while connecting", func(t *testing.T) {
		service := Service{}

		groups, err := service.GetGroupsOfUser("test")

		assert.Nil(t, groups)
		assert.Error(t, err)
	})
}

func TestCheck(t *testing.T) {
	t.Run("should return no true when ldap is healthy", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Search").Return(&ldap.SearchResult{}, nil)

		service := Service{
			Conn: ldapMock,
		}

		assert.True(t, service.IsAvailable())
	})

	t.Run("should return false when ldap is not healthy", func(t *testing.T) {
		ldapMock := &MockLdapConn{}

		ldapMock.On("Search").Return(&ldap.SearchResult{}, errors.New("test"))

		service := Service{
			Conn: ldapMock,
		}

		assert.False(t, service.IsAvailable())
	})

	t.Run("should return false when connecting to ldap return error", func(t *testing.T) {
		service := Service{}

		assert.False(t, service.IsAvailable())
	})
}
