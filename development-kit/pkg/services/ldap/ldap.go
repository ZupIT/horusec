package ldap

import (
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	goldapclient "github.com/jtblin/go-ldap-client"
)

type ILDAPService interface {
	Authenticate(username, password string) (bool, map[string]string, error)
}

type LDAPService struct {
	client goldapclient.LDAPClient
}

func NewLDAPClient() ILDAPService {
	client := goldapclient.LDAPClient{
		Base:               env.GetEnvOrDefault("HORUS_LDAP_BASE", ""),
		Host:               env.GetEnvOrDefault("HORUS_LDAP_HOST", ""),
		Port:               env.GetEnvOrDefaultInt("HORUS_LDAP_PORT", 0),
		UseSSL:             env.GetEnvOrDefaultBool("HORUS_LDAP_USESSL", false),
		SkipTLS:            env.GetEnvOrDefaultBool("HORUS_LDAP_SKIP_TLS", true),
		InsecureSkipVerify: env.GetEnvOrDefaultBool("HORUS_LDAP_INSECURE_SKIP_VERIFY", true),
		BindDN:             env.GetEnvOrDefault("HORUS_LDAP_BINDDN", ""),
		BindPassword:       env.GetEnvOrDefault("HORUS_LDAP_BINDPASSWORD", ""),
		UserFilter:         env.GetEnvOrDefault("HORUS_LDAP_USERFILTER", ""),
		GroupFilter:        env.GetEnvOrDefault("HORUS_LDAP_GROUPFILTER", ""),
	}

	return &LDAPService{
		client: client,
	}
}

func (s *LDAPService) Authenticate(username, password string) (bool, map[string]string, error) {
	return s.client.Authenticate(username, password)
}

func (s *LDAPService) GetGroupsOfUser(username string) ([]string, error) {
	return s.client.GetGroupsOfUser(username)
}
