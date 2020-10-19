package ldapconfig

import (
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/jtblin/go-ldap-client"
)

func NewLDAPClient() ldap.LDAPClient {
	client := ldap.LDAPClient{
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
	defer client.Close()

	return client
}
