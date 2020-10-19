package ldapconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLdapClieent(t *testing.T) {
	t.Run("should creates a new ldap client", func(t *testing.T) {
		ldapClient := NewLDAPClient()
		assert.NotNil(t, ldapClient)
	})
}
