package errors

import "errors"

var ErrorInvalidAuthType = errors.New("{ACCOUNT} invalid auth type, should be ldap, keycloak or horus")
