package errors

import "errors"

var ErrorInvalidAuthType = errors.New("{AUTH} invalid auth type, should be ldap, keycloak or horus")

const ErrorAuthTypeNotActive = "{AUTH} this auth type it is no active, should be %s"
