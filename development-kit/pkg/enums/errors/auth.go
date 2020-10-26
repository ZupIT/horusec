package errors

import "errors"

var ErrorInvalidAuthType = errors.New("{AUTH} invalid auth type, should be ldap, keycloak or horus")
var ErrorTokenCanNotBeEmpty = errors.New("{AUTH} token can not be empty in authorization header")

const ErrorAuthTypeNotActive = "{AUTH} this auth type it is no active, should be %s"
