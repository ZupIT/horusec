package errors

import "errors"

var ErrorEmptyBindDNOrBindPassword = errors.New("{LDAP} empty bind dn or bind password")
var ErrorUserDoesNotExist = errors.New("{LDAP} user does not exist")
var ErrorTooManyEntries = errors.New("{LDAP} too many entries returned")
