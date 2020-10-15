package auth

type AuthorizationType string

const (
	Keycloak AuthorizationType = "keycloak"
	Ldap     AuthorizationType = "ldap"
	Horus    AuthorizationType = "horus"
)

func (a AuthorizationType) IsInvalid() bool {
	for _, v := range a.Values() {
		if v == a {
			return false
		}
	}

	return true
}

func (a AuthorizationType) Values() []AuthorizationType {
	return []AuthorizationType{
		Keycloak,
		Ldap,
		Horus,
	}
}
