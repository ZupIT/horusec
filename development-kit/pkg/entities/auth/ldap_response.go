package auth

import "time"

type LdapAuthResponse struct {
	AccessToken        string    `json:"accessToken"`
	ExpiresAt          time.Time `json:"expiresAt"`
	Username           string    `json:"username"`
	Email              string    `json:"email"`
	IsApplicationAdmin bool      `json:"isApplicationAdmin"`
}
