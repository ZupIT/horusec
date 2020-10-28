package account

import "github.com/google/uuid"

type CreateAccountFromKeycloakResponse struct {
	AccountID          uuid.UUID `json:"accountID"`
	Username           string    `json:"username"`
	Email              string    `json:"email"`
	IsApplicationAdmin bool      `json:"isApplicationAdmin"`
}
