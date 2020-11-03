package entities

import "encoding/json"

type UserRepresentation struct {
	Username string `json:"username"`
	Email string `json:"email"`
	EmailVerified bool `json:"emailVerified"`
	Enabled bool `json:"enabled"`
}

type UserRepresentationCredentials struct {
	Temporary bool `json:"temporary"`
	Type string `json:"type"`
	Value string `json:"value"`
}

func (u *UserRepresentation) ToBytes() []byte {
	content, _ := json.Marshal(u)
	return content
}

func (u *UserRepresentationCredentials) ToBytes() []byte {
	content, _ := json.Marshal(u)
	return content
}
