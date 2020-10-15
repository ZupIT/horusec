package auth

import (
	"encoding/json"
	auth "github.com/ZupIT/horusec/development-kit/pkg/entities/credentials"
	"io"
)

type IUseCases interface {
	NewCredentialsFromReadCloser(body io.ReadCloser) (*auth.Credentials, error)
}

type UseCases struct {
}

func NewAuthUseCases() IUseCases {
	return &UseCases{}
}

func (u *UseCases) NewCredentialsFromReadCloser(body io.ReadCloser) (*auth.Credentials, error) {
	credentials := &auth.Credentials{}
	err := json.NewDecoder(body).Decode(&credentials)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return credentials, credentials.Validate()
}
