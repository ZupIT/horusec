package keycloak

import (
	"errors"
	"github.com/Nerzal/gocloak/v7"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewKeycloakAuthService(t *testing.T) {
	dbRead := &relational.MockRead{}
	k := NewKeycloakAuthService(dbRead)
	assert.NotEmpty(t, k)
}

func TestService_Authenticate(t *testing.T) {
	t.Run("Should run authentication without error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)
		k := &Service{mock}
		content, err := k.Authenticate(&authEntities.Credentials{
			Username: "admin",
			Password: "admin",
		})
		assert.NoError(t, err)
		assert.NotEmpty(t, content)
	})
	t.Run("Should run authentication with error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("LoginOtp").Return(&gocloak.JWT{}, errors.New("unexpected error"))
		k := &Service{mock}
		content, err := k.Authenticate(&authEntities.Credentials{
			Username: "admin",
			Password: "admin",
		})
		assert.Error(t, err)
		assert.Empty(t, content)
	})
}

func TestService_IsAuthorized(t *testing.T) {
	t.Run("Should run is_authorized without error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		email := "some@email.com"
		mock.On("GetUserInfo").Return(&gocloak.UserInfo{
			Email: &email,
		}, nil)

		mock.On("IsActiveToken").Return(true, nil)

		k := &Service{mock}
		isValid, err := k.IsAuthorized(&authEntities.AuthorizationData{
			Token:  "Access token",
			Groups: nil,
		})
		assert.NoError(t, err)
		assert.True(t, isValid)
	})
	t.Run("Should run is_authorized with error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("GetUserInfo").Return(&gocloak.UserInfo{}, errors.New("unexpected error"))

		mock.On("IsActiveToken").Return(false, errors.New("test"))

		k := &Service{mock}
		isValid, err := k.IsAuthorized(&authEntities.AuthorizationData{
			Token:  "Access token",
			Groups: nil,
		})
		assert.Error(t, err)
		assert.False(t, isValid)
	})
}
