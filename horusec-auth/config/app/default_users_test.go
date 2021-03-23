package app

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateDefaultUser(t *testing.T) {
	t.Run("Should not execute auto create default user", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		config := NewConfig()
		config.EnableDefaultUser = false
		assert.NotPanics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
	t.Run("Should not execute auto create default user with keycloak auth", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		config := NewConfig()
		config.EnableDefaultUser = true
		config.AuthType = authEnums.Keycloak
		assert.NotPanics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
	t.Run("Should not execute auto create default user with ldap auth", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		config := NewConfig()
		config.EnableDefaultUser = true
		config.AuthType = authEnums.Ldap
		assert.NotPanics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
	t.Run("Should execute auto create default user with success", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(1, nil, nil))
		config := NewConfig()
		assert.NotPanics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
	t.Run("Should execute auto create default user with error of user already exists", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		err := errors.New("duplicate key value violates unique constraint \"accounts_email_key\"")
		mockWrite.On("Create").Return(response.NewResponse(0, err, nil))
		config := NewConfig()
		assert.NotPanics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
	t.Run("Should execute auto create default user with error unexpected", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		err := errors.New("unexpected error")
		mockWrite.On("Create").Return(response.NewResponse(0, err, nil))
		config := NewConfig()
		assert.Panics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error when error when is not possible parse environment content to struct", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, nil, nil))
		config := NewConfig()
		config.EnableApplicationAdmin = true
		config.DefaultUserData = "some unexpected data"
		assert.Panics(t, func() {
			CreateDefaultUser(config, mockRead, mockWrite)
		})
	})
}

func TestCreateDefaultApplicationAdmin(t *testing.T) {
	t.Run("Should not execute auto create default application admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		config := NewConfig()
		assert.NotPanics(t, func() {
			CreateDefaultApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should execute auto create default application admin with success", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(1, nil, nil))
		config := NewConfig()
		config.EnableApplicationAdmin = true
		assert.NotPanics(t, func() {
			CreateDefaultApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error because application admin is setup wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(1, nil, nil))
		config := NewConfig()
		config.ApplicationAdminData = "some wrong content"
		config.EnableApplicationAdmin = true
		assert.Panics(t, func() {
			CreateDefaultApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error because is duplicated content in database", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("duplicate key value violates unique constraint \"accounts_email_key\""), nil))
		config := NewConfig()
		config.EnableApplicationAdmin = true
		assert.NotPanics(t, func() {
			CreateDefaultApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error when error when is not possible parse environment content to struct", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, nil, nil))
		config := NewConfig()
		config.EnableApplicationAdmin = true
		config.ApplicationAdminData = "some unexpected data"
		assert.Panics(t, func() {
			CreateDefaultApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error unexpected of the database", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("unexpected error"), nil))
		config := NewConfig()
		config.EnableApplicationAdmin = true
		assert.Panics(t, func() {
			CreateDefaultApplicationAdmin(config, mockRead, mockWrite)
		})
	})
}

func TestUserIsDuplicated(t *testing.T) {
	assert.False(t, userIsDuplicated(nil))
}