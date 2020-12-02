package admin

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateApplicationAdmin(t *testing.T) {
	t.Run("Should not execute auto create default application admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		config := app.NewConfig()
		assert.NotPanics(t, func() {
			CreateApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should execute auto create default application admin with success", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(1, nil, nil))
		config := app.NewConfig()
		config.EnableApplicationAdmin = true
		assert.NotPanics(t, func() {
			CreateApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error because application admin is setup wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(1, nil, nil))
		config := app.NewConfig()
		config.ApplicationAdminData = "some wrong content"
		config.EnableApplicationAdmin = true
		assert.Panics(t, func() {
			CreateApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error because is duplicated content in database", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("pq: duplicate key value violates unique constraint \"accounts_email_key\""), nil))
		config := app.NewConfig()
		config.EnableApplicationAdmin = true
		assert.NotPanics(t, func() {
			CreateApplicationAdmin(config, mockRead, mockWrite)
		})
	})
	t.Run("Should return error unexpected of the database", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("unexpected error"), nil))
		config := app.NewConfig()
		config.EnableApplicationAdmin = true
		assert.Panics(t, func() {
			CreateApplicationAdmin(config, mockRead, mockWrite)
		})
	})
}
