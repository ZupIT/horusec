package dto

import (
	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Run("should return no error when valid data", func(t *testing.T) {
		updateManagementData := &UpdateManagementData{
			Status: horusecEnum.Approved,
			Type:   horusecEnum.RiskAccepted,
		}

		err := updateManagementData.Validate()
		assert.NoError(t, err)
	})

	t.Run("should return error invalid type", func(t *testing.T) {
		updateManagementData := &UpdateManagementData{
			Status: horusecEnum.Approved,
			Type:   "test",
		}

		err := updateManagementData.Validate()
		assert.Error(t, err)
		assert.Equal(t, "type: must be a valid value.", err.Error())
	})

	t.Run("should return error invalid status", func(t *testing.T) {
		updateManagementData := &UpdateManagementData{
			Status: "test",
			Type:   horusecEnum.RiskAccepted,
		}

		err := updateManagementData.Validate()
		assert.Error(t, err)
		assert.Equal(t, "status: must be a valid value.", err.Error())
	})
}
