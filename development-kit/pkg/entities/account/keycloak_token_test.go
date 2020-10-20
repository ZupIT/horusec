package account

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLivePassTokenToBytes(t *testing.T) {
	t.Run("should success parse to bytes", func(t *testing.T) {
		livePassToken := &LivePassToken{}
		assert.NotEmpty(t, livePassToken.ToBytes())
	})
}

func TestLivePassTokenValidate(t *testing.T) {
	t.Run("should return no error when not empty", func(t *testing.T) {
		livePassToken := &LivePassToken{AccessToken: "test"}
		assert.NoError(t, livePassToken.Validate())
	})

	t.Run("should return error when empty access token", func(t *testing.T) {
		livePassToken := &LivePassToken{}
		assert.Error(t, livePassToken.Validate())
	})
}
