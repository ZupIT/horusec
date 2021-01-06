// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"errors"
	"testing"

	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/stretchr/testify/assert"
)

func TestLogPanic(t *testing.T) {
	t.Run("should log error and panic", func(t *testing.T) {
		assert.Panics(t, func() { LogPanic("test error", EnumErrors.ErrTest) })
	})

	t.Run("should log error with args and panic", func(t *testing.T) {
		args := map[string]interface{}{"test": "test"}
		assert.Panics(t, func() { LogPanic("test error", EnumErrors.ErrTest, args) })
	})
}

func TestLogError(t *testing.T) {
	t.Run("should log error without panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogError("test error", EnumErrors.ErrTest) })
	})

	t.Run("should log error with args without panic", func(t *testing.T) {
		args := map[string]interface{}{"test": "test"}
		assert.NotPanics(t, func() { LogError("test error", EnumErrors.ErrTest, args) })
	})
}

func TestLogInfo(t *testing.T) {
	t.Run("should log information log without panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogInfo("test") })
	})

	t.Run("should log information log without panic", func(t *testing.T) {
		args := map[string]interface{}{"test": "test"}
		assert.NotPanics(t, func() { LogInfo("test", args) })
	})
}

func TestLogPrint(t *testing.T) {
	t.Run("should log print log without panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogPrint("test") })
	})
}

func TestSetLogLevel(t *testing.T) {
	t.Run("should success set level", func(t *testing.T) {
		assert.NotPanics(t, func() { SetLogLevel(WarnLevel.String()) })
	})

	t.Run("should set info level when invalid value", func(t *testing.T) {
		assert.NotPanics(t, func() { SetLogLevel("test") })
	})
}

func TestLogPanicWithLevel(t *testing.T) {
	SetLogLevel(PanicLevel.String())
	t.Run("should panic with error", func(t *testing.T) {
		assert.Panics(t, func() { LogPanicWithLevel("test", errors.New("test")) })
	})

	t.Run("should panic with args", func(t *testing.T) {
		assert.Panics(t, func() { LogPanicWithLevel("test", errors.New("test"), map[string]interface{}{}) })
	})
}

func TestLogErrorWithLevel(t *testing.T) {
	SetLogLevel(ErrorLevel.String())
	t.Run("should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogErrorWithLevel("test", errors.New("test")) })
	})

	t.Run("should not panic when log with args", func(t *testing.T) {
		assert.NotPanics(t, func() { LogErrorWithLevel("test", errors.New("test"), map[string]interface{}{}) })
	})
}

func TestLogWarnWithLevel(t *testing.T) {
	SetLogLevel(WarnLevel.String())
	t.Run("should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogWarnWithLevel("test") })
	})

	t.Run("should not panic when log with args", func(t *testing.T) {
		assert.NotPanics(t, func() { LogWarnWithLevel("test", map[string]interface{}{}) })
	})
}

func TestLogInfoWithLevel(t *testing.T) {
	SetLogLevel(InfoLevel.String())
	t.Run("should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogInfoWithLevel("test") })
	})

	t.Run("should not panic when log with args", func(t *testing.T) {
		assert.NotPanics(t, func() { LogInfoWithLevel("test", map[string]interface{}{}) })
	})
}

func TestLogDebugWithLevel(t *testing.T) {
	SetLogLevel(DebugLevel.String())
	t.Run("should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogDebugWithLevel("test") })
	})

	t.Run("should not panic when log with args", func(t *testing.T) {
		assert.NotPanics(t, func() { LogDebugWithLevel("test", map[string]interface{}{}) })
	})
}

func TestLogTraceWithLevel(t *testing.T) {
	SetLogLevel(TraceLevel.String())
	t.Run("should not trace", func(t *testing.T) {
		assert.NotPanics(t, func() { LogTraceWithLevel("test") })
	})

	t.Run("should not panic when log with args", func(t *testing.T) {
		assert.NotPanics(t, func() { LogTraceWithLevel("test", map[string]interface{}{}) })
	})
}

func TestLogStringAsError(t *testing.T) {
	t.Run("should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { LogStringAsError("test") })
	})
}
