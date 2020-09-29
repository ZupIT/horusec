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

package horusec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMonitor(t *testing.T) {
	t.Run("should creates a Monitor instance", func(t *testing.T) {
		monitor := NewMonitor()
		assert.NotNil(t, monitor)
	})
}

func TestAddProcess(t *testing.T) {
	t.Run("should increment processes and start the monitor", func(t *testing.T) {
		monitor := NewMonitor()
		monitor.AddProcess(1)
		assert.True(t, monitor.IsRunning())
		assert.Equal(t, 1, monitor.GetProcess())
	})
}

func TestRemoveProcess(t *testing.T) {
	t.Run("should decrement processes and stop the monitor", func(t *testing.T) {
		monitor := NewMonitor()
		monitor.AddProcess(1)
		monitor.RemoveProcess(1)

		assert.True(t, monitor.IsFinished())
		assert.Equal(t, 0, monitor.GetProcess())
	})
}
