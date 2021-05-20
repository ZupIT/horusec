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

package monitor

type Monitor struct {
	process int
	started bool
}

func NewMonitor() *Monitor {
	return &Monitor{
		process: 0,
		started: false,
	}
}

func (m *Monitor) AddProcess(n int) {
	if !m.started {
		m.started = true
	}
	m.process += n
}

func (m *Monitor) RemoveProcess(n int) {
	m.process -= n
}

func (m *Monitor) IsFinished() bool {
	return m.started && m.process <= 0
}

func (m *Monitor) IsRunning() bool {
	return m.started && m.process > 0
}

func (m *Monitor) GetProcess() int {
	return m.process
}
