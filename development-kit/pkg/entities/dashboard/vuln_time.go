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

package dashboard

import "time"

type VulnByTime struct {
	Time   time.Time `json:"time"`
	Total  int       `json:"total"`
	Low    int       `json:"low"`
	Medium int       `json:"medium"`
	High   int       `json:"high"`
	Audit  int       `json:"audit"`
	Info   int       `json:"info"`
	NoSec  int       `json:"noSec"`
}
