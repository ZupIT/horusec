// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package entities

import (
	"fmt"
	"strings"
)

type Rule struct {
	ID              string  `json:"id"`
	FullDescription Message `json:"fullDescription"`
	HelpURI         string  `json:"helpUri"`
}

func (r *Rule) getFullDescription() string {
	fullDescription := strings.ReplaceAll(r.FullDescription.Text, "{", "")
	fullDescription = strings.ReplaceAll(fullDescription, "}", "")
	return fullDescription
}

func (r *Rule) GetDescription(vulnName string) string {
	return fmt.Sprintf("%s\n%s For more information, check the following url (%s).",
		vulnName, r.getFullDescription(), r.HelpURI)
}
