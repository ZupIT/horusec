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

package json

import (
	"encoding/json"
)

func ConvertInterfaceToOutput(input, output interface{}) error {
	bytes, err := json.Marshal(input)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, &output)
}

func ConvertStringToOutput(input string, output interface{}) error {
	return json.Unmarshal([]byte(input), &output)
}
