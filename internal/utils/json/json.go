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

func ConvertInterfaceToMapString(input interface{}) (output map[string]string, err error) {
	if input != nil {
		if _, ok := input.(map[string]string); ok {
			return input.(map[string]string), nil
		}
		if _, ok := input.(string); ok {
			return output, json.Unmarshal([]byte(input.(string)), &output)
		}
		bytes, err := json.Marshal(input)
		if err != nil {
			return map[string]string{}, nil
		}
		return output, json.Unmarshal(bytes, &output)
	}
	return map[string]string{}, nil
}
