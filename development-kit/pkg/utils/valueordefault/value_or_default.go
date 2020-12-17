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

package valueordefault

import "os"

func GetStringValueOrDefault(data, defaultValue string) string {
	if data != "" {
		return data
	}

	return defaultValue
}
func GetPathOrCurrentPath(path string) string {
	if path != "" {
		return path
	}
	currentPath, err := os.Getwd()
	if err != nil {
		return "./"
	}
	return currentPath
}
func GetInt64ValueOrDefault(data, defaultValue int64) int64 {
	if data != 0 {
		return data
	}

	return defaultValue
}

func GetSliceStringValueOrDefault(data, defaultValue []string) []string {
	if len(data) > 0 {
		return data
	}

	return defaultValue
}
func GetMapStringStringValueOrDefault(data, defaultValue map[string]string) map[string]string {
	if len(data) > 0 {
		return data
	}

	return defaultValue
}
func GetInterfaceValueOrDefault(data, defaultValue interface{}) interface{} {
	if data != nil {
		if _, ok := data.(map[string]interface{}); ok {
			if len(data.(map[string]interface{})) == 0 {
				return defaultValue
			}
		}
		return data
	}

	return defaultValue
}
