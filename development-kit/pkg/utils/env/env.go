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

package env

import (
	"os"
	"strconv"
	"strings"
)

func GetEnvOrDefault(env, defaultValue string) (value string) {
	if value = os.Getenv(env); value == "" {
		return defaultValue
	}

	return value
}

func GetEnvOrDefaultInt(env string, defaultValue int) int {
	value, err := strconv.Atoi(os.Getenv(env))
	if err != nil {
		return defaultValue
	}

	return value
}

func GetEnvOrDefaultInt64(env string, defaultValue int64) int64 {
	value, err := strconv.Atoi(os.Getenv(env))
	if err != nil {
		return defaultValue
	}

	return int64(value)
}

func GetEnvOrDefaultBool(env string, defaultValue bool) bool {
	value := os.Getenv(env)
	if value == "" {
		return defaultValue
	}

	return strings.EqualFold(value, "true") || value == "1"
}

func GetEnvOrDefaultInterface(env string, defaultValue interface{}) interface{} {
	value := os.Getenv(env)
	if value == "" {
		return defaultValue
	}

	return value
}

func GetHorusecManagerURL() string {
	return GetEnvOrDefault("HORUSEC_MANAGER_URL", "http://localhost:8043")
}
