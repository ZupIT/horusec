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

package dist

const falseString = "false"

var (
	// standAlone is a build flag used to check if build is stand alone.
	//
	// The value passed is a raw string contaning true or false.
	standAlone string = falseString
)

const (
	// StandAlone represents the build mode without Docker support.
	StandAlone = "stand-alone"

	// Normal represents the build mode with Docker support.
	Normal = "normal"
)

// IsStandAlone check if current build is in StandAlone mode.
func IsStandAlone() bool {
	return standAlone != falseString
}

// Mode return the build mode.
func Mode() string {
	if IsStandAlone() {
		return StandAlone
	}
	return Normal
}
