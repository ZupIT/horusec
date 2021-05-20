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

package shellcheck

const CMD = `
		{{WORK_DIR}}
		shell_files=$(printf "$(find . -type f -name "*.sh")" | tr '\n' ' ')
		bat_files=$(printf "$(find . -type f -name "*.bat")" | tr '\n' ' ')
		if [ ! "$shell_files" ]; then
			if [ ! "$bat_files" ]; then
				return 0
			fi
			shellcheck --format=json $bat_files
		else
			if [ ! "$bat_files" ]; then
				shellcheck --format=json $shell_files
			else
				shellcheck --format=json $shell_files $bat_files
			fi
		fi
  `
