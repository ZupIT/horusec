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

package gitleaks

// CMD contains the necessary code to execute Gitleaks inside the container. The 'git config diff.renames 0' command
// it's necessary to avoid the 'inexact rename detection was skipped due to too many files' error in big projects.
const CMD = `
	{{WORK_DIR}}
	git config diff.renames 0
	if ! gitleaks detect -c /rules/rules.toml -f json -r /tmp/leaks.json --exit-code 0 &> /tmp/leaks-output.txt; then
		cat /tmp/leaks-output.txt
	else
		cat /tmp/leaks.json
	fi
  `
