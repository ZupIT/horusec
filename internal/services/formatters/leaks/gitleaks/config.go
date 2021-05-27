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

//nolint
package gitleaks

const CMD = `
		{{WORK_DIR}}
		touch /tmp/results-ANALYSISID.json /tmp/error-ANALYSISID.txt
		gitleaks --config-path="/rules/rules.toml" --path="./" --leaks-exit-code="0" --verbose --report="/tmp/results-ANALYSISID.json" &> /tmp/error-ANALYSISID.txt
		if [ $? -eq 0 ];
		then
            jq -j -M -c . /tmp/results-ANALYSISID.json
        else
            cat /tmp/error-ANALYSISID.txt
        fi
  `
