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

const (
	ImageName = "horuszup/gitleaks"
	ImageTag  = "v1.0.2"
	// nolint
	ImageCmd = `
		{{WORK_DIR}}
        touch /tmp/results-ANALYSISID.json
        gitleaks --config="/rules/rules.toml" --owner-path=. --verbose --pretty --report="/tmp/results-ANALYSISID.json" &> /tmp/errorGitleaks-ANALYSISID
        if [ $? -eq 2 ]; then
            echo 'ERROR_RUNNING_GITLEAKS'
            cat /tmp/errorGitleaks-ANALYSISID
        else
            jq -j -M -c . /tmp/results-ANALYSISID.json
        fi
		chmod -R 777 .
  `
)
