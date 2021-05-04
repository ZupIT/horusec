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
package yarnaudit

const CMD = `
		{{WORK_DIR}}
        if [ -f yarn.lock ]; then
            yarn audit --groups dependencies --json > /tmp/results-ANALYSISID.json 2> /tmp/errorYarnAudit-ANALYSISID
            if [ ! -s /tmp/errorYarnAudit-ANALYSISID ]; then
                jq -c -M -j --slurp '{advisories: (. | map(select(.type == "auditAdvisory") | .data.advisory)), metadata: (. | map(select(.type == "auditSummary") | .data) | add)}' /tmp/results-ANALYSISID.json > /tmp/output-ANALYSISID.json
                cat /tmp/output-ANALYSISID.json
            else
                echo -n 'ERROR_RUNNING_YARN_AUDIT'
                cat /tmp/errorYarnAudit-ANALYSISID
            fi
        else
            if [ ! -f package-lock.json ]; then
                echo 'ERROR_YARN_LOCK_NOT_FOUND'
            fi
        fi
  `
