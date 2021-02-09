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

package npmaudit

const (
	ImageName = "horuszup/npmaudit"
	ImageTag  = "v1.0.0"
	ImageCmd  = `
		{{WORK_DIR}}
      if [ -f package-lock.json ]; then
        npm audit --only=prod --json > /tmp/results-ANALYSISID.json 2> /tmp/errorNpmaudit-ANALYSISID
        jq -j -M -c . /tmp/results-ANALYSISID.json
      else
        if [ ! -f yarn.lock ]; then
          echo 'ERROR_PACKAGE_LOCK_NOT_FOUND'
        fi
      fi
	  chmod -R 777 .
  `
)
