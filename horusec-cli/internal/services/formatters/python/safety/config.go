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

// nolint
package safety

import "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"

const (
	ImageRepository = docker.DefaultRepository
	ImageName       = "horuszup/safety"
	ImageTag        = "v1.0.0"
	ImageCmd        = `
		{{WORK_DIR}}
      touch /tmp/warning-ANALYSISID
	  touch /tmp/output-ANALYSISID.json
	  touch /tmp/errorRunning-ANALYSISID
	  if [ -f Pipfile.lock ]; then
		jq -r '.default | to_entries[] | if (.value.version | length) > 0 then "\(.key)\(.value.version)" else "\(.key)" end' Pipfile.lock >> requirements.txt
		sort -u -o requirements.txt requirements.txt
	  fi
	  find . -maxdepth 3 -name requirements.txt -exec cat {} \; > safety_horusec_analysis_all_requirements-ANALYSISID.txt
	  if [ -s safety_horusec_analysis_all_requirements-ANALYSISID.txt ]; then
		cat safety_horusec_analysis_all_requirements-ANALYSISID.txt | grep '=' | grep -v '#' 1> safety_horusec_analysis_requirements_raw-ANALYSISID.txt
		sed -i -e 's/>=/==/g; s/<=/==/g' safety_horusec_analysis_requirements_raw-ANALYSISID.txt
		cat safety_horusec_analysis_requirements_raw-ANALYSISID.txt | cut -f1 -d "," > safety_horusec_analysis_requirements-ANALYSISID.txt
		safety check -r safety_horusec_analysis_requirements-ANALYSISID.txt --json > /tmp/safety_horusec_analysis_output-ANALYSISID.json 2> /tmp/errorRunning-ANALYSISID
		safety check -r safety_horusec_analysis_requirements_raw-ANALYSISID.txt --json > /dev/null 2> /tmp/warning-ANALYSISID
		if [ -f /tmp/warning-ANALYSISID ]; then
		  if grep -q "unpinned requirement" "/tmp/warning-ANALYSISID"; then
			cat /tmp/warning-ANALYSISID
		  fi
		  jq -c '{"issues":map({"dependency": .[0], "vulnerable_below": .[1], "installed_verson": .[2], "description": .[3], "id": .[4]})}' /tmp/safety_horusec_analysis_output-ANALYSISID.json > /tmp/output-ANALYSISID.json
		  cat /tmp/output-ANALYSISID.json
		else
		  echo "ERROR_RUNNING_SAFETY"
		  cat /tmp/errorRunning-ANALYSISID
		fi
	  else
		echo "ERROR_REQ_NOT_FOUND"
	  fi
	  chmod -R 777 .
  `
)
