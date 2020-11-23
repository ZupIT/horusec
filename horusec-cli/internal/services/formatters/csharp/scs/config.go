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

package scs

const (
	ImageName = "horuszup/dotnet-core-3.1"
	ImageTag  = "v1.0.0"
	// nolint
	ImageCmd = `
		{{WORK_DIR}}
		touch /tmp/output_tmp-ANALYSISID.txt
		dotnet add package -n SecurityCodeScan.VS2017 > /tmp/add_packet_output-ANALYSISID.txt
		if [ $? -eq 0 ]; then
			dotnet build --nologo -v q > /tmp/output_tmp-ANALYSISID.txt
		else
			echo "ERROR_ADDING_PACKAGE"
			exit 1
		fi

    	while read -r LINE; do
		
			FILECODE=$(echo ${LINE} | awk -F ":" '{print $1}' | tr -d " ")
			IDDESC=$(echo ${LINE} | awk -F ":" '{print $2}' | awk '{print $1}' | tr -d " ")
			ID=$(echo ${LINE} | awk -F ":" '{print $2}' | awk '{print $2}' | tr -d " ")
			DESC=$(echo ${LINE} | awk -F ":" '{print $3}' | sed 's/^ *//')
		
			echo "{\"Filename\" : \"${FILECODE}\", \"IssueSeverity\" : \"${IDDESC}\", \"ErrorID\" : \"${ID}\", \"IssueText\" : \"${DESC}\"}" >> /tmp/output-ANALYSISID.txt
		
		done < /tmp/output_tmp-ANALYSISID.txt
		
		jq '.' /tmp/output-ANALYSISID.txt > /tmp/result-ANALYSISID.json

      	jq -j -M -c . /tmp/result-ANALYSISID.json
		chmod -R 777 .
  `
)
