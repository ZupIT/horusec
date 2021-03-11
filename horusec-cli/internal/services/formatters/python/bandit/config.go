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

package bandit

const (
	ImageName = "horuszup/horusec-python"
	ImageTag  = "v1.0.0"
	ImageCmd  = `
		{{WORK_DIR}}
      	chmod +x /usr/local/bin/horusec-file-ignore.sh
      	horusec-file-ignore.sh 2> /tmp/errorBanditIgnoreScript-ANALYSISID 1> /dev/null
      	bandit -r . -f json 2> /dev/null > results-ANALYSISID.json
      	jq -j -M -c . results-ANALYSISID.json
  `
)
