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

package gosec

const (
	ImageName = "horuszup/gosec"
	ImageTag  = "v1.0.0"
	//nolint
	ImageCmd = `
		{{WORK_DIR}}
		touch /tmp/results-ANALYSISID.json
		$(which gosec) -quiet -fmt=json -log=log-ANALYSISID.txt -out=/tmp/results-ANALYSISID.json ./... 2> /dev/null
		jq -j -M -c . /tmp/results-ANALYSISID.json
		chmod -R 777 .
	`
)
