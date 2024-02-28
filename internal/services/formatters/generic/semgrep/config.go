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

package semgrep
                  //removed --config=p/r2c-ci from the command 
				//  specifies a Semgrep configuration to use. In this case, it seems to be referencing a configuration named r2c-ci provided by the p organization or repository.
const CMD = ` 
	    {{WORK_DIR}}
		semgrep scan --config auto -q --json .
  `

