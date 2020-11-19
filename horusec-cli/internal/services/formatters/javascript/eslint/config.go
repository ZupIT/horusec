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

package eslint

const (
	ImageName = "horuszup/eslint"
	ImageTag  = "v0.0.1"
	ImageCmd  = `
		{{WORK_DIR}}
		eslint \
			--no-eslintrc \
			-f json \
			--resolve-plugins-relative-to /usr/local/lib/node_modules \
			--plugin security \
			--rule 'security/detect-buffer-noassert: warn' \
			--rule 'security/detect-child-process: warn' \
			--rule 'security/detect-disable-mustache-escape: warn' \
			--rule 'security/detect-eval-with-expression: warn' \
			--rule 'security/detect-new-buffer: warn' \
			--rule 'security/detect-no-csrf-before-method-override: warn' \
			--rule 'security/detect-non-literal-fs-filename: warn' \
			--rule 'security/detect-non-literal-regexp: warn' \
			--rule 'security/detect-non-literal-require: warn' \
			--rule 'security/detect-object-injection: warn' \
			--rule 'security/detect-possible-timing-attacks: warn' \
			--rule 'security/detect-pseudoRandomBytes: warn' \
			--rule 'security/detect-unsafe-regex: warn' \
			"*/**/*.{js,ts,tsx}" > /tmp/results.json
		cat /tmp/results.json
	`
)
