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

type Message struct {
	RuleID    string `json:"ruleId"`
	Severity  int    `json:"severity"`
	Message   string `json:"message"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	NodeType  string `json:"nodeType"`
	MessageID string `json:"messageId"`
	EndLine   int    `json:"endLine"`
	EndColumn int    `json:"endColumn"`
}

type Output struct {
	FilePath            string     `json:"filePath"`
	Messages            *[]Message `json:"messages"`
	ErrorCount          int        `json:"errorCount"`
	WarningCount        int        `json:"warningCount"`
	FixableErrorCount   int        `json:"fixableErrorCount"`
	FixableWarningCount int        `json:"fixableWarningCount"`
	Source              string     `json:"source"`
}
