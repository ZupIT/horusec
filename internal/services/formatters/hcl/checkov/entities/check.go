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

package entities

import (
	"fmt"
	"strconv"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type Check struct {
	CheckID       string  `json:"check_id"`
	BCCheckID     string  `json:"bc_check_id"`
	CheckName     string  `json:"check_name"`
	FilePath      string  `json:"file_path"`
	FileAbsPath   string  `json:"file_abs_path"`
	RepoFilePath  string  `json:"repo_file_path"`
	FileLineRange [2]int  `json:"file_line_range"`
	Resource      string  `json:"resource"`
	Guideline     *string `json:"guideline"`
}

func (c *Check) GetDetails() string {
	return fmt.Sprintf("%s -> [%s]", c.CheckID, c.CheckName)
}

func (c *Check) GetStartLine() string {
	return strconv.Itoa(c.FileLineRange[0])
}

func (c *Check) GetCode() string {
	return fmt.Sprintf("code beetween line %d and %d.", c.FileLineRange[0], c.FileLineRange[1])
}

func (c *Check) GetFilename() string {
	return c.FileAbsPath
}

func (c *Check) GetSeverity() severities.Severity {
	return severities.Unknown
}
