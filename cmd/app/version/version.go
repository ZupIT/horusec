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

package version

import (
	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/config/dist"
)

var (
	Version = "{{VERSION_NOT_FOUND}}"
	Commit  = "{{COMMIT_NOT_FOUND}}"
	Date    = "{{DATE_NOT_FOUND}}"
)

func CreateCobraCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Shows the current version of installed Horusec",
		Example: "horusec version",
		RunE: func(cmd *cobra.Command, args []string) error {
			printVersionInfo()
			return nil
		},
	}
}

func printVersionInfo() {
	logger.LogPrint("Version:          " + Version)
	logger.LogPrint("Git commit:       " + Commit)
	logger.LogPrint("Built:            " + Date)
	logger.LogPrint("Distribution:     " + dist.GetVersion())
}
