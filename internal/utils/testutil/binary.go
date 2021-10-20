// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/onsi/ginkgo"
)

func GomegaBuildHorusecBinary(customArgs ...string) string {
	binary := filepath.Join(os.TempDir(), "horusec-e2e")
	args := []string{
		"build",
		`-ldflags=-X 'github.com/ZupIT/horusec/cmd/app/version.Version=vTest'`,
		fmt.Sprintf("-o=%s", binary), filepath.Join(RootPath, "cmd", "app"),
	}
	args = append(args, customArgs...)

	cmd := exec.Command("go", args...)
	err := cmd.Run()

	if err != nil {
		ginkgo.Fail(fmt.Sprintf("Error on build Horusec binary for e2e test %v", err))
	}
	return binary
}
