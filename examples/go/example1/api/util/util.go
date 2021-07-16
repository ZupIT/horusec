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

// nolint
package util

import (
	"crypto/md5"
	"fmt"
	"io"
	"strings"
)

// HandleCmd will extract %GIT_REPO%, %GIT_BRANCH% and %INTERNAL_DEP_URL% from cmd and replace it with the proper repository URL.
func HandleCmd(repositoryURL, repositoryBranch, internalDepURL, cmd string) string {
	if repositoryURL != "" && repositoryBranch != "" && cmd != "" {
		replace1 := strings.Replace(cmd, "%GIT_REPO%", repositoryURL, -1)
		replace2 := strings.Replace(replace1, "%GIT_BRANCH%", repositoryBranch, -1)
		replace3 := strings.Replace(replace2, "%INTERNAL_DEP_URL%", internalDepURL, -1)
		return replace3
	}
	return ""
}

// GetMD5 returns the MD5 of a string.
func GetMD5(s string) string {
	h := md5.New()
	io.WriteString(h, s) // #nohorus
	md5Result := fmt.Sprintf("%x", h.Sum(nil))
	return md5Result
}

// ReturnError will return a nil error.
func ReturnError() error {
	return nil
}
