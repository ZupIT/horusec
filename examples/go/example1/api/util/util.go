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
