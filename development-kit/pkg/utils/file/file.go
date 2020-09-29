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

package file

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func GetAbsFilePathIntoBasePath(filePath, basePath string) string {
	bytes, err := exec.Command("find", basePath, "-type", "f").Output()
	if err != nil {
		return filePath
	}
	for _, path := range strings.Split(string(bytes), "\n") {
		if strings.Contains(path, filePath) {
			absPath, _ := filepath.Abs(path)
			return absPath
		}
	}
	return filePath
}

func GetPathIntoFilename(filename, basePath string) string {
	bytes, err := exec.Command("find", basePath, "-type", "f").Output()
	if err != nil {
		return ""
	}
	for _, path := range strings.Split(string(bytes), "\n") {
		if strings.Contains(path, filename) {
			if isSameExtensions(filename, path) {
				return strings.ReplaceAll(path, basePath, "")
			}
		}
	}
	return ""
}

func isSameExtensions(filename, path string) bool {
	filenameExt := filepath.Ext(filename)
	basePathExt := filepath.Ext(path)
	return filenameExt == basePathExt
}

func ReplacePathSeparator(path string) string {
	return strings.ReplaceAll(path, "/", string(os.PathSeparator))
}
