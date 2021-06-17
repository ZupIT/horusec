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
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func GetSubPathByExtension(projectPath, subPath, ext string) (finalPath string) {
	pathToWalk := setProjectPathWithSubPath(projectPath, subPath)
	_ = filepath.Walk(pathToWalk, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if result := verifyMathAndFormat(projectPath, walkPath, ext); result != "" {
			finalPath = result
			return io.EOF
		}
		return nil
	})

	return finalPath
}

func setExtension(ext string) string {
	return "*" + ext
}

func verifyMathAndFormat(projectPath, walkPath, ext string) string {
	matched, err := filepath.Match(setExtension(ext), filepath.Base(walkPath))
	if err != nil {
		return ""
	}

	if matched {
		return formatExtPath(projectPath, walkPath)
	}

	return ""
}

func setProjectPathWithSubPath(projectPath, projectSubPath string) string {
	if projectSubPath != "" {
		projectPath += "/"
		projectPath += projectSubPath
	}

	return projectPath
}

func formatExtPath(projectPath, walkPath string) string {
	basePathRemoved := strings.ReplaceAll(walkPath, projectPath, "")
	extensionFileRemoved := strings.ReplaceAll(basePathRemoved, filepath.Base(walkPath), "")

	if extensionFileRemoved != "" && extensionFileRemoved[0:1] == "/" {
		extensionFileRemoved = extensionFileRemoved[1:]
	}

	return extensionFileRemoved
}

func GetFilenameByExt(projectPath, subPath, ext string) (filename string) {
	pathToWalk := setProjectPathWithSubPath(projectPath, subPath)
	_ = filepath.Walk(pathToWalk, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(walkPath) == ext {
			filename = filepath.Base(walkPath)
			return io.EOF
		}

		return nil
	})

	return filename
}

func GetCode(projectPath, filepath string, desiredLine string) string {
	path := fmt.Sprintf("%s%s%s", projectPath, string(os.PathSeparator), filepath)

	file, err := os.Open(path)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(getCodeFromFileAndLine(file, getLine(desiredLine)))
}

func getLine(desiredLine string) int {
	desiredLineParsed, _ := strconv.Atoi(desiredLine)
	if desiredLineParsed <= 0 {
		return desiredLineParsed
	}

	return desiredLineParsed - 1
}

func getCodeFromFileAndLine(file *os.File, desiredLine int) string {
	var line int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line == desiredLine {
			return scanner.Text()
		}

		line++
	}

	return ""
}
