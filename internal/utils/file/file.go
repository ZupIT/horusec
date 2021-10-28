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

package file

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
)

// GetPathFromFilename return the relative file path inside basePath
// that match the filename. Return empty if not found or some error
// occurred.
//
// nolint:funlen,gocyclo
func GetPathFromFilename(filename, basePath string) string {
	var filePath string

	err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, filename) && isSameExtensions(filename, path) {
			p, err := filepath.Rel(basePath, path)
			if err != nil {
				return err
			}
			filePath = p
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		logger.LogError("Error to find filepath", err, map[string]interface{}{
			"filename": filename,
			"basePath": basePath,
		})
		return ""
	}

	return filePath
}

func isSameExtensions(filename, path string) bool {
	filenameExt := filepath.Ext(filename)
	basePathExt := filepath.Ext(path)
	return filenameExt == basePathExt
}

// ReplacePathSeparator replace slashes from path to OS specific.
//
// We usually use this function to replace paths that was returned by
// a tool running on Docker when running on Windows.
func ReplacePathSeparator(path string) string {
	return strings.ReplaceAll(path, "/", string(os.PathSeparator))
}

// GetSubPathByExtension returns the path inside projectPath + subPath that contains
// the files with a given ext inside projectPath.
//
// nolint: funlen
func GetSubPathByExtension(projectPath, subPath, ext string) (finalPath string) {
	pathToWalk := projectPathWithSubPath(projectPath, subPath)
	err := filepath.Walk(pathToWalk, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if result := verifyMatchAndFormat(projectPath, walkPath, ext); result != "" {
			finalPath = result
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		logger.LogError("Error to walk on path", err, map[string]interface{}{
			"path":        pathToWalk,
			"projectPath": projectPath,
			"subPath":     subPath,
			"ext":         ext,
		})
		return ""
	}

	return finalPath
}

func buildPattern(ext string) string {
	return "*" + ext
}

func verifyMatchAndFormat(projectPath, walkPath, ext string) string {
	matched, err := filepath.Match(buildPattern(ext), filepath.Base(walkPath))
	if err != nil || !matched {
		return ""
	}
	return formatExtPath(projectPath, walkPath)
}

func projectPathWithSubPath(projectPath, projectSubPath string) string {
	if projectSubPath != "" {
		projectPath = filepath.Join(projectPath, projectSubPath)
	}

	return projectPath
}

func formatExtPath(projectPath, walkPath string) string {
	// TODO(matheus): This code seems confusing. We should use a better approach here.
	basePathRemoved := strings.ReplaceAll(walkPath, projectPath, "")
	extensionFileRemoved := strings.ReplaceAll(basePathRemoved, filepath.Base(walkPath), "")

	if extensionFileRemoved != "" && extensionFileRemoved[0:1] == string(os.PathSeparator) {
		extensionFileRemoved = extensionFileRemoved[1:]
	}

	return extensionFileRemoved
}

// GetFilenameByExt return the first filename that match extension ext
// on projectPath. subPath is used with projectPath if not empty.
//
// nolint: funlen
func GetFilenameByExt(projectPath, subPath, ext string) (string, error) {
	pathToWalk := projectPathWithSubPath(projectPath, subPath)
	filename := ""
	err := filepath.Walk(pathToWalk, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(walkPath) == ext {
			filename = filepath.Base(walkPath)
			return io.EOF
		}

		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		logger.LogError("Error to walk on path", err, map[string]interface{}{
			"path":        pathToWalk,
			"projectPath": projectPath,
			"subPath":     subPath,
			"ext":         ext,
		})
		return "", err
	}

	return filename, nil
}

// GetCode return code to a given line of filename inside projectPath.
func GetCode(projectPath, filename, line string) (string, error) {
	path := filepath.Join(projectPath, filename)

	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		logger.LogError("Error to open file to get code sample", err, map[string]interface{}{
			"projectPath": projectPath,
			"filename":    filename,
			"line":        line,
		})
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	return strings.TrimSpace(getCodeFromDesiredLine(file, getLine(line))), nil
}

func getLine(desiredLine string) int {
	desiredLineParsed, _ := strconv.Atoi(desiredLine)
	if desiredLineParsed <= 0 {
		return desiredLineParsed
	}

	return desiredLineParsed - 1
}

func getCodeFromDesiredLine(file *os.File, desiredLine int) string {
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

func GetDependencyCodeFilepathAndLine(projectPath, subPath, ext, dependency string) (code, file, line string) {
	paths, err := getPathsByExtension(projectPath, subPath, ext)
	if err != nil {
		return "", "", ""
	}

	return getDependencyInfo(paths, dependency)
}

func getPathsByExtension(projectPath, subPath, ext string) ([]string, error) {
	var paths []string

	pathToWalk := projectPathWithSubPath(projectPath, subPath)
	return paths, filepath.Walk(pathToWalk, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(walkPath) == ext {
			paths = append(paths, walkPath)
		}

		return nil
	})
}

//nolint:funlen // improve in the future
func getDependencyInfo(paths []string, dependency string) (string, string, string) {
	var line int

	for _, path := range paths {
		file, err := os.Open(filepath.Clean(path))
		if err != nil {
			return "", "", ""
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line++

			if strings.Contains(scanner.Text(), dependency) {
				return strings.TrimSpace(scanner.Text()), path, strconv.Itoa(line)
			}
		}
	}

	return "", "", ""
}

func CreateAndWriteFile(input, filename string) error {
	path, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	_, err = file.WriteString(input)
	return err
}
