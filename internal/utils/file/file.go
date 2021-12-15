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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/helpers/messages"
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

// GetSubPathByFilename works like GetSubPathByExtension but for filenames.
//
// The value returned will be the first path that contains a file with a given
// filename, otherwise will return an empty string.
func GetSubPathByFilename(projectPath, subPath, filename string) string {
	pathToWalk := joinProjectPathWithSubPath(projectPath, subPath)
	logger.LogDebugWithLevel(fmt.Sprintf("Seaching for files with %s name on %s", filename, pathToWalk))

	if path := GetPathFromFilename(filename, pathToWalk); path != "" {
		logger.LogDebugWithLevel(fmt.Sprintf("Found file %s on %s", filename, path))
		return filepath.Dir(path)
	}

	return ""
}

// ReplacePathSeparator replace slashes from path to OS specific.
//
// We usually use this function to replace paths that was returned by
// a tool running on Docker when running on Windows.
func ReplacePathSeparator(path string) string {
	return strings.ReplaceAll(path, "/", string(os.PathSeparator))
}

// GetSubPathByExtension returns the path inside projectPath + subPath that contains
// the files with a given ext inside projectPath. Note that the path returned here will
// be the first path that match ext.
//
// nolint: funlen,gocyclo
func GetSubPathByExtension(projectPath, subPath, ext string) (extensionPath string) {
	pathToWalk := joinProjectPathWithSubPath(projectPath, subPath)
	logger.LogDebugWithLevel(fmt.Sprintf("Seaching for files with %s extension on %s", ext, pathToWalk))

	err := filepath.Walk(pathToWalk, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if result := relativeDirIfPathMatch(projectPath, path, ext); result != "" {
			extensionPath = result
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

	if extensionPath != "" {
		extensionPath = filepath.Clean(extensionPath)
		logger.LogDebugWithLevel(fmt.Sprintf("Found files of extension %s on %s", ext, extensionPath))
		return extensionPath
	}
	return ""
}

// relativeDirIfPathMatch return relative directory of path based on projectPath
// if path extension match ext.
func relativeDirIfPathMatch(projectPath, path, ext string) string {
	matched, err := filepath.Match(buildPattern(ext), filepath.Base(path))
	if err != nil || !matched {
		return ""
	}
	return relativeDirectoryFromPath(projectPath, path)
}

func joinProjectPathWithSubPath(projectPath, projectSubPath string) string {
	if projectSubPath != "" {
		return filepath.Join(projectPath, projectSubPath)
	}

	return projectPath
}

// relativeDirectoryFromPath return the relative path directory of path
// based on projectPath.
//
// Example:
// relativeDirectoryFromPath("/foo/bar/.horusec/123", "/foo/bar/.horusec/123/some/path/main.go")
// Return: some/path
func relativeDirectoryFromPath(projectPath, path string) string {
	rel, err := filepath.Rel(projectPath, path)
	if err != nil {
		// Since path always will be relative on projectPath this should never happen.
		logger.LogError("Error to get relative directory path", err)
		return path
	}

	return filepath.Dir(rel)
}

// GetFilenameByExt return the first filename that match extension ext
// on projectPath. subPath is used with projectPath if not empty.
//
// nolint: funlen
func GetFilenameByExt(projectPath, subPath, ext string) (string, error) {
	pathToWalk := joinProjectPathWithSubPath(projectPath, subPath)
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

// GetDependencyCodeFilepathAndLine find a file inside projectPath + subPath with
// ext that match the dependency name.
//
// Return the file, code sample and line that match the dependency name.
func GetDependencyCodeFilepathAndLine(
	projectPath, subPath, dependency string, extensions ...string,
) (code, file, line string) {
	paths, err := getPathsByExtension(projectPath, subPath, extensions...)
	if err != nil {
		return "", "", ""
	}

	return getDependencyInfo(paths, dependency)
}

// nolint: funlen
func getPathsByExtension(projectPath, subPath string, extensions ...string) ([]string, error) {
	var paths []string

	pathToWalk := joinProjectPathWithSubPath(projectPath, subPath)
	return paths, filepath.Walk(pathToWalk, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		fileExt := filepath.Ext(path)

		for _, ext := range extensions {
			if fileExt == ext {
				paths = append(paths, path)
			}
		}

		return nil
	})
}

// getDependencyInfo return the path inside paths that match the dependency.
//
// The line and the dependency trimmed is also returned.
//
//nolint:funlen,gocyclo
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
				if err := file.Close(); err != nil {
					logger.LogError(messages.MsgErrorDeferFileClose, err)
				}
				return strings.TrimSpace(scanner.Text()), path, strconv.Itoa(line)
			}
		}

		if err := file.Close(); err != nil {
			logger.LogError(messages.MsgErrorDeferFileClose, err)
			return "", "", ""
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

func isSameExtensions(filename, path string) bool {
	filenameExt := filepath.Ext(filename)
	basePathExt := filepath.Ext(path)
	return filenameExt == basePathExt
}

func buildPattern(ext string) string {
	return "*" + ext
}
