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

package copy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
)

// Copy copy src directory to dst ignoring files that make skip function return true.
//
// Note that symlink files will be ignored by default.
//
// nolint:gocyclo
func Copy(src, dst string, skip func(src string) bool) error {
	if err := os.MkdirAll(dst, os.ModePerm); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil || skip(path) || info.Mode()&os.ModeSymlink != 0 {
			return err
		}
		logger.LogTraceWithLevel(fmt.Sprintf("Copying src: %s dst: %s path: %s", src, dst, path))
		if info.IsDir() {
			return copyDir(src, dst, path)
		}
		return copyFile(src, dst, path)
	})
}

func copyFile(src, dst, path string) error {
	file, err := os.Create(replacePathSrcToDst(path, src, dst))
	if err != nil {
		return err
	}
	defer func() {
		logger.LogError("Error defer file close", file.Close())
	}()
	return copyContentSrcFileToDstFile(path, file)
}

func replacePathSrcToDst(path, src, dst string) string {
	return strings.ReplaceAll(path, src, dst)
}

func copyContentSrcFileToDstFile(srcPath string, dstFile *os.File) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() {
		logger.LogError("Error defer file close", srcFile.Close())
	}()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func copyDir(src, dst, path string) error {
	newPath := replacePathSrcToDst(path, src, dst)
	return os.MkdirAll(newPath, os.ModePerm)
}
