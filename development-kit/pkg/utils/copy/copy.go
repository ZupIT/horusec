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
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

func Copy(src, dst string, skip func(src string) bool) error {
	if err := os.MkdirAll(dst, os.ModePerm); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if isToSkip := skip(path); !isToSkip {
			return copyByType(src, dst, path, info)
		}
		return nil
	})
}

func copyByType(src, dst, path string, info os.FileInfo) error {
	switch {
	case info.IsDir():
		return copyDir(src, dst, path)
	case info.Mode()&os.ModeSymlink != 0:
		return copyLink(src, dst, path)
	default:
		return copyFile(src, dst, path)
	}
}

func copyFile(src, dst, path string) error {
	file, err := os.Create(replacePathSrcToDst(path, src, dst))
	if file != nil {
		defer func() {
			logger.LogError("Error defer file close", file.Close())
		}()
	}
	if err != nil {
		return err
	}
	return copyContentSrcFileToDstFile(path, file)
}

func replacePathSrcToDst(path, src, dst string) string {
	return strings.ReplaceAll(path, src, dst)
}

func copyContentSrcFileToDstFile(srcPath string, dstFile *os.File) error {
	srcFile, err := os.Open(srcPath)
	if srcFile != nil {
		defer func() {
			logger.LogError("Error defer file close", srcFile.Close())
		}()
	}
	if err != nil {
		return err
	}

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func copyDir(src, dst, path string) error {
	newPath := replacePathSrcToDst(path, src, dst)
	return os.MkdirAll(newPath, os.ModePerm)
}

func copyLink(src, dst, path string) error {
	orig, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}

	info, err := os.Lstat(orig)
	if err != nil {
		return err
	}

	return copyByType(orig, dst, path, info)
}
