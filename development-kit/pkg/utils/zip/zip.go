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

package zip

import (
	"archive/zip"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Interface interface {
	UnZip(src, dest string) error
	CompressFolderToZip(source, target string) error
	ConvertFilesToZip(filesAndFolders []string, directory, fileName string) error
}

type Zip struct{}

func NewZip() Interface {
	return &Zip{}
}

//nolint:funlen unzip is not necessary broken smaller methods
func (z *Zip) UnZip(src, dest string) error {
	r, err := zip.OpenReader(file.ReplacePathSeparator(src))
	if err != nil {
		return err
	}
	for _, fileOpenedOnZip := range r.File {
		contentFileOpenedOnZip, err := fileOpenedOnZip.Open()
		if err != nil {
			return err
		}
		err = z.createFileAndFolderToUnZip(file.ReplacePathSeparator(dest), contentFileOpenedOnZip, fileOpenedOnZip)
		if err != nil {
			return err
		}
	}
	return r.Close()
}

func (z *Zip) createFileAndFolderToUnZip(
	dest string, contentFileOpenedOnZip io.Reader, fileOpenedOnZip *zip.File) error {
	pathJoined := z.addFileNameOnDest(dest, fileOpenedOnZip.Name)
	if fileOpenedOnZip.FileInfo().IsDir() {
		if err := z.createFolderToUnzip(pathJoined); err != nil {
			return err
		}
	} else {
		if _, err := z.createFileToUnzip(pathJoined, fileOpenedOnZip, contentFileOpenedOnZip); err != nil {
			return err
		}
	}
	return nil
}

func (z *Zip) createFolderToUnzip(pathJoined string) error {
	return os.MkdirAll(pathJoined, 0750)
}

func (z *Zip) createFileToUnzip(
	pathJoined string, fileOpenedOnZip *zip.File, contentFileOpenedOnZip io.Reader) (int64, error) {
	pathFileToCreate := ""
	if lastIndex := strings.LastIndex(pathJoined, string(os.PathSeparator)); lastIndex > -1 {
		pathFileToCreate = pathJoined[:lastIndex]
	}
	err := os.MkdirAll(pathFileToCreate, 0750)
	if err != nil {
		return 0, err
	}
	fileToCreate, err := os.OpenFile(pathJoined, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileOpenedOnZip.Mode())
	if err != nil {
		return 0, err
	}
	return io.Copy(fileToCreate, contentFileOpenedOnZip)
}

func (z *Zip) addFileNameOnDest(dest, fileName string) string {
	if strings.Contains(fileName, "analysis-") {
		spliced := strings.Split(fileName, string(os.PathSeparator))
		if len(spliced) == 1 {
			fileName = spliced[0]
		} else {
			fileName = strings.Join(spliced[1:], string(os.PathSeparator))
		}
	}
	if dest[len(dest)-1:] == string(os.PathSeparator) {
		return dest + fileName
	}
	return fmt.Sprintf("%s%s%s", dest, string(os.PathSeparator), fileName)
}

func (z *Zip) ConvertFilesToZip(filesAndFolders []string, directory, fileName string) error {
	fullPathDestiny := z.getFullPathDestiny(file.ReplacePathSeparator(directory), file.ReplacePathSeparator(fileName))
	if err := z.createFolders(filesAndFolders, directory, fullPathDestiny); err != nil {
		return err
	}
	if err := z.copyFilesToDest(filesAndFolders, directory, fullPathDestiny); err != nil {
		return err
	}
	if err := z.CompressFolderToZip(fullPathDestiny, fullPathDestiny+".zip"); err != nil {
		return err
	}
	return os.RemoveAll(fullPathDestiny)
}

func (z *Zip) getFullPathDestiny(directory, fileName string) (defaultFullPathDestiny string) {
	if directory[len(directory)-1:] == string(os.PathSeparator) {
		defaultFullPathDestiny = fmt.Sprintf("%s.horusec%s%s", directory, string(os.PathSeparator), fileName)
	} else {
		defaultFullPathDestiny = fmt.Sprintf("%s%s.horusec%s%s",
			string(os.PathSeparator), string(os.PathSeparator), directory, fileName)
	}
	return defaultFullPathDestiny
}

func (z *Zip) CompressFolderToZip(source, target string) error {
	baseDir, zipFile, archive, err := z.createZipFile(file.ReplacePathSeparator(source), file.ReplacePathSeparator(target))
	if err != nil {
		return err
	}
	defer func() {
		logger.LogError("Error defer file close", zipFile.Close())
	}()
	defer func() {
		logger.LogError("Error defer file close", archive.Close())
	}()

	return z.walkToSendAllSubDirectories(source, baseDir, archive)
}

func (z *Zip) walkToSendAllSubDirectories(source, baseDir string, archive *zip.Writer) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := z.setupHeaderInSubDirectory(source, path, baseDir, info)
		if err != nil {
			return err
		}
		return z.createSubDirectoryOnZip(archive, header, info, path)
	})
}

func (z *Zip) copyFilesToDest(filesAndFolders []string, directory, fullPathDestiny string) error {
	for _, value := range filesAndFolders {
		fileOpened, err := os.Stat(file.ReplacePathSeparator(value))
		if err != nil {
			return err
		}
		if !fileOpened.IsDir() {
			fileDestiny := strings.ReplaceAll(value, directory, fullPathDestiny+string(os.PathSeparator))
			if err := z.copyFile(value, fileDestiny); err != nil {
				return err
			}
		}
	}
	return nil
}
func (z *Zip) createFolders(filesAndFolders []string, directory, fullPathDestiny string) error {
	if err := z.mkdir(fullPathDestiny); err != nil {
		return err
	}
	return z.runLoopToCreateAllFolders(filesAndFolders, directory, fullPathDestiny)
}

func (z *Zip) runLoopToCreateAllFolders(filesAndFolders []string, directory, fullPathDestiny string) error {
	for _, value := range filesAndFolders {
		fileOpened, err := os.Stat(file.ReplacePathSeparator(value))
		if err != nil {
			return err
		}
		if fileOpened.IsDir() {
			folderToCreate := strings.ReplaceAll(value, directory, fullPathDestiny)
			if err := z.mkdir(folderToCreate); err != nil {
				return err
			}
		}
	}
	return nil
}

func (z *Zip) mkdir(destination string) error {
	err := os.MkdirAll(destination, 0750)
	if err != nil {
		return fmt.Errorf("%s: making directory: %v", destination, err)
	}
	return nil
}

func (z *Zip) copyFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() {
		logger.LogError("Error defer file close", in.Close())
	}()

	return z.createFileAndCopyToDestiny(destination, in)
}

func (z *Zip) createFileAndCopyToDestiny(destination string, in *os.File) error {
	out, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer func() {
		logger.LogError("Error defer file close", out.Close())
	}()
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func (z *Zip) createZipFile(source, target string) (baseDir string, zipFile *os.File, archive *zip.Writer, err error) {
	zipFile, err = os.Create(target)
	if err != nil {
		return baseDir, zipFile, archive, err
	}
	archive = zip.NewWriter(zipFile)
	info, err := os.Stat(source)
	if err != nil {
		return baseDir, zipFile, archive, err
	}
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}
	return baseDir, zipFile, archive, err
}

func (z *Zip) setupHeaderInSubDirectory(source, path, baseDir string, info os.FileInfo) (*zip.FileHeader, error) {
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return nil, err
	}
	if baseDir != "" {
		header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
	}
	if info.IsDir() {
		header.Name += string(os.PathSeparator)
	} else {
		header.Method = zip.Deflate
	}
	return header, nil
}

func (z *Zip) createSubDirectoryOnZip(
	archive *zip.Writer, header *zip.FileHeader, info os.FileInfo, path string) error {
	writer, _ := archive.CreateHeader(header)
	if info.IsDir() {
		return nil
	}
	fileOpened, err := os.Open(path)
	if err != nil {
		return err
	}

	defer func() {
		logger.LogError("Error defer file close", fileOpened.Close())
	}()
	_, err = io.Copy(writer, fileOpened)
	return err
}
