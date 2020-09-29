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

// +build !windows

package text

import (
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// newUnicodeReader creates a transformer to read UTF16 LE or BE MS-Windows files
// essentially transforming everything to UTF-8, if and only if the file have the BOM
func newUnicodeReader(defaultReader io.Reader) io.Reader {
	decoder := unicode.UTF8.NewDecoder()
	return transform.NewReader(defaultReader, unicode.BOMOverride(decoder))
}

// ReadTextFile reads the content of a file, converting when possible
// the encoding to UTF-8.
func ReadTextFile(filename string) ([]byte, error) {
	fileDescriptor, err := os.Open(filename)

	if err != nil {
		return []byte{}, err
	}

	defer fileDescriptor.Close()

	reader := newUnicodeReader(fileDescriptor)

	utf8FormattedString, err := ioutil.ReadAll(reader)

	if err != nil {
		return []byte{}, err
	}

	return utf8FormattedString, nil
}
