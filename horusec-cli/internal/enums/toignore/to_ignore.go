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

package toignore

func GetDefaultFoldersToIgnore() []string {
	return []string{"/.horusec/", "/.idea/", "/.vscode/", "/tmp/", "/bin/", "/node_modules/", "/vendor/",
		"go.mod", "go.sum", "/.git/"}
}

func GetDefaultExtensionsToIgnore() []string {
	return []string{
		".jpg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd",
		".jpeg", ".svg", ".ai", ".eps", ".pdf", ".webm", ".mpg", ".mp2", ".mpeg", ".mpe",
		".mp4", ".m4p", ".m4v", ".avi", ".wmv", ".mov", ".qt", ".flv", ".swf", ".avchd", ".mpv", ".ogg",
		".ico",
	}
}
