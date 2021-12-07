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

package docker

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/helpers/messages"
)

const (
	MinVersionDockerAccept    = 19
	MinSubVersionDockerAccept = 0o3
)

var (
	// ErrMinVersion occur when the installed Docker version is not the minimum supported.
	ErrMinVersion = fmt.Errorf("%v.%v", MinVersionDockerAccept, MinSubVersionDockerAccept)

	// ErrDockerNotInstalled occurs when Docker is not installed.
	ErrDockerNotInstalled = errors.New("docker not found. Please check and try again")
)

func Validate() error {
	response, err := validateIfDockerIsInstalled()
	if err != nil {
		return err
	}
	return validateIfDockerIsSupported(response)
}

func validateIfDockerIsInstalled() (string, error) {
	response, err := execDockerVersion()
	if err != nil {
		logger.LogInfo(messages.MsgInfoHowToInstallDocker)
		return "", err
	}

	if !checkIfContainsDockerVersion(response) {
		return "", ErrDockerNotInstalled
	}
	return response, checkIfDockerIsRunning()
}

func validateIfDockerIsSupported(version string) error {
	err := validateIfDockerIsRunningInMinVersion(version)
	if err != nil {
		return err
	}
	return nil
}

func execDockerVersion() (string, error) {
	responseBytes, err := exec.Command("docker", "-v").CombinedOutput()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorWhenCheckRequirementsDocker, errors.New(string(responseBytes)))
		return "", err
	}
	return strings.ToLower(string(responseBytes)), nil
}

func checkIfDockerIsRunning() error {
	responseBytes, err := exec.Command("docker", "ps").CombinedOutput()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorWhenCheckDockerRunning, errors.New(string(responseBytes)))
	}
	return err
}

func validateIfDockerIsRunningInMinVersion(response string) error {
	version, subversion, err := extractDockerVersionFromString(response)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenDockerIsLowerVersion, ErrMinVersion)
		return err
	}

	if version <= MinVersionDockerAccept && subversion < MinSubVersionDockerAccept {
		fmt.Print("\n")
		logger.LogInfo(messages.MsgInfoDockerLowerVersion)
		fmt.Print("\n")
	}

	return nil
}

func extractDockerVersionFromString(response string) (int, int, error) {
	responseSpited := strings.Split(strings.ToLower(response), "docker version ")
	if len(responseSpited) < 1 || len(responseSpited) > 1 && len(responseSpited[1]) < 8 {
		return 0, 0, ErrDockerNotInstalled
	}
	return getVersionAndSubVersion(responseSpited[1])
}

func checkIfContainsDockerVersion(response string) bool {
	return strings.Contains(strings.ToLower(response), "docker version ")
}

func getVersionAndSubVersion(fullVersion string) (int, int, error) {
	version, err := strconv.Atoi(fullVersion[0:2])
	if err != nil {
		return 0, 0, ErrDockerNotInstalled
	}
	subversion, err := strconv.Atoi(fullVersion[3:5])
	if err != nil {
		return 0, 0, ErrDockerNotInstalled
	}
	return version, subversion, nil
}
