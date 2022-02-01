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
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/docker/client"
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
	version, err := validateIfDockerIsInstalled()
	if err != nil {
		return err
	}
	return validateIfDockerIsRunningInMinVersion(version)
}

func validateIfDockerIsInstalled() (string, error) {
	response, err := getDockerVersion()
	if err != nil {
		logger.LogInfo(messages.MsgInfoHowToInstallDocker)
		return "", err
	}
	return response, nil
}

func getDockerVersion() (string, error) {
	dockerClient := client.NewDockerClient()
	version, err := dockerClient.ServerVersion(context.Background())
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenCheckRequirementsDocker, err)
		return "", err
	}
	return version.Version, nil
}

func validateIfDockerIsRunningInMinVersion(response string) error {
	version, subversion, err := getVersionAndSubVersion(response)
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
