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

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
)

const MinVersionDockerAccept = 19
const MinSubVersionDockerAccept = 03

var (
	ErrMinVersion = fmt.Errorf("%v.%v", MinVersionDockerAccept, MinSubVersionDockerAccept)
)

type RequirementDocker struct{}

func NewRequirementDocker() *RequirementDocker {
	return &RequirementDocker{}
}

func (r *RequirementDocker) ValidateDocker() error {
	if err := r.validateIfDockerIsInstalled(); err != nil {
		return err
	}
	return r.validateIfDockerIsSupported()
}

func (r *RequirementDocker) validateIfDockerIsInstalled() error {
	response, err := r.execDockerVersion()
	if err != nil {
		return err
	}
	if !r.checkIfContainsDockerVersion(response) {
		return errorsEnums.ErrDockerNotInstalled
	}
	return r.checkIfDockerIsRunning()
}

func (r *RequirementDocker) validateIfDockerIsSupported() error {
	response, err := r.execDockerVersion()
	if err != nil {
		logger.LogInfo(messages.MsgInfoHowToInstallDocker)
		return err
	}
	if r.checkIfContainsDockerVersion(response) {
		err := r.validateIfDockerIsRunningInMinVersion(response)
		if err == nil {
			return nil
		}
		logger.LogInfo(messages.MsgInfoHowToInstallDocker)
	}
	return errorsEnums.ErrDockerNotInstalled
}

func (r *RequirementDocker) execDockerVersion() (string, error) {
	responseBytes, err := exec.Command("docker", "-v").CombinedOutput()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorWhenCheckRequirements+"output: ", errors.New(string(responseBytes)), logger.ErrorLevel)
		return "", err
	}
	return strings.ToLower(string(responseBytes)), nil
}

func (r *RequirementDocker) checkIfDockerIsRunning() error {
	responseBytes, err := exec.Command("docker", "ps").CombinedOutput()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorWhenCheckDockerRunnnig+"output: ", errors.New(string(responseBytes)), logger.ErrorLevel)
	}
	return err
}

func (r *RequirementDocker) validateIfDockerIsRunningInMinVersion(response string) error {
	version, subversion, err := r.extractDockerVersionFromString(response)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenDockerIsLowerVersion, ErrMinVersion, logger.ErrorLevel)
		return err
	}
	if version < MinVersionDockerAccept {
		return errorsEnums.ErrDockerLowerVersion
	} else if version == MinVersionDockerAccept && subversion < MinSubVersionDockerAccept {
		logger.LogErrorWithLevel(messages.MsgErrorWhenDockerIsLowerVersion, ErrMinVersion, logger.ErrorLevel)
		return errorsEnums.ErrDockerLowerVersion
	}
	return nil
}

func (r *RequirementDocker) extractDockerVersionFromString(response string) (int, int, error) {
	responseSpited := strings.Split(strings.ToLower(response), "docker version ")
	if len(responseSpited) < 1 || len(responseSpited) > 1 && len(responseSpited[1]) < 8 {
		return 0, 0, errorsEnums.ErrDockerNotInstalled
	}
	return r.getVersionAndSubVersion(responseSpited[1])
}

func (r *RequirementDocker) checkIfContainsDockerVersion(response string) bool {
	return strings.Contains(strings.ToLower(response), "docker version ")
}

func (r *RequirementDocker) getVersionAndSubVersion(fullVersion string) (int, int, error) {
	version, err := strconv.Atoi(fullVersion[0:2])
	if err != nil {
		return 0, 0, errorsEnums.ErrDockerNotInstalled
	}
	subversion, err := strconv.Atoi(fullVersion[3:5])
	if err != nil {
		return 0, 0, errorsEnums.ErrDockerNotInstalled
	}
	return version, subversion, nil
}
