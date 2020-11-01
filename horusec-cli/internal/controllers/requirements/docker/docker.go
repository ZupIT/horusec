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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
)

const MinVersionDockerApiAccept = "1.40"

type RequirementDocker struct{}

type DockerVersionClient struct {
	Version    string `json:"Version"`
	ApiVersion string `json:"ApiVersion"`
}

type DockerVersionServer struct {
	Version    string `json:"Version"`
	ApiVersion string `json:"ApiVersion"`
}

type DockerVersion struct {
	Client DockerVersionClient `json:"Client"`
	Server DockerVersionServer `json:"Server"`
}

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
	_, err := r.execDockerVersion()
	if err != nil {
		return err
	}
	return r.checkIfDockerIsRunning()
}

func (r *RequirementDocker) validateIfDockerIsSupported() error {
	dockerVersion, err := r.execDockerVersion()
	if err != nil {
		logger.LogInfo(messages.MsgInfoHowToInstallDocker)
		return err
	}

	err = r.validateIfDockerIsRunningInMinVersion(dockerVersion)
	if err == nil {
		return nil
	}
	logger.LogInfo(messages.MsgInfoHowToInstallDocker)

	return errorsEnums.ErrDockerNotInstalled
}

func (r *RequirementDocker) execDockerVersion() (DockerVersion, error) {
	var dockerVersion DockerVersion
	err := jsonUnmarshalDockerCmd(&dockerVersion, "version", "-f", "{{json .}}")
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorWhenCheckRequirements+"Error parsing json result from the Docker client: ", err, logger.ErrorLevel)
		return DockerVersion{}, err
	}

	return dockerVersion, nil
}

func (r *RequirementDocker) checkIfDockerIsRunning() error {
	responseBytes, err := exec.Command("docker", "ps").CombinedOutput()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorWhenCheckDockerRunnnig+"output: ", errors.New(string(responseBytes)), logger.ErrorLevel)
	}
	return err
}

func (r *RequirementDocker) validateIfDockerIsRunningInMinVersion(dockerVersion DockerVersion) error {
	versionConstraint, err := semver.NewConstraint(fmt.Sprintf(">= %s", MinVersionDockerApiAccept))
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenDockerIsLowerVersion+"info: Unable to create semver constraint for Docker Version.", err, logger.ErrorLevel)
		return err
	}

	currentDockerVersion, err := semver.NewVersion(dockerVersion.Server.ApiVersion)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenDockerIsLowerVersion+"info: Unable to parse Docker Version struct.", err, logger.ErrorLevel)
		return err
	}

	if versionConstraint.Check(currentDockerVersion) {
		return nil
	} else {
		err = fmt.Errorf("Current Docker API Version: %v (minimum required version: %v)", currentDockerVersion, MinVersionDockerApiAccept)
		logger.LogErrorWithLevel(messages.MsgErrorWhenDockerIsLowerVersion, err, logger.ErrorLevel)
		return err
	}
}

func jsonUnmarshalDockerCmd(i interface{}, arg ...string) error {
	var stderr bytes.Buffer
	var stdout bytes.Buffer

	cmd := exec.Command("docker", arg...)

	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		err := fmt.Errorf("Error launching Docker client: %+v", err)
		if stdErrStr := stderr.String(); stdErrStr != "" {
			err = fmt.Errorf("%s: %s", err, strings.TrimSpace(stdErrStr))
		}
		return err
	}

	if err := cmd.Wait(); err != nil {
		err := fmt.Errorf("Error waiting for the Docker client: %+v", err)
		if stdErrStr := stderr.String(); stdErrStr != "" {
			err = fmt.Errorf("%s: %s", err, strings.TrimSpace(stdErrStr))
		}
		return err
	}

	if err := json.Unmarshal([]byte(stdout.String()), &i); err != nil {
		return fmt.Errorf("Error unmarshaling the result of Docker client: %v", err)
	}

	return nil
}
