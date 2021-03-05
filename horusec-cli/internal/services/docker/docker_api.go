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
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	enumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	dockerService "github.com/ZupIT/horusec/horusec-cli/internal/services/docker/client"
	dockerTypes "github.com/docker/docker/api/types"
	dockerContainer "github.com/docker/docker/api/types/container"
	dockerTypesFilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/google/uuid"
	goContext "golang.org/x/net/context"
)

type Interface interface {
	CreateLanguageAnalysisContainer(data *dockerEntities.AnalysisData) (containerOutPut string, err error)
	PullImage(imageWithTagAndRegistry string) error
	DeleteContainersFromAPI()
}

type API struct {
	ctx                    goContext.Context
	dockerClient           dockerService.Interface
	config                 cliConfig.IConfig
	analysisID             uuid.UUID
	pathDestinyInContainer string
}

func NewDockerAPI(docker dockerService.Interface, config cliConfig.IConfig, analysisID uuid.UUID) Interface {
	return &API{
		ctx:                    goContext.Background(),
		dockerClient:           docker,
		config:                 config,
		analysisID:             analysisID,
		pathDestinyInContainer: "/src",
	}
}

func (d *API) CreateLanguageAnalysisContainer(data *dockerEntities.AnalysisData) (containerOutPut string, err error) {
	if data.IsInvalid() {
		return "", enumErrors.ErrImageTagCmdRequired
	}

	return d.logStatusAndExecuteCRDContainer(data.GetImageWithoutRegistry(), d.replaceCMDAnalysisID(data.CMD))
}

func (d *API) PullImage(imageWithTagAndRegistry string) error {
	if imageNotExist, err := d.checkImageNotExists(imageWithTagAndRegistry); err != nil || !imageNotExist {
		logger.LogError(fmt.Sprintf("%s -> %s",
			messages.MsgErrorFailedToPullImage, imageWithTagAndRegistry), err)
		return err
	}

	err := d.downloadImage(imageWithTagAndRegistry)
	logger.LogError(fmt.Sprintf("%s -> %s", messages.MsgErrorFailedToPullImage, imageWithTagAndRegistry), err)
	return err
}

func (d *API) downloadImage(imageWithTagAndRegistry string) error {
	d.loggerAPIStatus(messages.MsgDebugDockerAPIPullNewImage, imageWithTagAndRegistry)
	reader, err := d.dockerClient.ImagePull(d.ctx, imageWithTagAndRegistry, dockerTypes.ImagePullOptions{})
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerPullImage, err)
		return err
	}

	readResult, err := ioutil.ReadAll(reader)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerPullImage, err)
		logger.LogDebugWithLevel(string(readResult))
		return err
	}

	d.loggerAPIStatus(messages.MsgDebugDockerAPIDownloadWithSuccess, imageWithTagAndRegistry)
	return nil
}

func (d *API) checkImageNotExists(imageWithTagAndRegistry string) (bool, error) {
	args := dockerTypesFilters.NewArgs()
	args.Add("reference", d.removeRegistry(imageWithTagAndRegistry))
	options := dockerTypes.ImageListOptions{Filters: args}

	result, err := d.dockerClient.ImageList(d.ctx, options)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerListImages, err)
		return false, err
	}

	return len(result) == 0, nil
}

func (d *API) replaceCMDAnalysisID(cmd string) string {
	return strings.ReplaceAll(cmd, "ANALYSISID", d.analysisID.String())
}

func (d *API) logStatusAndExecuteCRDContainer(imageNameWithTag, cmd string) (containerOutput string, err error) {
	containerOutput, err = d.executeCRDContainer(imageNameWithTag, cmd)
	if err != nil {
		d.loggerAPIStatus(messages.MsgDebugDockerAPIFinishedError, imageNameWithTag)
		return "", err
	}

	d.loggerAPIStatus(messages.MsgDebugDockerAPIFinishedSuccess, imageNameWithTag)
	return containerOutput, nil
}

func (d *API) executeCRDContainer(imageNameWithTag, cmd string) (containerOutput string, err error) {
	containerID, err := d.createContainer(imageNameWithTag, cmd)
	if err != nil {
		return "", err
	}

	containerOutput, err = d.readContainer(containerID)
	d.loggerAPIStatus(messages.MsgDebugDockerAPIContainerRead, imageNameWithTag)

	time.Sleep(5 * time.Second)
	d.removeContainer(containerID)
	return containerOutput, err
}

func (d *API) removeContainer(containerID string) {
	err := d.dockerClient.ContainerRemove(d.ctx,
		containerID, dockerTypes.ContainerRemoveOptions{Force: true})
	logger.LogErrorWithLevel(messages.MsgErrorDockerRemoveContainer, err)
}

func (d *API) createContainer(imageNameWithTag, cmd string) (string, error) {
	config, host := d.getConfigAndHostToCreateContainer(imageNameWithTag, cmd)
	response, err := d.dockerClient.ContainerCreate(d.ctx, config, host, nil, nil, d.getImageID())
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerCreateContainer, err)
		return "", err
	}

	if err = d.dockerClient.ContainerStart(d.ctx, response.ID, dockerTypes.ContainerStartOptions{}); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerStartContainer, err)
		return "", err
	}

	d.loggerAPIStatusWithContainerID(messages.MsgDebugDockerAPIContainerCreated, imageNameWithTag, response.ID)
	return response.ID, nil
}

func (d *API) getImageID() string {
	return fmt.Sprintf("%s-%s", d.analysisID.String(), uuid.New().String())
}

func (d *API) readContainer(containerID string) (string, error) {
	d.loggerAPIStatusWithContainerID(messages.MsgDebugDockerAPIContainerWait, "", containerID)
	chanContainerStatus, _ := d.dockerClient.ContainerWait(d.ctx, containerID, "")
	if containerWaitStatus := <-chanContainerStatus; containerWaitStatus.Error != nil {
		message := fmt.Sprintf("Error on wait container %s: %s | Exited with status %s",
			containerID, containerWaitStatus.Error.Message,
			strconv.Itoa(int(containerWaitStatus.StatusCode)),
		)
		return "", errors.New(message)
	}
	containerOutput, err := d.dockerClient.ContainerLogs(d.ctx, containerID,
		dockerTypes.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return "", err
	}
	return d.getOutputString(containerOutput)
}

func (d *API) getOutputString(containerOutPut io.Reader) (string, error) {
	containerOutPutBytes, err := ioutil.ReadAll(containerOutPut)
	if err != nil {
		return "", err
	}

	return string(containerOutPutBytes), err
}

func (d *API) getConfigAndHostToCreateContainer(
	imageNameWithTag, cmd string) (*dockerContainer.Config, *dockerContainer.HostConfig) {
	config := d.getContainerConfig(imageNameWithTag, cmd)

	return config, d.getContainerHostConfig()
}

func (d *API) getContainerConfig(imageNameWithTag, cmd string) *dockerContainer.Config {
	return &dockerContainer.Config{
		Image: imageNameWithTag,
		Tty:   true,
		Cmd:   []string{"/bin/sh", "-c", fmt.Sprintf(`cd %s && %s`, d.pathDestinyInContainer, cmd)},
	}
}

func (d *API) getContainerHostConfig() *dockerContainer.HostConfig {
	return &dockerContainer.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: d.getSourceFolder(),
				Target: d.pathDestinyInContainer,
				BindOptions: &mount.BindOptions{
					Propagation: mount.PropagationPrivate,
				},
			},
		},
	}
}

func (d *API) loggerAPIStatus(message, imageNameWithTag string) {
	logger.LogDebugWithLevel(
		message,
		map[string]interface{}{
			"image":      imageNameWithTag,
			"analysisId": d.analysisID.String(),
		},
	)
}

func (d *API) loggerAPIStatusWithContainerID(message, imageNameWithTag, containerID string) {
	logger.LogDebugWithLevel(
		message,
		map[string]interface{}{
			"image":       imageNameWithTag,
			"containerId": containerID,
			"analysisId":  d.analysisID.String(),
		},
	)
}

func (d *API) DeleteContainersFromAPI() {
	containers, err := d.listContainersByAnalysisID()
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerListAllContainers, err)
		return
	}

	for index := range containers {
		err = d.dockerClient.ContainerRemove(d.ctx, containers[index].ID,
			dockerTypes.ContainerRemoveOptions{Force: true})

		logger.LogErrorWithLevel(messages.MsgErrorDockerRemoveContainer, err)
	}
}

func (d *API) getSourceFolder() (path string) {
	if d.config.GetContainerBindProjectPath() != "" {
		path = fmt.Sprintf("%s/.horusec/%s", d.config.GetContainerBindProjectPath(), d.analysisID.String())
	} else {
		path = fmt.Sprintf("%s/.horusec/%s", d.config.GetProjectPath(), d.analysisID.String())
	}

	separator := path[1:2]
	if separator == ":" {
		return d.getSourceFolderFromWindows(path)
	}
	return path
}

func (d *API) listContainersByAnalysisID() ([]dockerTypes.Container, error) {
	args := dockerTypesFilters.NewArgs()
	args.Add("name", d.analysisID.String())

	return d.dockerClient.ContainerList(d.ctx, dockerTypes.ContainerListOptions{
		All:     true,
		Filters: args,
	})
}

func (d *API) getSourceFolderFromWindows(path string) string {
	// C:/Users/usr/Documents/Horusec/charlescd/.horusec/ID
	partitionLower := strings.ToLower(path[0:1])
	pathSplit := strings.Split(path, ":")
	pathSplit[0] = partitionLower
	path = strings.Join(pathSplit, ":")
	// c:/Users/usr/Documents/Horusec/project/.horusec/ID
	path = strings.ReplaceAll(path, ":", "")
	// c/Users/usr/Documents/Horusec/project/.horusec/ID
	path = "/" + path
	// /c/Users/usr/Documents/Horusec/project/.horusec/ID
	path = strings.ReplaceAll(path, "\\", "/")
	// /c/Users/usr/Documents/Horusec/project/.horusec/ID
	path = strings.ReplaceAll(path, "/", "//")
	// //c//Users//usr//Documents//Horusec//project//.horusec//ID
	return path
}

func (d *API) removeRegistry(imageWithTagAndRegistry string) string {
	index := strings.Index(imageWithTagAndRegistry, "/")
	if index < 0 {
		return imageWithTagAndRegistry
	}

	return imageWithTagAndRegistry[index+1:]
}
