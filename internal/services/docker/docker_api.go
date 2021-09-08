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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	enumErrors "github.com/ZupIT/horusec/internal/enums/errors"

	"github.com/docker/docker/api/types"
	dockerTypesFilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/utils/env"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// Docker is the interface that abstract the Docker API.
type Docker interface {
	CreateLanguageAnalysisContainer(data *docker.AnalysisData) (containerOutPut string, err error)
	PullImage(imageWithTagAndRegistry string) error
	DeleteContainersFromAPI()
}

// Client is the interface that interact with the Docker API.
type Client interface {
	ContainerCreate(ctx context.Context, cfg *container.Config, hostCfg *container.HostConfig,
		netCfg *network.NetworkingConfig, plataform *specs.Platform, name string,
	) (container.ContainerCreateCreatedBody, error)

	ContainerStart(ctx context.Context, containerID string, options types.ContainerStartOptions) error

	ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)

	ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (
		<-chan container.ContainerWaitOKBody, <-chan error)

	ContainerLogs(ctx context.Context, containerID string, options types.ContainerLogsOptions) (io.ReadCloser, error)

	ContainerRemove(ctx context.Context, containerID string, options types.ContainerRemoveOptions) error

	ImageList(ctx context.Context, options types.ImageListOptions) ([]types.ImageSummary, error)

	ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error)

	Ping(ctx context.Context) (types.Ping, error)
}

type API struct {
	ctx                    context.Context
	dockerClient           Client
	config                 *config.Config
	analysisID             uuid.UUID
	pathDestinyInContainer string
}

func New(client Client, cfg *config.Config, analysisID uuid.UUID) *API {
	return &API{
		ctx:                    context.Background(),
		dockerClient:           client,
		config:                 cfg,
		analysisID:             analysisID,
		pathDestinyInContainer: "/src",
	}
}

func (d *API) CreateLanguageAnalysisContainer(data *docker.AnalysisData) (containerOutPut string, err error) {
	if data.IsInvalid() {
		return "", enumErrors.ErrImageTagCmdRequired
	}

	return d.logStatusAndExecuteCRDContainer(data.GetCustomOrDefaultImage(), d.replaceCMDAnalysisID(data.CMD))
}

func (d *API) PullImage(imageWithTagAndRegistry string) error {
	if d.config.DisableDocker {
		return nil
	}

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
	reader, err := d.dockerClient.ImagePull(d.ctx, imageWithTagAndRegistry, d.setPullOptions())
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerPullImage, err)
		return err
	}

	return d.readPullReader(imageWithTagAndRegistry, reader)
}

func (d *API) setPullOptions() types.ImagePullOptions {
	authConfig := types.AuthConfig{
		Username:      env.GetEnvOrDefault("HORUSEC_CLI_REGISTRY_USERNAME", ""),
		Password:      env.GetEnvOrDefault("HORUSEC_CLI_REGISTRY_PASSWORD", ""),
		ServerAddress: env.GetEnvOrDefault("HORUSEC_CLI_REGISTRY_ADDRESS", ""),
	}

	if authConfig.Username != "" && authConfig.Password != "" {
		encodedAuthConfig, _ := json.Marshal(authConfig)
		return types.ImagePullOptions{RegistryAuth: base64.URLEncoding.EncodeToString(encodedAuthConfig)}
	}

	return types.ImagePullOptions{}
}

func (d *API) readPullReader(imageWithTagAndRegistry string, reader io.ReadCloser) error {
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
	options := types.ImageListOptions{Filters: args}

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
	const maxTimeWaitToRemoveContainer = 5
	time.Sleep(maxTimeWaitToRemoveContainer * time.Second)
	d.removeContainer(containerID)
	return containerOutput, err
}

func (d *API) removeContainer(containerID string) {
	err := d.dockerClient.ContainerRemove(d.ctx,
		containerID, types.ContainerRemoveOptions{Force: true})
	logger.LogErrorWithLevel(messages.MsgErrorDockerRemoveContainer, err)
}

func (d *API) createContainer(imageNameWithTag, cmd string) (string, error) {
	cfg, host := d.getConfigAndHostToCreateContainer(imageNameWithTag, cmd)
	response, err := d.dockerClient.ContainerCreate(d.ctx, cfg, host, nil, nil, d.getImageID())
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorDockerCreateContainer, err)
		return "", err
	}

	if err = d.dockerClient.ContainerStart(d.ctx, response.ID, types.ContainerStartOptions{}); err != nil {
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
		types.ContainerLogsOptions{ShowStdout: true})
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
	imageNameWithTag, cmd string) (*container.Config, *container.HostConfig) {
	cfg := d.getContainerConfig(imageNameWithTag, cmd)

	return cfg, d.getContainerHostConfig()
}

func (d *API) getContainerConfig(imageNameWithTag, cmd string) *container.Config {
	return &container.Config{
		Image: imageNameWithTag,
		Tty:   true,
		Cmd:   []string{"/bin/sh", "-c", fmt.Sprintf(`cd %s && %s`, d.pathDestinyInContainer, cmd)},
	}
}

func (d *API) getContainerHostConfig() *container.HostConfig {
	return &container.HostConfig{
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
			types.ContainerRemoveOptions{Force: true})

		logger.LogErrorWithLevel(messages.MsgErrorDockerRemoveContainer, err)
	}
}

func (d *API) getSourceFolder() (path string) {
	if d.config.ContainerBindProjectPath != "" {
		path = fmt.Sprintf("%s/.horusec/%s", d.config.ContainerBindProjectPath, d.analysisID.String())
	} else {
		path = fmt.Sprintf("%s/.horusec/%s", d.config.ProjectPath, d.analysisID.String())
	}

	separator := path[1:2]
	if separator == ":" {
		return d.getSourceFolderFromWindows(path)
	}
	return path
}

func (d *API) listContainersByAnalysisID() ([]types.Container, error) {
	args := dockerTypesFilters.NewArgs()
	args.Add("name", d.analysisID.String())

	return d.dockerClient.ContainerList(d.ctx, types.ContainerListOptions{
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
	return strings.ReplaceAll(imageWithTagAndRegistry, images.DefaultRegistry+"/", "")
}
