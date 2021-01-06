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

package client

import (
	"io"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"golang.org/x/net/context"
)

type Interface interface {
	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig,
		networkingConfig *network.NetworkingConfig, containerName string) (container.ContainerCreateCreatedBody, error)
	ContainerStart(ctx context.Context, containerID string, options types.ContainerStartOptions) error
	ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)
	ContainerWait(ctx context.Context, containerID string) (int64, error)
	ContainerLogs(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error)
	ContainerRemove(ctx context.Context, containerID string, options types.ContainerRemoveOptions) error
	ImageList(ctx context.Context, options types.ImageListOptions) ([]types.ImageSummary, error)
	ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error)
	Ping(ctx context.Context) (types.Ping, error)
}

func NewDockerClient() Interface {
	dockerClient, err := docker.NewEnvClient()
	if err != nil {
		logger.LogPanicWithLevel(messages.MsgPanicNotConnectDocker, err)
	}

	return dockerClient
}
