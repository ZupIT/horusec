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
	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	networktypes "github.com/docker/docker/api/types/network"
	"io"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/mock"
	"golang.org/x/net/context"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) ContainerCreate(
	ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig,
	networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (
	containertypes.ContainerCreateCreatedBody, error) {
	args := m.MethodCalled("ContainerCreate")
	return args.Get(0).(containertypes.ContainerCreateCreatedBody), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) ContainerStart(ctx context.Context, container string, options types.ContainerStartOptions) error {
	args := m.MethodCalled("ContainerStart")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error) {
	args := m.MethodCalled("ContainerList")
	return args.Get(0).([]types.Container), utilsMock.ReturnNilOrError(args, 1)
}

func (m *Mock) ContainerWait(ctx context.Context, container string,
	condition containertypes.WaitCondition) (<-chan containertypes.ContainerWaitOKBody, <-chan error) {
	args := m.MethodCalled("ContainerWait")
	agr1 := make(chan containertypes.ContainerWaitOKBody)
	agr2 := make(chan error)
	go func() {
		agr1 <- args.Get(0).(containertypes.ContainerWaitOKBody)
	}()
	go func() {
		agr2 <- utilsMock.ReturnNilOrError(args, 1)
	}()
	return agr1, agr2
}

func (m *Mock) ContainerLogs(ctx context.Context, container string,
	options types.ContainerLogsOptions) (io.ReadCloser, error) {
	args := m.MethodCalled("ContainerLogs")
	return args.Get(0).(io.ReadCloser), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error {
	args := m.MethodCalled("ContainerRemove")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) ImageList(ctx context.Context, options types.ImageListOptions) ([]types.ImageSummary, error) {
	args := m.MethodCalled("ImageList")
	return args.Get(0).([]types.ImageSummary), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error) {
	args := m.MethodCalled("ImagePull")
	return args.Get(0).(io.ReadCloser), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) Ping(ctx context.Context) (types.Ping, error) {
	args := m.MethodCalled("Ping")
	return args.Get(0).(types.Ping), utilsMock.ReturnNilOrError(args, 1)
}
