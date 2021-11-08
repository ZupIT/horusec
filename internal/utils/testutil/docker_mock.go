// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package testutil

import (
	"io"

	"github.com/docker/docker/api/types/network"

	mockutils "github.com/ZupIT/horusec-devkit/pkg/utils/mock"

	"context"

	dockerentities "github.com/ZupIT/horusec/internal/entities/docker"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/mock"
)

type DockerClientMock struct {
	mock.Mock
}

func NewDockerClientMock() *DockerClientMock {
	return new(DockerClientMock)
}

func (m *DockerClientMock) ContainerCreate(_ context.Context, _ *container.Config, _ *container.HostConfig,
	_ *network.NetworkingConfig, _ *specs.Platform, _ string) (container.ContainerCreateCreatedBody, error) {
	args := m.MethodCalled("ContainerCreate")
	return args.Get(0).(container.ContainerCreateCreatedBody), mockutils.ReturnNilOrError(args, 1)
}

func (m *DockerClientMock) ContainerStart(_ context.Context, _ string, _ types.ContainerStartOptions) error {
	args := m.MethodCalled("ContainerStart")
	return mockutils.ReturnNilOrError(args, 0)
}

func (m *DockerClientMock) ContainerList(_ context.Context, _ types.ContainerListOptions) ([]types.Container, error) {
	args := m.MethodCalled("ContainerList")
	return args.Get(0).([]types.Container), mockutils.ReturnNilOrError(args, 1)
}

func (m *DockerClientMock) ContainerWait(_ context.Context, _ string, _ container.WaitCondition) (
	<-chan container.ContainerWaitOKBody, <-chan error) {
	args := m.MethodCalled("ContainerWait")
	agr1 := make(chan container.ContainerWaitOKBody)
	agr2 := make(chan error)
	go func() {
		agr1 <- args.Get(0).(container.ContainerWaitOKBody)
	}()
	go func() {
		agr2 <- mockutils.ReturnNilOrError(args, 1)
	}()
	return agr1, agr2
}

func (m *DockerClientMock) ContainerLogs(
	_ context.Context, _ string, _ types.ContainerLogsOptions,
) (io.ReadCloser, error) {
	args := m.MethodCalled("ContainerLogs")
	return args.Get(0).(io.ReadCloser), mockutils.ReturnNilOrError(args, 1)
}

func (m *DockerClientMock) ContainerRemove(_ context.Context, _ string, _ types.ContainerRemoveOptions) error {
	args := m.MethodCalled("ContainerRemove")
	return mockutils.ReturnNilOrError(args, 0)
}

func (m *DockerClientMock) ImageList(_ context.Context, _ types.ImageListOptions) ([]types.ImageSummary, error) {
	args := m.MethodCalled("ImageList")
	return args.Get(0).([]types.ImageSummary), mockutils.ReturnNilOrError(args, 1)
}

func (m *DockerClientMock) ImagePull(_ context.Context, _ string, _ types.ImagePullOptions) (io.ReadCloser, error) {
	args := m.MethodCalled("ImagePull")
	return args.Get(0).(io.ReadCloser), mockutils.ReturnNilOrError(args, 1)
}

func (m *DockerClientMock) Ping(_ context.Context) (types.Ping, error) {
	args := m.MethodCalled("Ping")
	return args.Get(0).(types.Ping), mockutils.ReturnNilOrError(args, 1)
}

type DockerMock struct {
	mock.Mock
}

func NewDockerMock() *DockerMock {
	return new(DockerMock)
}

func (m *DockerMock) CreateLanguageAnalysisContainer(_ *dockerentities.AnalysisData) (string, error) {
	args := m.MethodCalled("CreateLanguageAnalysisContainer")
	return args.Get(0).(string), mockutils.ReturnNilOrError(args, 1)
}

func (m *DockerMock) DeleteContainersFromAPI() {
	m.MethodCalled("DeleteContainerFromAPI")
}

func (m *DockerMock) PullImage(_ string) error {
	args := m.MethodCalled("PullImage")
	return mockutils.ReturnNilOrError(args, 0)
}
