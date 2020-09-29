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
	"errors"
	"io/ioutil"
	"os"
	"testing"

	goContext "golang.org/x/net/context"

	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker/client"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var ErrGeneric = errors.New("some error generic")

const (
	ImageName = "horuszup/gitleaks"
	ImageTag  = "latest"
	Cmd       = `
		mkdir -p ~/.ssh &&
		echo '%GIT_PRIVATE_SSH_KEY%' > ~/.ssh/horusec_id_rsa &&
		chmod 600 ~/.ssh/horusec_id_rsa &&
		echo "IdentityFile ~/.ssh/horusec_id_rsa" >> /etc/ssh/ssh_config &&
		echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config &&
		git clone -b %GIT_BRANCH% --single-branch %GIT_REPO% code --quiet 2> /tmp/errorGitCloneGitleaks
		if [ $? -eq 0 ]; then
			touch /tmp/results.json
			touch /tmp/errorGitleaks.txt
			$(which gitleaks) --report=/tmp/results.json --repo-path=./code --branch=%GIT_BRANCH% &> /tmp/errorGitleaks.txt
			if [ -s /tmp/errorGitleaks.txt ]
			then
				jq -j -M -c . /tmp/results.json
			else
				jq -j -M -c . /tmp/errorGitleaks.txt
			fi
		else
			echo "ERROR_CLONING"
			cat /tmp/errorGitCloneGitleaks
		fi
	`
)

func TestDockerAPI_CreateLanguageAnalysisContainer(t *testing.T) {
	t.Run("Should return return error when image is empty", func(t *testing.T) {
		api := NewDockerAPI(client.NewDockerClient(), &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: "",
			Tag:   "tag",
			CMD:   "cmd",
		})

		assert.Error(t, err)
	})

	t.Run("Should return return error when tag is empty", func(t *testing.T) {
		api := NewDockerAPI(client.NewDockerClient(), &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: "image",
			Tag:   "",
			CMD:   "cmd",
		})

		assert.Error(t, err)
	})

	t.Run("Should return return error when cmd is empty", func(t *testing.T) {
		api := NewDockerAPI(client.NewDockerClient(), &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: "image",
			Tag:   "tag",
			CMD:   "",
		})

		assert.Error(t, err)
	})

	t.Run("Should return error when pull image aleatory", func(t *testing.T) {
		api := NewDockerAPI(client.NewDockerClient(), &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: "john",
			Tag:   "doe",
			CMD:   "command",
		})

		assert.Error(t, err)
	})

	t.Run("Should create valid canonical image path", func(t *testing.T) {
		api := NewDockerAPI(client.NewDockerClient(), &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: "test/image-7.4.6",
			Tag:   "latest",
			CMD:   "cmd",
		})

		assert.Error(t, err)
	})

	t.Run("Should return error when list image to check if exist", func(t *testing.T) {
		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{}, ErrGeneric)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrGeneric, err)
	})

	t.Run("Should return error when pull new image", func(t *testing.T) {
		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{}, nil)
		dockerAPIClient.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte("Some data"))), ErrGeneric)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrGeneric, err)
	})

	t.Run("Should return error when create container", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_DOCKER_API_IMAGE_CHECK", "false")
		_ = os.Setenv("HORUSEC_DOCKER_API_RETRY_TIME_SLEEP_SECONDS", "1")

		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{{ID: uuid.New().String()}}, nil)
		dockerAPIClient.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte("Some data"))), nil)
		dockerAPIClient.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{ID: uuid.New().String()}, ErrGeneric)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrGeneric, err)
	})

	t.Run("Should return error when start container", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_DOCKER_API_IMAGE_CHECK", "false")
		_ = os.Setenv("HORUSEC_DOCKER_API_RETRY_TIME_SLEEP_SECONDS", "1")

		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{{ID: uuid.New().String()}}, nil)
		dockerAPIClient.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte("Some data"))), nil)
		dockerAPIClient.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{ID: uuid.New().String()}, nil)
		dockerAPIClient.On("ContainerStart").Return(ErrGeneric)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())
		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrGeneric, err)
	})

	t.Run("Should return error when wait container", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_DOCKER_API_IMAGE_CHECK", "false")
		_ = os.Setenv("HORUSEC_DOCKER_API_RETRY_TIME_SLEEP_SECONDS", "1")

		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{{ID: uuid.New().String()}}, nil)
		dockerAPIClient.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte("Some data"))), nil)
		dockerAPIClient.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{ID: uuid.New().String()}, nil)
		dockerAPIClient.On("ContainerStart").Return(nil)
		dockerAPIClient.On("ContainerWait").Return(int64(1), ErrGeneric)
		dockerAPIClient.On("ContainerRemove").Return(nil)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())

		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrGeneric, err)
	})

	t.Run("Should return error when read container logs", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_DOCKER_API_IMAGE_CHECK", "false")
		_ = os.Setenv("HORUSEC_DOCKER_API_RETRY_TIME_SLEEP_SECONDS", "1")

		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{{ID: uuid.New().String()}}, nil)
		dockerAPIClient.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte("Some data"))), nil)
		dockerAPIClient.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{ID: uuid.New().String()}, nil)
		dockerAPIClient.On("ContainerStart").Return(nil)
		dockerAPIClient.On("ContainerWait").Return(int64(1), nil)
		dockerAPIClient.On("ContainerLogs").Return(ioutil.NopCloser(bytes.NewReader(nil)), ErrGeneric)
		dockerAPIClient.On("ContainerRemove").Return(nil)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())

		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrGeneric, err)
	})

	t.Run("Should return analysis with success", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_DOCKER_API_IMAGE_CHECK", "false")
		_ = os.Setenv("HORUSEC_DOCKER_API_RETRY_TIME_SLEEP_SECONDS", "1")

		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ImageList").Return([]types.ImageSummary{{ID: uuid.New().String()}}, nil)
		dockerAPIClient.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte("Some data"))), nil)
		dockerAPIClient.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{ID: uuid.New().String()}, nil)
		dockerAPIClient.On("ContainerStart").Return(nil)
		dockerAPIClient.On("ContainerWait").Return(int64(1), nil)
		dockerAPIClient.On("ContainerLogs").Return(ioutil.NopCloser(bytes.NewReader([]byte("{}"))), nil)
		dockerAPIClient.On("ContainerRemove").Return(nil)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())

		_, err := api.CreateLanguageAnalysisContainer(&dockerEntities.AnalysisData{
			Image: ImageName,
			Tag:   ImageTag,
			CMD:   Cmd,
		})

		assert.NoError(t, err)
	})
}

func TestDeleteContainersFromAPI(t *testing.T) {
	t.Run("should not panics", func(t *testing.T) {
		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)
		dockerAPIClient.On("ContainerRemove").Return(nil)

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())

		assert.NotPanics(t, func() {
			api.DeleteContainersFromAPI()
		})
	})

	t.Run("should not panics but return error when container list", func(t *testing.T) {
		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ContainerList").Return([]types.Container{}, errors.New("test"))

		api := NewDockerAPI(dockerAPIClient, &cliConfig.Config{}, uuid.New())

		assert.NotPanics(t, func() {
			api.DeleteContainersFromAPI()
		})
	})

	t.Run("Test Replace docker bind folder to windows o.s", func(t *testing.T) {
		dockerAPIClient := &client.Mock{}
		dockerAPIClient.On("ContainerList").Return([]types.Container{}, errors.New("test"))
		config := &cliConfig.Config{}
		config.SetProjectPath("C:/Users/usr/Documents/Horusec/project")

		api := &API{
			ctx:                    goContext.Background(),
			dockerClient:           dockerAPIClient,
			config:                 config,
			analysisID:             uuid.New(),
			pathDestinyInContainer: "/src",
		}

		response := api.getSourceFolder()
		assert.Equal(t, "//c//Users//usr//Documents//Horusec//project//.horusec//"+api.analysisID.String(), response)
	})
}
