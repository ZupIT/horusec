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

package app

import (
	"errors"
	"testing"

	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestSetupApp(t *testing.T) {
	t.Run("should return panic when trying setup without mock", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = SetupApp(&grpc.ClientConn{})
		})
	})

	t.Run("should success get auth config", func(t *testing.T) {
		authGrpcMock := &authGrpc.Mock{}
		authGrpcMock.On("GetAuthConfig").Return(&authGrpc.GetAuthConfigResponse{DisabledBroker: true}, nil)

		config := &Config{
			grpcCon: authGrpcMock,
		}

		assert.NotNil(t, config.getAuthConfig())
	})

	t.Run("should panic when return error getting config", func(t *testing.T) {
		authGrpcMock := &authGrpc.Mock{}
		authGrpcMock.On("GetAuthConfig").Return(&authGrpc.GetAuthConfigResponse{}, errors.New("test"))

		config := &Config{
			grpcCon: authGrpcMock,
		}

		assert.Panics(t, func() {
			_ = config.getAuthConfig()
		})
	})
}

func TestIsDisabledBroker(t *testing.T) {
	t.Run("should success get disabled broken attribute", func(t *testing.T) {
		appConfig := &Config{
			ConfigAuth: authEntities.ConfigAuth{
				DisabledBroker: true,
			},
		}

		assert.True(t, appConfig.GetDisabledBroker())
	})
}

func TestIsApplicationAdminEnable(t *testing.T) {
	t.Run("should success get application admin attribute", func(t *testing.T) {
		appConfig := &Config{
			ConfigAuth: authEntities.ConfigAuth{
				ApplicationAdminEnable: true,
			},
		}

		assert.True(t, appConfig.IsApplicationAdminEnable())
	})
}

func TestGetAuthType(t *testing.T) {
	t.Run("should success get auth type ldap", func(t *testing.T) {
		appConfig := &Config{
			ConfigAuth: authEntities.ConfigAuth{
				AuthType: authEnums.Ldap,
			},
		}

		assert.Equal(t, authEnums.Ldap, appConfig.GetAuthType())
	})
}
