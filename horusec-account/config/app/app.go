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
	"context"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"google.golang.org/grpc"
)

type Config struct {
	auth.ConfigAuth
	grpcCon authGrpc.AuthServiceClient
	context context.Context
}

type IAppConfig interface {
	IsDisabledBroker() bool
	IsApplicationAdminEnable() bool
	GetAuthType() authEnums.AuthorizationType
}

func SetupApp(grpcCon grpc.ClientConnInterface) IAppConfig {
	appConfig := &Config{
		grpcCon: authGrpc.NewAuthServiceClient(grpcCon),
		context: context.Background(),
	}

	return appConfig.getAuthConfig()
}

func (c *Config) getAuthConfig() IAppConfig {
	response, err := c.grpcCon.GetAuthConfig(c.context, &authGrpc.GetAuthConfigData{})
	if err != nil {
		logger.LogPanic("failed to setup app config, while getting auth config", err)
	}

	c.AuthType = authEnums.AuthorizationType(response.AuthType)
	c.DisabledBroker = response.DisabledBroker
	c.ApplicationAdminEnable = response.ApplicationAdminEnable
	return c
}

func (c *Config) IsDisabledBroker() bool {
	return c.DisabledBroker
}

func (c *Config) IsApplicationAdminEnable() bool {
	return c.ApplicationAdminEnable
}

func (c *Config) GetAuthType() authEnums.AuthorizationType {
	return c.AuthType
}
