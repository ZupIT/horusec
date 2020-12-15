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

package grpc

import (
	"fmt"
	"net"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/grpc/health"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func SetUpGRPCServer(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, appConfig *app.Config) {
	if env.GetEnvOrDefaultBool("HORUSEC_GRPC_USE_CERTS", false) {
		setupWithCerts(postgresRead, postgresWrite, appConfig)
	}

	setupWithoutCerts(postgresRead, postgresWrite, appConfig)
}

func setupWithoutCerts(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, appConfig *app.Config) {
	server := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(server, health.NewHealthCheckGrpc())
	authGrpc.RegisterAuthServiceServer(server, authController.NewAuthController(postgresRead, postgresWrite, appConfig))
	if err := server.Serve(getNetListener()); err != nil {
		logger.LogPanic("failed to setup grpc server", err)
	}
}

func setupWithCerts(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, appConfig *app.Config) {
	grpCredentials, err := credentials.NewServerTLSFromFile(env.GetEnvOrDefault("HORUSEC_GRPC_CERT_PATH", ""),
		env.GetEnvOrDefault("HORUSEC_GRPC_KEY_PATH", ""))
	if err != nil {
		logger.LogPanic("failed to get grpc credentials", err)
	}

	server := grpc.NewServer(grpc.Creds(grpCredentials))
	grpc_health_v1.RegisterHealthServer(server, health.NewHealthCheckGrpc())
	authGrpc.RegisterAuthServiceServer(server, authController.NewAuthController(postgresRead, postgresWrite, appConfig))
	if err := server.Serve(getNetListener()); err != nil {
		logger.LogPanic("failed to setup grpc server", err)
	}
}

func getNetListener() net.Listener {
	port := env.GetEnvOrDefaultInt("HORUSEC_GRPC_PORT", 8007)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.LogPanic("failed to get net listener", err)
	}

	return listener
}
