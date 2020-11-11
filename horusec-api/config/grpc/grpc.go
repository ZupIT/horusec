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
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func SetupGrpcConnection() *grpc.ClientConn {
	if env.GetEnvOrDefaultBool("HORUSEC_GRPC_USE_CERTS", false) {
		return setupWithCerts()
	}

	return setupWithoutCerts()
}

func setupWithoutCerts() *grpc.ClientConn {
	conn, err := grpc.Dial(env.GetEnvOrDefault("HORUSEC_GRPC_AUTH_URL", "localhost:8007"), grpc.WithInsecure())
	if err != nil {
		logger.LogPanic("failed to connect to auth grpc", err)
	}

	return conn
}

func setupWithCerts() *grpc.ClientConn {
	cred, err := credentials.NewClientTLSFromFile(env.GetEnvOrDefault("HORUSEC_GRPC_CERT_PATH", ""), "")
	if err != nil {
		logger.LogPanic("failed to get grpc credentials", err)
	}

	conn, err := grpc.Dial(env.GetEnvOrDefault("HORUSEC_GRPC_AUTH_URL", "localhost:8007"),
		grpc.WithTransportCredentials(cred))
	if err != nil {
		logger.LogPanic("failed to connect to auth grpc", err)
	}

	return conn
}
