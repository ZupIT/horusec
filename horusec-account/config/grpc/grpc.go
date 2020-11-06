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
