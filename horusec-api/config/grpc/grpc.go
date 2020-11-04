package grpc

import (
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"google.golang.org/grpc"
)

func SetupGrpcConnection() *grpc.ClientConn {
	conn, err := grpc.Dial(env.GetEnvOrDefault("HORUSEC_AUTH_URL", "localhost:8007"), grpc.WithInsecure())
	if err != nil {
		logger.LogPanic("failed to connect to auth grpc", err)
	}

	return conn
}
