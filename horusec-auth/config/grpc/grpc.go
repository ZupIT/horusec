package grpc

import (
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"google.golang.org/grpc"
	"net"
)

func SetUpGRPCServer(postgresRead relational.InterfaceRead, appConfig *app.Config) {
	server := grpc.NewServer()
	authGrpc.RegisterAuthServiceServer(server, authController.NewAuthController(postgresRead, appConfig))

	err := server.Serve(getNetListener())
	if err != nil {
		logger.LogPanic("failed to setup grpc server", err)
	}

	logger.LogInfo("grpc server is running on port: 8007")
}

func getNetListener() net.Listener {
	port := env.GetEnvOrDefaultInt("HORUSEC_PORT", 8007)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.LogPanic("failed to get net listener", err)
	}

	return listener
}
