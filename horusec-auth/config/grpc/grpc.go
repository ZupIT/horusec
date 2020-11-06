package grpc

import (
	"fmt"
	"net"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
