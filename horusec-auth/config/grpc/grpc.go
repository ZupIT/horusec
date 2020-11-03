package grpc

import (
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"google.golang.org/grpc"
	"net"
)

func SetUpGRPCServer() {
	server := grpc.NewServer()
	// register

	err := server.Serve(getNetListener())
	if err != nil {
		logger.LogPanic("failed to setup grpc server", err)
	}

	logger.LogInfo("grpc server is running on port: 8006")
}

func getNetListener() net.Listener {
	port := env.GetEnvOrDefaultInt("HORUSEC_PORT", 8007)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.LogPanic("failed to get net listener", err)
	}

	return listener
}
