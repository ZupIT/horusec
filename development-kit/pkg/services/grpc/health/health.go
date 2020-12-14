package health

import (
	"context"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type Check struct {
}

func NewHealthCheckGrpc() *Check {
	return &Check{}
}

func (c *Check) Check(context.Context,
	*grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	logger.LogInfo("sending the grpc Check request for health check")

	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

func (c *Check) Watch(_ *grpc_health_v1.HealthCheckRequest, server grpc_health_v1.Health_WatchServer) error {
	logger.LogInfo("sending the grpc Watch request for health check")

	return server.Send(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	})
}
