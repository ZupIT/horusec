package health

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

type ICheckClient interface {
	IsAvailable() (bool, string)
}

type CheckClient struct {
	grpcCon *grpc.ClientConn
}

func NewHealthCheckGrpcClient(grpcCon *grpc.ClientConn) ICheckClient {
	return &CheckClient{
		grpcCon: grpcCon,
	}
}

func (c *CheckClient) IsAvailable() (bool, string) {
	if state := c.grpcCon.GetState(); state != connectivity.Idle && state != connectivity.Ready {
		return false, c.grpcCon.GetState().String()
	}

	return true, c.grpcCon.GetState().String()
}
