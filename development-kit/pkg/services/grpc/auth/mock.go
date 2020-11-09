package auth

import (
	"context"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) IsAuthorized(
	_ context.Context, _ *IsAuthorizedData, _ ...grpc.CallOption) (*IsAuthorizedResponse, error) {
	args := m.MethodCalled("IsAuthorized")
	return args.Get(0).(*IsAuthorizedResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetAccountID(
	ctx context.Context, in *GetAccountIDData, opts ...grpc.CallOption) (*GetAccountIDResponse, error) {
	args := m.MethodCalled("GetAccountID")
	return args.Get(0).(*GetAccountIDResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetAuthConfig(
	ctx context.Context, in *GetAuthConfigData, opts ...grpc.CallOption) (*GetAuthConfigResponse, error) {
	args := m.MethodCalled("GetAuthConfig")
	return args.Get(0).(*GetAuthConfigResponse), mockUtils.ReturnNilOrError(args, 1)
}
