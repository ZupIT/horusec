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

package auth

import (
	"context"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type MockAuthController struct {
	mock.Mock
}

func (m *MockAuthController) AuthByType(_ *dto.Credentials) (interface{}, error) {
	args := m.MethodCalled("AuthByType")
	return args.Get(0), mockUtils.ReturnNilOrError(args, 1)
}

func (m *MockAuthController) IsAuthorized(_ context.Context, _ *authGrpc.IsAuthorizedData) (*authGrpc.IsAuthorizedResponse, error) {
	args := m.MethodCalled("IsAuthorized")
	return args.Get(0).(*authGrpc.IsAuthorizedResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *MockAuthController) GetAuthConfig(_ context.Context, _ *authGrpc.GetAuthConfigData) (*authGrpc.GetAuthConfigResponse, error) {
	args := m.MethodCalled("GetAuthType")
	return args.Get(0).(*authGrpc.GetAuthConfigResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *MockAuthController) GetAccountID(_ context.Context, _ *authGrpc.GetAccountIDData) (*authGrpc.GetAccountIDResponse, error) {
	args := m.MethodCalled("GetAccountID")
	return args.Get(0).(*authGrpc.GetAccountIDResponse), mockUtils.ReturnNilOrError(args, 1)
}
