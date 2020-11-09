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
