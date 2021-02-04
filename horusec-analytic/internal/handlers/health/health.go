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

package health

import (
	"fmt"
	netHTTP "net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/services/grpc/health"
	"google.golang.org/grpc"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
)

type Handler struct {
	httpUtil.Interface
	postgresRead           relational.InterfaceRead
	grpcCon                *grpc.ClientConn
	grpcHealthCheckService health.ICheckClient
}

func NewHandler(postgresRead relational.InterfaceRead, grpcCon *grpc.ClientConn) httpUtil.Interface {
	return &Handler{
		postgresRead:           postgresRead,
		grpcCon:                grpcCon,
		grpcHealthCheckService: health.NewHealthCheckGrpcClient(grpcCon),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Health
// @Description Check if Health of service it's OK!
// @ID health
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /analytic/health [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	if !h.postgresRead.IsAvailable() {
		httpUtil.StatusInternalServerError(w, EnumErrors.ErrorDatabaseIsNotHealth)
		return
	}

	if isAvailable, state := h.grpcHealthCheckService.IsAvailable(); !isAvailable {
		httpUtil.StatusInternalServerError(w, fmt.Errorf(EnumErrors.ErrorGrpcConnectionNotReady, state))
		return
	}

	httpUtil.StatusOK(w, "service is healthy")
}
