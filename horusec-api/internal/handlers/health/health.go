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
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-api/config/app"

	netHTTP "net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
)

type Handler struct {
	httpUtil.Interface
	postgresRead  relational.InterfaceRead
	postgresWrite relational.InterfaceWrite
	config        app.IAppConfig
	broker        brokerLib.IBroker
}

func NewHandler(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite,
	broker brokerLib.IBroker, config app.IAppConfig) httpUtil.Interface {
	return &Handler{
		broker:        broker,
		config:        config,
		postgresRead:  postgresRead,
		postgresWrite: postgresWrite,
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Health
// @Description Check if Health of service it's OK!
// @ID health
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/health [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	if !h.postgresRead.IsAvailable() || !h.postgresWrite.IsAvailable() {
		httpUtil.StatusInternalServerError(w, errors.ErrorDatabaseIsNotHealth)
		return
	}
	if !h.config.IsDisabledBroker() {
		if !h.broker.IsAvailable() {
			httpUtil.StatusInternalServerError(w, errors.ErrorBrokerIsNotHealth)
			return
		}
	}
	httpUtil.StatusOK(w, "service is healthy")
}
