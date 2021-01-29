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
	netHTTP "net/http"

	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	mailerLib "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer"
)

type Handler struct {
	httpUtil.Interface
	mailer mailerLib.IMailer
	broker brokerLib.IBroker
}

func NewHandler(mailer mailerLib.IMailer, broker brokerLib.IBroker) httpUtil.Interface {
	return &Handler{mailer: mailer, broker: broker}
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
// @Router /messages/health [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	if !h.mailer.IsAvailable() {
		httpUtil.StatusInternalServerError(w, EnumErrors.ErrorSMTPServerIsNotAvailable)
		return
	}

	if !h.broker.IsAvailable() {
		httpUtil.StatusInternalServerError(w, EnumErrors.ErrorBrokerIsNotHealth)
		return
	}

	httpUtil.StatusOK(w, "service is healthy")
}
