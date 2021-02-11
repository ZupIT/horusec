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

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	enumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	ldapService "github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
)

type Handler struct {
	httpUtil.Interface
	postgresRead  relational.InterfaceRead
	postgresWrite relational.InterfaceWrite
	ldap          ldapService.ILDAPService
	appConfig     app.IConfig
}

func NewHandler(postgresRead relational.InterfaceRead,
	postgresWrite relational.InterfaceWrite, appConfig app.IConfig) httpUtil.Interface {
	return &Handler{
		postgresRead:  postgresRead,
		postgresWrite: postgresWrite,
		appConfig:     appConfig,
		ldap:          ldapService.NewLDAPClient(postgresRead),
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
// @Router /auth/health [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	if !h.postgresRead.IsAvailable() || !h.postgresWrite.IsAvailable() {
		httpUtil.StatusInternalServerError(w, enumErrors.ErrorDatabaseIsNotHealth)
		return
	}

	httpUtil.StatusOK(w, "service is healthy")
}
