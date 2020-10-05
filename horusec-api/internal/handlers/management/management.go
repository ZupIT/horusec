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

package management

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-api/internal/controllers/management"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	netHTTP "net/http"
	"strconv"
)

type Handler struct {
	managementController management.IController
}

func NewHandler(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) *Handler {
	return &Handler{
		managementController: management.NewManagementController(postgresRead, postgresWrite),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Management
// @Security ApiKeyAuth
// @Description Get all vuln management data in repository
// @ID get-vuln-data
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param page query string false "page query string"
// @Param size query string false "size query string"
// @Param status query string false "status query string"
// @Param type query string false "type query string"
// @Router /api/management/{repositoryID} [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	page, size := h.getPageSize(r)
	result, err := h.managementController.GetAllVulnManagementData(repositoryID, page, size,
		h.getVulnType(r), h.getVulnStatus(r))
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

func (h *Handler) getPageSize(r *netHTTP.Request) (page, size int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	size, _ = strconv.Atoi(r.URL.Query().Get("size"))
	return page, size
}

func (h *Handler) getVulnType(r *netHTTP.Request) horusec.AnalysisVulnerabilitiesType {
	return horusec.AnalysisVulnerabilitiesType(r.URL.Query().Get("type"))
}

func (h *Handler) getVulnStatus(r *netHTTP.Request) horusec.AnalysisVulnerabilitiesStatus {
	return horusec.AnalysisVulnerabilitiesStatus(r.URL.Query().Get("status"))
}
