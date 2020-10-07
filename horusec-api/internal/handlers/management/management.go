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
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	managementUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/management"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-api/internal/controllers/management"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	netHTTP "net/http"
	"strconv"
)

type Handler struct {
	managementController management.IController
	managementUseCases   managementUseCases.IUseCases
}

func NewHandler(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) *Handler {
	return &Handler{
		managementController: management.NewManagementController(postgresRead, postgresWrite),
		managementUseCases:   managementUseCases.NewManagementUseCases(),
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
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/repositories/{repositoryID}/management [get]
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

func (h *Handler) getVulnType(r *netHTTP.Request) horusec.VulnerabilityType {
	return horusec.VulnerabilityType(r.URL.Query().Get("type"))
}

func (h *Handler) getVulnStatus(r *netHTTP.Request) horusec.VulnerabilityStatus {
	return horusec.VulnerabilityStatus(r.URL.Query().Get("status"))
}

// @Tags Management
// @Security ApiKeyAuth
// @Description update vulnerability status and type
// @ID update-vuln-data
// @Accept  json
// @Produce  json
// @Param UpdateVulnManagementData body dto.UpdateVulnManagementData true "type and status of vulnerability"
// @Param vulnerabilityID path string true "vulnerabilityID of the vulnerability"
// @Param repositoryID path string true "repositoryID of the repository"
// @Success 200 {object} http.Response{content=string} "OK"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/repositories/{repositoryID}/management/{vulnerabilityID} [put]
func (h *Handler) Put(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	data, err := h.managementUseCases.NewUpdateVulnManagementDataFromReadCloser(r.Body)
	vulnerabilityID, _ := uuid.Parse(chi.URLParam(r, "vulnerabilityID"))
	if err != nil || vulnerabilityID == uuid.Nil {
		h.checkInvalidRequestErrors(w, err)
		return
	}

	result, err := h.managementController.Update(vulnerabilityID, data)
	if err != nil {
		h.checkSaveAnalysisErrors(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

func (h *Handler) checkSaveAnalysisErrors(w netHTTP.ResponseWriter, err error) {
	if err == errors.ErrNotFoundRecords {
		httpUtil.StatusNotFound(w, errors.ErrVulnerabilityNotFound)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

func (h *Handler) checkInvalidRequestErrors(w netHTTP.ResponseWriter, err error) {
	if err == nil {
		httpUtil.StatusBadRequest(w, errors.ErrInvalidVulnerabilityID)
		return
	}

	httpUtil.StatusBadRequest(w, err)
}
