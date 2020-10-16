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
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
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
// @Description Get all vuln vulnerability data in repository
// @ID get-vuln-data
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param page query string false "page query string"
// @Param size query string false "size query string"
// @Param vulnHash query string false "vulnHash query string"
// @Param vulnType query string false "vulnType query string"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/management [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	page, size := h.getPageSize(r)
	result, err := h.managementController.ListVulnManagementData(repositoryID, page, size,
		h.getVulnSeverity(r), h.getVulnType(r), h.getVulnHash(r))
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

func (h *Handler) getVulnSeverity(r *netHTTP.Request) severity.Severity {
	return severity.Severity(r.URL.Query().Get("vulnSeverity"))
}

func (h *Handler) getVulnType(r *netHTTP.Request) horusecEnums.VulnerabilityType {
	return horusecEnums.VulnerabilityType(r.URL.Query().Get("vulnType"))
}

func (h *Handler) getVulnHash(r *netHTTP.Request) string {
	return r.URL.Query().Get("vulnHash")
}

// @Tags Management
// @Security ApiKeyAuth
// @Description update vulnerability type
// @ID update-vuln-type
// @Accept  json
// @Produce  json
// @Param UpdateVulnType body dto.UpdateVulnType true "type of vulnerability"
// @Param vulnerabilityID path string true "vulnerabilityID of the vulnerability"
// @Param repositoryID path string true "repositoryID of the repository"
// @Success 200 {object} http.Response{content=string} "OK"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/management/{vulnerabilityID}/type [put]
func (h *Handler) UpdateVulnType(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	updateData, err := h.managementUseCases.NewUpdateVulnTypeFromReadCloser(r.Body)
	vulnerabilityID, _ := uuid.Parse(chi.URLParam(r, "vulnerabilityID"))
	if err != nil || vulnerabilityID == uuid.Nil {
		h.checkInvalidRequestErrors(w, err)
		return
	}

	result, err := h.managementController.UpdateVulnType(vulnerabilityID, updateData)
	if err != nil {
		h.checkUpdateErrors(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

func (h *Handler) checkUpdateErrors(w netHTTP.ResponseWriter, err error) {
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
