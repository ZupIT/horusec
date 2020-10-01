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

package dashboard

import (
	"errors"
	"fmt"
	netHTTP "net/http"
	"strconv"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/go-chi/chi"
	"github.com/google/uuid"

	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-analytic/internal/controllers/dashboard"
	"github.com/graphql-go/graphql"
)

type Handler struct {
	controller dashboard.IController
}

func NewDashboardHandler(postgresRead relational.InterfaceRead) *Handler {
	return &Handler{
		controller: dashboard.NewDashboardController(postgresRead),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Dashboard Company
// @Description get vuln details
// @ID vuln-details
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param query query string false "graphql query string"
// @Param page query string false "graphql query string"
// @Param size query string false "graphql query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Router /api/dashboard/companies/{companyID}/details [get]
// @Security ApiKeyAuth
func (h *Handler) GetVulnDetails(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorMissingGraphqlQuery)
		return
	}

	result, _ := h.controller.GetVulnerabilitiesByAuthor(query, h.getPaginationPage(r), h.getPaginationSize(r))
	if result.HasErrors() {
		httpUtil.StatusBadRequest(w, h.getErrorFromGraphQlResponse(result))
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total developers
// @ID company-total-dev
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/total-developers [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyTotalDevelopers(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetTotalDevelopers(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total repositories
// @ID company-total-repositories
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/total-repositories [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyTotalRepositories(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetTotalRepositories(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total vulnerabilities by author
// @ID company-vulnerabilities-by-author
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/vulnerabilities-by-author [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyVulnByDeveloper(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByDeveloper(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total vulnerabilities by language
// @ID company-vulnerabilities-by-language
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/vulnerabilities-by-language [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyVulnByLanguage(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByLanguage(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total vulnerabilities by repository
// @ID company-vulnerabilities-by-repository
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/vulnerabilities-by-repository [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyVulnByRepository(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByRepository(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total vulnerabilities by time
// @ID company-vulnerabilities-by-time
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/vulnerabilities-by-time [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyVulnByTime(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByTime(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Company
// @Description get total vulnerabilities by severity
// @ID company-vulnerabilities-by-severity
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/all-vulnerabilities [get]
// @Security ApiKeyAuth
func (h *Handler) GetCompanyVulnBySeverity(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnBySeverity(companyID, uuid.Nil, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get total developers
// @ID repository-total-dev
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/total-developers [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryTotalDevelopers(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetTotalDevelopers(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get total repositories
// @ID repository-total-repositories
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/total-repositories [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryTotalRepositories(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetTotalRepositories(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get vuln by developer
// @ID repository-by-developer
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/vulnerabilities-by-author [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryVulnByDeveloper(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByDeveloper(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get vuln by language
// @ID repository-by-language
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/vulnerabilities-by-language [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryVulnByLanguage(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByLanguage(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get vuln by repository
// @ID repository-by-repository
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/vulnerabilities-by-repository [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryVulnByRepository(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByRepository(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get vuln by time
// @ID repository-by-time
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/vulnerabilities-by-time [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryVulnByTime(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnByTime(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

// @Tags Dashboard Repository
// @Description get vuln by severity
// @ID repository-by-severity
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Param initialDate query string false "initialDate query string"
// @Param finalDate query string false "finalDate query string"
// @Success 200 "OK"
// @Failure 400 "BAD REQUEST"
// @Failure 500 "INTERNAL SERVER ERROR"
// @Router /api/dashboard/companies/{companyID}/repositories/{repositoryID}/all-vulnerabilities [get]
// @Security ApiKeyAuth
func (h *Handler) GetRepositoryVulnBySeverity(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
	initialDate, finalDate, err := getDateRangeFromRequestQuery(r)
	if err != nil {
		httpUtil.StatusUnprocessableEntity(w, err)
		return
	}

	result, err := h.controller.GetVulnBySeverity(uuid.Nil, repositoryID, *initialDate, *finalDate)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, result)
}

func getDateRangeFromRequestQuery(r *netHTTP.Request) (*time.Time, *time.Time, error) {
	initial, err := getDateFromRequestQuery(r, "initialDate")
	if err != nil {
		return nil, nil, err
	}

	final, err := getDateFromRequestQuery(r, "finalDate")
	if err != nil {
		return nil, nil, err
	}

	return &initial, &final, nil
}

func getDateFromRequestQuery(r *netHTTP.Request, queryStrKey string) (time.Time, error) {
	date := r.URL.Query().Get(queryStrKey)
	return time.Parse("2006-01-02T15:04:05Z", date)
}

func (h *Handler) getPaginationPage(r *netHTTP.Request) (page int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	return page
}

func (h *Handler) getPaginationSize(r *netHTTP.Request) (size int) {
	size, _ = strconv.Atoi(r.URL.Query().Get("size"))
	return size
}

func (h *Handler) getErrorFromGraphQlResponse(result *graphql.Result) error {
	var errorMsg string

	for _, item := range result.Errors {
		if errorMsg == "" {
			errorMsg = fmt.Sprintf("%s;", item.Message)
		}

		errorMsg = fmt.Sprintf("%s;%s", errorMsg, item.Message)
	}

	return errors.New(errorMsg)
}
