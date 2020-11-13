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

package analysis

import (
	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-api/config/app"
	netHTTP "net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/middlewares"
	usecasesAnalysis "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/horusec-api/internal/controllers/analysis"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Handler struct {
	httpUtil.Interface
	analysisController analysis.IController
	useCases           usecasesAnalysis.Interface
}

func NewHandler(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, broker brokerLib.IBroker, config app.IAppConfig) httpUtil.Interface {
	return &Handler{
		useCases:           usecasesAnalysis.NewAnalysisUseCases(),
		analysisController: analysis.NewAnalysisController(postgresRead, postgresWrite, broker, config),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Analysis
// @Security ApiKeyAuth
// @Description Start new analysis
// @ID start-new-analysis
// @Accept  json
// @Produce  json
// @Param SendNewAnalysis body horusec.Analysis true "send new analysis info"
// @Success 201 {object} http.Response{content=string} "CREATED"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/analysis [post]
func (h *Handler) Post(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	analysisData, err := h.getAnalysisBody(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	analysisID, err := h.analysisController.SaveAnalysis(analysisData)
	if err != nil {
		h.checkSaveAnalysisErrors(w, err)
		return
	}

	httpUtil.StatusCreated(w, analysisID)
}

func (h *Handler) checkSaveAnalysisErrors(w netHTTP.ResponseWriter, err error) {
	if err == errors.ErrNotFoundRecords {
		httpUtil.StatusNotFound(w, errors.ErrorRepositoryNotFound)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

func (h *Handler) getAnalysisBody(r *netHTTP.Request) (*apiEntities.AnalysisData, error) {
	analysisData, err := h.useCases.DecodeAnalysisDataFromIoRead(r.Body)
	if err != nil {
		return nil, err
	}
	companyID, repositoryID, err := h.getCompanyIDAndRepositoryIDInCxt(r)
	if err != nil {
		return nil, err
	}
	analysisData.Analysis.CompanyID = companyID
	analysisData.Analysis.RepositoryID = repositoryID
	return analysisData, nil
}

func (h *Handler) getCompanyIDAndRepositoryIDInCxt(r *netHTTP.Request) (uuid.UUID, uuid.UUID, error) {
	companyIDCtx := r.Context().Value(middlewares.CompanyIDCtxKey)
	if companyIDCtx == nil {
		return uuid.Nil, uuid.Nil, errors.ErrorDoNotHavePermissionToThisAction
	}
	repositoryIDCtx := r.Context().Value(middlewares.RepositoryIDCtxKey)
	if repositoryIDCtx == nil {
		return companyIDCtx.(uuid.UUID), uuid.Nil, nil
	}
	return companyIDCtx.(uuid.UUID), repositoryIDCtx.(uuid.UUID), nil
}

// @Tags Analysis
// @Security ApiKeyAuth
// @Description Get analysis on database
// @ID get-one-analysis
// @Accept  json
// @Produce  json
// @Param analysisID path string true "analysisID of the analysis"
// @Success 200 {object} http.Response{content=horusec.Analysis{vulnerabilities=[]horusec.Vulnerability{commitAuthor=horusec.CommitAuthor{}}}} "OK"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/analysis/{analysisID} [get]
func (h *Handler) Get(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	analysisID, err := uuid.Parse(chi.URLParam(r, "analysisID"))
	if err != nil || analysisID == uuid.Nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	response, err := h.analysisController.GetAnalysis(analysisID)
	if err != nil {
		if err != errors.ErrNotFoundRecords {
			httpUtil.StatusInternalServerError(w, err)
		} else {
			httpUtil.StatusNotFound(w, err)
		}
	} else {
		httpUtil.StatusOK(w, response)
	}
}

func (h *Handler) Put(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusMethodNotAllowed(w, nil)
}

func (h *Handler) Delete(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusMethodNotAllowed(w, nil)
}
