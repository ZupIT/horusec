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

package webhook

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http"    // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook" // [swagger-import]
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	webhookController "github.com/ZupIT/horusec/horusec-account/internal/controller/webhook"
	webhookUseCases "github.com/ZupIT/horusec/horusec-account/internal/usecases/webhook"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	netHTTP "net/http"
)

type Handler struct {
	webhookController webhookController.IController
	webhookUseCases   webhookUseCases.IWebhook
}

func NewHandler(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead) *Handler {
	return &Handler{
		webhookController: webhookController.NewController(databaseWrite, databaseRead),
		webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Webhooks
// @Description create webhook!
// @ID create-webhook
// @Accept  json
// @Produce  json
// @Param Webhook body webhook.Webhook{headers=[]webhook.Headers} true "webhook info, method allowed is POST"
// @Param companyID path string true "companyID of the webhook"
// @Param repositoryID path string true "repositoryID of the webhook"
// @Success 201 {object} http.Response{content=string} "CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/webhook/{companyID}/{repositoryID} [post]
// @Security ApiKeyAuth
func (h *Handler) Create(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	webhookEntity, err := h.webhookUseCases.NewWebhookFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	webhookEntity, err = webhookEntity.
		SetCompanyIDAndRepositoryID(chi.URLParam(r, "companyID"), chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	h.executeCreateController(webhookEntity, w)
}

func (h *Handler) executeCreateController(webhookEntity *webhook.Webhook, w netHTTP.ResponseWriter) {
	response, err := h.webhookController.Create(webhookEntity)
	if err != nil {
		if err == errorsEnum.ErrorAlreadyExistsWebhookToRepository {
			httpUtil.StatusConflict(w, err)
		} else {
			httpUtil.StatusInternalServerError(w, err)
		}
		return
	}
	httpUtil.StatusCreated(w, response)
}

// @Tags Webhooks
// @Description get webhook!
// @ID get-webhook
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the webhook"
//nolint:lll swagger-line
// @Success 200 {object} http.Response{content=[]webhook.ResponseWebhook{headers=[]webhook.Headers,repository=account.RepositoryResponse}} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/webhook/{companyID} [get]
// @Security ApiKeyAuth
func (h *Handler) ListAll(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	response, err := h.webhookController.ListAll(companyID)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}
	httpUtil.StatusOK(w, response)
}

// @Tags Webhooks
// @Description get webhook by repositoryID!
// @ID update-webhook
// @Accept  json
// @Produce  json
// @Param Webhook body webhook.Webhook{headers=[]webhook.Headers} true "webhook info, method allowed is POST"
// @Param companyID path string true "companyID of the webhook"
// @Param repositoryID path string true "repositoryID of the webhook"
// @Param webhookID path string true "webhookID of the webhook"
// @Success 204
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/webhook/{companyID}/{repositoryID}/{webhookID} [put]
// @Security ApiKeyAuth
func (h *Handler) Update(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	webhookEntity, err := h.getWebhookEntityToUpdate(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	h.executeUpdateController(webhookEntity, w)
}

func (h *Handler) getWebhookEntityToUpdate(r *netHTTP.Request) (*webhook.Webhook, error) {
	webhookID, err := uuid.Parse(chi.URLParam(r, "webhookID"))
	if err != nil || webhookID == uuid.Nil {
		return nil, err
	}
	webhookEntity, err := h.webhookUseCases.NewWebhookFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}
	return webhookEntity.SetWebhookID(webhookID).
		SetCompanyIDAndRepositoryID(chi.URLParam(r, "companyID"), chi.URLParam(r, "repositoryID"))
}

func (h *Handler) executeUpdateController(webhookEntity *webhook.Webhook, w netHTTP.ResponseWriter) {
	if err := h.webhookController.Update(webhookEntity); err != nil {
		switch err {
		case errorsEnum.ErrNotFoundRecords:
			httpUtil.StatusNotFound(w, err)
		case errorsEnum.ErrorAlreadyExistsWebhookToRepository:
			httpUtil.StatusConflict(w, err)
		default:
			httpUtil.StatusInternalServerError(w, err)
		}
		return
	}
	httpUtil.StatusNoContent(w)
}

// @Tags Webhooks
// @Description get webhook by repositoryID!
// @ID delete-webhook
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the webhook"
// @Param repositoryID path string true "repositoryID of the webhook"
// @Param webhookID path string true "webhookID of the webhook"
// @Success 204
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/webhook/{companyID}/{repositoryID}/{webhookID} [delete]
// @Security ApiKeyAuth
func (h *Handler) Remove(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	webhookID, err := uuid.Parse(chi.URLParam(r, "webhookID"))
	if err != nil || webhookID == uuid.Nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	if err := h.webhookController.Remove(webhookID); err != nil {
		if err == errorsEnum.ErrNotFoundRecords {
			httpUtil.StatusNotFound(w, err)
		} else {
			httpUtil.StatusInternalServerError(w, err)
		}
		return
	}
	httpUtil.StatusNoContent(w)
}
