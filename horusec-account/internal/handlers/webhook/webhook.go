package webhook

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http"    // [swagger-import]
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook" // [swagger-import]
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	webhookUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/webhook"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	webhookController "github.com/ZupIT/horusec/horusec-account/internal/controller/webhook"
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
// @Param Webhook body webhook.Webhook{headers=[]webhook.WebhookHeaders} true "webhook info, only method allowed is POST"
// @Param companyID path string true "companyID of the webhook"
// @Param repositoryID path string true "repositoryID of the webhook"
// @Success 201 {object} http.Response{content=string} "CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/webhook/{companyID}/{repositoryID} [post]
// @Security ApiKeyAuth
func (h *Handler) Create(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	webhook, err := h.webhookUseCases.NewWebhookFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	webhook, err = webhook.SetCompanyIDAndRepositoryID(chi.URLParam(r, "companyID"), chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	response, err := h.webhookController.Create(webhook)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
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
// @Success 200 {object} http.Response{content=[]webhook.WebhookResponse{headers=[]webhook.WebhookHeaders}} "OK"
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
		if err == errorsEnum.ErrNotFoundRecords {
			httpUtil.StatusNotFound(w, err)
		} else {
			httpUtil.StatusInternalServerError(w, err)
		}
		return
	}
	httpUtil.StatusOK(w, response)
}

// @Tags Webhooks
// @Description get webhook by repositoryID!
// @ID get-webhook-by-repository-id
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the webhook"
// @Param repositoryID path string true "repositoryID of the webhook"
// @Success 200 {object} http.Response{content=[]webhook.WebhookResponse{headers=[]webhook.WebhookHeaders}} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/webhook/{companyID}/{repositoryID} [get]
// @Security ApiKeyAuth
func (h *Handler) ListAllByRepositoryID(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	response, err := h.webhookController.ListAllByRepositoryID(repositoryID)
	if err != nil {
		if err == errorsEnum.ErrNotFoundRecords {
			httpUtil.StatusNotFound(w, err)
		} else {
			httpUtil.StatusInternalServerError(w, err)
		}
		return
	}
	httpUtil.StatusOK(w, response)
}

// @Tags Webhooks
// @Description get webhook by repositoryID!
// @ID update-webhook
// @Accept  json
// @Produce  json
// @Param Webhook body webhook.Webhook{headers=[]webhook.WebhookHeaders} true "webhook info, only method allowed is POST"
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
	webhookID, err := uuid.Parse(chi.URLParam(r, "webhookID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	webhook, err := h.webhookUseCases.NewWebhookFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	webhook, err = webhook.SetWebhookID(webhookID).SetCompanyIDAndRepositoryID(chi.URLParam(r, "companyID"), chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	if err := h.webhookController.Update(webhook); err != nil {
		if err == errorsEnum.ErrNotFoundRecords {
			httpUtil.StatusNotFound(w, err)
		} else {
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
	if err != nil {
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
