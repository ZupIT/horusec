package webhook

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	"io"
)

type IWebhook interface {
	NewWebhookFromReadCloser(body io.ReadCloser) (*webhook.Webhook, error)
}

type Webhook struct {
}

func NewWebhookUseCases() IWebhook {
	return &Webhook{}
}

func (w *Webhook) NewWebhookFromReadCloser(body io.ReadCloser) (webhookData *webhook.Webhook, err error) {
	err = json.NewDecoder(body).Decode(&webhookData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return webhookData, webhookData.Validate()
}
