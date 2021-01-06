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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestWebhook_NewWebhookFromReadCloser(t *testing.T) {
	t.Run("should parse read closer to webhook with success", func(t *testing.T) {
		w := &webhook.Webhook{
			URL:    "http://example.com",
			Method: "POST",
		}
		readCloser := ioutil.NopCloser(strings.NewReader(string(w.ToBytes())))

		useCases := NewWebhookUseCases()
		w, err := useCases.NewWebhookFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, w)
	})
	t.Run("should parse read closer to webhook with error", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader("wrong data type"))

		useCases := NewWebhookUseCases()
		w, err := useCases.NewWebhookFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Empty(t, w)
	})
}
