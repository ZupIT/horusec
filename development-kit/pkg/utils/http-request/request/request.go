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

package request

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type Interface interface {
	Request(method, url string, body interface{}, headers map[string]string) (*http.Request, error)
}

type HTTPRequest struct {
}

func NewHTTPRequest() Interface {
	return &HTTPRequest{}
}

func (h *HTTPRequest) Request(method, url string, body interface{}, headers map[string]string) (*http.Request, error) {
	data, err := h.parseToBody(body)
	if err != nil {
		return &http.Request{}, err
	}
	req, err := http.NewRequest(strings.ToUpper(method), url, data)
	if err == nil && req != nil {
		req = h.setHTTPRequestHeaders(req, headers)
	}
	return req, err
}

func (h *HTTPRequest) parseToBody(body interface{}) (io.Reader, error) {
	if body == nil || body == "" {
		return nil, nil
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

func (h *HTTPRequest) setHTTPRequestHeaders(req *http.Request, headers map[string]string) *http.Request {
	for key, value := range headers {
		if key != "" && value != "" {
			req.Header.Add(key, value)
		}
	}
	return req
}
