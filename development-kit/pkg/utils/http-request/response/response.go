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

package response

import (
	"errors"
	"io/ioutil"
	"net/http"

	enumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type HTTPResponse struct {
	response *http.Response
}

type Interface interface {
	ErrorByStatusCode() error
	GetBody() ([]byte, error)
	GetResponse() *http.Response
	GetStatusCode() int
	GetStatusCodeString() string
	GetContentType() string
	CloseBody()
}

func NewHTTPResponse(response *http.Response) Interface {
	return &HTTPResponse{
		response: response,
	}
}

func (h *HTTPResponse) GetResponse() *http.Response {
	return h.response
}

func (h *HTTPResponse) GetBody() ([]byte, error) {
	if h.response.Body == nil {
		return []byte{}, nil
	}

	return ioutil.ReadAll(h.response.Body)
}

func (h *HTTPResponse) ErrorByStatusCode() error {
	body, _ := h.GetBody()
	switch {
	case h.response.StatusCode >= 500:
		logger.LogError(enumErrors.ErrHTTPResponse.Error(), errors.New(string(body)), h.mapResponseStatus())
		return enumErrors.ErrDoHTTPServiceSide
	case h.response.StatusCode >= 400 && h.response.StatusCode < 500:
		logger.LogError(enumErrors.ErrHTTPResponse.Error(), errors.New(string(body)), h.mapResponseStatus())
		return enumErrors.ErrDoHTTPClientSide
	default:
		return nil
	}
}

func (h *HTTPResponse) GetStatusCode() int {
	return h.response.StatusCode
}

func (h *HTTPResponse) GetStatusCodeString() string {
	return http.StatusText(h.GetStatusCode())
}

func (h *HTTPResponse) GetContentType() string {
	return h.response.Header.Get("Content-type")
}

func (h *HTTPResponse) CloseBody() {
	err := h.response.Body.Close()
	logger.LogError("Error on close body", err)
}

func (h *HTTPResponse) mapResponseStatus() map[string]interface{} {
	return map[string]interface{}{
		"statusCode": h.GetStatusCode(),
		"status":     h.GetStatusCodeString(),
	}
}
