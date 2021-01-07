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

package http

import (
	"encoding/json"
	"net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"

	httpEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/http"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

func StatusOK(w http.ResponseWriter, content interface{}) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusOK, http.StatusText(http.StatusOK), content)

	setResponseWriter(w, response)
}

func StatusCreated(w http.ResponseWriter, content interface{}) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusCreated, http.StatusText(http.StatusCreated), content)

	setResponseWriter(w, response)
}

func StatusNoContent(w http.ResponseWriter) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusNoContent, http.StatusText(http.StatusNoContent), nil)

	setResponseWriter(w, response)
}

func StatusBadRequest(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusBadRequest, http.StatusText(http.StatusBadRequest), getErrorMessage(err))

	setResponseWriter(w, response)
}

func StatusUnauthorized(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), getErrorMessage(err))

	setResponseWriter(w, response)
}

func StatusForbidden(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusForbidden, http.StatusText(http.StatusForbidden), getErrorMessage(err))

	setResponseWriter(w, response)
}

func StatusNotFound(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusNotFound, http.StatusText(http.StatusNotFound), getErrorMessage(err))

	setResponseWriter(w, response)
}

func StatusMethodNotAllowed(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusMethodNotAllowed,
		http.StatusText(http.StatusMethodNotAllowed), getErrorMessage(err))

	setResponseWriter(w, response)
}

func StatusConflict(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusConflict, http.StatusText(http.StatusConflict), getErrorMessage(err))

	setResponseWriter(w, response)
}

func StatusInternalServerError(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusInternalServerError,
		http.StatusText(http.StatusInternalServerError), getErrorMessage(internalServerError(err)))

	setResponseWriter(w, response)
}

func StatusUnprocessableEntity(w http.ResponseWriter, err error) {
	response := &httpEntities.Response{}
	response.SetResponseData(http.StatusUnprocessableEntity,
		http.StatusText(http.StatusUnprocessableEntity), getErrorMessage(err))

	setResponseWriter(w, response)
}

func setResponseWriter(w http.ResponseWriter, response *httpEntities.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(response.GetStatusCode())
	_ = json.NewEncoder(w).Encode(response)
}

func getErrorMessage(err error) string {
	if err != nil {
		return err.Error()
	}

	return ""
}

func internalServerError(err error) error {
	logger.LogError("{INTERNAL_SERVER_ERROR} ->", err)
	return errors.ErrorGenericInternalError
}
