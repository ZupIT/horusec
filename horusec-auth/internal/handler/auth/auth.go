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

package auth

import (
	"github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	netHTTP "net/http"
)

type Handler struct {
	authUseCases authUseCases.IUseCases
}

func NewAuthHandler() *Handler {
	return &Handler{
		authUseCases: authUseCases.NewAuthUseCases(),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

func (h *Handler) Login(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	authType := auth.AuthorizationType(r.Header.Get("X_AUTH_TYPE"))
	if authType.IsInvalid() {
		httpUtil.StatusBadRequest(w, errors.ErrorInvalidAuthType)
		return
	}

	credentials, err := h.authUseCases.NewCredentialsFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, errors.ErrorInvalidAuthType)
		return
	}

	print(credentials)
	//TODO call controller
	//TODO add login response
	httpUtil.StatusOK(w, "login data")
}
