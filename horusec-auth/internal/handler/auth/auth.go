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
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/auth" // [swagger-import]
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	netHTTP "net/http"
)

type Handler struct {
	authUseCases   authUseCases.IUseCases
	authController authController.IController
}

func NewAuthHandler() *Handler {
	return &Handler{
		authUseCases: authUseCases.NewAuthUseCases(),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Auth
// @Description authenticate login by type!
// @ID authenticate login
// @Accept  json
// @Produce  json
// @Param Credentials body auth.Credentials true "auth info"
// @Success 200 {object} http.Response{content=string} "STATUS OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/auth/authenticate [post]
func (h *Handler) AuthByType(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	credentials, authType, err := h.getCredentialsAndAuthType(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}
	
	response, err := h.authController.AuthByType(credentials, authType)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getCredentialsAndAuthType(
	r *netHTTP.Request) (*authEntities.Credentials, authEnums.AuthorizationType, error) {
	authType := authEnums.AuthorizationType(r.Header.Get("X_AUTH_TYPE"))
	if authType.IsInvalid() {
		return nil, "", errors.ErrorInvalidAuthType
	}

	credentials, err := h.authUseCases.NewCredentialsFromReadCloser(r.Body)
	if err != nil {
		return credentials, "", err
	}

	return credentials, authType, nil
}
