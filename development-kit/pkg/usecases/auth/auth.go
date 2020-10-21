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
	"encoding/json"
	"fmt"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"io"
)

type IUseCases interface {
	NewCredentialsFromReadCloser(body io.ReadCloser) (*authEntities.Credentials, error)
	NewAuthorizationDataFromReadCloser(body io.ReadCloser) (*authEntities.AuthorizationData, error)
	IsInvalidAuthType(authType authEnums.AuthorizationType) error
}

type UseCases struct {
}

func NewAuthUseCases() IUseCases {
	return &UseCases{}
}

func (u *UseCases) NewCredentialsFromReadCloser(body io.ReadCloser) (*authEntities.Credentials, error) {
	credentials := &authEntities.Credentials{}
	err := json.NewDecoder(body).Decode(&credentials)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return credentials, credentials.Validate()
}

func (u *UseCases) NewAuthorizationDataFromReadCloser(body io.ReadCloser) (*authEntities.AuthorizationData, error) {
	authorizationData := &authEntities.AuthorizationData{}
	err := json.NewDecoder(body).Decode(&authorizationData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return authorizationData, authorizationData.Validate()
}

func (u *UseCases) IsInvalidAuthType(authType authEnums.AuthorizationType) error {
	validType := env.GetEnvOrDefault("HORUSEC_AUTH_TYPE", authEnums.Horusec.ToString())
	if authType.ToString() != validType {
		return fmt.Errorf(errors.ErrorAuthTypeNotActive, validType)
	}

	return nil
}
