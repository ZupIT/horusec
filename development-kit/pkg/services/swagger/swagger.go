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

package swagger

import (
	"fmt"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/go-chi/chi"
	httpSwagger "github.com/swaggo/http-swagger"
)

type Swagger struct {
	router *chi.Mux
	port   string
	host   string
}

func NewSwagger(router *chi.Mux, defaultPort string) *Swagger {
	return &Swagger{
		router: router,
		port:   env.GetEnvOrDefault("HORUSEC_PORT", defaultPort),
		host:   env.GetEnvOrDefault("HORUSEC_SWAGGER_HOST", "localhost"),
	}
}

func (s *Swagger) RouterSwagger() {
	s.router.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("http://%s:%s/swagger/doc.json", s.host, s.port)),
	))
}

func (s *Swagger) GetSwaggerDocsHost() string {
	return fmt.Sprintf("%s:%s", s.host, s.port)
}
