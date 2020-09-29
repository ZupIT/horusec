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

package server

import (
	"compress/flate"
	"fmt"
	"net/http"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/go-chi/cors"
)

type Server struct {
	port       string
	timeout    time.Duration
	corsConfig *cors.Options
}

func NewServerConfig(defaultPort string, corsConfig *cors.Options) *Server {
	return &Server{
		port:       env.GetEnvOrDefault("HORUSEC_PORT", defaultPort),
		corsConfig: corsConfig,
	}
}

func (s *Server) Cors(next http.Handler) http.Handler {
	return cors.New(*s.corsConfig).Handler(next)
}

func (s *Server) Timeout(timeInSeconds int) *Server {
	s.timeout = time.Duration(timeInSeconds) * time.Second
	return s
}

func (s *Server) GetTimeout() time.Duration {
	return s.timeout
}

func (s *Server) GetCompression() int {
	return flate.BestCompression
}

func (s *Server) GetPort() string {
	return fmt.Sprintf(":%s", s.port)
}
