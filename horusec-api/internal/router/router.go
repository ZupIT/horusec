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

//nolint
package router

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/middlewares"
	serverConfig "github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	"github.com/ZupIT/horusec/horusec-api/config/app"
	"github.com/ZupIT/horusec/horusec-api/internal/handlers/analysis"
	"github.com/ZupIT/horusec/horusec-api/internal/handlers/health"
	"github.com/ZupIT/horusec/horusec-api/internal/handlers/management"
	tokensCompany "github.com/ZupIT/horusec/horusec-api/internal/handlers/tokens/company"
	tokensRepository "github.com/ZupIT/horusec/horusec-api/internal/handlers/tokens/repository"
	"github.com/ZupIT/horusec/horusec-api/internal/router/routes"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

type Router struct {
	config *serverConfig.Server
	router *chi.Mux
}

func NewRouter(config *serverConfig.Server) *Router {
	return &Router{
		config: config,
		router: chi.NewRouter(),
	}
}

func (r *Router) setMiddleware() {
	r.EnableRealIP()
	r.EnableLogger()
	r.EnableRecover()
	r.EnableTimeout()
	r.EnableCompress()
	r.EnableRequestID()
	r.EnableCORS()
	r.RouterMetrics()
}

func (r *Router) GetRouter(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, broker brokerLib.IBroker, config app.IAppConfig, grpcCon *grpc.ClientConn) *chi.Mux {
	r.setMiddleware()
	r.RouterHealth(postgresRead, postgresWrite)
	r.RouterAnalysis(postgresRead, postgresWrite, broker, config)
	r.RouterTokensRepository(postgresRead, postgresWrite, grpcCon)
	r.RouterTokensCompany(postgresRead, postgresWrite, grpcCon)
	r.RouterManagement(postgresRead, postgresWrite, grpcCon)
	return r.router
}

func (r *Router) EnableRealIP() *Router {
	r.router.Use(middleware.RealIP)
	return r
}

func (r *Router) EnableLogger() *Router {
	r.router.Use(middleware.Logger)
	return r
}

func (r *Router) EnableRecover() *Router {
	r.router.Use(middleware.Recoverer)
	return r
}

func (r *Router) EnableTimeout() *Router {
	r.router.Use(middleware.Timeout(r.config.GetTimeout()))
	return r
}

func (r *Router) EnableCompress() *Router {
	r.router.Use(middleware.Compress(r.config.GetCompression()))
	return r
}

func (r *Router) EnableRequestID() *Router {
	r.router.Use(middleware.RequestID)
	return r
}

func (r *Router) EnableCORS() *Router {
	r.router.Use(r.config.Cors)
	return r
}

func (r *Router) RouterMetrics() *Router {
	r.router.Handle("/metrics", promhttp.Handler())
	return r
}

func (r *Router) RouterHealth(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) *Router {
	handler := health.NewHandler(postgresRead, postgresWrite)
	r.router.Route(routes.HealthHandler, func(router chi.Router) {
		router.Get("/", handler.Get)
		router.Options("/", handler.Options)
	})

	return r
}

func (r *Router) RouterAnalysis(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, broker brokerLib.IBroker, config app.IAppConfig) *Router {
	handler := analysis.NewHandler(postgresRead, postgresWrite, broker, config)
	tokenMiddleware := middlewares.NewTokenAuthz(postgresRead)
	r.router.Route(routes.AnalysisHandler, func(router chi.Router) {
		router.Use(tokenMiddleware.IsAuthorized)
		router.Get("/{analysisID}", handler.Get)
		router.Post("/", handler.Post)
		router.Options("/", handler.Options)
	})

	return r
}

func (r *Router) RouterTokensRepository(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, grpcCon *grpc.ClientConn) *Router {
	handler := tokensRepository.NewHandler(postgresRead, postgresWrite)
	authMiddleware := middlewares.NewHorusAuthzMiddleware(grpcCon)
	r.router.Route(routes.TokensRepositoryHandler, func(router chi.Router) {
		router.With(authMiddleware.IsRepositoryAdmin).Post("/", handler.Post)
		router.With(authMiddleware.IsRepositoryAdmin).Get("/", handler.Get)
		router.With(authMiddleware.IsRepositoryAdmin).Delete("/{tokenID}", handler.Delete)
		router.Options("/", handler.Options)
	})

	return r
}

func (r *Router) RouterTokensCompany(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, grpcCon *grpc.ClientConn) *Router {
	handler := tokensCompany.NewHandler(postgresRead, postgresWrite)
	companyMiddleware := middlewares.NewHorusAuthzMiddleware(grpcCon)
	r.router.Route(routes.TokensCompanyHandler, func(router chi.Router) {
		router.With(companyMiddleware.IsCompanyAdmin).Post("/", handler.Post)
		router.With(companyMiddleware.IsCompanyAdmin).Get("/", handler.Get)
		router.With(companyMiddleware.IsCompanyAdmin).Delete("/{tokenID}", handler.Delete)
		router.Options("/", handler.Options)
	})

	return r
}

func (r *Router) RouterManagement(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, grpcCon *grpc.ClientConn) *Router {
	repositoryMiddleware := middlewares.NewHorusAuthzMiddleware(grpcCon)
	handler := management.NewHandler(postgresRead, postgresWrite)
	r.router.Route(routes.ManagementHandler, func(router chi.Router) {
		router.With(repositoryMiddleware.IsRepositoryMember).Get("/", handler.Get)
		router.With(repositoryMiddleware.IsRepositorySupervisor).Put("/{vulnerabilityID}/type",
			handler.UpdateVulnType)
		router.Options("/", handler.Options)
	})

	return r
}
