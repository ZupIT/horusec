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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/middlewares"
	serverConfig "github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	company "github.com/ZupIT/horusec/horusec-account/internal/handlers/companies"
	"github.com/ZupIT/horusec/horusec-account/internal/handlers/health"
	"github.com/ZupIT/horusec/horusec-account/internal/handlers/repositories"
	"github.com/ZupIT/horusec/horusec-account/internal/router/routes"
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

func (r *Router) GetRouter(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite,
	appConfig app.IAppConfig, grpcCon *grpc.ClientConn) *chi.Mux {
	r.setMiddleware()
	r.setAPIRoutes(broker, databaseRead, databaseWrite, appConfig, grpcCon)
	return r.router
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

func (r *Router) setAPIRoutes(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite,
	appConfig app.IAppConfig, grpcCon *grpc.ClientConn) {
	r.RouterHealth(broker, databaseRead, databaseWrite, appConfig)
	r.RouterCompany(broker, databaseRead, databaseWrite, appConfig, grpcCon)
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

func (r *Router) RouterCompany(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, appConfig app.IAppConfig, grpcCon *grpc.ClientConn) *Router {
	handler := company.NewHandler(databaseWrite, databaseRead, broker, appConfig)
	authzMiddleware := middlewares.NewHorusAuthzMiddleware(grpcCon)
	r.router.Route(routes.CompanyHandler, func(router chi.Router) {
		router.With(authzMiddleware.IsApplicationAdmin).Post("/", handler.Create)
		router.With(authzMiddleware.SetContextAccountID).Get("/", handler.List)
		router.With(authzMiddleware.IsCompanyMember).Get("/{companyID}", handler.Get)
		router.With(authzMiddleware.IsCompanyAdmin).Get("/{companyID}/roles", handler.GetAccounts)
		router.With(authzMiddleware.IsCompanyAdmin).Patch("/{companyID}", handler.Update)
		router.With(authzMiddleware.IsCompanyAdmin).Patch("/{companyID}/roles/{accountID}", handler.UpdateAccountCompany)
		router.With(authzMiddleware.IsCompanyAdmin).Post("/{companyID}/roles", handler.InviteUser)
		router.With(authzMiddleware.IsCompanyAdmin).Delete("/{companyID}", handler.Delete)
		router.With(authzMiddleware.IsCompanyAdmin).Delete("/{companyID}/roles/{accountID}", handler.RemoveUser)
		router.Route("/{companyID}/repositories",
			r.routerCompanyRepositories(databaseRead, databaseWrite, broker, appConfig, grpcCon))
	})
	return r
}

func (r *Router) routerCompanyRepositories(databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, broker brokerLib.IBroker,
	appConfig app.IAppConfig, grpcCon *grpc.ClientConn) func(router chi.Router) {
	handler := repositories.NewRepositoryHandler(databaseWrite, databaseRead, broker, appConfig)
	authzMiddleware := middlewares.NewHorusAuthzMiddleware(grpcCon)
	return func(router chi.Router) {
		router.Use(authzMiddleware.IsCompanyMember)
		router.With(authzMiddleware.SetContextAccountID).Get("/", handler.List)
		router.With(authzMiddleware.IsCompanyAdmin).Post("/", handler.Create)
		router.With(authzMiddleware.IsRepositoryMember).Get("/{repositoryID}", handler.Get)
		router.With(authzMiddleware.IsRepositoryAdmin).Patch("/{repositoryID}", handler.Update)
		router.With(authzMiddleware.IsRepositoryAdmin).Delete("/{repositoryID}", handler.Delete)
		router.With(authzMiddleware.IsRepositoryAdmin).Patch(
			"/{repositoryID}/roles/{accountID}", handler.UpdateAccountRepository)
		router.With(authzMiddleware.IsRepositoryAdmin).Post("/{repositoryID}/roles", handler.InviteUser)
		router.With(authzMiddleware.IsRepositoryAdmin).Get("/{repositoryID}/roles", handler.GetAccounts)
		router.With(authzMiddleware.IsRepositoryAdmin).Delete("/{repositoryID}/roles/{accountID}", handler.RemoveUser)
	}
}

func (r *Router) RouterHealth(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, appConfig app.IAppConfig) *Router {
	handler := health.NewHandler(broker, databaseRead, databaseWrite, appConfig)
	r.router.Route(routes.HealthHandler, func(router chi.Router) {
		router.Get("/", handler.Get)
		router.Options("/", handler.Options)
	})

	return r
}
