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

package router

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/services/middlewares"
	configUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	"github.com/ZupIT/horusec/horusec-analytic/internal/handlers/dashboard"
	"github.com/ZupIT/horusec/horusec-analytic/internal/handlers/health"
	"github.com/ZupIT/horusec/horusec-analytic/internal/router/routes"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Router struct {
	config *configUtil.Server
	router *chi.Mux
}

func NewRouter(config *configUtil.Server) *Router {
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

func (r *Router) GetRouter(postgresRead relational.InterfaceRead) *chi.Mux {
	r.setMiddleware()
	r.RouterCompanyAnalytic(postgresRead)
	r.RouterRepositoryAnalytic(postgresRead)
	r.RouterHealth(postgresRead)
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

func (r *Router) RouterHealth(postgresRead relational.InterfaceRead) *Router {
	handler := health.NewHandler(postgresRead)
	r.router.Route(routes.HealthHandler, func(router chi.Router) {
		router.Get("/", handler.Get)
		router.Options("/", handler.Options)
	})

	return r
}

// nolint
func (r *Router) RouterCompanyAnalytic(postgresRead relational.InterfaceRead) *Router {
	handler := dashboard.NewDashboardHandler(postgresRead)
	authz := middlewares.NewCompanyAuthzMiddleware(postgresRead, nil)
	r.router.Route(routes.CompanyHandler, func(router chi.Router) {
		router.Use(jwt.AuthMiddleware)
		router.With(authz.IsCompanyMember).Get("/{companyID}/details", handler.GetVulnDetails)
		router.With(authz.IsCompanyMember).Get("/{companyID}/total-developers", handler.GetCompanyTotalDevelopers)
		router.With(authz.IsCompanyMember).Get("/{companyID}/total-repositories", handler.GetCompanyTotalRepositories)
		router.With(authz.IsCompanyMember).Get("/{companyID}/all-vulnerabilities", handler.GetCompanyVulnBySeverity)
		router.With(authz.IsCompanyMember).Get("/{companyID}/vulnerabilities-by-language", handler.GetCompanyVulnByLanguage)
		router.With(authz.IsCompanyMember).Get("/{companyID}/vulnerabilities-by-author", handler.GetCompanyVulnByDeveloper)
		router.With(authz.IsCompanyMember).Get(
			"/{companyID}/vulnerabilities-by-repository", handler.GetCompanyVulnByRepository)
		router.With(authz.IsCompanyMember).Get("/{companyID}/vulnerabilities-by-time", handler.GetCompanyVulnByTime)
		router.Options("/", handler.Options)
	})

	return r
}

// nolint
func (r *Router) RouterRepositoryAnalytic(postgresRead relational.InterfaceRead) *Router {
	handler := dashboard.NewDashboardHandler(postgresRead)
	authz := middlewares.NewRepositoryAuthzMiddleware(postgresRead, nil)
	r.router.Route(routes.RepositoryHandler, func(router chi.Router) {
		router.Use(jwt.AuthMiddleware)
		router.With(authz.IsRepositoryMember).Get("/{repositoryID}/details", handler.GetVulnDetails)
		router.With(authz.IsRepositoryMember).Get("/{repositoryID}/total-developers", handler.GetRepositoryTotalDevelopers)
		router.With(authz.IsRepositoryMember).Get(
			"/{repositoryID}/total-repositories", handler.GetRepositoryTotalRepositories)
		router.With(authz.IsRepositoryMember).Get("/{repositoryID}/all-vulnerabilities", handler.GetRepositoryVulnBySeverity)
		router.With(authz.IsRepositoryMember).Get(
			"/{repositoryID}/vulnerabilities-by-language", handler.GetRepositoryVulnByLanguage)
		router.With(authz.IsRepositoryMember).Get(
			"/{repositoryID}/vulnerabilities-by-author", handler.GetRepositoryVulnByDeveloper)
		router.With(authz.IsRepositoryMember).Get(
			"/{repositoryID}/vulnerabilities-by-repository", handler.GetRepositoryVulnByRepository)
		router.With(authz.IsRepositoryMember).Get("/{repositoryID}/vulnerabilities-by-time", handler.GetRepositoryVulnByTime)
		router.Options("/", handler.Options)
	})
	return r
}
