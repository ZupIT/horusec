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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/services/middlewares"
	serverConfig "github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/ZupIT/horusec/horusec-account/internal/handlers/account"
	company "github.com/ZupIT/horusec/horusec-account/internal/handlers/companies"
	"github.com/ZupIT/horusec/horusec-account/internal/handlers/health"
	"github.com/ZupIT/horusec/horusec-account/internal/handlers/repositories"
	"github.com/ZupIT/horusec/horusec-account/internal/router/routes"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func (r *Router) GetRouter(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cacheRepository cache.Interface, appConfig app.IAppConfig) *chi.Mux {
	r.setMiddleware()
	r.setAPIRoutes(broker, databaseRead, databaseWrite, cacheRepository, appConfig)
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

func (r *Router) setAPIRoutes(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cacheRepository cache.Interface, appConfig app.IAppConfig) {
	r.RouterHealth(broker, databaseRead, databaseWrite, appConfig)
	r.RouterAccount(broker, databaseRead, databaseWrite, cacheRepository, appConfig)
	r.RouterCompany(databaseRead, databaseWrite, broker, appConfig)
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

// nolint
func (r *Router) RouterAccount(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cacheRepository cache.Interface, appConfig app.IAppConfig) *Router {
	handler := account.NewHandler(broker, databaseRead, databaseWrite, cacheRepository, appConfig)
	r.router.Route(routes.AccountHandler, func(router chi.Router) {
		router.Post("/login", handler.Login)
		router.Post("/create-account", handler.CreateAccount)
		router.Get("/validate/{accountID}", handler.ValidateEmail)
		router.Post("/send-code", handler.SendResetPasswordCode)
		router.Post("/validate-code", handler.ValidateResetPasswordCode)
		router.With(jwt.AuthMiddleware).Post("/change-password", handler.ChangePassword)
		router.Post("/renew-token", handler.RenewToken)
		router.Post("/logout", handler.Logout)
		router.Delete("/delete", handler.DeleteAccount)
		router.Post("/verify-already-used", handler.VerifyAlreadyInUse)
		router.Options("/", handler.Options)
	})

	return r
}

// nolint
func (r *Router) RouterCompany(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite,
	broker brokerLib.IBroker, appConfig app.IAppConfig) *Router {
	handler := company.NewHandler(databaseWrite, databaseRead, broker, appConfig)
	companyAuthzMiddleware := middlewares.NewCompanyAuthzMiddleware(databaseRead, databaseWrite)
	r.router.Route(routes.CompanyHandler, func(router chi.Router) {
		router.Use(jwt.AuthMiddleware)
		router.Post("/", handler.Create)
		router.Get("/", handler.List)
		router.With(companyAuthzMiddleware.IsCompanyMember).Get("/{companyID}", handler.Get)
		router.With(companyAuthzMiddleware.IsCompanyAdmin).Get("/{companyID}/roles", handler.GetAccounts)
		router.With(companyAuthzMiddleware.IsCompanyAdmin).Patch("/{companyID}", handler.Update)
		router.With(companyAuthzMiddleware.IsCompanyAdmin).Patch("/{companyID}/roles/{accountID}", handler.UpdateAccountCompany)
		router.With(companyAuthzMiddleware.IsCompanyAdmin).Post("/{companyID}/roles", handler.InviteUser)
		router.With(companyAuthzMiddleware.IsCompanyAdmin).Delete("/{companyID}", handler.Delete)
		router.With(companyAuthzMiddleware.IsCompanyAdmin).Delete("/{companyID}/roles/{accountID}", handler.RemoveUser)
		router.Route("/{companyID}/repositories",
			r.routerCompanyRepositories(databaseRead, databaseWrite, companyAuthzMiddleware, broker, appConfig))
	})
	return r
}

// nolint
func (r *Router) routerCompanyRepositories(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite,
	companyMiddleware middlewares.ICompanyAuthzMiddleware, broker brokerLib.IBroker,
	appConfig app.IAppConfig) func(router chi.Router) {
	repositoryAuthzMiddleware := middlewares.NewRepositoryAuthzMiddleware(databaseRead, databaseWrite)
	handler := repositories.NewRepositoryHandler(databaseWrite, databaseRead, broker, appConfig)
	return func(router chi.Router) {
		router.Use(companyMiddleware.IsCompanyMember)
		router.Get("/", handler.List)
		router.With(companyMiddleware.IsCompanyAdmin).Post("/", handler.Create)
		router.With(repositoryAuthzMiddleware.IsRepositoryMember).Get("/{repositoryID}", handler.Get)
		router.With(repositoryAuthzMiddleware.IsRepositoryAdmin).Patch("/{repositoryID}", handler.Update)
		router.With(repositoryAuthzMiddleware.IsRepositoryAdmin).Delete("/{repositoryID}", handler.Delete)
		router.With(repositoryAuthzMiddleware.IsRepositoryAdmin).Patch(
			"/{repositoryID}/roles/{accountID}", handler.UpdateAccountRepository)
		router.With(repositoryAuthzMiddleware.IsRepositoryAdmin).Post("/{repositoryID}/roles", handler.InviteUser)
		router.With(repositoryAuthzMiddleware.IsRepositoryAdmin).Get("/{repositoryID}/roles", handler.GetAccounts)
		router.With(repositoryAuthzMiddleware.IsRepositoryAdmin).Delete("/{repositoryID}/roles/{accountID}", handler.RemoveUser)
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
