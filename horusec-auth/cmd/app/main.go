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

package main

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	brokerConfig "github.com/ZupIT/horusec/horusec-auth/config/broker"
	"log"
	"net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	serverUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	adminConfig "github.com/ZupIT/horusec/horusec-auth/config/admin"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/ZupIT/horusec/horusec-auth/config/cors"
	grpcConfig "github.com/ZupIT/horusec/horusec-auth/config/grpc"
	"github.com/ZupIT/horusec/horusec-auth/config/swagger"
	"github.com/ZupIT/horusec/horusec-auth/internal/router"
)

// @title Horusec-Auth
// @description Service of Horusec.
// @termsOfService http://swagger.io/terms/

// @contact.name Horusec
// @contact.url https://github.com/ZupIT/horusec
// @contact.email horusec@zup.com.br

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-Horusec-Authorization
// nolint
func main() {
	var broker brokerLib.IBroker

	appConfig := app.NewConfig()
	if !appConfig.IsDisabledBroker() {
		broker = brokerConfig.SetUp()
	}

	postgresRead := adapter.NewRepositoryRead()
	postgresWrite := adapter.NewRepositoryWrite()
	cacheRepository := cache.NewCacheRepository(postgresRead, postgresWrite)

	adminConfig.CreateApplicationAdmin(appConfig, postgresRead, postgresWrite)

	server := serverUtil.NewServerConfig("8006", cors.NewCorsConfig()).Timeout(10)
	chiRouter := router.NewRouter(server).GetRouter(postgresRead, postgresWrite, broker, cacheRepository, appConfig)

	log.Println("service running on port", server.GetPort())
	swagger.SetupSwagger(chiRouter, "8006")

	go grpcConfig.SetUpGRPCServer(postgresRead, postgresWrite, appConfig)
	log.Fatal(http.ListenAndServe(server.GetPort(), chiRouter))
}
