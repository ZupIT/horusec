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
package main

import (
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	grpcConfig "github.com/ZupIT/horusec/horusec-account/config/grpc"
	"log"
	"net/http"

	databaseSQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	serverUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http/server"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	brokerConfig "github.com/ZupIT/horusec/horusec-account/config/broker"
	"github.com/ZupIT/horusec/horusec-account/config/cors"
	"github.com/ZupIT/horusec/horusec-account/config/swagger"
	"github.com/ZupIT/horusec/horusec-account/internal/router"
)

// @title Horusec-Account
// @description Service of Horusec.
// @termsOfService http://swagger.io/terms/

// @contact.name Horusec
// @contact.url https://github.com/ZupIT/horusec
// @contact.email horusec@zup.com.br

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	var broker brokerLib.IBroker

	appConfig := app.SetupApp()
	if !appConfig.IsEmailServiceDisabled() {
		broker = brokerConfig.SetUp()
	}

	databaseRead := databaseSQL.NewRepositoryRead()
	databaseWrite := databaseSQL.NewRepositoryWrite()

	server := serverUtil.NewServerConfig("8003", cors.NewCorsConfig()).Timeout(10)
	chiRouter := router.NewRouter(server).GetRouter(broker, databaseRead, databaseWrite,
		appConfig, grpcConfig.SetupGrpcConnection())

	log.Println("service running on port", server.GetPort())
	swagger.SetupSwagger(chiRouter, "8003")

	log.Fatal(http.ListenAndServe(server.GetPort(), chiRouter))
}
