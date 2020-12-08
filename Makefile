GO ?= go
GOFMT ?= gofmt
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
GOCILINT ?= ./bin/golangci-lint
DOCKER_COMPOSE ?= docker-compose

# Format all files founded in GO
fmt:
	$(GOFMT) -w $(GOFMT_FILES)

# Run converage with threshold
coverage: coverage-development-kit coverage-horusec-api coverage-horusec-cli coverage-horusec-messages coverage-horusec-account coverage-horusec-analytic coverage-horusec-auth

coverage-development-kit:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 91 "./development-kit"
coverage-horusec-api:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-api"
coverage-horusec-cli:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 90 "./horusec-cli"
coverage-horusec-messages:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 98 "./horusec-messages"
coverage-horusec-account:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 98 "./horusec-account"
coverage-horusec-analytic:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 98 "./horusec-analytic"
coverage-horusec-auth:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 96 "./horusec-auth"
coverage-horusec-webhook:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-webhook"

# Check lint of project setup on file .golangci.yml
lint:
    ifeq ($(wildcard $(GOCILINT)), $(GOCILINT))
		$(GOCILINT) run -v --timeout=2m -c .golangci.yml ./...
    else
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.25.0
		$(GOCILINT) run -v --timeout=2m -c .golangci.yml ./...
    endif

# Run all tests of project but stop the execution on the first test fail
test:
	$(GO) clean -testcache && $(GO) test -v ./... -timeout=20m -parallel=1 -failfast -short

test-e2e-cli:
	$(GO) get -v ./e2e/...
	$(GO) get -v ./horusec-cli/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/cli/scan_languages/scan_languages_test.go -timeout=5m -parallel=1 -failfast
test-e2e-server-horusec: compose-e2e-server-horusec
	$(GO) get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/server/horusec/... -timeout=5m -parallel=1 -failfast
test-e2e-application-admin-horusec: compose-e2e-application-admin-horusec
	$(GO) get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/application_admin/horusec/... -timeout=5m -parallel=1 -failfast
test-e2e-messages: compose-e2e-messages
	$(GO) get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/server/messages/... -timeout=5m -parallel=1 -failfast
test-e2e-server-keycloak: compose-e2e-server-keycloak
	$(GO) get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/server/keycloak/... -timeout=5m -parallel=1 -failfast

# ========================================================================================= #

# Run all steps required to pass on pipeline
pipeline: fmt lint test coverage install-manager lint-manager build-manager

# ========================================================================================= #

install-manager:
	cd ./horusec-manager && npm install && cd ..

lint-manager:
	cd ./horusec-manager && npm run lint && cd ..

build-manager:
	cd ./horusec-manager && npm run build && cd ..

# ========================================================================================= #

# Down and Up all containers on depends to the project run
COMPOSE_FILE_NAME ?= docker-compose.yaml

compose: compose-down compose-up

compose-dev:
	$(DOCKER_COMPOSE) -f deployments/docker-compose.dev.yaml up -d --build

# Down all containers on depends to the project run
compose-down:
	$(DOCKER_COMPOSE) -f deployments/$(COMPOSE_FILE_NAME) down -v

# Up all containers on depends to the project run
compose-up:
	$(DOCKER_COMPOSE) -f deployments/$(COMPOSE_FILE_NAME) up -d --build --force-recreate

# ========================================================================================= #

compose-development-kit:
	$(DOCKER_COMPOSE) -f development-kit/deployments/docker-compose.yaml up -d --build --force-recreate
compose-horusec-api:
	$(DOCKER_COMPOSE) -f horusec-api/deployments/docker-compose.yaml up -d --build --force-recreate
compose-horusec-messages:
	$(DOCKER_COMPOSE) -f horusec-messages/deployments/docker-compose.yaml up -d --build --force-recreate
compose-horusec-webhook:
	$(DOCKER_COMPOSE) -f horusec-webhook/deployments/docker-compose.yaml up -d --build --force-recreate
compose-horusec-account:
	$(DOCKER_COMPOSE) -f horusec-account/deployments/docker-compose.yaml up -d --build --force-recreate
compose-horusec-analytic:
	$(DOCKER_COMPOSE) -f horusec-analytic/deployments/docker-compose.yaml up -d --build --force-recreate
compose-horusec-auth:
	$(DOCKER_COMPOSE) -f horusec-auth/deployments/docker-compose.yaml up -d --build --force-recreate
compose-e2e-server-horusec:
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.horusec.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.horusec.yaml up -d --build --force-recreate
compose-e2e-application-admin-horusec:
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.application-admin.horusec.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.application-admin.horusec.yaml up -d --build --force-recreate
compose-e2e-messages:
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.messages.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.messages.yaml up -d --build --force-recreate
compose-e2e-server-keycloak:
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.keycloak.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.keycloak.yaml up -d --build --force-recreate postgresql postgresql_keycloak keycloak horusec-account horusec-analytic

# ========================================================================================= #

migrate:
	chmod +x ./deployments/scripts/migration-run.sh
	sleep 3 && ./deployments/scripts/migration-run.sh up

# ========================================================================================= #

install: compose migrate install-cli

install-dev: install-manager build-manager install-cli compose-dev migrate

install-cli:
	curl -fsSL https://horusec.io/bin/install.sh | bash

install-semver:
	chmod +x ./deployments/scripts/install-semver.sh
	./deployments/scripts/install-semver.sh

PATH_BINARY_BUILD_CLI ?= $(GOPATH)/bin
build-install-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec" ./horusec-cli/cmd/horusec/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec"
	horusec version

build-install-leaks-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-leaks" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-leaks" ./horusec-leaks/cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-leaks"
	horusec-leaks version

build-install-kotlin-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-kotlin" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-kotlin" ./horusec-kotlin/cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-kotlin"
	horusec-kotlin version

build-install-java-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-java" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-java" ./horusec-java/cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-java"
	horusec-java version

build-install-csharp-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-csharp" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-csharp" ./horusec-csharp/cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-csharp"
	horusec-csharp version

build-install-kubernetes-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-kubernetes" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-kubernetes" ./horusec-kubernetes/cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-kubernetes"
	horusec-kubernetes version

build-install-nodejs-cli:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-nodejs" &> /dev/null
	$(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-nodejs" ./horusec-nodejs/cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-nodejs"
	horusec-nodejs version

# ========================================================================================= #

# HELM_SERVICE_NAME="horusec-account" make helm-upgrade
HELM_SERVICE_NAME ?= ""
KUBE_NAMESPACE ?= "horus-dev"

helm-upgrade:
	helm upgrade --wait -i $(HELM_SERVICE_NAME) ./$(HELM_SERVICE_NAME)/deployments/helm/$(HELM_SERVICE_NAME) -n $(KUBE_NAMESPACE) --debug
