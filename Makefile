NPM ?= npm
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
	deployments/scripts/coverage.sh 78 "./development-kit"
coverage-horusec-api:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 97 "./horusec-api"
coverage-horusec-cli:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 87 "./horusec-cli"
coverage-horusec-messages:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 98 "./horusec-messages"
coverage-horusec-account:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 97 "./horusec-account"
coverage-horusec-analytic:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 98 "./horusec-analytic"
coverage-horusec-auth:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 96 "./horusec-auth"
coverage-horusec-webhook:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-webhook"
coverage-horusec-kotlin:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-kotlin"
coverage-horusec-java:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-java"
coverage-horusec-leaks:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-leaks"
coverage-horusec-csharp:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-csharp"
coverage-horusec-kubernetes:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-kubernetes"
coverage-horusec-nodejs:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-nodejs"
coverage-horusec-dart:
	chmod +x deployments/scripts/coverage.sh
	deployments/scripts/coverage.sh 99 "./horusec-dart"
# Check lint of project setup on file .golangci.yml
lint:
    ifeq ($(wildcard $(GOCILINT)), $(GOCILINT))
		$(GOCILINT) run -v --timeout=5m -c .golangci.yml ./...
    else
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.25.0
		$(GOCILINT) run -v --timeout=5m -c .golangci.yml ./...
    endif

# Run all tests of project but stop the execution on the first test fail
test-e2e-cli:
	$(GO) get -v ./e2e/...
	$(GO) get -v ./horusec-cli/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/cli/scan_languages/scan_languages_test.go -timeout=10m -parallel=1 -failfast
test-e2e-auth-horusec-without-application-admin:
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-horusec.without-application-admin.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-horusec.without-application-admin.yaml up -d --build --force-recreate postgresql
	make e2e-migrate
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-horusec.without-application-admin.yaml up -d --build --force-recreate horusec-auth horusec-account horusec-analytic horusec-api horusec-manager
	cd ./e2e/cypress && $(NPM) install && cd ../..
	cd ./e2e/cypress && $(NPM) run test::auth-horusec::without-application-admin && cd ../..
test-e2e-auth-keycloak-without-application-admin: compose-e2e-auth-keycloak-without-application-admin
	cd ./e2e/cypress && $(NPM) install && cd ../..
	sleep 15
	cd ./e2e/cypress && $(NPM) run test::auth-keycloak::without-application-admin && cd ../..

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

compose-network-host:
	$(DOCKER_COMPOSE) -f deployments/docker-compose-network-host up

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
compose-e2e-auth-horusec-without-application-admin:
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-horusec.without-application-admin.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-horusec.without-application-admin.yaml up -d --build --force-recreate
compose-e2e-auth-keycloak-without-application-admin:
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-keycloak.without-application-admin.yaml down -v
	$(DOCKER_COMPOSE) -f e2e/cypress/deployments/docker-compose.auth-keycloak.without-application-admin.yaml up -d --build --force-recreate

# ========================================================================================= #

migrate:
	sleep 3
	make run-migrate-up

run-migrate-up:
	chmod +x ./deployments/scripts/migration-run.sh
	./deployments/scripts/migration-run.sh up

run-migrate-drop:
	chmod +x ./deployments/scripts/migration-run.sh
	./deployments/scripts/migration-run.sh drop -f

e2e-migrate: run-migrate-drop run-migrate-up

# ========================================================================================= #

install: compose migrate install-cli

install-dev: install-manager build-manager install-cli compose-dev migrate

install-cli:
	curl -fsSL https://horusec.io/bin/install.sh | bash

install-semver:
	chmod +x ./deployments/scripts/install-semver.sh
	./deployments/scripts/install-semver.sh

PATH_BINARY_BUILD_CLI ?= $(GOPATH)/bin
build-install-cli-linux:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec" &> /dev/null
	CGO_ENABLED=0 GOOS=linux $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec" ./horusec-cli/cmd/horusec/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec"
	horusec version
build-install-cli-darwin:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec" &> /dev/null
	CGO_ENABLED=0 GOOS=darwin $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec" ./horusec-cli/cmd/horusec/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec"
	horusec version
build-install-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec.exe" ./horusec-cli/cmd/horusec/main.go
