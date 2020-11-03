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
	deployments/scripts/coverage.sh 90 "./development-kit"
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
	deployments/scripts/coverage.sh 98 "./horusec-auth"

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
	go get -v ./e2e/...
	go get -v ./horusec-cli/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/cli/scan_languages/scan_languages_test.go -timeout=5m -parallel=1 -failfast
test-e2e-server-horusec:
	make compose-e2e-server-horusec
	go get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/server/horusec/... -timeout=5m -parallel=1 -failfast
test-e2e-application-admin-horusec:
	make compose-e2e-application-admin-horusec
	go get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/application_admin/horusec/... -timeout=5m -parallel=1 -failfast
test-e2e-messages:
	make compose-e2e-messages
	go get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/server/messages/... -timeout=5m -parallel=1 -failfast
test-e2e-server-keycloak:
	make compose-e2e-server-keycloak
	go get -v ./e2e/...
	$(GO) clean -testcache
	$(GO) test -v ./e2e/server/keycloak/... -timeout=5m -parallel=1 -failfast

# ========================================================================================= #

# Run all steps required to pass on pipeline
pipeline: fmt lint test coverage build install-manager lint-manager build-manager

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
	$(DOCKER_COMPOSE) -f e2e/deployments/docker-compose.server.keycloak.yaml up -d --build --force-recreate postgresql keycloak horusec-account horusec-analytic horusec-api

# ========================================================================================= #

migrate:
	chmod +x ./deployments/scripts/migration-run.sh
	sleep 3 && ./deployments/scripts/migration-run.sh up

# ========================================================================================= #

install: compose migrate install-cli

install-dev: install-manager build-manager install-cli compose-dev migrate

install-cli:
	curl -fsSL https://horusec-cli.s3.amazonaws.com/install.sh | bash

build-install-cli:
	go build -o horusec ./horusec-cli/cmd/horusec/main.go
	chmod +x horusec
	rm -rf $(GOPATH)/bin/horusec
	mv horusec $(GOPATH)/bin
	cd ..
	horusec version

build-install-leaks-cli:
	go build -o horusec ./horusec-leaks/cmd/app/main.go
	chmod +x horusec
	rm -rf $(GOPATH)/bin/horusec-leaks
	mv horusec $(GOPATH)/bin/horusec-leaks
	cd ..
	horusec-leaks version

build-install-kotlin-cli:
	go build -o horusec ./horusec-kotlin/cmd/app/main.go
	chmod +x horusec
	rm -rf $(GOPATH)/bin/horusec-kotlin
	mv horusec $(GOPATH)/bin/horusec-kotlin
	cd ..
	horusec-kotlin version

build-install-java-cli:
	go build -o horusec ./horusec-java/cmd/app/main.go
	chmod +x horusec
	rm -rf $(GOPATH)/bin/horusec-java
	mv horusec $(GOPATH)/bin/horusec-java
	cd ..
	horusec-java version

# ========================================================================================= #

update-cli:
	chmod +x ./horusec-cli/deployments/scripts/update-image.sh
	./horusec-cli/deployments/scripts/update-image.sh $UPDATE_TYPE $SEND_NEW_VERSION_TO_S3 $IS_TO_UPDATE_LATEST