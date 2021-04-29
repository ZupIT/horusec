GO ?= go
GOFMT ?= gofmt
GO_FILES ?= $$(find . -name '*.go' | grep -v vendor)
GOLANG_CI_LINT ?= ./bin/golangci-lint
GO_IMPORTS ?= goimports
GO_IMPORTS_LOCAL ?= github.com/ZupIT/horusec
HORUSEC ?= horusec
DOCKER_COMPOSE ?= docker-compose

compose:
	$(DOCKER_COMPOSE) -f ./deployments/docker-compose.yaml up -d --build --force-recreate

fmt:
	$(GOFMT) -w $(GO_FILES)

lint:
    ifeq ($(wildcard $(GOLANG_CI_LINT)), $(GOLANG_CI_LINT))
		$(GOLANG_CI_LINT) run -v --timeout=5m -c .golangci.yml ./...
    else
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s latest
		$(GOLANG_CI_LINT) run -v --timeout=5m -c .golangci.yml ./...
    endif

coverage:
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/develop/scripts/coverage.sh | bash -s 91 .

test:
	$(GO) clean -testcache
	$(GO) test -v ./... -timeout=2m -parallel=1 -failfast -short

fix-imports:
    ifeq (, $(shell which $(GO_IMPORTS)))
		$(GO) get -u golang.org/x/tools/cmd/goimports
		$(GO_IMPORTS) -local $(GO_IMPORTS_LOCAL) -w $(GO_FILES)
    else
		$(GO_IMPORTS) -local $(GO_IMPORTS_LOCAL) -w $(GO_FILES)
    endif

security:
    ifeq (, $(shell which $(HORUSEC)))
		curl -fsSL https://horusec.io/bin/install.sh | bash
		$(HORUSEC) start -p="./" -e="true"
    else
		$(HORUSEC) start -p="./" -e="true"
    endif

PATH_BINARY_BUILD_CLI ?= $(GOPATH)/bin
build-install-cli-linux:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-cli" &> /dev/null
	CGO_ENABLED=0 GOOS=linux $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-cli" ./cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-cli"
	horusec-cli version
build-install-cli-darwin:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-darwin" &> /dev/null
	CGO_ENABLED=0 GOOS=darwin $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-darwin" ./cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-darwin"
	horusec version
build-install-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" ./cmd/app/main.go

pipeline: fmt fix-imports lint test coverage build security
