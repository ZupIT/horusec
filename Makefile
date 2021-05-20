GO ?= go
GOFMT ?= gofmt
GO_FILES ?= $$(find . -name '*.go' | grep -v vendor)
GO_LIST_TO_TEST ?= $$(go list ./... | grep -v /examples/ | grep -v /e2e/)
GOLANG_CI_LINT ?= ./bin/golangci-lint
GO_IMPORTS ?= goimports
GO_IMPORTS_LOCAL ?= github.com/ZupIT/horusec
HORUSEC ?= horusec
DOCKER_COMPOSE ?= docker-compose
PATH_BINARY_BUILD_CLI ?= $(GOPATH)/bin

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
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/develop/scripts/coverage.sh | bash -s 91 ./cmd
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/develop/scripts/coverage.sh | bash -s 90 ./config
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/develop/scripts/coverage.sh | bash -s 86 ./internal

test:
	$(GO) clean -testcache
	$(GO) test -v $(GO_LIST_TO_TEST) -timeout=5m -parallel=1 -failfast -short

test-e2e:
	$(GO) clean -testcache
	$(GO) test -v ./e2e/scan_languages/scan_languages_test.go -timeout=10m -parallel=1 -failfast

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

build-install-cli-linux:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux" &> /dev/null
	CGO_ENABLED=0 GOOS=linux $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux" ./cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux"
	horusec-linux version

build-install-cli-darwin:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac" &> /dev/null
	CGO_ENABLED=0 GOOS=darwin $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac" ./cmd/app/main.go
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac"
	horusec-mac version

build-install-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" ./cmd/app/main.go

pipeline: fmt fix-imports lint test coverage build security
