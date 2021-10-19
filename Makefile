GO ?= go
GOFMT ?= gofmt
GO_FILES ?= $$(find . -name '*.go' | grep -v vendor)
GO_LIST_TO_TEST ?= $$(go list ./... | grep -v /examples/ | grep -v /e2e/)
GOLANG_CI_LINT ?= ./bin/golangci-lint
GO_IMPORTS ?= goimports
GO_IMPORTS_LOCAL ?= github.com/ZupIT/horusec
ADDLICENSE ?= addlicense
HORUSEC ?= horusec
DOCKER_COMPOSE ?= docker-compose
PATH_BINARY_BUILD_CLI ?= $(GOPATH)/bin
MAIN = ./cmd/app

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
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/coverage.sh | bash -s 91 ./cmd
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/coverage.sh | bash -s 90 ./config
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/coverage.sh | bash -s 86 ./internal

test:
	$(GO) clean -testcache
	$(GO) test -v $(GO_LIST_TO_TEST) -race -timeout=5m -parallel=1 -failfast -short

test-e2e:
	$(GO) clean -testcache
	$(GO) test -v ./e2e/... -timeout=10m -parallel=1 -failfast

fix-imports:
    ifeq (, $(shell which $(GO_IMPORTS)))
		$(GO) get -u golang.org/x/tools/cmd/goimports
		$(GO_IMPORTS) -local $(GO_IMPORTS_LOCAL) -w $(GO_FILES)
    else
		$(GO_IMPORTS) -local $(GO_IMPORTS_LOCAL) -w $(GO_FILES)
    endif

license:
	$(GO) get -u github.com/google/addlicense
	@$(ADDLICENSE) -check -f ./copyright.txt $(shell find -regex '.*\.\(go\|js\|ts\|yml\|yaml\|sh\|dockerfile\)')

license-fix:
	$(GO) get -u github.com/google/addlicense
	@$(ADDLICENSE) -f ./copyright.txt $(shell find -regex '.*\.\(go\|js\|ts\|yml\|yaml\|sh\|dockerfile\)')

security:
    ifeq (, $(shell which $(HORUSEC)))
		make install
		$(HORUSEC) start -p="./" -e="true"
    else
		$(HORUSEC) start -p="./" -e="true"
    endif

build-dev:
	$(GO) build -o horusec $(MAIN)

build-install-cli-linux:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux" &> /dev/null
	CGO_ENABLED=0 GOOS=linux $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux"
	horusec-linux version

build-install-cli-darwin:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac" &> /dev/null
	CGO_ENABLED=0 GOOS=darwin $(GO) build -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac"
	horusec-mac version

build-install-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" $(MAIN)

build-install-stand-alone-cli-linux:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux" &> /dev/null
	CGO_ENABLED=0 GOOS=linux $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux"
	horusec-linux version

build-install-stand-alone-cli-darwin:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac" &> /dev/null
	CGO_ENABLED=0 GOOS=darwin $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -a -installsuffix cgo -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac"
	horusec-mac version

build-install-stand-alone-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -o "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" $(MAIN)

install:
	./deployments/scripts/install.sh latest

pipeline: fmt fix-imports lint test coverage security
