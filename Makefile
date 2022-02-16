GO ?= go
GOFMT ?= gofmt
GO_FILES ?= $$(find . -name '*.go' | grep -v vendor | grep -v /examples/)
GO_LIST_TO_TEST ?= $$(go list ./... | grep -v /examples/ | grep -v /e2e/)
GOLANG_CI_LINT ?= golangci-lint
GO_IMPORTS ?= goimports
GO_IMPORTS_LOCAL ?= github.com/ZupIT/horusec/
GO_FUMPT ?= gofumpt
GO_GCI ?= gci
ADDLICENSE ?= addlicense
HORUSEC ?= horusec
DOCKER_COMPOSE ?= docker-compose
PATH_BINARY_BUILD_CLI ?= $(GOPATH)/bin
ARCH_ARM64 ?= arm64
ARCH_AMD64 ?= amd64
MAIN = ./cmd/app

lint:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOLANG_CI_LINT) run -v --timeout=5m -c .golangci.yml ./...

coverage:
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/coverage.sh | bash -s 90 ./cmd
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/coverage.sh | bash -s 90 ./config
	curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec-devkit/main/scripts/coverage.sh | bash -s 86 ./internal

test:
	$(GO) clean -testcache
	$(GO) test -v $(GO_LIST_TO_TEST) -race -timeout=5m -parallel=1 -failfast -short

test-e2e:
	sh ./deployments/scripts/build-all-tools.sh
	$(GO) clean -testcache
	$(GO) test -v ./e2e/analysis/... -timeout=30m -parallel=1 -failfast
	$(GO) clean -testcache
	$(GO) test -v ./e2e/commands/... -timeout=30m -parallel=1 -failfast

format: install-format-dependencies
	$(GOFMT) -s -l -w $(GO_FILES)
	$(GO_IMPORTS) -w -local $(GO_IMPORTS_LOCAL) $(GO_FILES)
	$(GO_FUMPT) -l -w $(GO_FILES)
	$(GO_GCI) -w -local $(GO_IMPORTS_LOCAL) $(GO_FILES)

install-format-dependencies:
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	$(GO) install mvdan.cc/gofumpt@latest
	$(GO) install github.com/daixiang0/gci@v0.2.9

license:
	$(GO) install github.com/google/addlicense@latest
	@$(ADDLICENSE) -check -f ./copyright.txt $(shell find -regex '.*\.\(go\|js\|ts\|yml\|yaml\|sh\|dockerfile\)')

license-fix:
	$(GO) install github.com/google/addlicense@latest
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

build-install-cli-linux-amd64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_AMD64)" &> /dev/null
	GOOS=linux GOARCH=$(ARCH_AMD64) $(GO) build -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_AMD64)" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_AMD64)"
	horusec-linux-$(ARCH_AMD64) version

build-install-cli-linux-arm64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_ARM64)" &> /dev/null
	GOOS=linux GOARCH=$(ARCH_ARM64) $(GO) build -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_ARM64)" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_ARM64)"
	horusec-linux-$(ARCH_ARM64) version

build-install-cli-darwin-amd64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_AMD64)" &> /dev/null
	GOOS=darwin GOARCH=$(ARCH_AMD64) $(GO) build -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_AMD64)" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_AMD64)"
	horusec-mac-$(ARCH_AMD64) version

build-install-cli-darwin-arm64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_ARM64)" &> /dev/null
	GOOS=darwin GOARCH=$(ARCH_ARM64) $(GO) build -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_ARM64)" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_ARM64)"
	horusec-mac-$(ARCH_ARM64) version


build-install-cli-linux:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux" &> /dev/null
	GOOS=linux $(GO) build -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux"
	horusec-linux version

build-install-cli-darwin:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac" &> /dev/null
	GOOS=darwin $(GO) build -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac"
	horusec-mac version

build-install-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -o "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" $(MAIN)

build-install-stand-alone-cli-linux-amd64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_AMD64)" &> /dev/null
	GOOS=linux GOARCH=$(ARCH_AMD64) $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux-amd64" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_AMD64)"
	horusec-linux-$(ARCH_AMD64) version

build-install-stand-alone-cli-linux-arm64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_ARM64)" &> /dev/null
	GOOS=linux GOARCH=$(ARCH_ARM64) $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-linux-arm64" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-linux-$(ARCH_ARM64)"
	horusec-linux-$(ARCH_ARM64) version

build-install-stand-alone-cli-darwin-amd64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_AMD64)" &> /dev/null
	GOOS=darwin GOARCH=$(ARCH_ARM64) $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_AMD64)"
	horusec-mac-$(ARCH_AMD64) version

build-install-stand-alone-cli-darwin-arm64:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-mac-$(ARCH_ARM64)" &> /dev/null
	GOOS=darwin GOARCH=$(ARCH_ARM64) $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -a  -o "$(PATH_BINARY_BUILD_CLI)/horusec-mac" $(MAIN)
	chmod +x "$(PATH_BINARY_BUILD_CLI)/horusec-mac-arm64"
	horusec-mac-$(ARCH_ARM64) version

build-install-stand-alone-cli-windows:
	rm -rf "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" &> /dev/null
	env GOOS=windows GOARCH=amd64 $(GO) build -ldflags "-X github.com/ZupIT/horusec/config/dist.standAlone=true" -o "$(PATH_BINARY_BUILD_CLI)/horusec-win.exe" $(MAIN)

install:
	./deployments/scripts/install.sh latest

install-beta:
	./deployments/scripts/install.sh latest-beta

install-rc:
	./deployments/scripts/install.sh latest-rc


pipeline: format lint test coverage security
