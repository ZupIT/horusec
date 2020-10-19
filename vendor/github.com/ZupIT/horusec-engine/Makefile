GO ?= go
GOFMT ?= gofmt
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
GOCILINT ?= ./bin/golangci-lint

# Format all files founded in GO
fmt:
	$(GOFMT) -w $(GOFMT_FILES)

# Run converage with threshold
coverage:
	deployments/scripts/coverage.sh 75

# Check lint of project setup on file .golangci.yml
lint:
    ifeq ($(wildcard $(GOCILINT)), $(GOCILINT))
#		$(GOCILINT) run -v --timeout=2m -c .golangci.yml ./... # not implemented lint equals of the horusec
		$(GOCILINT) run -v --timeout=2m ./...
    else
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.25.0
#		$(GOCILINT) run -v --timeout=2m -c .golangci.yml ./...  # not implemented lint equals of the horusec
		$(GOCILINT) run -v --timeout=2m ./...  # not implemented lint equals of the horusec
    endif

# Run all tests of project but stop the execution on the first test fail
test:
	$(GO) clean -testcache && $(GO) test -v ./... -timeout=2m -parallel=1 -failfast -short

# Run all steps required to pass on pipeline
pipeline: fmt lint test coverage
