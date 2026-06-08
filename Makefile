VERSION    ?= 0.0.0-dev
GIT_SHA    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOBIN      := $(shell go env GOPATH)/bin

GOLANGCI_LINT_VERSION := v2.12.2
GOFUMPT_VERSION       := latest

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(GIT_SHA) -X main.date=$(BUILD_DATE)

.PHONY: setup build lint test test-coverage test-integration ci fmt clean tools

setup: tools
	git config core.hooksPath .githooks
	@echo "ready to develop"

tools:
	@command -v golangci-lint >/dev/null 2>&1 || \
	  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@command -v gofumpt >/dev/null 2>&1 || \
	  go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

build:
	@mkdir -p bin
	go build -ldflags '$(LDFLAGS)' -o ./bin/ogl ./cmd/ogl

lint: tools
	go vet ./...
	$(GOBIN)/golangci-lint run ./...

test:
	go test -race ./...

test-coverage:
	go test -race -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...
	@./scripts/check-coverage.sh coverage.out

test-integration:
	@if [ -d ./internal/integration ]; then \
	  go test -tags=integration -race -covermode=atomic -coverprofile=coverage-integration.out ./internal/integration/...; \
	else \
	  echo "no integration package yet; skipping"; \
	fi

fmt: tools
	$(GOBIN)/gofumpt -w .

ci: lint test-coverage build

clean:
	rm -rf ./bin coverage.out coverage.html coverage-integration.out
