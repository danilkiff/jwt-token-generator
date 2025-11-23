# SPDX-License-Identifier: MIT

# List of CLI binaries to build.
BINS := jwt-claims jwt-sign-hs256 jwt-sign-rs256 jwt-sign-es256 jwe-encrypt-rsa-oaep-a256gcm

# Directory where built binaries will be placed.
BIN_DIR := bin

# Go command to use (can be overridden: GO=gotip make build).
GO ?= go

.PHONY: all build test cover cover-html fmt tidy vet lint clean help

all: test build ## Default target: run tests and build all CLI binaries into ./bin

build: $(BINS:%=$(BIN_DIR)/%) ## Build all CLI binaries into ./bin

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: | $(BIN_DIR) ## Build a single CLI binary into ./bin
	$(GO) build -o $@ ./cmd/$*

test: ## Run all tests
	$(GO) test ./...

cover: ## Run tests with coverage and print a short summary
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out

cover-html: cover ## Generate HTML coverage report and open it in a browser
	$(GO) tool cover -html=coverage.out

fmt: ## Format Go source files
	$(GO) fmt ./...

tidy: ## Run go mod tidy and ensure go.mod/go.sum are unchanged
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

vet: ## Run basic static analysis with go vet
	$(GO) vet ./...

lint: vet ## Run linting (currently aliased to go vet)

clean: ## Remove build and coverage artifacts
	$(GO) clean -testcache
	rm -rf $(BIN_DIR) coverage.out

help: ## Show this help message
	@echo "Usage: make <target>"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*##"} {printf "  %-16s %s\n", $$1, $$2}'
