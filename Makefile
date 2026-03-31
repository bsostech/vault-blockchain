.PHONY: build-local
.PHONY: lint install-lint-tools
.PHONY: run-local setup-plugin-local smoke-local setup-plugin-local-smoke

ROOT_TOKEN ?= root
VAULT_ADDR ?= http://localhost:8200

build-local:
	CGO_ENABLED=0 GOOS=$(shell go env GOOS) GOARCH=$(shell go env GOARCH) go build \
	-ldflags="-s -w" \
	-o plugins/vault-blockchain cmd/blockchain/main.go

install-lint-tools:
	GO111MODULE=off go get -u -d golang.org/x/lint/golint
	GO111MODULE=off go install golang.org/x/lint/golint
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.23.7

lint:
	golint -set_exit_status ./...
	golangci-lint run ./...

run-local:
	vault server -dev -dev-root-token-id=${ROOT_TOKEN} -dev-plugin-dir=./plugins

setup-plugin-local:
	ROOT_TOKEN=${ROOT_TOKEN} VAULT_ADDR=${VAULT_ADDR} bash scripts/setup_plugin_local.sh

# Same as setup-plugin-local then run scripts/e2e_smoke.sh (requires Vault already running).
setup-plugin-local-smoke:
	ROOT_TOKEN=${ROOT_TOKEN} VAULT_ADDR=${VAULT_ADDR} SMOKE=1 bash scripts/setup_plugin_local.sh

# Assumes plugin is registered and blockchain/ is enabled; only runs smoke (set VAULT_TOKEN).
smoke-local:
	VAULT_ADDR=${VAULT_ADDR} VAULT_TOKEN=${ROOT_TOKEN} bash scripts/e2e_smoke.sh

