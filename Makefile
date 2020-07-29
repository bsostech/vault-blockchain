.PHONY: build-local
.PHONY: lint install-lint-tools
.PHONY: run-local setup-plugin-local

ROOT_TOKEN ?= root
VAULT_ADDR ?= http://localhost:8200

build-local:
	CGO_ENABLED=1 go build \
	-ldflags="-s -w" \
	-o plugins/vault-bridgex cmd/bridgex/main.go

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

