install-lint-tools:
	GO111MODULE=off go get -u -d golang.org/x/lint/golint
	GO111MODULE=off go install golang.org/x/lint/golint
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.23.7

lint:
	golint -set_exit_status ./...
	golangci-lint run ./...
