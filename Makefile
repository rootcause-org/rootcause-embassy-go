.PHONY: check build vet lint test fmt

# The one gate. CI and a release run exactly this.
check: build vet lint test

build:
	go build ./...

vet:
	go vet ./...

# golangci-lint is optional locally: skip gracefully rather than fail a checkout
# that has not installed it.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed — skipping"; \
	fi

test:
	go test ./...

fmt:
	gofmt -w .
