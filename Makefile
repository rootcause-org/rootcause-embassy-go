.PHONY: check build vet lint test conformance fmt

# The one gate. CI and a release run exactly this.
check: build vet lint test

build:
	go build ./...

vet:
	go vet ./...

# depguard and forbidigo carry posture rules, not style preferences, so a missing
# linter is a failed check rather than a silent skip.
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is required: brew install golangci-lint (or see https://golangci-lint.run/welcome/install/)"; \
		exit 1; \
	}
	golangci-lint run

test:
	go test ./...

conformance:
	go test ./internal/contract

fmt:
	gofmt -w .
